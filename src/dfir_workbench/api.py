"""Durable HTTP API service shell for DFIR Evidence Workbench.

Smallest runnable FastAPI boundary providing:
- env-only config (DFIRWB_* prefix, pydantic-settings) with no secrets in source
- /healthz and /readyz returning deterministic JSON
- structured error responses
- dependency wiring seams for config, principal (trusted analyst+tenant context)
- synthetic dev-only principal for local tests (explicitly isolated/gated)
- integration of *only* reviewed domain modules (adapters + interop) via import
- dev-only synthetic routes explicitly labeled; never used for real data

The request context boundary (get_current_principal) is used by all protected
routes. Tenant scope is *always* derived from the trusted Principal returned by
the dependency; caller-supplied tenant/analyst values (headers, query, body)
are ignored for authorization decisions.

Current implementation: dev/test = isolated synthetic context only.
Prod: fail-closed (raises until real auth wired).

Do not claim production auth, persistence, or full routes (see child cards).
Invalid configuration fails closed.

Launch (native):
  DFIRWB_ENV=dev uvicorn dfir_workbench.api:app --host 127.0.0.1 --port 8080

Podman example documented in README.md.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

from dfir_workbench import __version__

# Wire reviewed domain/service modules at import time (seam; no claims beyond shell)
# These are the only integrated modules in this card.
import dfir_workbench.adapters.disk_memory_adapter as _disk  # noqa: F401
import dfir_workbench.adapters.uac_adapter as _uac  # noqa: F401
import dfir_workbench.adapters.velociraptor_adapter as _velo  # noqa: F401
import dfir_workbench.adapters.thehive_ingest_adapter as _hive  # noqa: F401
import dfir_workbench.adapters.dfir_iris_ingest_adapter as _iris  # noqa: F401
import dfir_workbench.interop as _interop  # noqa: F401
import dfir_workbench.db as _db  # noqa: F401  # postgres seam + timeline_entry_flag contract + repo
import dfir_workbench.ingest as _ingest  # noqa: F401  # pre-commit boundary using schemas + both vendor projections
import dfir_workbench.audit as _audit  # noqa: F401  # structured audit event sink
import dfir_workbench.metrics as _metrics  # noqa: F401  # in-process metrics registry
import dfir_workbench.alerts as _alerts  # noqa: F401  # alert rule evaluation over metrics
import dfir_workbench.local_runner as _runner  # noqa: F401  # synthetic local prototype runner
from psycopg_pool import AsyncConnectionPool


class Settings(BaseSettings):
    """Environment-driven configuration. Secrets NEVER appear here or in source.

    All values come from DFIRWB_* env vars or safe defaults.
    Invalid values cause immediate fail-closed (ValidationError).
    """

    env: str = Field(
        default="dev",
        description="One of dev|test|prod. prod disables dev-only routes and synthetic context.",
    )
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: str = Field(default="info")
    # Explicitly synthetic / dev-only. Never use for real tenants or evidence.
    synthetic_tenant: str = Field(
        default="synthetic-org-1",
        description="DEV/TEST ONLY synthetic tenant. Labeled and gated; absent from prod responses.",
    )
    cors_origins: str = Field(
        default="",
        description="Optional comma-separated origins for separately hosted dev clients; same-origin proxy is the default.",
    )

    # Database configuration. The URL (which may contain secrets) MUST come exclusively
    # from the DFIRWB_DATABASE_URL environment variable. No default, no fallback in source.
    # Invalid format or missing when required will cause fail-closed behavior downstream.
    database_url: str | None = Field(
        default=None,
        description="PostgreSQL connection URL (postgresql://user:***@host/dbname). ONLY from DFIRWB_DATABASE_URL env var. Secrets never in source or defaults.",
    )

    # Production authentication configuration. Secrets are supplied only by env/
    # secret injection; there are intentionally no usable production defaults.
    oidc_issuer: str | None = Field(default=None)
    oidc_audience: str | None = Field(default=None)
    oidc_hs256_secret: str | None = Field(default=None, repr=False)
    oidc_jwks_json: str | None = Field(default=None, repr=False)
    oidc_required_scopes: str = Field(default="cases:read")

    model_config = {
        "env_prefix": "DFIRWB_",
        "case_sensitive": False,
        "extra": "ignore",
    }

    @field_validator("env")
    @classmethod
    def _validate_env(cls, v: str) -> str:
        allowed = {"dev", "test", "prod"}
        if v not in allowed:
            raise ValueError(f"env must be one of {allowed}, got {v!r}")
        return v

    @field_validator("synthetic_tenant")
    @classmethod
    def _validate_synthetic_tenant(cls, v: str, info: Any) -> str:
        # At construction time we can only warn via validation; gating is in code paths.
        if not v or not isinstance(v, str):
            raise ValueError("synthetic_tenant must be non-empty string")
        return v

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str) or not (v.startswith("postgresql://") or v.startswith("postgres://")):
            raise ValueError("database_url must be a postgresql:// or postgres:// URL")
        return v


# Instantiate at module load: forces validation fail-closed for bad config before any request.
# Tests set DFIRWB_ENV etc. *before* importing this module.
settings = Settings()


@dataclass(frozen=True)
class Principal:
    """Trusted request context carrying tenant/analyst scope for authorization.

    This is the *only* source of truth for tenant and analyst identity on
    protected routes. All reads, mutations, and queries MUST use
    principal.tenant_id for scoping (server-side filter/join).

    - tenant_id: stable tenant/organization identifier (never client chosen)
    - analyst_id: stable analyst identifier within tenant
    - is_synthetic: True only for the dev/test synthetic context

    Interface contract (stable for future cards):
    - Real auth (Entra ID / OIDC / JWT) will populate this from validated
      claims/tokens. Mapping from identity provider subject/org to
      (tenant_id, analyst_id) happens inside the seam.
    - No raw PII, tokens, emails, object IDs, or other sensitive identity
      fields are carried or leaked through this interface or responses.
    - Dev-only synthetic is *clearly isolated*: constructed only from
      DFIRWB_SYNTHETIC_TENANT (gated by env != prod); never mixed with
      real data paths.

    Fail-closed: get_current_principal raises on prod or absent context;
    protected routes depending on it cannot execute without it.
    Never treat X-*-Tenant / analyst headers or body fields as auth.
    """

    tenant_id: str
    analyst_id: str
    is_synthetic: bool = True
    subject: str | None = field(default=None, repr=False)
    roles: frozenset[str] = field(default_factory=frozenset, repr=False)
    scopes: frozenset[str] = field(default_factory=frozenset, repr=False)


def get_settings() -> Settings:
    """Dependency seam. Returns validated settings or fails closed."""
    # settings already constructed at import; this seam allows override in tests.
    return settings


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _jwt_error(message: str = "invalid bearer token") -> HTTPException:
    # Never expose token contents, claims, or provider errors.
    return HTTPException(status_code=401, detail=message)


def _verify_jwt(token: str, s: Settings) -> dict[str, Any]:
    """Verify compact JWTs for deterministic fixtures (HS256) and Entra JWKS (RS256)."""
    try:
        head, body, signature = token.split(".")
        header = json.loads(_b64url_decode(head))
        claims = json.loads(_b64url_decode(body))
        alg = header.get("alg")
        signing_input = f"{head}.{body}".encode()
        if alg == "HS256":
            if not s.oidc_hs256_secret:
                raise ValueError
            expected = hmac.new(s.oidc_hs256_secret.encode(), signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _b64url_decode(signature)):
                raise ValueError
        elif alg == "RS256":
            if not s.oidc_jwks_json:
                raise ValueError
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
            jwks = json.loads(s.oidc_jwks_json)
            key = next(k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid") and k.get("kty") == "RSA")
            n = int.from_bytes(_b64url_decode(key["n"]), "big")
            e = int.from_bytes(_b64url_decode(key["e"]), "big")
            rsa.RSAPublicNumbers(e, n).public_key().verify(
                _b64url_decode(signature), signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        else:
            raise ValueError
        now = int(time.time())
        if s.oidc_issuer is None or claims.get("iss") != s.oidc_issuer:
            raise ValueError
        aud = claims.get("aud")
        if s.oidc_audience is None or s.oidc_audience not in (aud if isinstance(aud, list) else [aud]):
            raise ValueError
        if not isinstance(claims.get("exp"), (int, float)) or now >= claims["exp"]:
            raise ValueError
        if "nbf" in claims and (not isinstance(claims["nbf"], (int, float)) or now < claims["nbf"]):
            raise ValueError
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise ValueError
        return claims
    except Exception as exc:
        raise _jwt_error() from exc


def _principal_from_claims(claims: dict[str, Any]) -> Principal:
    tenant_id = claims.get("tid") or claims.get("tenant_id")
    # Prefer a server-side directory mapping claim; otherwise use the opaque sub.
    # Do not expose Entra's raw oid/object-id as an analyst identifier.
    analyst_id = claims.get("analyst_id") or claims.get("sub")
    if not isinstance(tenant_id, str) or not tenant_id or not isinstance(analyst_id, str) or not analyst_id:
        raise _jwt_error()
    raw_scopes = claims.get("scp", "")
    raw_roles = claims.get("roles", [])
    scopes = frozenset(raw_scopes.split()) if isinstance(raw_scopes, str) else frozenset()
    roles = frozenset(raw_roles) if isinstance(raw_roles, list) and all(isinstance(x, str) for x in raw_roles) else frozenset()
    return Principal(tenant_id=tenant_id, analyst_id=analyst_id, is_synthetic=False, subject=claims["sub"], roles=roles, scopes=scopes)


def get_current_principal(
    settings: Settings = Depends(get_settings),
    request: Request = None,
) -> Principal:
    """Return trusted scope from a validated bearer JWT; synthetic only in dev/test."""
    auth = request.headers.get("authorization", "") if request is not None else ""
    if auth:
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise _jwt_error()
        return _principal_from_claims(_verify_jwt(token, settings))
    if settings.env == "prod":
        raise _jwt_error("authentication required")
    return Principal(tenant_id=settings.synthetic_tenant, analyst_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", is_synthetic=True, scopes=frozenset({"cases:read", "cases:write"}))


def require_scopes(*required: str):
    """FastAPI dependency factory enforcing scopes/roles with a generic 403."""
    def dependency(p: Principal = Depends(get_current_principal)) -> Principal:
        if not set(required).issubset(p.scopes | p.roles):
            raise HTTPException(status_code=403, detail="insufficient scope")
        return p
    return dependency


# ------------------------------------------------------------------
# PostgreSQL / DB seams (added for durable persistence wiring)
# - pool managed via lifespan
# - get_db_pool and get_timeline_flag_repository are the DI seams
# - tenant isolation is enforced inside the repository implementation (db.py)
# - fails closed on unavailable DB
# ------------------------------------------------------------------

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan that manages the AsyncConnectionPool if database_url configured.

    Pool creation failure does not crash startup (allows healthz to report); protected
    DB routes will fail-closed via their deps when pool missing or bad.
    In dev with DB configured, auto-bootstrap schema + apply migrations (idempotent).
    """
    pool = None
    if settings.database_url:
        try:
            pool = AsyncConnectionPool(
                settings.database_url,
                min_size=1,
                max_size=8,
                open=False,
            )
            await pool.open()
            # Dev-only automatic bootstrap for persistent dev volumes (idempotent, safe)
            if settings.env == "dev":
                try:
                    from dfir_workbench.db import ensure_dev_schema_and_migrations  # local import to avoid circulars

                    applied = await ensure_dev_schema_and_migrations(pool)
                    if _db.TimelineFlagRepository._is_uuid(settings.synthetic_tenant):
                        async with pool.connection() as conn:
                            await conn.execute(
                                "INSERT INTO dfir.analyst (tenant_id, analyst_id, name) VALUES (%s::uuid,%s::uuid,%s) ON CONFLICT DO NOTHING",
                                (settings.synthetic_tenant, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "synthetic-dev-analyst"),
                            )
                    if applied:
                        import logging

                        logging.getLogger(__name__).info("dev migrations applied: %s", applied)
                except Exception:
                    # Do not fail startup; health/readiness will surface issues
                    pass
        except Exception:
            if pool is not None:
                try:
                    await pool.close()
                except Exception:
                    pass
            # do not prevent startup; readyz and route deps will surface the problem
            pool = None
    app.state.db_pool = pool
    try:
        yield
    finally:
        if pool is not None:
            await pool.close()


async def get_db_pool(request: Request) -> AsyncConnectionPool:
    """Dependency that returns the managed pool or fails closed (503)."""
    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        s = get_settings()
        if s.database_url:
            raise HTTPException(status_code=503, detail="database pool unavailable or failed to initialize")
        raise HTTPException(status_code=503, detail="database not configured (set DFIRWB_DATABASE_URL)")
    return pool


def get_timeline_flag_repository(
    pool: AsyncConnectionPool = Depends(get_db_pool),
) -> _db.TimelineFlagRepository:
    """DI seam for the tenant-scoped flag repository. All operations go through principal scope."""
    return _db.TimelineFlagRepository(pool)


def get_ingest_repository(
    pool: AsyncConnectionPool = Depends(get_db_pool),
) -> _db.IngestRepository:
    """DI seam for tenant-scoped ingest envelope repository (preview/approval/commit/quarantine)."""
    return _db.IngestRepository(pool)


def get_audit_repository(request: Request) -> _audit.AuditRepository:
    """DI seam for the append-only audit sink. Degrades to structured logging if DB is down

    (fail-visible, never silently drops the event; see audit.py docstring).
    """
    pool = getattr(request.app.state, "db_pool", None)
    return _audit.AuditRepository(pool)


# ------------------------------------------------------------------
# Dev-only synthetic tenant-scoped store (for authz boundary regression tests ONLY)
# This is a minimal in-memory demonstration of server-enforced scoping.
# - Keyed exclusively by principal.tenant_id
# - Real persistence (Postgres etc.) will use the same principal.tenant_id filter
# - Cleared explicitly in tests; never survives across runs
# - Absolutely not for real evidence or production data
# ------------------------------------------------------------------
_dev_scoped_store: dict[str, dict[str, list[dict[str, Any]]]] = {"cases": {}}

_case_seq: int = 0


def _next_case_id() -> str:
    """Generate unique case id across tenants for the dev demo store."""
    global _case_seq
    _case_seq += 1
    return f"case-{_case_seq}"


def _reset_dev_scoped_store() -> None:
    """Test helper to isolate synthetic store between authz tests."""
    global _case_seq
    _dev_scoped_store["cases"] = {}
    _case_seq = 0


def _structured_error(code: str, message: str, retryable: bool = False) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "retryable": retryable}}


def create_app() -> FastAPI:
    """Factory for the FastAPI app (supports test overrides if needed)."""
    app = FastAPI(
        title="DFIR Evidence Workbench",
        version=__version__,
        description=(
            "Durable API service shell. Health contract, config, principal, and persistence seams. "
            "Synthetic dev-only context is explicitly labeled and never used for real evidence. "
            "Postgres wiring (migrations + tenant-scoped repos) added; full routes in follow-on cards."
        ),
        # Hide docs in prod shell (defense in depth)
        docs_url="/docs" if settings.env != "prod" else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    if settings.env != "prod":
        cors_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
        if cors_origins:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=cors_origins,
                allow_methods=["GET", "POST", "DELETE"],
                allow_headers=["content-type", "authorization"],
            )

    @app.middleware("http")
    async def _request_size_limit(request: Request, call_next: Any) -> JSONResponse:
        """Reject oversized JSON before parsing or persistence."""
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > 1_048_576:
            return JSONResponse(status_code=413, content=_structured_error("REQUEST_TOO_LARGE", "request exceeds 1 MiB", False))
        return await call_next(request)

    def _principal_for_audit(request: Request) -> Principal | None:
        """Resolve whichever Principal will/did authorize this request, honoring test overrides.

        Respects app.dependency_overrides for get_current_principal (as FastAPI's own DI
        would) so tests that override authentication still produce tenant-attributed audit
        rows; production has no override and this simply re-derives the trusted principal.
        """
        override = request.app.dependency_overrides.get(get_current_principal)
        try:
            return override() if override is not None else get_current_principal(settings, request)
        except Exception:
            return None

    _OBJECT_ID_PATH_PARAMS = ("case_id", "envelope_id", "evidence_id", "finding_id", "timeline_entry_id")

    @app.middleware("http")
    async def _observability(request: Request, call_next: Any) -> JSONResponse:
        """Attach a correlation ID, time the request, and emit request metrics + an audit event.

        The audit event here is a coarse HTTP-level record (method/path/status/correlation_id)
        attributed to the resolved principal's tenant/actor, plus any object id present in the
        route's path params. Route handlers doing sensitive mutations may additionally emit
        their own richer audit.record(...) calls with case/object detail. This middleware never
        blocks the response on audit-write failure (get_audit_repository degrades to logging).
        """
        correlation_id = request.headers.get("x-correlation-id") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            _metrics.inc_counter("http_requests_total", {"path": request.url.path, "method": request.method, "status": "500"})
            raise
        duration = time.monotonic() - start
        response.headers["x-correlation-id"] = correlation_id
        _metrics.inc_counter(
            "http_requests_total",
            {"path": request.url.path, "method": request.method, "status": str(response.status_code)},
        )
        _metrics.observe_histogram("http_request_duration_seconds", duration, {"path": request.url.path})
        if request.url.path not in ("/healthz", "/readyz", "/metrics", "/alerts"):
            audit_repo = get_audit_repository(request)
            result = "success" if response.status_code < 400 else ("denied" if response.status_code in (401, 403) else "error")
            principal = _principal_for_audit(request)
            tenant_id = principal.tenant_id if principal and _db.TimelineFlagRepository._is_uuid(principal.tenant_id) else None
            object_type = object_id = None
            for key in _OBJECT_ID_PATH_PARAMS:
                if key in request.path_params:
                    object_type, object_id = key.removesuffix("_id"), request.path_params[key]
                    break
            try:
                await audit_repo.record(
                    action=f"http.{request.method.lower()}",
                    result=result,
                    correlation_id=correlation_id,
                    source="api",
                    actor_type="user" if principal else "system",
                    actor_id=principal.analyst_id if principal else None,
                    tenant_id=tenant_id,
                    object_type=object_type,
                    object_id=object_id,
                    metadata={"path": request.url.path, "status_code": response.status_code},
                )
            except Exception:
                _metrics.inc_counter("audit_write_failures_total")
        return response

    # Structured error handlers (consistent envelope, no trace leaks)
    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Any, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_structured_error(
                code=f"HTTP_{exc.status_code}",
                message=str(exc.detail),
                retryable=exc.status_code < 500,
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Any, exc: Exception) -> JSONResponse:
        # Fail closed, generic message
        return JSONResponse(
            status_code=500,
            content=_structured_error(
                code="INTERNAL_ERROR",
                message="internal server error",
                retryable=False,
            ),
        )

    # Public health endpoints (deterministic, no side effects, always available)
    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        """Liveness probe. Returns deterministic JSON."""
        return {
            "status": "healthy",
            "version": __version__,
            "service": "dfir-evidence-workbench",
        }

    @app.get("/readyz", tags=["health"])
    async def readyz(
        s: Settings = Depends(get_settings),
        p: Principal | None = None,  # optional for seam demo; not required for ready
    ) -> JSONResponse:
        """Readiness including wiring seams for reviewed modules.

        Uses get_settings and (synthetic) principal seam. Reports reviewed adapters
        and interop as wired. Actually probes the DB pool with SELECT 1 when
        configured (a real dependency check, not just "was a pool object created").
        """
        principal_info: dict[str, Any] | None = None
        if s.env != "prod":
            # exercise the seam in non-prod without failing ready
            try:
                pp = p or get_current_principal(s)
                principal_info = {
                    "tenant_id": pp.tenant_id,
                    "is_synthetic": pp.is_synthetic,
                }
            except Exception:
                principal_info = {"status": "synthetic_seam_unavailable"}

        db_status = "not_configured"
        if s.database_url:
            db_status = "unreachable"
            try:
                async with app.state.db_pool.connection() as conn:
                    await conn.execute("SELECT 1")
                db_status = "ok"
            except Exception:
                db_status = "unreachable"

        body = {
            "status": "ready" if db_status in ("ok", "not_configured") else "degraded",
            "version": __version__,
            "env": s.env,
            "dependencies": {
                "config": "ok",
                "reviewed_adapters": ["disk_memory", "uac", "velociraptor", "thehive_ingest", "dfir_iris_ingest"],
                "interop": "wired",
                "ingest_boundary": "wired (preview redaction idempotency quarantine using projections)",
                "principal_seam": "synthetic-dev-only" if s.env != "prod" else "not_wired_prod",
                "persistence": "wired" if s.database_url else "not_configured",
                "database": db_status,
                "db_driver": "psycopg",
                "ingest": "wired (preview/approve/commit/quarantine)",
                "audit_sink": "wired" if s.database_url else "degraded (logging fallback only)",
            },
            "principal": principal_info,
            "note": (
                "synthetic context only where explicitly labeled dev-only. "
                "Postgres migrations + TimelineFlagRepository wired via seams; "
                "use DFIRWB_DATABASE_URL for real DB (tenant isolation at repo layer)."
            )
            if s.env != "prod"
            else "production shell - no synthetic data",
        }
        status_code = 200 if db_status in ("ok", "not_configured") else 503
        return JSONResponse(status_code=status_code, content=body)

    @app.get("/metrics", tags=["health"], include_in_schema=False)
    def metrics_endpoint() -> Any:
        """Prometheus text-format exposition. No auth: contains no tenant data, only aggregate counters."""
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(_metrics.render_prometheus_text(), media_type="text/plain; version=0.0.4")

    @app.get("/alerts", tags=["health"], include_in_schema=False)
    def alerts_endpoint() -> dict[str, Any]:
        """Evaluate alert rules against current in-process metrics.

        No auth: aggregate counters only, no tenant data. A real deployment
        wires the same rule conditions into Prometheus Alertmanager; this
        endpoint lets synthetic requests prove the rule logic actually fires
        (see docs/observability-and-incident-operations.md).
        """
        results = _alerts.evaluate_all()
        return {
            "alerts": [{"name": r.name, "firing": r.firing, "detail": r.detail} for r in results],
            "any_firing": any(r.firing for r in results),
        }



    @app.get("/api/v1/whoami", tags=["auth"])
    def whoami(p: Principal = Depends(require_scopes("cases:read"))) -> dict[str, Any]:
        """Authenticated identity projection; never returns raw token/PII claims."""
        return {
            "tenant_id": p.tenant_id,
            "analyst_id": p.analyst_id,
            "roles": sorted(p.roles),
            "scopes": sorted(p.scopes),
        }

    def _db_uuid(p: Principal) -> str:
        try:
            return str(uuid.UUID(p.tenant_id))
        except (ValueError, AttributeError):
            raise HTTPException(400, "authenticated tenant is not database-addressable")

    async def _resource_list(pool: AsyncConnectionPool, table: str, p: Principal, *, case_id: str | None, q: str | None, limit: int, offset: int) -> dict[str, Any]:
        tenant = _db_uuid(p)
        where = "tenant_id = %s::uuid"
        args: list[Any] = [tenant]
        if case_id:
            where += " AND case_id = %s"
            args.append(case_id)
        if q:
            where += " AND payload::text ILIKE %s"
            args.append(f"%{q}%")
        async with pool.connection() as conn:
            async with conn.cursor(row_factory=_db.dict_row) as cur:
                await cur.execute(f"SELECT payload, created_at::text AS created_at FROM dfir.{table} WHERE {where} ORDER BY created_at DESC LIMIT %s OFFSET %s", (*args, limit, offset))
                rows = await cur.fetchall()
                await cur.execute(f"SELECT count(*) AS count FROM dfir.{table} WHERE {where}", args)
                total = (await cur.fetchone())["count"]
        return {"items": [{**dict(r["payload"]), "created_at": r["created_at"]} for r in rows], "count": total, "limit": limit, "offset": offset}

    async def _resource_create(pool: AsyncConnectionPool, table: str, id_column: str, p: Principal, payload: dict[str, Any]) -> dict[str, Any]:
        tenant = _db_uuid(p)
        item_id = str(payload.get("id") or f"{table}-{uuid.uuid4().hex[:12]}")
        case_id = str(payload.get("case_id") or "")
        if table != "case_record" and not case_id:
            raise HTTPException(400, "case_id required")
        stored = {**payload, "id": item_id, "tenant_id": p.tenant_id}
        if case_id:
            stored["case_id"] = case_id
        async with pool.connection() as conn:
            async with conn.transaction():
                async with conn.cursor(row_factory=_db.dict_row) as cur:
                    if table == "case_record":
                        await cur.execute("INSERT INTO dfir.case_record (tenant_id, case_id, payload) VALUES (%s::uuid,%s,%s::jsonb) RETURNING payload, created_at::text AS created_at", (tenant, item_id, json.dumps(stored)))
                    else:
                        await cur.execute(f"INSERT INTO dfir.{table} (tenant_id, {id_column}, case_id, payload) VALUES (%s::uuid,%s,%s,%s::jsonb) RETURNING payload, created_at::text AS created_at", (tenant, item_id, case_id, json.dumps(stored)))
                    row = await cur.fetchone()
        return {**dict(row["payload"]), "created_at": row["created_at"]}

    @app.post("/api/v1/ingest/preview", tags=["ingest"])
    async def ingest_preview(payload: dict[str, Any], p: Principal = Depends(require_scopes("cases:write")), pool: AsyncConnectionPool = Depends(get_db_pool)) -> dict[str, Any]:
        try:
            return await _ingest.ingest_preview_batch(get_ingest_repository(pool=pool), p, payload.get("items", []), source_system=payload.get("source_system", ""), entity=payload.get("entity"), source_scope=payload.get("source_scope", ""), integration_id=payload.get("integration_id", "default"))
        except _interop.IngestValidationError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/v1/ingest/{envelope_id}/approve", tags=["ingest"])
    async def ingest_approve(envelope_id: str, p: Principal = Depends(require_scopes("cases:write")), repo: _db.IngestRepository = Depends(get_ingest_repository)) -> dict[str, Any]:
        try:
            return (await repo.approve(p, envelope_id)).as_dict()
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/v1/ingest/{envelope_id}/commit", tags=["ingest"])
    async def ingest_commit(envelope_id: str, payload: dict[str, Any] | None = None, p: Principal = Depends(require_scopes("cases:write")), repo: _db.IngestRepository = Depends(get_ingest_repository)) -> dict[str, Any]:
        try:
            return (await repo.apply_commit(p, envelope_id, target_id=(payload or {}).get("target_id"))).as_dict()
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/v1/ingest/{envelope_id}/quarantine", tags=["ingest"])
    async def ingest_quarantine(envelope_id: str, payload: dict[str, Any] | None = None, p: Principal = Depends(require_scopes("cases:write")), repo: _db.IngestRepository = Depends(get_ingest_repository)) -> dict[str, Any]:
        try:
            return (await repo.mark_quarantined(p, envelope_id, reason=(payload or {}).get("reason"))).as_dict()
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/v1/timeline/flags", tags=["timeline"])
    async def create_timeline_flag(payload: dict[str, Any], p: Principal = Depends(require_scopes("cases:write")), repo: _db.TimelineFlagRepository = Depends(get_timeline_flag_repository)) -> dict[str, Any]:
        try:
            return (await repo.create_flag(p, timeline_entry_id=payload.get("timeline_entry_id", ""), note=payload.get("note"))).as_dict()
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/v1/timeline/flags", tags=["timeline"])
    async def list_timeline_flags(timeline_entry_id: str = Query(...), p: Principal = Depends(require_scopes("cases:read")), repo: _db.TimelineFlagRepository = Depends(get_timeline_flag_repository)) -> dict[str, Any]:
        return {"items": [x.as_dict() for x in await repo.list_for_entry(p, timeline_entry_id)]}

    @app.get("/api/v1/cases", tags=["cases"])
    async def list_cases(q: str | None = None, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), p: Principal = Depends(require_scopes("cases:read")), pool: AsyncConnectionPool = Depends(get_db_pool)) -> dict[str, Any]:
        return await _resource_list(pool, "case_record", p, case_id=None, q=q, limit=limit, offset=offset)

    @app.post("/api/v1/cases", tags=["cases"])
    async def create_case(payload: dict[str, Any], p: Principal = Depends(require_scopes("cases:write")), pool: AsyncConnectionPool = Depends(get_db_pool)) -> dict[str, Any]:
        return {"case": await _resource_create(pool, "case_record", "case_id", p, payload)}

    @app.get("/api/v1/evidence", tags=["evidence"])
    async def list_evidence(case_id: str | None = None, q: str | None = None, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), p: Principal = Depends(require_scopes("cases:read")), pool: AsyncConnectionPool = Depends(get_db_pool)) -> dict[str, Any]:
        return await _resource_list(pool, "evidence_metadata", p, case_id=case_id, q=q, limit=limit, offset=offset)

    @app.post("/api/v1/evidence", tags=["evidence"])
    async def create_evidence(payload: dict[str, Any], p: Principal = Depends(require_scopes("cases:write")), pool: AsyncConnectionPool = Depends(get_db_pool)) -> dict[str, Any]:
        if payload.get("content_transferred", False):
            raise HTTPException(400, "evidence content transfer is not supported")
        return {"evidence": await _resource_create(pool, "evidence_metadata", "evidence_id", p, {**payload, "content_transferred": False})}

    @app.get("/api/v1/findings", tags=["findings"])
    async def list_findings(case_id: str | None = None, q: str | None = None, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), p: Principal = Depends(require_scopes("cases:read")), pool: AsyncConnectionPool = Depends(get_db_pool)) -> dict[str, Any]:
        return await _resource_list(pool, "finding", p, case_id=case_id, q=q, limit=limit, offset=offset)

    @app.post("/api/v1/findings", tags=["findings"])
    async def create_finding(payload: dict[str, Any], p: Principal = Depends(require_scopes("cases:write")), pool: AsyncConnectionPool = Depends(get_db_pool)) -> dict[str, Any]:
        return {"finding": await _resource_create(pool, "finding", "finding_id", p, payload)}

    @app.get("/api/v1/audit-events", tags=["audit"])
    async def list_audit_events(
        case_id: str | None = None,
        action: str | None = None,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
        p: Principal = Depends(require_scopes("cases:read")),
        audit_repo: _audit.AuditRepository = Depends(get_audit_repository),
    ) -> dict[str, Any]:
        """Tenant-scoped, paginated audit query. Read access itself is audited by the middleware."""
        tenant = _db_uuid(p)
        return await audit_repo.query(tenant_id=tenant, case_id=case_id, action=action, limit=limit, offset=offset)

    # Dev-only synthetic integration of reviewed interop module + principal boundary demos.
    # Explicitly labeled, not present for prod env, not in OpenAPI schema for prod.
    # All dev routes here depend on get_current_principal to exercise the authz boundary.
    if settings.env != "prod":
        @app.get("/__dev__/runner/catalog", include_in_schema=False, tags=["dev-only"])
        def runner_catalog(p: Principal = Depends(get_current_principal)) -> dict[str, Any]:
            return {"synthetic": True, "fixtures": _runner.runner.catalog(), "tenant_scope": "trusted-principal"}

        @app.post("/__dev__/runner/register", include_in_schema=False, tags=["dev-only"])
        def runner_register(payload: dict[str, Any], p: Principal = Depends(get_current_principal)) -> dict[str, Any]:
            fixture_id = payload.get("fixture_id")
            if not isinstance(fixture_id, str):
                raise HTTPException(400, "fixture_id required")
            try:
                return {"registration": _runner.runner.register(p.tenant_id, fixture_id), "synthetic": True}
            except (ValueError, OSError) as exc:
                raise HTTPException(400, str(exc)) from exc

        @app.post("/__dev__/runner/jobs", include_in_schema=False, tags=["dev-only"])
        def runner_submit(payload: dict[str, Any], p: Principal = Depends(get_current_principal)) -> dict[str, Any]:
            fixture_id = payload.get("fixture_id")
            if not isinstance(fixture_id, str):
                raise HTTPException(400, "fixture_id required")
            try:
                return _runner.runner.submit(p.tenant_id, fixture_id)
            except (ValueError, OSError) as exc:
                raise HTTPException(400, str(exc)) from exc

        @app.get("/__dev__/runner/jobs/{job_id}", include_in_schema=False, tags=["dev-only"])
        def runner_status(job_id: str, p: Principal = Depends(get_current_principal)) -> dict[str, Any]:
            try:
                return _runner.runner.get(p.tenant_id, job_id)
            except KeyError as exc:
                raise HTTPException(404, "job not found for authenticated tenant") from exc

        @app.post("/__dev__/runner/jobs/{job_id}/review", include_in_schema=False, tags=["dev-only"])
        def runner_review(job_id: str, payload: dict[str, Any], p: Principal = Depends(get_current_principal)) -> dict[str, Any]:
            try:
                return _runner.runner.review(p.tenant_id, job_id, payload.get("decision", ""))
            except KeyError as exc:
                raise HTTPException(404, "job not found for authenticated tenant") from exc
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc

        @app.post("/__dev__/runner/jobs/{job_id}/retry", include_in_schema=False, tags=["dev-only"])
        def runner_retry(job_id: str, p: Principal = Depends(get_current_principal)) -> dict[str, Any]:
            try:
                return _runner.runner.retry(p.tenant_id, job_id)
            except KeyError as exc:
                raise HTTPException(409, "job is not retryable for authenticated tenant") from exc

        @app.delete("/__dev__/runner/teardown", include_in_schema=False, tags=["dev-only"])
        def runner_teardown(p: Principal = Depends(get_current_principal)) -> dict[str, Any]:
            return _runner.runner.teardown(p.tenant_id)

        @app.post(
            "/__dev__/synthetic/ingest-preview",
            include_in_schema=False,
            tags=["dev-only"],
        )
        def synthetic_ingest_preview(
            payload: dict[str, Any],
            s: Settings = Depends(get_settings),
            p: Principal = Depends(get_current_principal),
        ) -> dict[str, Any]:
            """DEV-ONLY: exercise reviewed interop helpers on synthetic input only.

            Now requires trusted principal to demonstrate boundary.
            Tenant scope shown in response; real routes will filter by it.
            Rejects secrets (via interop), computes deterministic sha256 and
            idempotency key. Never for real evidence or production use.
            """
            if s.env == "prod":
                raise HTTPException(403, "dev-only endpoint disabled in prod")
            try:
                # Use the reviewed interop module
                sha = _interop.payload_sha256(payload)
                # Demonstrate idempotency helper with synthetic values
                idem = _interop.idempotency_key(
                    integration_id="dev-shell",
                    direction="in",
                    source_system="synthetic",
                    source_entity="preview",
                    source_id="shell-1",
                    source_revision="v1",
                )
                _interop.reject_secret_keys(payload)  # will raise on secrets
                return {
                    "status": "preview",
                    "payload_sha256": sha,
                    "idempotency_key": idem,
                    "synthetic": True,
                    "tenant_id": p.tenant_id,
                    "note": "dev-only synthetic use of reviewed interop module (scoped to principal)",
                }
            except _interop.IngestValidationError as ve:
                raise HTTPException(status_code=400, detail=str(ve))
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"preview failed: {e}")

        @app.get(
            "/__dev__/principal",
            include_in_schema=False,
            tags=["dev-only"],
        )
        def dev_principal(
            p: Principal = Depends(get_current_principal),
        ) -> dict[str, Any]:
            """DEV-ONLY: surface the synthetic principal seam for tests and local dev."""
            return {
                "tenant_id": p.tenant_id,
                "analyst_id": p.analyst_id,
                "is_synthetic": p.is_synthetic,
                "note": "explicitly synthetic dev-only principal seam (auth card will harden)",
            }

        @app.get(
            "/__dev__/synthetic/whoami",
            include_in_schema=False,
            tags=["dev-only"],
        )
        def synthetic_whoami(
            p: Principal = Depends(get_current_principal),
        ) -> dict[str, Any]:
            """DEV-ONLY: returns the *trusted* principal context (the boundary).

            Protected routes consume this exact dependency.
            Tenant/analyst identity is *never* taken from client headers, query
            params, or request bodies for authorization.
            """
            return {
                "tenant_id": p.tenant_id,
                "analyst_id": p.analyst_id,
                "is_synthetic": p.is_synthetic,
                "note": (
                    "principal derived from trusted context seam only. "
                    "Future Entra ID / OIDC adapter will validate tokens here "
                    "and map claims to (tenant_id, analyst_id). "
                    "Sensitive fields (raw emails, object ids, tokens) are never "
                    "present in this interface or responses."
                ),
            }

        @app.get(
            "/__dev__/synthetic/cases",
            include_in_schema=False,
            tags=["dev-only"],
        )
        def synthetic_list_cases(
            p: Principal = Depends(get_current_principal),
        ) -> dict[str, Any]:
            """DEV-ONLY: tenant-scoped list (simulated read).

            Demonstrates server-enforced tenant isolation.
            Real implementation will apply WHERE tenant_id = p.tenant_id at query layer.
            """
            cases = _dev_scoped_store["cases"].get(p.tenant_id, [])
            return {
                "tenant_id": p.tenant_id,
                "cases": cases,
                "count": len(cases),
                "note": "server-enforced scope from principal.tenant_id; caller-supplied tenant claims ignored",
            }

        @app.post(
            "/__dev__/synthetic/cases",
            include_in_schema=False,
            tags=["dev-only"],
        )
        def synthetic_create_case(
            payload: dict[str, Any],
            p: Principal = Depends(get_current_principal),
        ) -> dict[str, Any]:
            """DEV-ONLY: tenant-scoped create (simulated mutation).

            Ignores any 'tenant_id' or 'analyst' fields in payload body.
            Scope always taken from the trusted principal dep.
            """
            title = payload.get("title", "untitled")
            if not isinstance(title, str) or not title.strip():
                raise HTTPException(400, "title required")
            tenant_cases = _dev_scoped_store["cases"].setdefault(p.tenant_id, [])
            case_id = _next_case_id()
            case = {
                "id": case_id,
                "title": title.strip(),
                "tenant_id": p.tenant_id,  # enforced from principal
                "created_by": p.analyst_id,
            }
            tenant_cases.append(case)
            return {
                "case": case,
                "synthetic": True,
                "note": "scope from principal.tenant_id (body tenant ignored)",
            }

        @app.get(
            "/__dev__/synthetic/cases/{case_id}",
            include_in_schema=False,
            tags=["dev-only"],
        )
        def synthetic_get_case(
            case_id: str,
            p: Principal = Depends(get_current_principal),
        ) -> dict[str, Any]:
            """Tenant-scoped get by ID.

            Returns 404 (not 200 with other tenant's data) if the case
            does not belong to p.tenant_id. This is the cross-tenant denial.
            """
            cases = _dev_scoped_store["cases"].get(p.tenant_id, [])
            for c in cases:
                if c["id"] == case_id:
                    return {"case": c}
            raise HTTPException(
                status_code=404,
                detail="case not found for authenticated tenant",
            )

    return app


app = create_app()

# Convenience for direct execution (uvicorn prefers the app object)
def serve() -> None:
    """Entry for python -m or script."""
    import uvicorn

    uvicorn.run(
        "dfir_workbench.api:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=settings.env in ("dev", "test"),
    )


if __name__ == "__main__":
    serve()
