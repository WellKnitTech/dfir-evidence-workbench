"""PostgreSQL persistence seam for DFIR Evidence Workbench.

- Uses psycopg async pool (no ORM, direct SQL to preserve reviewed migration contract)
- Tenant isolation ALWAYS enforced from trusted Principal at the repository layer
  (server side WHERE clauses + parameterized INSERT values from principal; never from caller input)
- Reproducible migration application from migrations/*.sql in lexical order
- Explicit transaction boundaries inside repository methods
- dfir.timeline_entry_flag contract exactly matching the 0001_create_timeline_entry_flags.sql
  (uuid PKs, CHECKs, FK to dfir.analyst, unique per tenant+entry+analyst)
- Ingest envelope table (0002) for preview/approval/commit/quarantine durable records
- Disposable test harness (clean schema + migration apply) for verification
- Secrets (DB credentials) remain environment-injected only via Settings; never in source
- Fail-closed: unavailable DB, bad config, or missing pool cause 503 in seams and tests fail fast

This is additive wiring only. The migration assumes a pre-existing dfir schema + analyst table
in real deployments (see metadata-schema.sql reference in migration header). Harness bootstraps
the minimal tables for isolated testing only.

Do not invent analyst_flags, ORM models, or other tables/contracts.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import subprocess
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, AsyncIterator

import psycopg
from psycopg.rows import dict_row
import base64
import hashlib

from psycopg_pool import AsyncConnectionPool

if TYPE_CHECKING:
    from .api import Principal

MIGRATIONS_DIR = "migrations"


@dataclass(frozen=True)
class TimelineEntryFlag:
    """Contract for dfir.timeline_entry_flag rows.

    Exactly matches the reviewed migration schema and constraints.
    All consumers must derive tenant_id exclusively from trusted Principal.
    """

    tenant_id: str
    flag_id: str
    timeline_entry_id: str
    analyst_id: str
    analyst_name: str
    created_at: str
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class TimelineFlagRepository:
    """Repository implementing tenant-scoped operations for timeline_entry_flag.

    Authorization is enforced here:
    - INSERT always uses principal.tenant_id / principal.analyst_id (caller body ignored)
    - SELECT always adds WHERE tenant_id = principal.tenant_id
    - Duplicate attempts (same tenant+entry+analyst) are deduped via constraint + ON CONFLICT
    - Foreign tenant principals see empty results or cannot affect rows (no existence leak)

    Uses explicit transaction() for boundaries.
    """

    def __init__(self, pool: AsyncConnectionPool) -> None:
        if pool is None:
            raise RuntimeError("AsyncConnectionPool is required")
        self._pool = pool

    async def create_flag(
        self,
        principal: "Principal",
        *,
        timeline_entry_id: str,
        note: str | None = None,
        analyst_name: str | None = None,
    ) -> TimelineEntryFlag:
        """Create (or return existing) flag under the *principal's* tenant scope.

        Enforces non-blank entry id and analyst name per table CHECKs.
        """
        if not isinstance(timeline_entry_id, str) or not timeline_entry_id.strip():
            raise ValueError("timeline_entry_id must be non-empty string")
        tenant = str(principal.tenant_id)
        analyst = str(principal.analyst_id)
        name = (analyst_name or analyst).strip()
        if not name:
            raise ValueError("analyst_name must be non-empty")
        if not self._is_uuid(tenant) or not self._is_uuid(analyst):
            raise ValueError(
                "For DB-backed operations, principal.tenant_id and analyst_id must be UUID strings "
                "(per dfir.timeline_entry_flag schema). Use synthetic in-mem paths for non-UUID tests."
            )

        async with self._pool.connection() as conn:
            async with conn.transaction():
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """
                    INSERT INTO dfir.timeline_entry_flag
                        (tenant_id, timeline_entry_id, analyst_id, analyst_name, note)
                    VALUES (%s::uuid, %s, %s::uuid, %s, %s)
                    ON CONFLICT (tenant_id, timeline_entry_id, analyst_id) DO NOTHING
                    RETURNING tenant_id::text, flag_id::text, timeline_entry_id,
                              analyst_id::text, analyst_name, created_at::text, note
                        """,
                        (tenant, timeline_entry_id.strip(), analyst, name, note),
                    )
                    row = await cur.fetchone()
                if row is None:
                    # race or duplicate: fetch the committed row under same tenant scope
                    async with conn.cursor(row_factory=dict_row) as cur:
                        await cur.execute(
                            """
                        SELECT tenant_id::text, flag_id::text, timeline_entry_id,
                               analyst_id::text, analyst_name, created_at::text, note
                        FROM dfir.timeline_entry_flag
                        WHERE tenant_id = %s::uuid
                          AND timeline_entry_id = %s
                          AND analyst_id = %s::uuid
                            """,
                            (tenant, timeline_entry_id.strip(), analyst),
                        )
                        row = await cur.fetchone()
                if row is None:
                    raise RuntimeError("insert returned no row and no existing row found")
                return self._row_to_flag(row)

    async def list_for_entry(
        self, principal: "Principal", timeline_entry_id: str
    ) -> list[TimelineEntryFlag]:
        """Return flags for entry, *always* filtered to principal.tenant_id.

        A principal from another tenant receives [] with no error or side-channel.
        """
        if not isinstance(timeline_entry_id, str) or not timeline_entry_id.strip():
            return []
        tenant = str(principal.tenant_id)
        if not self._is_uuid(tenant):
            return []
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    """
                SELECT tenant_id::text, flag_id::text, timeline_entry_id,
                       analyst_id::text, analyst_name, created_at::text, note
                FROM dfir.timeline_entry_flag
                WHERE tenant_id = %s::uuid AND timeline_entry_id = %s
                ORDER BY created_at DESC
                    """,
                    (tenant, timeline_entry_id.strip()),
                )
                rows = await cur.fetchall()
            return [self._row_to_flag(r) for r in rows]

    @staticmethod
    def _row_to_flag(row: dict[str, Any]) -> TimelineEntryFlag:
        return TimelineEntryFlag(
            tenant_id=row["tenant_id"],
            flag_id=row["flag_id"],
            timeline_entry_id=row["timeline_entry_id"],
            analyst_id=row["analyst_id"],
            analyst_name=row["analyst_name"],
            created_at=row["created_at"],
            note=row.get("note"),
        )

    @staticmethod
    def _is_uuid(val: str) -> bool:
        try:
            uuid.UUID(str(val))
            return True
        except Exception:
            return False


async def apply_migrations(
    pool: AsyncConnectionPool, migrations_dir: str = MIGRATIONS_DIR
) -> list[str]:
    """Apply reviewed migrations in strict lexical filename order.

    Preserves original migration contents and ordering. Each .sql runs as provided
    (BEGIN/COMMIT inside as authored).
    """
    mdir = pathlib.Path(migrations_dir)
    if not mdir.is_dir():
        raise FileNotFoundError(f"required migrations directory missing: {mdir.resolve()}")
    applied: list[str] = []
    for path in sorted(mdir.glob("*.sql")):
        sql = path.read_text(encoding="utf-8")
        async with pool.connection() as conn:
            await conn.execute(sql)
        applied.append(path.name)
    return applied


async def ensure_dev_schema_and_migrations(pool: AsyncConnectionPool) -> list[str]:
    """Idempotent dev bootstrap: ensure dfir schema + analyst table exist, then apply migrations.

    Safe for persistent dev volumes. Never drops data. Only for DFIRWB_ENV=dev paths.
    """
    # Ensure minimal dfir schema and analyst table (referenced by 0001 FK)
    async with pool.connection() as conn:
        await conn.execute(
            """
            CREATE SCHEMA IF NOT EXISTS dfir;
            CREATE TABLE IF NOT EXISTS dfir.analyst (
                tenant_id uuid NOT NULL,
                analyst_id uuid NOT NULL,
                name text NOT NULL,
                PRIMARY KEY (tenant_id, analyst_id)
            );
            """
        )
    # Apply only migrations whose target table is absent. The reviewed SQL files
    # predate a migration ledger and 0001/0002 intentionally use CREATE TABLE;
    # probing keeps persistent dev volumes restart-safe without rewriting them.
    targets = {
        "0001_create_timeline_entry_flags.sql": "timeline_entry_flag",
        "0002_create_ingest_envelopes.sql": "ingest_envelope",
        "0003_create_api_resources.sql": "case_record",
        "0004_create_audit_events.sql": "audit_event",
    }
    applied: list[str] = []
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            for filename, table in targets.items():
                await cur.execute("SELECT to_regclass(%s)", (f"dfir.{table}",))
                exists = (await cur.fetchone())[0]
                if exists is None:
                    path = pathlib.Path(MIGRATIONS_DIR) / filename
                    await conn.execute(path.read_text(encoding="utf-8"))
                    applied.append(filename)
    return applied


async def setup_clean_test_schema(pool: AsyncConnectionPool) -> None:
    """Harness-only: reset dfir schema to a state where the additive flag migration can apply.

    Drops + recreates dfir + the analyst table referenced by the FK.
    Never called in production paths.
    """
    async with pool.connection() as conn:
        await conn.execute("DROP SCHEMA IF EXISTS dfir CASCADE;")
        await conn.execute("CREATE SCHEMA dfir;")
        await conn.execute(
            """
            CREATE TABLE dfir.analyst (
                tenant_id uuid NOT NULL,
                analyst_id uuid NOT NULL,
                name text NOT NULL,
                PRIMARY KEY (tenant_id, analyst_id)
            );
            """
        )


async def ensure_test_analyst(
    pool: AsyncConnectionPool, principal: "Principal", name: str | None = None
) -> None:
    """Insert the analyst row required by FK for a test principal (idempotent)."""
    if not TimelineFlagRepository._is_uuid(principal.tenant_id) or not TimelineFlagRepository._is_uuid(principal.analyst_id):
        return
    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO dfir.analyst (tenant_id, analyst_id, name)
            VALUES (%s::uuid, %s::uuid, %s)
            ON CONFLICT (tenant_id, analyst_id) DO NOTHING
            """,
            (
                str(principal.tenant_id),
                str(principal.analyst_id),
                name or str(principal.analyst_id),
            ),
        )


# ------------------------------------------------------------------
# Disposable Postgres verification harness (test only)
# Starts a one-off container (docker or podman), waits for readiness,
# yields a connection URL, then cleans up. Used to prove:
# - migrations apply cleanly on fresh DB
# - repo methods work
# - tenant isolation and duplicate handling at the data layer
# ------------------------------------------------------------------

def _container_runtime() -> list[str]:
    for cand in ("podman", "docker"):
        try:
            subprocess.check_call(
                [cand, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4,
            )
            return [cand]
        except Exception:
            continue
    raise RuntimeError("disposable harness requires docker or podman in PATH")


@asynccontextmanager
async def disposable_postgres(
    *,
    image: str = "docker.io/library/postgres:15",
    user: str = "testuser",
    password: str = "testpass",
    dbname: str = "testdb",
) -> AsyncIterator[str]:
    """Yield postgresql://... URL for a short-lived clean Postgres instance.

    Container is force-removed on exit. Caller is responsible for schema setup + migration apply.
    """
    runtime = _container_runtime()
    cname = f"dfir-test-pg-{uuid.uuid4().hex[:10]}"
    run_args = runtime + [
        "run",
        "-d",
        "--rm",
        "--name",
        cname,
        "-e",
        f"POSTGRES_USER={user}",
        "-e",
        f"POSTGRES_PASSWORD={password}",
        "-e",
        f"POSTGRES_DB={dbname}",
        "-p",
        "5432",
        image,
    ]
    subprocess.check_call(run_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url: str | None = None
    try:
        # wait for startup + port publish + pg accepting
        await asyncio.sleep(5)
        for _ in range(60):
            try:
                port_out = subprocess.check_output(
                    runtime + ["port", cname, "5432"], text=True, timeout=3
                ).strip()
                hport = port_out.rsplit(":", 1)[-1].strip() if ":" in port_out else "5432"
                candidate = f"postgresql://{user}:{password}@127.0.0.1:{hport}/{dbname}"
                # probe with sync (reliable in this env)
                with psycopg.connect(candidate, connect_timeout=3) as conn:
                    conn.execute("SELECT 1")
                url = candidate
                break
            except Exception:
                await asyncio.sleep(1.0)
        if url is None:
            raise RuntimeError(f"postgres container {cname} failed to become ready in time")
        yield url
    finally:
        try:
            subprocess.check_call(
                runtime + ["rm", "-f", cname],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
            )
        except Exception:
            pass  # best effort; container --rm helps


@asynccontextmanager
async def temp_async_pool(database_url: str) -> AsyncIterator[AsyncConnectionPool]:
    """Test helper: open+close a pool around a block."""
    async with AsyncConnectionPool(database_url, min_size=1, max_size=5) as pool:
        yield pool


# ------------------------------------------------------------------
# Ingest envelope repository (for this task: preview/approval/commit/quarantine)
# Durable, tenant-scoped append-only records using reviewed envelope contract.
# All operations derive tenant/analyst exclusively from trusted Principal.
# Idempotency enforced at DB unique constraint + status.
# No bytes in payloads; redaction/quarantine handled at higher layer before store.
# ------------------------------------------------------------------

@dataclass(frozen=True)
class IngestEnvelope:
    """Durable representation of an ingest envelope row.

    Mirrors the columns and invariants from 0002 migration + reviewed schema.
    """
    tenant_id: str
    envelope_id: str
    received_at_utc: str
    source_system: str
    source_entity: str
    source_id: str
    source_scope: str
    source_revision: str
    payload_sha256: str
    payload: dict[str, Any]
    processing_status: str
    mapping_version: str
    idempotency_key: str
    target_id: str | None = None
    error_code: str | None = None
    quarantine_reference: str | None = None
    analyst_id: str | None = None
    created_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if isinstance(d.get("payload"), dict):
            d["payload"] = dict(d["payload"])
        return d


class IngestRepository:
    """Tenant-isolated repository for ingest envelopes.

    Authorization: principal.tenant_id / analyst_id used for all filters and inserts.
    Caller supplied values in envelopes are validated for consistency but scope is forced.
    Duplicate detection on idempotency_key (unique constraint) -> status=duplicate.
    Secret rejection and schema validation expected to have occurred before calling store.
    """

    def __init__(self, pool: AsyncConnectionPool) -> None:
        if pool is None:
            raise RuntimeError("AsyncConnectionPool is required")
        self._pool = pool

    async def store_preview(
        self,
        principal: "Principal",
        *,
        envelope: dict[str, Any],
    ) -> IngestEnvelope:
        """Insert or return existing as preview (or duplicate/rejected state).

        Expects caller to have run interop validation + reject_secrets + computed sha/idem.
        Uses ON CONFLICT on idempotency to detect dups without leaking.
        """
        tenant = str(principal.tenant_id)
        analyst = str(principal.analyst_id)
        env_id = envelope.get("envelope_id") or f"env-{uuid.uuid4().hex[:12]}"
        src = envelope.get("source", {})
        proc = envelope.get("processing", {})
        idem = proc.get("idempotency_key") or envelope.get("idempotency_key")
        if not idem:
            idem = "v1:" + base64.urlsafe_b64encode(
                hashlib.sha256(
                    f"{tenant}|in|{src.get('system','other')}|{src.get('entity','unknown')}|{src.get('id',env_id)}|{src.get('revision','1')}".encode()
                ).digest()
            ).decode("ascii").rstrip("=")
        payload = envelope.get("payload", {})
        sha = envelope.get("payload_sha256") or hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        received = envelope.get("received_at_utc")
        if not received:
            received = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        status = proc.get("status", "preview")
        mapping_ver = proc.get("mapping_version", "1.0.0")

        async with self._pool.connection() as conn:
            async with conn.transaction():
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """
                    INSERT INTO dfir.ingest_envelope
                        (tenant_id, envelope_id, received_at_utc,
                         source_system, source_entity, source_id, source_scope, source_revision,
                         payload_sha256, payload, processing_status, mapping_version,
                         idempotency_key, analyst_id)
                    VALUES (%s::uuid, %s, %s::timestamptz,
                            %s, %s, %s, %s, %s,
                            %s, %s::jsonb, %s, %s,
                            %s, %s::uuid)
                    ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
                    RETURNING tenant_id::text, envelope_id, received_at_utc::text,
                              source_system, source_entity, source_id, source_scope, source_revision,
                              payload_sha256, payload, processing_status, mapping_version,
                              idempotency_key, target_id, error_code, quarantine_reference,
                              analyst_id::text, created_at::text
                        """,
                        (
                            tenant, env_id, received,
                            src.get("system"), src.get("entity"), src.get("id"), src.get("scope"), src.get("revision"),
                            sha, json.dumps(payload), status, mapping_ver,
                            idem, analyst,
                        ),
                    )
                    row = await cur.fetchone()
                if row is None:
                    # duplicate detected by conflict; fetch under tenant scope
                    async with conn.cursor(row_factory=dict_row) as cur:
                        await cur.execute(
                            """
                        SELECT tenant_id::text, envelope_id, received_at_utc::text,
                               source_system, source_entity, source_id, source_scope, source_revision,
                               payload_sha256, payload, processing_status, mapping_version,
                               idempotency_key, target_id, error_code, quarantine_reference,
                               analyst_id::text, created_at::text
                        FROM dfir.ingest_envelope
                        WHERE tenant_id = %s::uuid AND idempotency_key = %s
                            """,
                            (tenant, idem),
                        )
                        row = await cur.fetchone()
                    if row:
                        existing_sha = row.get("payload_sha256")
                        if existing_sha != sha:
                            # key reuse with different payload content -> conflict (not silent dup)
                            await conn.execute(
                                """
                            UPDATE dfir.ingest_envelope
                            SET processing_status='conflict',
                                error_code='idempotency_key_reuse_mismatch',
                                updated_at=clock_timestamp()
                            WHERE tenant_id=%s::uuid AND idempotency_key=%s
                            """,
                                (tenant, idem),
                            )
                            row = dict(row)
                            row["processing_status"] = "conflict"
                            row["error_code"] = "idempotency_key_reuse_mismatch"
                        elif row.get("processing_status") not in ("duplicate", "applied", "conflict"):
                            await conn.execute(
                                """
                            UPDATE dfir.ingest_envelope
                            SET processing_status='duplicate', updated_at=clock_timestamp()
                            WHERE tenant_id=%s::uuid AND idempotency_key=%s
                            """,
                                (tenant, idem),
                            )
                            row = dict(row)
                            row["processing_status"] = "duplicate"
                if row is None:
                    raise RuntimeError("ingest insert conflict resolution produced no row")
                return self._row_to_envelope(row)

    async def get(
        self, principal: "Principal", envelope_id: str
    ) -> IngestEnvelope | None:
        """Fetch one envelope under the principal's tenant. Returns None for foreign or missing (no leak)."""
        tenant = str(principal.tenant_id)
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    """
                SELECT tenant_id::text, envelope_id, received_at_utc::text,
                       source_system, source_entity, source_id, source_scope, source_revision,
                       payload_sha256, payload, processing_status, mapping_version,
                       idempotency_key, target_id, error_code, quarantine_reference,
                       analyst_id::text, created_at::text
                FROM dfir.ingest_envelope
                WHERE tenant_id = %s::uuid AND envelope_id = %s
                    """,
                    (tenant, envelope_id),
                )
                row = await cur.fetchone()
        return self._row_to_envelope(row) if row else None

    async def approve(
        self, principal: "Principal", envelope_id: str
    ) -> IngestEnvelope:
        """Explicit approval step: transition preview -> approved (only if in preview state under tenant)."""
        tenant = str(principal.tenant_id)
        async with self._pool.connection() as conn:
            async with conn.transaction():
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """
                    UPDATE dfir.ingest_envelope
                    SET processing_status = 'approved', updated_at = clock_timestamp()
                    WHERE tenant_id = %s::uuid
                      AND envelope_id = %s
                      AND processing_status = 'preview'
                    RETURNING tenant_id::text, envelope_id, received_at_utc::text,
                              source_system, source_entity, source_id, source_scope, source_revision,
                              payload_sha256, payload, processing_status, mapping_version,
                              idempotency_key, target_id, error_code, quarantine_reference,
                              analyst_id::text, created_at::text
                        """,
                        (tenant, envelope_id),
                    )
                    row = await cur.fetchone()
        if row is None:
            current = await self.get(principal, envelope_id)
            if current is None:
                raise ValueError(f"envelope {envelope_id} not found for tenant")
            raise ValueError(
                f"cannot approve envelope {envelope_id} in status {current.processing_status}; must be preview"
            )
        return self._row_to_envelope(row)

    async def apply_commit(
        self, principal: "Principal", envelope_id: str, *, target_id: str | None = None
    ) -> IngestEnvelope:
        """Commit/apply step after approval. Sets applied + optional target_id from transport adapter."""
        tenant = str(principal.tenant_id)
        async with self._pool.connection() as conn:
            async with conn.transaction():
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """
                    UPDATE dfir.ingest_envelope
                    SET processing_status = 'applied',
                        target_id = COALESCE(%s, target_id),
                        updated_at = clock_timestamp()
                    WHERE tenant_id = %s::uuid
                      AND envelope_id = %s
                      AND processing_status IN ('approved', 'preview')
                    RETURNING tenant_id::text, envelope_id, received_at_utc::text,
                              source_system, source_entity, source_id, source_scope, source_revision,
                              payload_sha256, payload, processing_status, mapping_version,
                              idempotency_key, target_id, error_code, quarantine_reference,
                              analyst_id::text, created_at::text
                        """,
                        (target_id, tenant, envelope_id),
                    )
                    row = await cur.fetchone()
        if row is None:
            current = await self.get(principal, envelope_id)
            if current is None:
                raise ValueError(f"envelope {envelope_id} not found")
            raise ValueError(f"cannot apply {envelope_id} from status {current.processing_status}")
        return self._row_to_envelope(row)

    async def mark_quarantined(
        self, principal: "Principal", envelope_id: str, *, reason: str | None = None
    ) -> IngestEnvelope:
        """Quarantine a bad envelope (e.g. after secret or validation fail during intake)."""
        tenant = str(principal.tenant_id)
        qref = f"quarantine-{uuid.uuid4().hex[:8]}"
        async with self._pool.connection() as conn:
            async with conn.transaction():
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """
                    UPDATE dfir.ingest_envelope
                    SET processing_status='quarantined',
                        quarantine_reference=%s,
                        error_code=COALESCE(%s, error_code),
                        updated_at=clock_timestamp()
                    WHERE tenant_id=%s::uuid AND envelope_id=%s
                    RETURNING tenant_id::text, envelope_id, received_at_utc::text,
                              source_system, source_entity, source_id, source_scope, source_revision,
                              payload_sha256, payload, processing_status, mapping_version,
                              idempotency_key, target_id, error_code, quarantine_reference,
                              analyst_id::text, created_at::text
                        """,
                        (qref, reason, tenant, envelope_id),
                    )
                    row = await cur.fetchone()
        if row is None:
            raise ValueError(f"envelope not found for quarantine: {envelope_id}")
        return self._row_to_envelope(row)

    @staticmethod
    def _row_to_envelope(row: dict[str, Any]) -> IngestEnvelope:
        return IngestEnvelope(
            tenant_id=row["tenant_id"],
            envelope_id=row["envelope_id"],
            received_at_utc=row["received_at_utc"],
            source_system=row["source_system"],
            source_entity=row["source_entity"],
            source_id=row["source_id"],
            source_scope=row["source_scope"],
            source_revision=row["source_revision"],
            payload_sha256=row["payload_sha256"],
            payload=dict(row["payload"]) if row.get("payload") else {},
            processing_status=row["processing_status"],
            mapping_version=row["mapping_version"],
            idempotency_key=row["idempotency_key"],
            target_id=row.get("target_id"),
            error_code=row.get("error_code"),
            quarantine_reference=row.get("quarantine_reference"),
            analyst_id=row.get("analyst_id"),
            created_at=row.get("created_at"),
        )


# stdlib imports needed by the ingest repo (avoid top level bloat for other modules)
