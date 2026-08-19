"""Structured audit event logging with a queryable, append-only Postgres sink.

Every event carries actor, tenant, object, action, outcome, correlation ID, and
a UTC timestamp (see migrations/0004_create_audit_events.sql). The repository
only ever INSERTs; no UPDATE/DELETE path exists in this module.

If the DB pool is unavailable, the event is emitted as structured JSON to the
process log instead of being silently dropped (see docs/observability-and-incident-operations.md
for why this is a documented gap, not a real WORM sink).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

if TYPE_CHECKING:
    from .api import Principal

_logger = logging.getLogger("dfir_workbench.audit")
_REDACT_KEYS = frozenset({"authorization", "cookie", "password", "secret", "token", "api_key", "access_token", "refresh_token"})

VALID_ACTOR_TYPES = frozenset({"user", "service", "job", "system"})
VALID_RESULTS = frozenset({"success", "denied", "validation_failed", "not_found", "conflict", "error", "partial"})


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    tenant_id: str | None
    case_id: str | None
    actor_type: str
    actor_id: str | None
    object_type: str | None
    object_id: str | None
    action: str
    result: str
    correlation_id: str
    source: str
    occurred_at: str
    recorded_at: str | None = None
    metadata: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _redact(value: Any) -> Any:
    """Keep degraded logs useful without copying credentials or bearer tokens."""
    if isinstance(value, dict):
        return {k: "[REDACTED]" if k.lower() in _REDACT_KEYS else _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


class AuditRepository:
    """Insert-only repository for dfir.audit_event. No update/delete methods exist."""

    def __init__(self, pool: AsyncConnectionPool | None) -> None:
        self._pool = pool

    async def record(
        self,
        *,
        action: str,
        result: str,
        correlation_id: str,
        source: str = "api",
        actor_type: str = "user",
        actor_id: str | None = None,
        tenant_id: str | None = None,
        case_id: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        if actor_type not in VALID_ACTOR_TYPES:
            raise ValueError(f"actor_type must be one of {sorted(VALID_ACTOR_TYPES)}")
        if result not in VALID_RESULTS:
            raise ValueError(f"result must be one of {sorted(VALID_RESULTS)}")
        if not action or not correlation_id:
            raise ValueError("action and correlation_id are required")

        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            case_id=case_id,
            actor_type=actor_type,
            actor_id=actor_id,
            object_type=object_type,
            object_id=object_id,
            action=action,
            result=result,
            correlation_id=correlation_id,
            source=source,
            occurred_at=_utc_now_iso(),
            metadata=metadata or {},
        )

        if self._pool is None:
            # Degraded mode: never drop the event silently. See module docstring.
            _logger.warning("audit_sink_unavailable event=%s", json.dumps(_redact(event.as_dict()), sort_keys=True))
            return event

        try:
            async with self._pool.connection() as conn:
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """
                        INSERT INTO dfir.audit_event
                            (event_id, tenant_id, case_id, actor_type, actor_id,
                             object_type, object_id, action, result, correlation_id,
                             source, occurred_at, metadata)
                        VALUES (%s::uuid, %s::uuid, %s, %s, %s,
                                %s, %s, %s, %s, %s,
                                %s, %s::timestamptz, %s::jsonb)
                        RETURNING recorded_at::text
                        """,
                        (
                            event.event_id, tenant_id, case_id, actor_type, actor_id,
                            object_type, object_id, action, result, correlation_id,
                            source, event.occurred_at, json.dumps(event.metadata),
                        ),
                    )
                    row = await cur.fetchone()
        except Exception as exc:
            # A pool can exist while its connection or INSERT is unavailable.
            # Preserve the same fail-visible, redacted fallback as pool=None.
            from . import metrics

            metrics.inc_counter("audit_write_failures_total")
            _logger.warning(
                "audit_sink_unavailable error=%s event=%s",
                type(exc).__name__,
                json.dumps(_redact(event.as_dict()), sort_keys=True),
            )
            return event
        return AuditEvent(**{**event.as_dict(), "recorded_at": row["recorded_at"]})

    async def query(
        self,
        *,
        tenant_id: str,
        case_id: str | None = None,
        action: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Tenant-scoped, paginated read. Never accepts a caller-supplied tenant filter override."""
        if self._pool is None:
            return {"items": [], "count": 0, "limit": limit, "offset": offset}
        where = "tenant_id = %s::uuid"
        args: list[Any] = [tenant_id]
        if case_id:
            where += " AND case_id = %s"
            args.append(case_id)
        if action:
            where += " AND action = %s"
            args.append(action)
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    f"""
                    SELECT event_id::text, tenant_id::text, case_id, actor_type, actor_id,
                           object_type, object_id, action, result, correlation_id, source,
                           occurred_at::text, recorded_at::text, metadata
                    FROM dfir.audit_event
                    WHERE {where}
                    ORDER BY recorded_at DESC, event_id DESC
                    LIMIT %s OFFSET %s
                    """,
                    (*args, limit, offset),
                )
                rows = await cur.fetchall()
                await cur.execute(f"SELECT count(*) AS count FROM dfir.audit_event WHERE {where}", args)
                total = (await cur.fetchone())["count"]
        return {"items": [dict(r) for r in rows], "count": total, "limit": limit, "offset": offset}
