"""Metadata-only OpenRelik-compatible adapter; LocalTransport is a test harness only."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from .openrelik_contract import build_idempotency_key, validate_job_request, validate_job_result

_TERMINAL = {"succeeded", "failed", "quarantined"}

class OpenRelikTransport(Protocol):
    def submit(self, request: dict[str, Any], *, idempotency_key: str) -> dict[str, Any]: ...
    def status(self, workflow_id: str, task_id: str | None = None) -> dict[str, Any]: ...

class AuditSink(Protocol):
    def emit(self, event: str, payload: dict[str, Any]) -> None: ...

class NullAuditSink:
    def emit(self, event: str, payload: dict[str, Any]) -> None:
        return None

@dataclass(frozen=True)
class JobRecord:
    job_id: str; tenant_id: str; case_id: str; analyst_id: str; evidence_id: str; asset_id: str
    idempotency_key: str; workflow_id: str | None; task_id: str | None; external_status: str
    review_state: str; attempts: int; error_code: str | None; outputs: list[dict[str, Any]]

class SQLiteJobStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path); self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE IF NOT EXISTS openrelik_jobs (job_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, analyst_id TEXT NOT NULL, evidence_id TEXT NOT NULL, asset_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, workflow_id TEXT, task_id TEXT, external_status TEXT NOT NULL, review_state TEXT NOT NULL, attempts INTEGER NOT NULL, error_code TEXT, outputs TEXT NOT NULL, request TEXT NOT NULL, updated_at REAL NOT NULL)")
        self.db.commit()
    def close(self) -> None:
        self.db.close()
    def create(self, request: dict[str, Any], tenant_id: str, case_id: str, analyst_id: str, key: str) -> JobRecord:
        c = request["immutable_context"]
        try:
            self.db.execute("INSERT INTO openrelik_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (request["request_id"], tenant_id, case_id, analyst_id, c["evidence"]["evidence_id"], c["asset"]["asset_id"], key, None, None, "queued", "unreviewed", 0, None, "[]", json.dumps(request), time.time())); self.db.commit()
        except sqlite3.IntegrityError:
            existing = self.by_key(key)
            if existing is None: raise
            stored = json.loads(self.db.execute("SELECT request FROM openrelik_jobs WHERE job_id=?", (existing.job_id,)).fetchone()[0])
            if stored != request:
                raise ValueError("IDEMPOTENCY_CONFLICT")
            return existing
        return self.get(request["request_id"])
    def get(self, job_id: str) -> JobRecord:
        row = self.db.execute("SELECT * FROM openrelik_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None: raise KeyError(job_id)
        return self._record(row)
    def scoped_get(self, job_id: str, tenant_id: str, case_id: str) -> JobRecord:
        row = self.db.execute("SELECT * FROM openrelik_jobs WHERE job_id=? AND tenant_id=? AND case_id=?", (job_id, tenant_id, case_id)).fetchone()
        if row is None: raise KeyError("job not found")
        return self._record(row)
    def by_key(self, key: str) -> JobRecord | None:
        row = self.db.execute("SELECT * FROM openrelik_jobs WHERE idempotency_key=?", (key,)).fetchone(); return self._record(row) if row else None
    def request(self, job_id: str, tenant_id: str, case_id: str) -> dict[str, Any]:
        self.scoped_get(job_id, tenant_id, case_id)
        row = self.db.execute("SELECT request FROM openrelik_jobs WHERE job_id=?", (job_id,)).fetchone(); return json.loads(row[0])
    def update(self, job_id: str, **fields: Any) -> JobRecord:
        allowed = {"workflow_id", "task_id", "external_status", "attempts", "error_code", "outputs"}
        if not fields or not set(fields) <= allowed: raise ValueError("invalid job update")
        values = {k: json.dumps(v) if k == "outputs" else v for k, v in fields.items()}; sql = ",".join(f"{k}=?" for k in values) + ",updated_at=?"
        self.db.execute(f"UPDATE openrelik_jobs SET {sql} WHERE job_id=?", (*values.values(), time.time(), job_id)); self.db.commit(); return self.get(job_id)
    def add_outputs(self, job_id: str, tenant_id: str, case_id: str, outputs: list[dict[str, Any]]) -> JobRecord:
        self.scoped_get(job_id, tenant_id, case_id)
        return self.update(job_id, external_status="succeeded", outputs=outputs)
    def _record(self, row: sqlite3.Row) -> JobRecord:
        d = dict(row); return JobRecord(d["job_id"], d["tenant_id"], d["case_id"], d["analyst_id"], d["evidence_id"], d["asset_id"], d["idempotency_key"], d["workflow_id"], d["task_id"], d["external_status"], d["review_state"], d["attempts"], d["error_code"], json.loads(d["outputs"]))

class OpenRelikAdapter:
    def __init__(self, transport: OpenRelikTransport, store: SQLiteJobStore | None = None, *, max_attempts: int = 3, audit_sink: AuditSink | None = None) -> None:
        self.transport = transport; self.store = store or SQLiteJobStore(); self.max_attempts = max(1, max_attempts); self.audit = audit_sink or NullAuditSink()
    @staticmethod
    def _scope(principal: Any) -> tuple[str, str]:
        values = tuple(getattr(principal, x, None) for x in ("tenant_id", "analyst_id"))
        if not all(isinstance(x, str) and x.strip() for x in values): raise PermissionError("authenticated principal required")
        return values  # type: ignore[return-value]
    def _deny(self, operation: str, job_id: str | None, exc: Exception) -> None:
        self.audit.emit("openrelik.deny", {"operation": operation, "job_id": job_id, "error": type(exc).__name__})
    def submit(self, principal: Any, request: dict[str, Any]) -> JobRecord:
        tenant, analyst = self._scope(principal)
        try:
            request = validate_job_request(request); c = request["immutable_context"]
            case = c["case"]["case_id"]
            if c["tenant"]["tenant_id"] != tenant or c["case"]["case_id"] != case: raise PermissionError("job scope denied")
            key = build_idempotency_key(tenant, case, c["evidence"]["evidence_id"], c["evidence"]["sha256"], request["execution"]["tool_profile"])
            if request["idempotency"]["key"] != key: raise ValueError("idempotency key mismatch")
            record = self.store.create(request, tenant, case, analyst, key); self.audit.emit("openrelik.submit", {"job_id": record.job_id, "tenant_id": tenant, "case_id": case})
            if record.workflow_id: return record
            response = self.transport.submit(request, idempotency_key=key); workflow_id = response.get("workflow_id")
            if not isinstance(workflow_id, str) or not workflow_id: raise RuntimeError("transport returned no workflow_id")
            return self.store.update(record.job_id, workflow_id=workflow_id, task_id=response.get("task_id"), external_status=response.get("status", "queued"), attempts=record.attempts + 1)
        except PermissionError as exc: self._deny("submit", request.get("request_id") if isinstance(request, dict) else None, exc); raise
    def _get(self, operation: str, principal: Any, job_id: str, case_id: str) -> tuple[JobRecord, str, str]:
        tenant, _ = self._scope(principal)
        try: return self.store.scoped_get(job_id, tenant, case_id), tenant, case_id
        except KeyError as exc: self._deny(operation, job_id, exc); raise PermissionError("job not found") from None
    def poll(self, principal: Any, job_id: str, case_id: str) -> JobRecord:
        record, tenant, case = self._get("poll", principal, job_id, case_id); self.audit.emit("openrelik.poll", {"job_id": job_id, "tenant_id": tenant, "case_id": case})
        if not record.workflow_id or record.external_status in _TERMINAL: return record
        raw = validate_job_result(self.transport.status(record.workflow_id, record.task_id)); state = raw["workflow"]["status"]
        return self.store.update(job_id, external_status=state, outputs=raw.get("artifacts", []), error_code=(raw.get("failure") or {}).get("code"))
    def retry(self, principal: Any, job_id: str, case_id: str) -> JobRecord:
        record, tenant, case = self._get("retry", principal, job_id, case_id); self.audit.emit("openrelik.retry", {"job_id": job_id, "tenant_id": tenant, "case_id": case})
        if record.workflow_id or record.external_status in _TERMINAL or record.attempts >= self.max_attempts: return record
        response = self.transport.submit(self.store.request(job_id, tenant, case), idempotency_key=record.idempotency_key); return self.store.update(job_id, workflow_id=response["workflow_id"], task_id=response.get("task_id"), external_status=response.get("status", "queued"), attempts=record.attempts + 1)

    def approve(self, principal: Any, job_id: str, case_id: str) -> JobRecord:
        record, tenant, case = self._get("approve", principal, job_id, case_id)
        self.store.db.execute("UPDATE openrelik_jobs SET review_state='approved', updated_at=? WHERE job_id=? AND tenant_id=? AND case_id=?", (time.time(), job_id, tenant, case))
        self.store.db.commit()
        return self.store.scoped_get(job_id, tenant, case)

class LocalTransport:
    """Synthetic harness only; this is not live OpenRelik compatibility."""
    def __init__(self, statuses: list[dict[str, Any]] | None = None) -> None: self.statuses = list(statuses or []); self.submissions = []; self.workflow = "wf-" + uuid.uuid4().hex[:8]
    def submit(self, request: dict[str, Any], *, idempotency_key: str) -> dict[str, Any]: self.submissions.append((request, idempotency_key)); return {"workflow_id": self.workflow, "task_id": "task-1", "status": "queued"}
    def status(self, workflow_id: str, task_id: str | None = None) -> dict[str, Any]: return self.statuses.pop(0)
