"""Velociraptor -> Workbench -> schema-backed OpenRelik metadata workflow."""
from __future__ import annotations

import csv
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from .adapters.velociraptor_adapter import SafetyLimits, VelociraptorAdapter
from .openrelik_adapter import JobRecord, OpenRelikAdapter
from .openrelik_contract import build_idempotency_key


class FastPathError(RuntimeError):
    pass


class VelociraptorTimelineFastPath:
    def __init__(self, *, openrelik: OpenRelikAdapter, evidence_store: Any = None, principal: Any = None,
                 max_upload_bytes: int = 5 * 1024 * 1024 * 1024, timeout_seconds: float = 300.0,
                 limits: SafetyLimits | None = None, audit: Callable[[dict[str, Any]], Any] | None = None):
        if max_upload_bytes <= 0 or timeout_seconds <= 0:
            raise ValueError("limits must be positive")
        self.openrelik, self.evidence_store, self.principal = openrelik, evidence_store, principal
        self.max_upload_bytes, self.timeout_seconds = max_upload_bytes, timeout_seconds
        self.limits, self.audit = limits or SafetyLimits(), audit

    def _audit(self, **event: Any) -> None:
        if self.audit:
            self.audit(event)

    def submit_collection(self, *, source: str | Path, tenant_id: str, case_id: str, asset_id: str,
                          evidence_id: str, expected_sha256: str | None = None,
                          workflow: str = "velociraptor-plaso-hayabusa-timeline-v1") -> dict[str, Any]:
        started = time.monotonic()
        source_path = Path(source).expanduser().resolve(strict=False)
        if not source_path.is_file() or source_path.is_symlink():
            raise FastPathError("source must be a regular non-symlink collection archive")
        size = source_path.stat().st_size
        if size > self.max_upload_bytes:
            raise FastPathError("UPLOAD_LIMIT_EXCEEDED")
        sha = self._hash(source_path)
        if expected_sha256 is not None and sha != expected_sha256:
            raise FastPathError("CHECKSUM_MISMATCH")
        self._deadline(started)
        adapter = VelociraptorAdapter(source_path, source_path.parent / (".analysis-" + evidence_id), self.limits)
        if adapter.validate()["status"] != "valid":
            raise FastPathError("COLLECTION_INVALID")
        if self.evidence_store is not None and (self.principal is None or str(self.principal.tenant_id) != tenant_id):
            raise FastPathError("TENANT_SCOPE_MISMATCH")
        key = build_idempotency_key(tenant_id, case_id, evidence_id, sha, workflow)
        request = self._request(tenant_id, case_id, asset_id, evidence_id, sha, workflow, key)
        principal = self.principal or SimpleNamespace(tenant_id=tenant_id, analyst_id="local-analyst")
        try:
            job = self.openrelik.submit(principal, request)
        except (ValueError, PermissionError, RuntimeError) as exc:
            raise FastPathError(str(exc)) from exc
        # A completed claim is safe to reuse. Incomplete claims deliberately resume.
        reused = bool(job.external_status == "succeeded" and job.outputs)
        if not reused:
            try:
                manifest = None
                if self.evidence_store is not None:
                    quarantine = self._quarantine_for_retry(source_path, sha)
                    manifest = self.evidence_store.promote_to_evidence(case_id=case_id, evidence_id=evidence_id,
                        quarantine_id=quarantine.quarantine_id, expected_sha256=sha)
                record = adapter.collect(self._candidate_paths(adapter.inventory()))
                self._deadline(started)
                outputs = self._normalized_outputs(record)
                job = self.openrelik.store.add_outputs(job.job_id, tenant_id, case_id, outputs)
                job = self.openrelik.store.update(job.job_id, attempts=job.attempts + 1)
                evidence = {"evidence_id": evidence_id, "sha256": sha, "size": size,
                            "collection": record["collection_coverage"]}
                if manifest:
                    evidence.update(case_id=manifest.case_id, source_quarantine_id=manifest.source_quarantine_id)
                self._audit(action="submission_completed", result="success", tenant_id=tenant_id, case_id=case_id,
                            evidence_id=evidence_id)
                return self._result(job, sha, size, outputs, evidence)
            except Exception:
                self._audit(action="submission_incomplete", result="failed", tenant_id=tenant_id, case_id=case_id,
                            evidence_id=evidence_id)
                raise
        self._audit(action="submission_reused", result="success", tenant_id=tenant_id, case_id=case_id,
                    evidence_id=evidence_id, reused=True)
        return self._result(job, sha, size, job.outputs)

    def _quarantine_for_retry(self, source: Path, sha: str) -> Any:
        finder = getattr(self.evidence_store, "find_quarantine_by_sha", None)
        if finder:
            found = finder(sha)
            if found:
                return found
        return self.evidence_store.ingest_to_quarantine(source)

    @staticmethod
    def _request(tenant: str, case: str, asset: str, evidence: str, sha: str, workflow: str, key: str) -> dict[str, Any]:
        return {"contract_version": "1.0.0", "request_id": "req-" + key[3:19],
            "submitted_at_utc": "2026-01-01T00:00:00Z",
            "immutable_context": {"tenant": {"tenant_id": tenant}, "case": {"case_id": case},
                "asset": {"asset_id": asset, "asset_type": "endpoint"},
                "evidence": {"evidence_id": evidence, "sha256": sha, "metadata_uri": "metadata://" + evidence},
                "acquisition": {"acquisition_id": "acq-" + key[3:19], "method": "velociraptor", "acquired_at_utc": "2026-01-01T00:00:00Z"}},
            "execution": {"read_only": True, "tool_profile": workflow, "capability_requirements": ["filesystem_read"],
                "reviewer": {"reviewer_id": "pending", "approval_reference": "pending"},
                "retention": {"policy_id": "case-default", "retain_until_utc": "2099-01-01T00:00:00Z"},
                "expected_outputs": [{"output_type": "report", "logical_name": "timeline", "required": True}]},
            "idempotency": {"key": key, "scope": f"{tenant}:{case}:{evidence}"},
            "retry_policy": {"max_attempts": 3, "backoff_seconds": 0},
            "redaction_policy": {"policy_id": "safe-v1", "version": "1.0.0"}}

    def approve(self, *, job_id: str, tenant_id: str, case_id: str) -> JobRecord:
        return self.openrelik.approve(self.principal, job_id, case_id)

    @staticmethod
    def export_timesketch(result: dict[str, Any], exporter: Callable[[list[dict[str, Any]]], Any] | None = None) -> Any:
        return {"status": "not_configured", "exported": False} if exporter is None else exporter(result.get("timeline", []))

    def _hash(self, path: Path) -> str:
        started, digest = time.monotonic(), hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
                if time.monotonic() - started > self.timeout_seconds:
                    raise FastPathError("TIMEOUT")
        return digest.hexdigest()

    def _deadline(self, started: float) -> None:
        if time.monotonic() - started > self.timeout_seconds:
            raise FastPathError("TIMEOUT")

    @staticmethod
    def _candidate_paths(entries: list[dict[str, Any]]) -> list[str]:
        names = ("plaso", "hayabusa", "timeline", "event")
        return [x["path"] for x in entries if x["kind"] == "file" and any(n in x["path"].lower() for n in names)][:100]

    @staticmethod
    def _normalized_outputs(record: dict[str, Any]) -> list[dict[str, Any]]:
        outputs = []
        for item in record["safe_extraction"].get("extracted", []):
            try: rows = VelociraptorTimelineFastPath._read_rows(Path(item["output_path"]))
            except (OSError, UnicodeError, ValueError, csv.Error): continue
            for row_number, raw in enumerate(rows, 1):
                ts = raw.get("timestamp") or raw.get("timestamp_utc") or raw.get("datetime") or raw.get("Timestamp")
                outputs.append({"occurred_at_utc": VelociraptorTimelineFastPath._utc(ts), "timestamp_raw": ts,
                    "message": str(raw.get("message") or raw.get("Message") or raw.get("description") or ""),
                    "artifact_type": "hayabusa" if "hayabusa" in item["path"].lower() else "plaso",
                    "source_path": item["path"], "source_row": row_number, "source_sha256": item["sha256"],
                    "provenance": {"mapping_version": "timeline-normalizer-1", "analyst_review_required": True},
                    "fields": {k: v for k, v in raw.items() if k not in {"timestamp", "timestamp_utc", "datetime", "Timestamp", "message", "Message", "description"}}})
        return outputs

    @staticmethod
    def _read_rows(path: Path) -> list[dict[str, Any]]:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".jsonl": return [json.loads(line) for line in text.splitlines() if line.strip()]
        if path.suffix.lower() == ".json":
            data = json.loads(text); return data if isinstance(data, list) else [data]
        if path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8-sig") as stream: return list(csv.DictReader(stream))
        return []

    @staticmethod
    def _utc(value: Any) -> str | None:
        if not value: return None
        try: dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError: return None
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _result(job: JobRecord, sha: str, size: int, outputs: list[dict[str, Any]], evidence: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"job": {"job_id": job.job_id, "workflow_id": job.workflow_id, "task_id": job.task_id,
            "status": job.external_status, "review_state": job.review_state, "output_count": len(outputs)},
            "evidence": evidence or {"evidence_id": job.evidence_id, "sha256": sha, "size": size}, "timeline": outputs,
            "provenance": {"source": "velociraptor", "workflow_id": job.workflow_id, "task_id": job.task_id,
                           "mapping_version": "timeline-normalizer-1"}, "timesketch": {"status": "optional-downstream", "exported": False}}
