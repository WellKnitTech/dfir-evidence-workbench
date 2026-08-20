"""Bounded, local-only MXRay email worker.

The worker consumes staged metadata plus a read-only path; raw message bytes never
cross the result boundary.  It uses stdlib parsers and deliberately does not
execute or extract attachments.
"""
from __future__ import annotations

import hashlib
import html
import io
import json
import mailbox
import mimetypes
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from .mxray_contract import validate_job_request, validate_job_result

WORKER_VERSION = "1.0.0"
MXRAY_VERSION = "stdlib-core-1.0.0"
IMPLEMENTED_CAPABILITIES = ("message_metadata", "authentication", "routing", "attachments", "archives", "reports")


class MXRayWorkerError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False, quarantine: bool = False) -> None:
        super().__init__(message)
        self.code, self.message, self.retryable, self.quarantine = code, message, retryable, quarantine


@dataclass(frozen=True)
class LocalTransport:
    """Deterministic in-process transport harness; no network operations."""

    workflow_id: str = "mxray-local"

    def submit(self, request: dict[str, Any], staged_path: str | Path) -> dict[str, Any]:
        result = MXRayWorker().process(request, staged_path, workflow_id=self.workflow_id)
        return {"workflow_id": self.workflow_id, "status": result["terminal_state"], "result": result}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _utc(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return None


def _addresses(value: str | None) -> list[str]:
    return [address for _, address in getaddresses([value or ""]) if address]


def _id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:16]}"


def _artifact(kind: str, value: bytes, uri: str) -> dict[str, Any]:
    return {"artifact_id": _id(kind, uri), "artifact_type": kind, "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value), "metadata_uri": uri}


def _safe_headers(message: Any) -> dict[str, str]:
    """Expose ordinary headers only; header values can contain credentials."""
    return {
        key: str(value)
        for key, value in message.items()
        if not any(word in key.lower().replace("-", "_") for word in ("authorization", "cookie", "token", "api_key", "apikey", "secret", "password"))
    }


def _safe_archive_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    return bool(normalized) and not PurePosixPath(normalized).is_absolute() and all(part not in {"", ".", ".."} for part in parts)


class MXRayWorker:
    """Analyze EML/mbox metadata with strict request and resource limits."""

    def process(self, request: dict[str, Any], staged_path: str | Path, *, workflow_id: str = "mxray-local") -> dict[str, Any]:
        request = validate_job_request(request)
        context, limits = request["context"], request["limits"]
        path = Path(staged_path)
        actual_hash = request["input"]["sha256"]
        try:
            if path.is_symlink() or not path.is_file():
                raise MXRayWorkerError("SOURCE_INVALID", "staged input must be a regular file", quarantine=True)
            with path.open("rb") as handle:
                source_bytes = handle.read()
            actual_hash = hashlib.sha256(source_bytes).hexdigest()
            if actual_hash.lower() != request["input"]["sha256"].lower():
                raise MXRayWorkerError("INTEGRITY_MISMATCH", "staged input SHA-256 does not match request", quarantine=True)
            if path.stat().st_size != request["input"]["size_bytes"]:
                raise MXRayWorkerError("INTEGRITY_MISMATCH", "staged input size does not match request", quarantine=True)
            if request["input"]["media_type"] not in {"eml", "mbox", "mbx"}:
                raise MXRayWorkerError("PARSER_UNSUPPORTED", "local worker supports EML and mbox only")
            if request["input"]["media_type"] in {"mbox", "mbx"}:
                box = mailbox.mbox(path, create=False)
                try:
                    if len(box) != 1:
                        raise MXRayWorkerError("PARSER_UNSUPPORTED", "multi-message mbox is fail-closed; submit one message at a time")
                finally:
                    box.close()
            message = BytesParser(policy=policy.default).parsebytes(source_bytes)
            return validate_job_result(self._result(request, message, path, workflow_id, limits))
        except MXRayWorkerError as exc:
            return validate_job_result(self._failure(request, workflow_id, actual_hash if "actual_hash" in locals() else request["input"]["sha256"], exc))
        except (OSError, ValueError, UnicodeError) as exc:
            failure = MXRayWorkerError("PARSER_ERROR", f"parser failed safely: {type(exc).__name__}", quarantine=True)
            return validate_job_result(self._failure(request, workflow_id, request["input"]["sha256"], failure))

    def _result(self, request: dict[str, Any], message: Any, path: Path, workflow_id: str, limits: dict[str, int]) -> dict[str, Any]:
        context = request["context"]
        headers = _safe_headers(message)
        message_id = str(message.get("Message-ID") or _id("message", context["source_id"]))
        source_header = lambda name: f"header:{name}"
        findings: list[dict[str, Any]] = []
        if message.get("Authentication-Results"):
            auth = str(message["Authentication-Results"])
            if any(word in auth.lower() for word in ("fail", "softfail", "none")):
                findings.append({"finding_id": _id("finding", "auth" + auth), "category": "authentication", "title": "Authentication result requires review", "confidence": "high", "summary": "Authentication-Results contains a non-passing result.", "source_ids": [source_header("Authentication-Results")]})
        received = message.get_all("Received", [])
        if received:
            findings.append({"finding_id": _id("finding", "received" + str(received[0])), "category": "routing", "title": "Routing headers present", "confidence": "confirmed", "summary": f"Message contains {len(received)} Received header(s).", "source_ids": [source_header("Received")]})
        attachments: list[dict[str, Any]] = []
        total = 0
        limitations: list[str] = ["MXRay core is local stdlib parsing; external enrichment is disabled."]
        for index, part in enumerate(message.walk()):
            filename = part.get_filename()
            if not filename:
                continue
            payload = part.get_payload(decode=True) or b""
            source_id = f"attachment:{index}:{filename}"
            digest = hashlib.sha256(payload).hexdigest()
            status = "analyzed"
            if len(payload) > limits["max_attachment_bytes"] or total + len(payload) > limits["max_total_attachment_bytes"]:
                status = "rejected"
                limitations.append(f"Attachment limit exceeded for {filename}.")
            total += len(payload)
            attachment = {"attachment_id": _id("attachment", source_id), "source_id": source_id, "media_type": part.get_content_type() or mimetypes.guess_type(filename)[0] or "application/octet-stream", "size_bytes": len(payload), "sha256": digest, "status": status}
            if status == "analyzed" and zipfile.is_zipfile(io.BytesIO(payload)):
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    members = archive.infolist()
                    unsafe = any(not _safe_archive_name(member.filename) or stat.S_ISLNK((member.external_attr >> 16) & 0xFFFF) for member in members)
                    if unsafe:
                        attachment["status"] = "rejected"
                        limitations.append(f"Unsafe archive member rejected for {filename}.")
                    elif len(members) > limits["max_archive_members"]:
                        attachment["status"] = "rejected"
                        limitations.append(f"Archive member limit exceeded for {filename}.")
                    else:
                        findings.append({"finding_id": _id("finding", source_id + "archive"), "category": "archive", "title": "Archive attachment inspected", "confidence": "confirmed", "summary": f"Archive contains {len(members)} bounded member(s); no files were extracted.", "source_ids": [source_id]})
            attachments.append(attachment)
        if len(findings) > limits["max_findings"]:
            raise MXRayWorkerError("FINDING_LIMIT_EXCEEDED", "finding limit exceeded", quarantine=True)
        safe_html = {"status": "not_requested", "artifact_id": None}
        if "safe_html" in request["policies"]["analysis"]["capabilities"]:
            body = message.get_body(preferencelist=("html", "plain"))
            raw = (body.get_content() if body else "").encode("utf-8", "replace")
            if len(raw) <= limits["max_html_bytes"] and body and body.get_content_type() == "text/html":
                cleaned = re.sub(r"<(script|style|iframe)\b[^>]*>.*?</\1>", "", raw.decode("utf-8", "replace"), flags=re.I | re.S)
                safe_bytes = html.escape(cleaned).encode("utf-8")
                safe_html = {"status": "omitted", "artifact_id": None}
                limitations.append("Safe HTML was not persisted because this worker has no artifact store.")
            elif body and body.get_content_type() == "text/html":
                safe_html["status"] = "omitted"
                limitations.append("HTML exceeded configured safe-render limit.")
        citations = [{"citation_id": _id("citation", key), "source_id": source_header(key), "kind": "header", "detail": f"Parsed {key} header"} for key in ("From", "To", "Date") if message.get(key)]
        manifest = json.dumps({"source_id": context["source_id"], "source_sha256": request["input"]["sha256"], "toolchain": request["toolchain"]}, sort_keys=True).encode()
        report = json.dumps({"message_id": message_id, "finding_ids": [item["finding_id"] for item in findings], "attachment_ids": [item["attachment_id"] for item in attachments], "limitations": limitations}, sort_keys=True).encode()
        reports = [_artifact("report", report, f"artifact://{context['case_id']}/{context['source_id']}/report")] if len(report) <= limits["max_report_bytes"] else []
        if not reports:
            limitations.append("Report exceeded configured report limit.")
        audit_event = {"event_id": _id("event", request["request_id"]), "event_type": "mxray.email.analyze", "at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "detail": "local parser; no egress", "tenant_id": context["tenant_id"], "case_id": context["case_id"], "evidence_id": context["evidence_id"], "source_sha256": request["input"]["sha256"], "decision": "ready_for_review"}
        return {"contract_version": "1.0.0", "request_id": request["request_id"], "workflow": {"workflow_id": workflow_id, "status": "succeeded", "worker_version": WORKER_VERSION}, "toolchain": request["toolchain"], "capabilities": list(IMPLEMENTED_CAPABILITIES), "message": {"message_id": message_id, "subject": message.get("Subject"), "date_utc": _utc(message.get("Date")), "from": (_addresses(message.get("From")) or [None])[0], "to": _addresses(message.get("To")), "cc": _addresses(message.get("Cc")), "headers": headers}, "findings": findings, "attachments": attachments, "safe_html": safe_html, "citations": citations, "limitations": limitations, "reports": reports, "artifacts": [_artifact("manifest", manifest, f"artifact://{context['case_id']}/{context['source_id']}/manifest")], "provenance": {"tenant_id": context["tenant_id"], "case_id": context["case_id"], "evidence_id": context["evidence_id"], "source_id": context["source_id"], "source_sha256": request["input"]["sha256"], "idempotency_key": request["idempotency"]["key"]}, "audit": {"events": [audit_event], "egress": "none"}, "terminal_state": "succeeded"}

    def _failure(self, request: dict[str, Any], workflow_id: str, source_hash: str, failure: MXRayWorkerError) -> dict[str, Any]:
        context = request["context"]
        return {"contract_version": "1.0.0", "request_id": request["request_id"], "workflow": {"workflow_id": workflow_id, "status": "quarantined" if failure.quarantine else "failed", "worker_version": WORKER_VERSION}, "toolchain": request["toolchain"], "capabilities": list(IMPLEMENTED_CAPABILITIES), "message": {"message_id": _id("message", request["request_id"]), "subject": None, "date_utc": None, "from": None, "to": [], "headers": {}}, "findings": [], "attachments": [], "safe_html": {"status": "failed", "artifact_id": None}, "citations": [], "limitations": ["Analysis stopped before message parsing."], "reports": [], "artifacts": [], "provenance": {"tenant_id": context["tenant_id"], "case_id": context["case_id"], "evidence_id": context["evidence_id"], "source_id": context["source_id"], "source_sha256": source_hash, "idempotency_key": request["idempotency"]["key"]}, "audit": {"events": [{"event_id": _id("event", request["request_id"]), "event_type": "mxray.email.failure", "at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "detail": failure.code}], "egress": "none"}, "terminal_state": "quarantined" if failure.quarantine else "failed", "failure": {"code": failure.code, "retryable": failure.retryable, "message": failure.message, **({"quarantine_reference": f"quarantine://{context['case_id']}/{request['request_id']}"} if failure.quarantine else {})}}

def analyze_email(request: dict[str, Any], staged_path: str | Path) -> dict[str, Any]:
    return MXRayWorker().process(request, staged_path)
