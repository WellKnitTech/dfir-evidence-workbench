import hashlib
import zipfile
from email.message import EmailMessage

from dfir_workbench.mxray_contract import build_idempotency_key
from dfir_workbench.mxray_worker import MXRayWorker


def _request(data: bytes):
    digest = hashlib.sha256(data).hexdigest()
    key = build_idempotency_key(tenant_id="tenant-1", case_id="case-1", evidence_id="evidence-1", source_id="source-1", sha256=digest, worker_version="1.0.0")
    return {
        "contract_version": "1.0.0", "request_id": "request-1", "submitted_at_utc": "2026-08-20T12:00:00Z",
        "context": {"tenant_id": "tenant-1", "case_id": "case-1", "evidence_id": "evidence-1", "source_id": "source-1"},
        "input": {"media_type": "eml", "sha256": digest, "size_bytes": len(data), "staged_uri": "evidence://case-1/source-1", "read_only": True},
        "toolchain": {"worker_version": "1.0.0", "mxray_version": "1.0.0", "parser_versions": {"email": "stdlib"}},
        "policies": {"analysis": {"capabilities": ["message_metadata", "routing", "safe_html", "reports"], "policy_id": "default", "version": "1.0.0"}, "enrichment": {"enabled": False, "network_egress": "disabled", "providers": [], "approval_required": True}},
        "limits": {"max_attachment_bytes": 1000, "max_total_attachment_bytes": 1000, "max_archive_members": 5, "max_html_bytes": 1000, "max_findings": 10, "max_report_bytes": 1000},
        "idempotency": {"key": key, "scope": "tenant-1/case-1"}, "audit": {"correlation_id": "corr-1", "requested_by": "analyst-1", "event_type": "mxray.email.analyze"},
    }


def test_worker_emits_bounded_metadata_and_no_egress(tmp_path):
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "analyst@example.test"
    message["Subject"] = "Hello"
    message["Date"] = "Thu, 20 Aug 2026 12:00:00 +0000"
    message["Received"] = "from host.example.test"
    message.set_content("plain")
    message.add_alternative("<p>safe</p>", subtype="html")
    message.add_attachment(b"bytes", maintype="application", subtype="octet-stream", filename="sample.bin")
    source = tmp_path / "mail.eml"
    data = message.as_bytes()
    source.write_bytes(data)

    result = MXRayWorker().process(_request(data), source)

    assert result["terminal_state"] == "succeeded"
    assert result["audit"]["egress"] == "none"
    assert result["message"]["from"] == "sender@example.test"
    assert result["attachments"][0]["sha256"] == hashlib.sha256(b"bytes").hexdigest()
    assert source.read_bytes() == data
    assert all("raw" not in item for item in result.values() if isinstance(item, dict))


def test_worker_quarantines_integrity_mismatch(tmp_path):
    source = tmp_path / "mail.eml"
    source.write_bytes(b"From: a@example.test\n\nbody\n")
    request = _request(b"different")

    result = MXRayWorker().process(request, source)

    assert result["terminal_state"] == "quarantined"
    assert result["failure"]["code"] == "INTEGRITY_MISMATCH"
    assert result["failure"]["quarantine_reference"].startswith("quarantine://")


def test_secret_shaped_headers_are_redacted_without_quarantine(tmp_path):
    message = b"From: sender@example.test\nTo: analyst@example.test\nAuthorization: Bearer super-secret\nX-Api-Key: hidden-key\nCookie: session=secret\nX-Trace: retained\n\nbody\n"
    source = tmp_path / "mail.eml"
    source.write_bytes(message)

    result = MXRayWorker().process(_request(message), source)

    assert result["terminal_state"] == "succeeded"
    assert result["message"]["headers"]["X-Trace"] == "retained"
    assert all("authorization" not in key.lower() and "api-key" not in key.lower() and "cookie" not in key.lower() for key in result["message"]["headers"])
    assert "super-secret" not in str(result)
    assert "hidden-key" not in str(result)
    assert "session=secret" not in str(result)


def test_safe_html_is_omitted_without_artifact_store_and_uses_text_only_cleaning(tmp_path):
    message = b"Content-Type: text/html; charset=utf-8\n\n<script>alert(1)</script><p>ok</p>"
    source = tmp_path / "mail.eml"
    source.write_bytes(message)

    result = MXRayWorker().process(_request(message), source)

    assert result["terminal_state"] == "succeeded"
    assert result["safe_html"] == {"status": "omitted", "artifact_id": None}


def test_msg_is_fail_closed_as_unsupported(tmp_path):
    message = b"not an outlook message"
    source = tmp_path / "mail.msg"
    source.write_bytes(message)
    request = _request(message)
    request["input"]["media_type"] = "msg"

    result = MXRayWorker().process(request, source)

    assert result["terminal_state"] == "failed"
    assert result["failure"]["code"] == "PARSER_UNSUPPORTED"


def test_archive_inspection_value_error_rejects_attachment_and_keeps_message_metadata(tmp_path, monkeypatch):
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["Subject"] = "Archive"
    message.set_content("body")
    message.add_attachment(b"corrupt", maintype="application", subtype="zip", filename="bad.zip")
    data = message.as_bytes()
    source = tmp_path / "mail.eml"
    source.write_bytes(data)

    def raise_value_error(_payload):
        raise ValueError("negative seek")

    monkeypatch.setattr(zipfile, "is_zipfile", raise_value_error)
    result = MXRayWorker().process(_request(data), source)

    assert result["terminal_state"] == "succeeded"
    assert result["message"]["subject"] == "Archive"
    assert result["attachments"][0]["status"] == "rejected"
    assert any("archive inspection failed" in limitation.lower() for limitation in result["limitations"])


def test_archive_inspection_bad_zip_file_does_not_escape_process(tmp_path, monkeypatch):
    message = EmailMessage()
    message.set_content("body")
    message.add_attachment(b"corrupt", maintype="application", subtype="zip", filename="bad.zip")
    data = message.as_bytes()
    source = tmp_path / "mail.eml"
    source.write_bytes(data)

    monkeypatch.setattr(zipfile, "is_zipfile", lambda _payload: True)

    class RaisingZipFile:
        def __init__(self, *_args, **_kwargs):
            raise zipfile.BadZipFile("central directory missing")

    monkeypatch.setattr(zipfile, "ZipFile", RaisingZipFile)
    result = MXRayWorker().process(_request(data), source)

    assert result["terminal_state"] == "succeeded"
    assert result["attachments"][0]["status"] == "rejected"
    assert "PARSER_ERROR" not in str(result)