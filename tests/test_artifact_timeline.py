import json
import zipfile
from pathlib import Path

from dfir_workbench.artifact_timeline import OpenRelikFastPath, process_artifact


def test_jsonl_timeline_normalizes_and_preserves_provenance(tmp_path):
    path = tmp_path / "hayabusa.jsonl"
    path.write_text(json.dumps({"timestamp": "2026-08-18T12:00:00-05:00", "rule_title": "Synthetic"}) + "\n")
    result = process_artifact(path)
    assert result["status"] == "complete"
    row = result["records"][0]
    assert row["payload"]["time_utc"] == "2026-08-18T17:00:00Z"
    assert row["payload"]["time_raw"].endswith("-05:00")
    assert row["provenance"]["source_sha256"] == result["source"]["sha256"]
    assert row["provenance"]["review_state"] == "unreviewed"


def test_archive_and_malformed_variants_are_explicit(tmp_path):
    archive = tmp_path / "vr-triage.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("results.jsonl", '{"timestamp": "2026-08-18T00:00:00Z", "client": "C.1"}\n')
        bundle.writestr("bad.jsonl", '{not-json}\n')
    result = process_artifact(archive)
    assert result["status"] == "invalid_input"
    assert result["stats"]["record_count"] == 1
    assert any(error["code"] == "MALFORMED_INPUT" for error in result["errors"])


def test_binary_optional_formats_do_not_claim_empty_success(tmp_path):
    for name in ("events.evtx", "SYSTEM.hive"):
        path = tmp_path / name
        path.write_bytes(b"synthetic binary")
        result = process_artifact(path)
        assert result["status"] == "partial"
        assert result["records"] == []
        assert result["unresolved"][0]["code"] == "OPTIONAL_PARSER_UNAVAILABLE"


def test_yara_strings_hash_and_browser_rows_are_deterministic(tmp_path):
    path = tmp_path / "browser.csv"
    path.write_text("url,timestamp\nhttps://example.test/,2026-08-18T12:00:00Z\n")
    first = process_artifact(path)
    second = process_artifact(path)
    assert first == second
    assert first["records"][0]["payload"]["url"] == "https://example.test/"


def test_velociraptor_openrelik_fast_path_retry_and_conflict(tmp_path):
    path = tmp_path / "vr.jsonl"
    path.write_text('{"timestamp":"2026-08-18T00:00:00Z","value":"one"}\n')
    result = process_artifact(path)
    fast_path = OpenRelikFastPath()
    accepted = fast_path.submit(result, case_id="case-synthetic")
    duplicate = fast_path.submit(result, case_id="case-synthetic")
    changed = dict(result)
    changed["records"] = [dict(result["records"][0], payload={"value": "changed"})]
    conflict = fast_path.submit(changed, case_id="case-synthetic")
    assert accepted["status"] == "accepted"
    assert duplicate["status"] == "duplicate"
    assert conflict["status"] == "conflict"
    assert conflict["code"] == "IDEMPOTENCY_CONFLICT"
