"""Schema and projection tests for TheHive ingest adapter.

Uses synthetic fixtures only. Validates produced entities against interop schema.
Covers required projections (case/alert/observable/timeline) + explicit quarantine for
secrets and unsupported types (attachment, cortex, misp).
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from dfir_workbench.adapters.thehive_ingest_adapter import (
    IngestValidationError,
    TheHiveIngestAdapter,
    project_thehive_case,
    project_thehive_observable,
)
from dfir_workbench.interop import idempotency_key

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "thehive"


def validate_interop(value: dict) -> None:
    schema = json.loads((ROOT / "schemas" / "interop-entity.schema.json").read_text())
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=str,
    )
    assert not errors, "\n".join(error.message for error in errors)


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_project_case_minimal_validates_and_preserves_fields():
    raw = load("case_minimal.json")
    adapter = TheHiveIngestAdapter(integration_id="int-hive-1")
    ent = adapter.project_case(raw, source_scope="org-kerr-215")
    validate_interop(ent)
    assert ent["entity_type"] == "case"
    assert ent["provenance"]["source_system"] == "hive"
    assert ent["provenance"]["source_scope"] == "org-kerr-215"
    assert ent["provenance"]["source_id"] == "AW5vZ3p4xY7Z2pQ8rT9uV"
    p = ent["payload"]
    assert p["title"] == "Phishing report from user"
    assert p["tlp"] == "amber"
    assert p["pap"] == "amber"
    assert "status" not in p
    assert "owner" not in p
    assert "dropped:status" in ent["provenance"]["lossy_transformations"]
    assert "dropped:ownership" in ent["provenance"]["lossy_transformations"]
    assert ent["provenance"]["idempotency_key"].startswith("v1:")


def test_project_alert_and_observable_roundtrip():
    raw_alert = load("alert_minimal.json")
    aent = TheHiveIngestAdapter("int-2").project_alert(raw_alert, source_scope="org-1")
    validate_interop(aent)
    assert aent["entity_type"] == "alert"
    assert "dropped:embedded-observables" in aent["provenance"]["lossy_transformations"]

    raw_ip = load("observable_ip.json")
    oent = project_thehive_observable(raw_ip, integration_id="int-2", source_scope="org-1")
    validate_interop(oent)
    assert oent["entity_type"] == "ioc"
    assert oent["payload"]["value"] == "198.51.100.10"
    assert oent["payload"]["type"] == "ip"
    assert oent["payload"]["classification"] == "ioc"
    assert oent["payload"]["tlp"] == "amber"


def test_project_timeline_from_task_and_log():
    task = load("task_triage.json")
    tent = TheHiveIngestAdapter("int-3").project_timeline_event(task, source_scope="org-1", category="task")
    validate_interop(tent)
    assert tent["entity_type"] == "timeline_event"
    assert tent["payload"]["category"] == "task"
    assert "dropped:task-status-ownership" in tent["provenance"]["lossy_transformations"]

    log = load("log_comment.json")
    lent = TheHiveIngestAdapter("int-3").project( log, entity="log", source_scope="org-1")
    validate_interop(lent)
    assert lent["payload"]["title"] == "Initial review complete. No user impact observed."


def test_domain_observable_exact_value_type():
    dom = load("observable_domain.json")
    ent = TheHiveIngestAdapter().project_observable(dom, source_scope="org-scope-x")
    validate_interop(ent)
    assert ent["payload"]["value"] == "malicious.example.net"
    assert ent["payload"]["type"] == "domain"
    assert ent["provenance"]["source_scope"] == "org-scope-x"


def test_rejects_secrets_explicit_quarantine_case():
    bad = load("quarantine_secret.json")
    with pytest.raises(IngestValidationError) as exc:
        TheHiveIngestAdapter().project_case(bad, source_scope="org-1")
    assert "forbidden secret field" in str(exc.value).lower()


def test_quarantines_unsupported_attachment_type():
    att = load("quarantine_attachment.json")
    ent = TheHiveIngestAdapter().project_observable(att, source_scope="org-1")
    validate_interop(ent)
    prov = ent["provenance"]
    rf = prov["redaction_flags"]
    assert rf.get("dataType", {}).get("decision") == "quarantined"
    assert "quarantined:unsupported-type" in prov["lossy_transformations"]
    assert ent["payload"]["type"] == "attachment"


def test_quarantine_cortex_and_misp_recorded_as_lossy():
    c = load("quarantine_cortex.json")
    ent = TheHiveIngestAdapter().project_case(c, source_scope="org-1")
    validate_interop(ent)
    lossy = ent["provenance"]["lossy_transformations"]
    assert any("cortex" in x or "misp" in x for x in lossy)

    m = load("quarantine_misp.json")
    aent = TheHiveIngestAdapter().project_alert(m, source_scope="org-1")
    validate_interop(aent)
    assert any("misp" in x for x in aent["provenance"]["lossy_transformations"])


def test_idempotency_and_utc_preserved_across_projections():
    raw = load("case_minimal.json")
    e1 = TheHiveIngestAdapter("fixed-int").project_case(raw, source_scope="s1", source_revision="r1")
    e2 = TheHiveIngestAdapter("fixed-int").project_case(raw, source_scope="s1", source_revision="r1")
    assert e1["provenance"]["idempotency_key"] == e2["provenance"]["idempotency_key"]
    assert e1["provenance"]["source_updated_at_utc"].endswith("Z")
    assert e1["provenance"]["source_updated_at_raw"].endswith("Z") or "+" in e1["provenance"]["source_updated_at_raw"]


def test_schema_rejects_bad_approval_like_before():
    # sanity that interop schema still enforces
    p = {
        "integration_id": "x",
        "source_system": "hive",
        "source_entity": "finding",
        "source_id": "f1",
        "source_scope": "s",
        "source_revision": "r",
        "source_updated_at_raw": "2026-08-07T12:00:00Z",
        "source_updated_at_utc": "2026-08-07T12:00:00Z",
        "source_timezone": "UTC",
        "mapping_version": "1.0.0",
        "idempotency_key": idempotency_key(
            integration_id="x", direction="in", source_system="hive", source_entity="finding", source_id="f1", source_revision="r"
        ),
        "redaction_flags": {},
        "lossy_transformations": [],
    }
    bad = {"schema_version": "1.0", "entity_type": "finding", "provenance": p, "payload": {"title": "f", "body": "b", "approval_required": False}}
    schema = json.loads((ROOT / "schemas" / "interop-entity.schema.json").read_text())
    errs = list(Draft202012Validator(schema).iter_errors(bad))
    assert errs
