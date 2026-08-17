"""Schema and projection tests for DFIR-IRIS ingest adapter.

Uses synthetic fixtures only. Validates produced entities against interop schema.
Covers required projections (case/ioc/asset/timeline/finding/evidence) + explicit
quarantine for secrets and unsupported types (attachment ioc).
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from dfir_workbench.adapters.dfir_iris_ingest_adapter import (
    IngestValidationError,
    DFIRIRISIngestAdapter,
    project_dfir_iris_case,
    project_dfir_iris_ioc,
)
from dfir_workbench.interop import idempotency_key

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "iris"


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
    adapter = DFIRIRISIngestAdapter(integration_id="int-iris-1")
    ent = adapter.project_case(raw, source_scope="kerrville-org:42")
    validate_interop(ent)
    assert ent["entity_type"] == "case"
    assert ent["provenance"]["source_system"] == "iris"
    assert ent["provenance"]["source_scope"] == "kerrville-org:42"
    assert ent["provenance"]["source_id"] == "507a5fab-358a-4946-82d0-625ef8a9fa0d"
    p = ent["payload"]
    assert p["title"] == "Phishing report from user"
    assert "client_name" in p.get("custom_fields", {})
    assert "owner" not in p
    assert any("ownership" in x for x in ent["provenance"]["lossy_transformations"])
    assert ent["provenance"]["idempotency_key"].startswith("v1:")


def test_project_alert_and_ioc_roundtrip():
    raw_alert = load("alert_minimal.json")
    aent = DFIRIRISIngestAdapter("int-2").project_alert(raw_alert, source_scope="customer-1")
    validate_interop(aent)
    assert aent["entity_type"] == "alert"

    raw_ip = load("ioc_ip.json")
    oent = project_dfir_iris_ioc(raw_ip, integration_id="int-2", source_scope="customer-1")
    validate_interop(oent)
    assert oent["entity_type"] == "ioc"
    assert oent["payload"]["value"] == "198.51.100.10"
    assert oent["payload"]["type"] == "ip-dst"
    assert oent["payload"]["classification"] == "ioc"
    assert oent["payload"]["tlp"] == "amber"


def test_project_asset_and_timeline():
    asset = load("asset_server.json")
    aent = DFIRIRISIngestAdapter("int-3").project_asset(asset, source_scope="customer-1")
    validate_interop(aent)
    assert aent["entity_type"] == "asset"
    assert aent["payload"]["name"] == "FILESERVER1231"
    assert aent["payload"]["ip"] == "10.0.0.15"

    ev = load("timeline_event.json")
    tent = DFIRIRISIngestAdapter("int-3").project_timeline_event(ev, source_scope="customer-1", category="task")
    validate_interop(tent)
    assert tent["entity_type"] == "timeline_event"
    assert tent["payload"]["category"] == "task"
    assert "Initial triage" in tent["payload"]["title"]


def test_project_note_to_finding_and_evidence():
    note = load("note_finding.json")
    fent = DFIRIRISIngestAdapter().project(note, entity="note", source_scope="customer-1")
    validate_interop(fent)
    assert fent["entity_type"] == "finding"
    assert fent["payload"]["approval_required"] is True
    assert "phishing vector" in fent["payload"]["title"]

    ev = load("evidence_minimal.json")
    eent = DFIRIRISIngestAdapter().project_evidence_reference(ev, source_scope="customer-1")
    validate_interop(eent)
    assert eent["entity_type"] == "evidence_reference"
    assert eent["payload"]["content_transferred"] is False
    assert len(eent["payload"]["sha256"]) == 64


def test_domain_ioc_exact_value_type():
    dom = load("ioc_domain.json")
    ent = DFIRIRISIngestAdapter().project_ioc(dom, source_scope="org-scope-x")
    validate_interop(ent)
    assert ent["payload"]["value"] == "malicious.example.net"
    assert ent["payload"]["type"] == "domain"
    assert ent["provenance"]["source_scope"] == "org-scope-x"


def test_rejects_secrets_explicit_quarantine_case():
    bad = load("quarantine_secret.json")
    with pytest.raises(IngestValidationError) as exc:
        DFIRIRISIngestAdapter().project_case(bad, source_scope="customer-1")
    assert "forbidden secret field" in str(exc.value).lower()


def test_quarantines_unsupported_ioc_attachment_type():
    att = load("quarantine_ioc_attachment.json")
    ent = DFIRIRISIngestAdapter().project_ioc(att, source_scope="customer-1")
    validate_interop(ent)
    prov = ent["provenance"]
    rf = prov["redaction_flags"]
    assert rf.get("ioc_type", {}).get("decision") == "quarantined"
    assert "quarantined:unsupported-type" in prov["lossy_transformations"]
    assert ent["payload"]["type"] == "attachment"


def test_quarantine_misp_recorded_as_lossy():
    m = load("quarantine_misp_ioc.json")
    ent = DFIRIRISIngestAdapter().project_ioc(m, source_scope="customer-1")
    validate_interop(ent)
    lossy = ent["provenance"]["lossy_transformations"]
    assert any("misp" in x.lower() or "lossy" in x for x in lossy)  # misp link dropped as lossy in practice


def test_idempotency_and_utc_preserved_across_projections():
    raw = load("case_minimal.json")
    e1 = DFIRIRISIngestAdapter("fixed-int").project_case(raw, source_scope="s1", source_revision="r1")
    e2 = DFIRIRISIngestAdapter("fixed-int").project_case(raw, source_scope="s1", source_revision="r1")
    assert e1["provenance"]["idempotency_key"] == e2["provenance"]["idempotency_key"]
    assert e1["provenance"]["source_updated_at_utc"].endswith("Z")
    assert "Z" in e1["provenance"]["source_updated_at_raw"] or "+" in e1["provenance"]["source_updated_at_raw"]


def test_schema_rejects_bad_approval_like_before():
    # sanity that interop schema still enforces finding approval
    p = {
        "integration_id": "x",
        "source_system": "iris",
        "source_entity": "finding",
        "source_id": "f1",
        "source_scope": "s",
        "source_revision": "r",
        "source_updated_at_raw": "2026-08-07T12:00:00Z",
        "source_updated_at_utc": "2026-08-07T12:00:00Z",
        "source_timezone": "UTC",
        "mapping_version": "1.0.0",
        "idempotency_key": idempotency_key(
            integration_id="x", direction="in", source_system="iris", source_entity="finding", source_id="f1", source_revision="r"
        ),
        "redaction_flags": {},
        "lossy_transformations": [],
    }
    bad = {"schema_version": "1.0", "entity_type": "finding", "provenance": p, "payload": {"title": "f", "body": "b", "approval_required": False}}
    schema = json.loads((ROOT / "schemas" / "interop-entity.schema.json").read_text())
    errs = list(Draft202012Validator(schema).iter_errors(bad))
    assert errs
