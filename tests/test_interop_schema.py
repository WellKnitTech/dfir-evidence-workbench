import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from dfir_workbench.interop import (
    IngestValidationError,
    canonical_json,
    idempotency_key,
    payload_sha256,
    reject_secret_keys,
    utc_timestamp,
)

ROOT = Path(__file__).parents[1]


def validate(name, value):
    schema = json.loads((ROOT / "schemas" / name).read_text())
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value), key=str)
    assert not errors, "\n".join(error.message for error in errors)


def provenance(entity="case", source_id="case-1"):
    return {
        "integration_id": "test-integration",
        "source_system": "hive",
        "source_entity": entity,
        "source_id": source_id,
        "source_scope": "org-1",
        "source_revision": "etag-1",
        "source_updated_at_raw": "2026-08-07T12:00:00-05:00",
        "source_updated_at_utc": "2026-08-07T17:00:00Z",
        "source_timezone": "-05:00",
        "mapping_version": "1.0.0",
        "idempotency_key": idempotency_key(
            integration_id="test-integration", direction="in", source_system="hive",
            source_entity=entity, source_id=source_id, source_revision="etag-1",
        ),
        "redaction_flags": {},
        "lossy_transformations": [],
    }


def test_case_and_indicator_entities_validate():
    validate("interop-entity.schema.json", {
        "schema_version": "1.0", "entity_type": "case", "provenance": provenance(),
        "payload": {"title": "Suspicious login", "tags": ["triage"]},
    })
    p = provenance("ioc", "ioc-1")
    validate("interop-entity.schema.json", {
        "schema_version": "1.0", "entity_type": "ioc", "provenance": p,
        "payload": {"value": "198.51.100.10", "type": "ip", "tags": []},
    })


def test_schema_preserves_ingest_safety_boundaries():
    p = provenance("finding", "finding-1")
    finding = {"schema_version": "1.0", "entity_type": "finding", "provenance": p,
               "payload": {"title": "Finding", "body": "Observed", "approval_required": True}}
    validate("interop-entity.schema.json", finding)
    finding["payload"]["approval_required"] = False
    schema = json.loads((ROOT / "schemas" / "interop-entity.schema.json").read_text())
    assert list(Draft202012Validator(schema).iter_errors(finding))


def test_ingest_envelope_and_deterministic_identity():
    payload = {"title": "Alert", "observables": [{"dataType": "ip", "data": "198.51.100.10"}]}
    key = idempotency_key(integration_id="x", direction="in", source_system="hive", source_entity="alert", source_id="a1", source_revision="r1")
    assert key == idempotency_key(integration_id="x", direction="in", source_system="hive", source_entity="alert", source_id="a1", source_revision="r1")
    assert key.startswith("v1:") and len(key) == 46
    validate("ingest-envelope.schema.json", {
        "schema_version": "1.0", "envelope_id": "env-1", "received_at_utc": "2026-08-07T17:00:00Z",
        "source": {"system": "hive", "entity": "alert", "id": "a1", "scope": "org-1", "revision": "r1",
                   "updated_at_raw": "2026-08-07T12:00:00-05:00", "updated_at_utc": "2026-08-07T17:00:00Z", "timezone": "-05:00"},
        "payload_sha256": payload_sha256(payload), "payload": payload,
        "processing": {"status": "received", "mapping_version": "1.0.0", "idempotency_key": key},
    })


def test_timestamp_and_secret_guards():
    raw, utc = utc_timestamp("2026-08-07T12:00:00-05:00")
    assert raw.endswith("-05:00") and utc == "2026-08-07T17:00:00Z"
    with pytest.raises(IngestValidationError):
        utc_timestamp("2026-08-07T12:00:00")
    with pytest.raises(IngestValidationError):
        reject_secret_keys({"description": "ok", "nested": [{"api_key": "nope"}]})


def test_canonical_json_determinism_and_separation():
    """canonical_json produces stable output for sha; raw vendor payload kept distinct from normalized projection."""
    raw_vendor = {
        "dataType": "ip",
        "data": "198.51.100.10",
        "tags": ["suspicious"],
        "message": "observed from hive",
    }
    # normalized projection example (for interop-entity payload)
    normalized = {
        "value": "198.51.100.10",
        "type": "ip",
        "description": "observed from hive",
        "tags": ["suspicious"],
    }
    c_raw = canonical_json(raw_vendor)
    c_norm = canonical_json(normalized)
    assert c_raw != c_norm  # different structures
    assert '"dataType"' in c_raw  # raw vendor kept as-is for envelope
    assert '"dataType"' not in c_norm
    assert "data" in raw_vendor  # raw intact
    # sha over raw
    sha = payload_sha256(raw_vendor)
    assert len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)


def test_idempotency_over_integration_direction_source_tuple():
    """v1 key over the (integration, direction, source_*) 6-tuple; deterministic and schema compliant."""
    k = idempotency_key(
        integration_id="int-42",
        direction="in",
        source_system="iris",
        source_entity="observable",
        source_id="obs-007",
        source_revision="rev-xyz",
    )
    assert k.startswith("v1:")
    assert len(k) == 46
    # same inputs -> same key (identity)
    k2 = idempotency_key(
        integration_id="int-42",
        direction="in",
        source_system="iris",
        source_entity="observable",
        source_id="obs-007",
        source_revision="rev-xyz",
    )
    assert k == k2
    # different source -> different
    k3 = idempotency_key(
        integration_id="int-42",
        direction="in",
        source_system="iris",
        source_entity="observable",
        source_id="obs-008",
        source_revision="rev-xyz",
    )
    assert k != k3


def test_secret_detection_fail_closed_more_cases():
    for bad in [
        {"password": "hunter2"},
        {"private-key": "-----BEGIN"},
        {"X-Api-Key": "abc"},
        {"nested": {"secret": 1}},
        [{"token": "t"}],
    ]:
        with pytest.raises(IngestValidationError):
            reject_secret_keys(bad)

    # clean passes
    reject_secret_keys({"title": "ok", "tags": ["a", "b"], "custom": {"note": "safe"}})
    reject_secret_keys({"value": "1.2.3.4", "type": "ip"})
