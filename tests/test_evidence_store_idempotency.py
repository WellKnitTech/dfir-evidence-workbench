import hashlib
from pathlib import Path

import pytest

from dfir_workbench.api import Principal
from dfir_workbench.evidence_store import EvidenceStore, EvidenceStoreError


def test_evidence_registration_reuses_matching_manifest(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"immutable evidence")
    store = EvidenceStore(tmp_path / "store", Principal(tenant_id="tenant-a", analyst_id="analyst-a"))
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    quarantine = store.ingest_to_quarantine(source)
    first = store.promote_to_evidence(case_id="case-1", evidence_id="evidence-1", quarantine_id=quarantine.quarantine_id, expected_sha256=digest)
    second = store.promote_to_evidence(case_id="case-1", evidence_id="evidence-1", quarantine_id="missing", expected_sha256=digest)
    assert second == first
    assert store.verify_integrity("case-1", "evidence-1")


def test_evidence_registration_rejects_mismatched_existing_manifest(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"immutable evidence")
    store = EvidenceStore(tmp_path / "store", Principal(tenant_id="tenant-a", analyst_id="analyst-a"))
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    quarantine = store.ingest_to_quarantine(source)
    store.promote_to_evidence(case_id="case-1", evidence_id="evidence-1", quarantine_id=quarantine.quarantine_id, expected_sha256=digest)
    with pytest.raises(EvidenceStoreError) as exc_info:
        store.promote_to_evidence(case_id="case-1", evidence_id="evidence-1", quarantine_id="missing", expected_sha256="0" * 64)
    assert exc_info.value.code == "EVIDENCE_CONFLICT"
