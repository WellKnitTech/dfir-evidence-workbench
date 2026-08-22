from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from dfir_workbench.api import Principal
from dfir_workbench.evidence_store import EvidenceStore, EvidenceStoreError


def _store(root: Path, tenant: str = "tenant-a") -> EvidenceStore:
    return EvidenceStore(root, Principal(tenant_id=tenant, analyst_id="analyst"))


def _promote(
    store: EvidenceStore,
    source: Path,
    *,
    case: str = "case-1",
    evidence: str = "evidence-1",
    retention_days: int = 365,
):
    quarantine = store.ingest_to_quarantine(source)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    return store.promote_to_evidence(
        case_id=case,
        evidence_id=evidence,
        quarantine_id=quarantine.quarantine_id,
        expected_sha256=digest,
        retention_days=retention_days,
    )


def test_store_preserves_hash_and_immutable_original(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"chain of custody")
    store = _store(tmp_path / "objects")

    manifest = _promote(store, source)
    original = store.original_path("case-1", "evidence-1")

    assert manifest.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert manifest.size == source.stat().st_size
    assert store.verify_integrity("case-1", "evidence-1")
    assert original.read_bytes() == source.read_bytes()
    assert original.stat().st_mode & 0o222 == 0
    with pytest.raises(PermissionError):
        original.write_bytes(b"tampered")


def test_tenant_prefix_denies_cross_tenant_lookup(tmp_path: Path):
    root = tmp_path / "objects"
    source = tmp_path / "source.bin"
    source.write_bytes(b"tenant scoped")
    _promote(_store(root, "tenant-a"), source)
    other = _store(root, "tenant-b")

    with pytest.raises(EvidenceStoreError) as exc:
        other.read_manifest("case-1", "evidence-1")
    assert exc.value.code == "EVIDENCE_NOT_FOUND"
    assert "tenant-a" in str(root / "tenants" / "tenant-a")


def test_retention_and_legal_hold_fail_closed(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"retain me")
    store = _store(tmp_path / "objects")
    _promote(store, source, retention_days=365)

    with pytest.raises(EvidenceStoreError) as retention:
        store.delete_evidence("case-1", "evidence-1", force_after_hold_cleared=True)
    assert retention.value.code == "RETENTION_ACTIVE"

    store.set_legal_hold("case-1", "evidence-1", True)
    with pytest.raises(EvidenceStoreError) as hold:
        store.delete_evidence("case-1", "evidence-1", force_after_hold_cleared=True)
    assert hold.value.code == "LEGAL_HOLD_ACTIVE"


def test_quarantine_size_limit_rejects_without_admission(tmp_path: Path):
    source = tmp_path / "too-large.bin"
    source.write_bytes(b"0123456789")
    root = tmp_path / "objects"
    store = EvidenceStore(root, Principal(tenant_id="tenant-a", analyst_id="analyst"), max_quarantine_bytes=5)

    with pytest.raises(EvidenceStoreError) as exc:
        store.ingest_to_quarantine(source)
    assert exc.value.code == "QUARANTINE_LIMIT_EXCEEDED"
    assert not (root / "tenants" / "tenant-a" / "quarantine").exists()


def test_path_ids_reject_traversal(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"safe")
    store = _store(tmp_path / "objects")
    manifest = _promote(store, source)

    with pytest.raises(EvidenceStoreError) as exc:
        store.read_manifest("../tenant-a", "evidence-1")
    assert exc.value.code == "INVALID_ID"
    assert manifest.tenant_id == "tenant-a"
