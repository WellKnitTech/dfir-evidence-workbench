import hashlib
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from dfir_workbench.evidence_store import EvidenceStore
from dfir_workbench.openrelik_adapter import LocalTransport, OpenRelikAdapter, SQLiteJobStore
from dfir_workbench.velociraptor_openrelik import VelociraptorTimelineFastPath


def bundle(tmp_path: Path) -> Path:
    path = tmp_path / "triage.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("client/metadata.json", '{"client_id":"C.1"}')
        archive.writestr("client/hayabusa_timeline.jsonl", json.dumps({"timestamp": "2026-08-17T12:00:00-05:00", "message": "start"}) + "\n")
    return path


def test_claim_then_promote_failure_resumes_and_cleans_quarantine(tmp_path, monkeypatch):
    source = bundle(tmp_path)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    principal = SimpleNamespace(tenant_id="tenant-a", analyst_id="analyst-a")
    evidence = EvidenceStore(tmp_path / "evidence", principal)
    original = evidence.promote_to_evidence
    calls = 0

    def fail_once(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated_promote_failure")
        return original(**kwargs)

    monkeypatch.setattr(evidence, "promote_to_evidence", fail_once)
    store = SQLiteJobStore(tmp_path / "jobs.sqlite")
    fast = VelociraptorTimelineFastPath(openrelik=OpenRelikAdapter(LocalTransport(), store), evidence_store=evidence, principal=principal)
    args = dict(source=source, tenant_id="tenant-a", case_id="case-1", asset_id="asset-1", evidence_id="evidence-1", expected_sha256=digest)
    with pytest.raises(RuntimeError, match="simulated_promote_failure"):
        fast.submit_collection(**args)
    result = fast.submit_collection(**args)
    assert result["job"]["status"] == "succeeded"
    assert evidence.verify_integrity("case-1", "evidence-1")
    assert list((tmp_path / "evidence" / "tenants" / "tenant-a" / "quarantine").glob("*")) == []
    store.close()


def test_fast_path_uses_schema_contract_and_explicit_case_scope(tmp_path):
    source = bundle(tmp_path)
    store = SQLiteJobStore(tmp_path / "jobs.sqlite")
    principal = SimpleNamespace(tenant_id="tenant-a", analyst_id="analyst-a")
    adapter = OpenRelikAdapter(LocalTransport(), store)
    fast = VelociraptorTimelineFastPath(openrelik=adapter, principal=principal)
    result = fast.submit_collection(source=source, tenant_id="tenant-a", case_id="case-1", asset_id="asset-1", evidence_id="evidence-1")
    job = adapter.poll(principal, result["job"]["job_id"], "case-1")
    assert job.case_id == "case-1"
    assert result["timeline"][0]["occurred_at_utc"] == "2026-08-17T17:00:00Z"
    store.close()
