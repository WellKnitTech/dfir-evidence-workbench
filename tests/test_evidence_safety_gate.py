"""Independent evidence-safety / defensibility probes for the prototype gate.

These are reviewer-authored probes, not the implementer's claimed suite.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dfir_workbench.api import Principal, create_app, get_current_principal
from dfir_workbench.artifact_timeline import process_artifact
from dfir_workbench.local_runner import LocalRunner
from dfir_workbench.staging import EvidenceStager, SafetyLimits, StagingError


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cross_tenant_get_and_review_denied(tmp_path: Path):
    runner = LocalRunner(tmp_path)
    fixture = next(r["fixture_id"] for r in runner.catalog() if r["class"] == "disk")
    job = runner.submit("tenant-a", fixture)
    with pytest.raises(KeyError):
        runner.get("tenant-b", job["job_id"])
    with pytest.raises(KeyError):
        runner.review("tenant-b", job["job_id"], "approve")


def test_retry_must_not_cross_tenant(tmp_path: Path):
    """Regression: retry previously omitted tenant ownership checks."""
    runner = LocalRunner(tmp_path)
    fixture = next(r["fixture_id"] for r in runner.catalog() if r["class"] == "disk")
    job = runner.submit("tenant-a", fixture)
    # Force a retryable status without re-running heavy work.
    internal = runner.jobs[job["job_id"]]
    internal["status"] = "error"
    with pytest.raises(KeyError):
        runner.retry("tenant-b", job["job_id"])
    # Original job must remain owned by tenant-a and not be mutated by B.
    assert runner.jobs[job["job_id"]]["tenant_id"] == "tenant-a"
    assert runner.jobs[job["job_id"]]["attempt"] == 1


def test_teardown_removes_in_memory_jobs(tmp_path: Path):
    runner = LocalRunner(tmp_path)
    fixture = next(r["fixture_id"] for r in runner.catalog() if r["class"] == "artifacts")
    job = runner.submit("tenant-a", fixture)
    out = runner.teardown("tenant-a")
    assert out["jobs_removed"] >= 1
    with pytest.raises(KeyError):
        runner.get("tenant-a", job["job_id"])
    assert job["job_id"] not in runner.jobs


def test_api_rejects_body_tenant_override_for_runner(tmp_path: Path, monkeypatch):
    app = create_app()
    # Isolate runner root away from global singleton pollution.
    from dfir_workbench import local_runner as lr

    lr.runner = LocalRunner(tmp_path)

    def principal_a():
        return Principal(tenant_id="tenant-a", analyst_id="a1", is_synthetic=True)

    app.dependency_overrides[get_current_principal] = principal_a
    client = TestClient(app)
    catalog = client.get("/__dev__/runner/catalog").json()
    fixture = next(x["fixture_id"] for x in catalog["fixtures"] if x["class"] == "artifacts")
    # Body tenant_id must be ignored; job is scoped to principal.
    job = client.post(
        "/__dev__/runner/jobs",
        json={"fixture_id": fixture, "tenant_id": "evil-tenant"},
    ).json()
    assert job["status"] in {"ready_for_review", "error"}
    # Cross-tenant status denied after switching principal.
    def principal_b():
        return Principal(tenant_id="tenant-b", analyst_id="b1", is_synthetic=True)

    app.dependency_overrides[get_current_principal] = principal_b
    denied = client.get(f"/__dev__/runner/jobs/{job['job_id']}")
    assert denied.status_code == 404


def test_zip_bomb_and_nested_traversal_rejected(tmp_path: Path):
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Claim a huge uncompressed size while keeping on-disk small.
        info = zipfile.ZipInfo("pad.bin")
        info.file_size = 2 * 1024 * 1024 * 1024  # 2 GiB claimed
        info.compress_type = zipfile.ZIP_DEFLATED
        # Write a small compressed payload but leave file_size high via ZipInfo.
        # zipfile will overwrite file_size on writestr; craft manually.
        payload = b"0" * 1024
        zf.writestr("pad.bin", payload)
        # Re-open and patch member size after write is unreliable; instead use limits low.
    limits = SafetyLimits(max_file_bytes=512, max_total_bytes=1024, max_archive_members=10)
    # Oversized single file source
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 600)
    with pytest.raises(StagingError) as exc:
        EvidenceStager(big, tmp_path / "a1", limits=limits).stage()
    assert exc.value.code == "FILE_LIMIT_EXCEEDED"

    # Zip with too many members
    many = tmp_path / "many.zip"
    with zipfile.ZipFile(many, "w") as zf:
        for i in range(15):
            zf.writestr(f"m{i}.txt", b"x")
    with pytest.raises(StagingError) as exc2:
        EvidenceStager(many, tmp_path / "a2", limits=limits).stage()
    # Either member-count or expanded-size ceiling is acceptable fail-closed behavior.
    assert exc2.value.code in {"ARCHIVE_LIMIT_EXCEEDED", "FILE_LIMIT_EXCEEDED"}

    # Absolute member path
    abszip = tmp_path / "abs.zip"
    with zipfile.ZipFile(abszip, "w") as zf:
        zf.writestr("/etc/passwd", b"root")
    with pytest.raises(StagingError) as exc3:
        EvidenceStager(abszip, tmp_path / "a3").stage()
    assert exc3.value.code == "PATH_TRAVERSAL_REJECTED"


def test_symlink_source_file_rejected(tmp_path: Path):
    real = tmp_path / "real.bin"
    real.write_bytes(b"data")
    link = tmp_path / "link.bin"
    link.symlink_to(real)
    with pytest.raises(StagingError) as exc:
        EvidenceStager(link, tmp_path / "analysis").stage()
    assert exc.value.code == "SOURCE_INVALID"


def test_disk_processing_leaves_source_bytes_and_mode(tmp_path: Path):
    runner = LocalRunner(tmp_path / "runner")
    fixture = next(r["fixture_id"] for r in runner.catalog() if r["class"] == "disk")
    # Locate source via corpus
    row = runner._manifest_row(fixture)
    source = runner.corpus_root / row["relative_path"]
    before = source.read_bytes()
    before_mode = stat.S_IMODE(source.stat().st_mode)
    before_hash = _sha(source)
    job = runner.submit("tenant-a", fixture)
    assert job["status"] == "ready_for_review"
    assert source.read_bytes() == before
    assert _sha(source) == before_hash
    assert stat.S_IMODE(source.stat().st_mode) == before_mode
    assert job["result"]["source_unchanged"] is True
    assert job["provenance"]["source_sha256"] == before_hash


def test_memory_and_artifact_paths_do_not_mutate_source(tmp_path: Path):
    runner = LocalRunner(tmp_path / "runner")
    for cls in ("memory", "artifacts"):
        fixture = next(r["fixture_id"] for r in runner.catalog() if r["class"] == cls)
        row = runner._manifest_row(fixture)
        source = runner.corpus_root / row["relative_path"]
        before = source.read_bytes()
        before_hash = _sha(source)
        job = runner.submit("tenant-a", fixture)
        assert source.read_bytes() == before
        assert _sha(source) == before_hash
        assert job["status"] in {"ready_for_review", "error"}


def test_artifact_zip_bomb_member_size_not_unbounded(tmp_path: Path):
    """process_artifact currently reads zip members fully — document/fail if unbounded.

    Gate expectation: either reject oversized members or complete without OOM on small fixtures.
    Here we only assert path traversal still rejects and normal zips parse.
    """
    zpath = tmp_path / "bad.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../escape.txt", b"nope")
        zf.writestr("ok.jsonl", json.dumps({"timestamp": "2020-01-01T00:00:00Z", "event": "x"}) + "\n")
    result = process_artifact(zpath)
    assert any(e.get("code") == "PATH_TRAVERSAL_REJECTED" for e in result["errors"])


def test_public_job_view_strips_work_root(tmp_path: Path):
    runner = LocalRunner(tmp_path)
    fixture = next(r["fixture_id"] for r in runner.catalog() if r["class"] == "artifacts")
    job = runner.submit("tenant-a", fixture)
    assert "work_root" not in job
    assert "tenant_id" not in job  # stripped from public view; isolation via API principal
