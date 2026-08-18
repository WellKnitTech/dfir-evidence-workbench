import hashlib
import json
import os
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from dfir_workbench.staging import EvidenceStager, SafetyLimits, StagingError, run_fixture


def test_file_stages_with_provenance_and_never_changes_source(tmp_path):
    source = tmp_path / "fixture.bin"
    source.write_bytes(b"fixture bytes")
    source.chmod(0o640)
    before_mode = stat.S_IMODE(source.stat().st_mode)
    before_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    analysis = tmp_path / "analysis"

    result = EvidenceStager(source, analysis).run(lambda staged: staged.write_bytes(b"derived"))

    assert source.read_bytes() == b"fixture bytes"
    assert stat.S_IMODE(source.stat().st_mode) == before_mode
    assert result["manifest"]["source"]["sha256"] == before_hash
    assert result["manifest"]["verification"]["source_unchanged"] is True
    assert "fixture bytes" not in (analysis / "evidence-manifest.json").read_text()
    assert (analysis / "custody-events.jsonl").read_text().count("source_verified") == 1


def test_directory_retains_metadata_and_detects_source_mutation(tmp_path):
    source = tmp_path / "fixture"
    source.mkdir()
    child = source / "answer.txt"
    child.write_text("answer")
    child.chmod(0o640)
    before_mode = stat.S_IMODE(child.stat().st_mode)

    def mutate(_staged: Path):
        child.chmod(0o600)

    with pytest.raises(StagingError, match="permissions changed"):
        EvidenceStager(source, tmp_path / "analysis").run(mutate)
    assert stat.S_IMODE(child.stat().st_mode) == 0o600
    child.chmod(before_mode)


def test_symlink_and_limits_fail_closed(tmp_path):
    source = tmp_path / "fixture"
    source.mkdir()
    (source / "outside-link").symlink_to(tmp_path / "outside")
    with pytest.raises(StagingError, match="symlinks"):
        EvidenceStager(source, tmp_path / "analysis").stage()

    large = tmp_path / "large.bin"
    large.write_bytes(b"x" * 10)
    with pytest.raises(StagingError, match="file limit"):
        EvidenceStager(large, tmp_path / "analysis2", limits=SafetyLimits(max_file_bytes=9)).stage()


def test_archive_traversal_and_malformed_inputs_fail_closed(tmp_path):
    archive = tmp_path / "fixture.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", b"no")
    with pytest.raises(StagingError, match="unsafe archive"):
        EvidenceStager(archive, tmp_path / "analysis").stage()

    malformed = tmp_path / "broken.zip"
    malformed.write_bytes(b"not zip")
    with pytest.raises(StagingError, match="invalid ZIP"):
        EvidenceStager(malformed, tmp_path / "analysis2").stage()


def test_temporary_fixture_run_cleans_analysis_root(tmp_path):
    source = tmp_path / "fixture.txt"
    source.write_text("metadata only")
    result = run_fixture(source)
    assert result["manifest"]["verification"]["source_unchanged"] is True
    assert not Path(result["analysis_root"]).exists()
