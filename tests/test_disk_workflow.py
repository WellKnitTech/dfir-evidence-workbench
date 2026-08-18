import json
from pathlib import Path

from jsonschema import Draft202012Validator

from corpus.generate import build
from dfir_workbench.disk_workflow import run_disk_fixture


GOLDENS = Path(__file__).parent / "goldens" / "disk"


def test_ext4_fixture_runs_read_only_and_matches_golden(tmp_path):
    corpus = build("corpus-v1", 41001, tmp_path / "corpus")
    source = next((corpus / "fixtures" / "disk").glob("disk-ext4-normal-001.*"))

    result = run_disk_fixture(source, tmp_path / "analysis")
    expected = json.loads((GOLDENS / "disk-ext4-normal-001.json").read_text())

    assert result["source_unchanged"] is True
    assert result["record"]["source_type"] == "disk_image"
    assert result["record"]["partition_filesystem"]["partitions"][0]["offset_bytes"] == expected["partition_offset_bytes"]
    assert result["record"]["partition_filesystem"]["partitions"][0]["filesystem"] == expected["filesystem"]
    assert result["record"]["collection_coverage"]["deleted_files"] is False
    assert Path(result["analysis_root"], "evidence-manifest.json").is_file()


def test_partitioned_reference_fixture_reports_supported_limits(tmp_path):
    corpus = build("corpus-v1", 41001, tmp_path / "corpus")
    source = next((corpus / "fixtures" / "disk").glob("disk-gpt-mbr-001.*"))

    result = run_disk_fixture(source, tmp_path / "analysis")
    expected = json.loads((GOLDENS / "disk-gpt-mbr-001.json").read_text())

    assert result["source_unchanged"] is True
    assert result["record"]["partition_filesystem"]["image_format"] == expected["image_format"]
    assert result["record"]["partition_filesystem"]["partitions"] == []
    assert "file inventory is limited" in result["record"]["collection_coverage"]["notes"][0]


def test_disk_workflow_never_extracts_outside_analysis_root(tmp_path):
    source = tmp_path / "sample.img"
    source.write_bytes(b"synthetic")

    result = run_disk_fixture(source, tmp_path / "analysis", extract=True)
    extracted = result["extraction"]["extracted"][0]["path"]
    assert Path(extracted).is_relative_to(tmp_path / "analysis")
    assert not (tmp_path / "escape").exists()


def test_disk_record_matches_normalized_evidence_schema(tmp_path):
    corpus = build("corpus-v1", 41001, tmp_path / "corpus")
    source = next((corpus / "fixtures" / "disk").glob("disk-ext4-normal-001.*"))
    record = run_disk_fixture(source, tmp_path / "analysis")["record"]
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "normalized-evidence.schema.json").read_text())

    assert list(Draft202012Validator(schema).iter_errors(record)) == []
