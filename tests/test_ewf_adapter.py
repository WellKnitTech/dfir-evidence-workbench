import hashlib
from pathlib import Path
import pytest
from dfir_workbench.adapters.disk_memory_adapter import AdapterError, DiskMemoryAdapter
from dfir_workbench.ewf import raw_view

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"

def test_e01_segment_metadata_hashes_all_segments_and_degrades_without_libewf(tmp_path):
    first, second = tmp_path / "case.E01", tmp_path / "case.E02"
    first.write_bytes(SIGNATURE + b"first"); second.write_bytes(SIGNATURE + b"second")
    record = DiskMemoryAdapter(first, tmp_path / "analysis").normalized_record("disk_image")
    assert record["adapter_metadata"]["validation"]["detected_format"] == "ewf"
    assert [item["path"] for item in record["adapter_metadata"]["ewf"]["segments"]] == ["case.E01", "case.E02"]
    assert record["adapter_metadata"]["ewf"]["segments"][0]["sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()
    assert record["adapter_metadata"]["libewf"]["status"] == "unavailable"
    with raw_view(first, tmp_path / "views", max_total_bytes=1024) as view: assert view["status"] == "degraded"
    assert not (tmp_path / "views").exists(); assert first.read_bytes() == SIGNATURE + b"first"

def test_ewf_limits_cover_segment_set(tmp_path):
    first = tmp_path / "limited.E01"; first.write_bytes(SIGNATURE + b"0123456789")
    with pytest.raises(AdapterError, match="FILE_LIMIT_EXCEEDED"):
        DiskMemoryAdapter(first, tmp_path / "analysis", max_file_bytes=8).validate("disk_image")
