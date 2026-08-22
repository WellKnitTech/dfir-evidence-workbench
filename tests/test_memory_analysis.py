import json
from pathlib import Path
import pytest
from dfir_workbench.memory_analysis import analyze_memory, capability_report, detect_memory_profile, validate_profile

def _elf_core(path: Path, machine: int = 62) -> None:
    data=bytearray(512); data[:4]=b"\x7fELF"; data[4:8]=bytes((2,1,1,0)); data[16:18]=(4).to_bytes(2,"little"); data[18:20]=machine.to_bytes(2,"little"); path.write_bytes(data+b"process residue\x00socket residue")

def test_elf_profile_is_valid_only_for_supported_architecture(tmp_path):
    source=tmp_path/"vmcore.elf"; _elf_core(source); detection=detect_memory_profile(source); assert detection["platform"] == "linux-elf"; assert validate_profile(detection,"linux-x86_64")["status"] == "valid"; assert validate_profile(detection,"windows-x64")["status"] == "unsupported"

def test_unknown_profile_fails_closed_and_labels_strings_as_residue(tmp_path):
    source=tmp_path/"unknown.bin"; source.write_bytes(b"not a dump process-name 10.0.0.1"); result=analyze_memory(source, requested_profile="linux-x86_64"); assert result["profile_validation"]["status"] == "unsupported"; assert result["capabilities"]["structured_checks"] == []; assert result["residue"]["type"] == "bounded-strings"; assert "not evidence" in result["residue"]["interpretation"]; assert result["custody"]["unchanged"] is True

def test_capability_report_is_serializable_and_fail_closed():
    report=capability_report(); assert report["policy"]["unsupported_profiles_fail_closed"] is True; assert report["policy"]["strings_are_residue"] is True; assert json.loads(json.dumps(report))["schema_version"] == "1.0"

def test_analysis_rejects_symlink(tmp_path):
    source=tmp_path/"real.bin"; source.write_bytes(b"DUMP"); link=tmp_path/"link.dmp"; link.symlink_to(source)
    with pytest.raises(ValueError, match="regular file"): analyze_memory(link)
