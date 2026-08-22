import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("check_forensic_tools", ROOT / "tools" / "check-forensic-tools.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

def test_forensic_manifest_is_fail_closed_and_complete():
    manifest = MODULE.load()
    assert len(manifest["tools"]) == 7
    assert all(item["network_policy"] == "none" for item in manifest["tools"])
    assert all(item["status"] != "available" for item in manifest["tools"])

def test_unsupported_tool_requires_approved_artifact():
    tool = next(item for item in MODULE.load()["tools"] if item["name"] == "sleuthkit")
    try:
        MODULE.verify_artifact(tool, ROOT / "README.md")
    except RuntimeError as exc:
        assert "unsupported" in str(exc)
    else:
        raise AssertionError("unavailable tool was accepted")
