"""Consistency gates for packaged PUBLIC-REFERENCE P0 metadata (no evidence binaries)."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs" / "public-reference-p0-registry.json"
VALIDATION = ROOT / "docs" / "public-reference-p0-validation.md"
CAPABILITY = ROOT / "docs" / "public-reference-p0-capability-report.md"

FORBIDDEN_BINARY_SUFFIXES = {".e01", ".ex01", ".rar", ".7z", ".zip", ".dd", ".img", ".raw", ".mem", ".vmem"}


def test_registry_counts_and_hashes() -> None:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    items = data["items"]
    assert data["counts"]["evidence_items"] == 9
    assert len(items) == 9
    pub_true = sum(1 for i in items if i["publisher_hash_flag"] is True)
    assert data["counts"]["publisher_hash_flag_true"] == pub_true == 6
    assert data["counts"]["publisher_hash_flag_false"] == 3
    assert data["source_manifest_sha256"] == "79be847d08ae555a16e098cdc8cb0e77a214174c1c7953f1798483650a4e6893"
    assert data["signatures"] == {"ewf": 4, "zip": 3, "rar": 1, "7z": 1}
    assert sum(data["signatures"].values()) == 9
    sha_re = re.compile(r"^[0-9a-f]{64}$")
    paths = set()
    for item in items:
        assert sha_re.match(item["sha256"])
        assert item["bytes"] > 0
        assert item["path"] not in paths
        paths.add(item["path"])
        assert item["publisher_hash_status"] in {
            "not_independently_verified",
            "not_claimed",
        }
        assert item["workbench_status"]
    assert data["registration_defaults"]["corpus_v1"] is False
    assert data["registration_defaults"]["ci_bundle"] is False
    assert data["registration_defaults"]["execution_prohibited"] is True


def test_validation_report_truthfulness() -> None:
    text = VALIDATION.read_text(encoding="utf-8")
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    assert "exactly 9 evidence files" in text
    assert "All **9** local SHA-256" in text or "All 9 local SHA-256" in text
    assert "six" in text.lower() and "publisher_hash" in text
    assert "All 10 local SHA-256" not in text
    assert "exactly the 10 files named by the acquisition manifest plus" not in text
    assert data["source_manifest_sha256"] in text
    for item in data["items"]:
        assert item["sha256"] in text
        assert f"{item['bytes']:,}" in text
        assert f"`{item['path']}`" in text


def test_capability_report_is_fail_closed() -> None:
    text = CAPABILITY.read_text(encoding="utf-8")
    assert "docs/public-reference-p0-registry.json" in text
    assert "unavailable" in text.lower()
    assert "corpus-v1" in text
    assert "PR #11" in text
    # Must not overclaim structured memory/process coverage.
    assert "Volatility" in text or "volatility" in text
    assert "degraded" in text.lower()
    for banned in (
        "full filesystem coverage confirmed",
        "publisher hashes independently verified: yes",
        "volatility structured analysis available on host",
    ):
        assert banned not in text.lower()
    assert "are publisher hashes independently verified? | **no**" in text.lower()


def test_repo_does_not_bundle_p0_binaries() -> None:
    # Guard against accidental evidence commits under docs/ or tests/.
    roots = [ROOT / "docs", ROOT / "tests", ROOT / "src", ROOT / "schemas"]
    offenders: list[str] = []
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in FORBIDDEN_BINARY_SUFFIXES:
                offenders.append(str(path.relative_to(ROOT)))
            # Known large memory/rar names must not appear as files.
            name = path.name.lower()
            if name in {
                "memory-images.rar",
                "nps-2010-emails.e01",
                "ntfs1-gen2.e01",
                "ubnist1.casper-rw.gen3.e01",
                "nps-2009-canon2-gen6.e01",
            }:
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
