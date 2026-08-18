import hashlib
from pathlib import Path

import pytest

from corpus.generate import build
from corpus.verify import ManifestError, verify_release


def test_generated_release_is_deterministic(tmp_path):
    first = build("corpus-v1", 41001, tmp_path / "one")
    second = build("corpus-v1", 41001, tmp_path / "two")
    assert hashlib.sha256((first / "manifest.jsonl").read_bytes()).hexdigest() == hashlib.sha256((second / "manifest.jsonl").read_bytes()).hexdigest()
    assert verify_release(first)["fixture_count"] == 49


def test_verifier_rejects_member_tampering(tmp_path):
    root = build("corpus-v1", 41001, tmp_path / "release")
    member = next(path for path in (root / "fixtures").rglob("*") if path.is_file())
    member.write_bytes(member.read_bytes() + b"tamper")
    with pytest.raises(ManifestError, match="(size|sha256) mismatch"):
        verify_release(root)
