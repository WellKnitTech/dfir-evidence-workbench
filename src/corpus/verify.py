"""Integrity verification for generated corpus releases."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

class ManifestError(ValueError):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()


def _confined(root: Path, relative: str) -> Path:
    candidate = Path(os.path.abspath(root / relative))
    if Path(relative).is_absolute() or not candidate.is_relative_to(root): raise ManifestError(f"path escapes release: {relative}")
    return candidate


def load_and_verify_manifest(fixture_id: str, root: str | Path = "build/corpus-v1") -> list[dict]:
    root = Path(root).resolve(); manifest = root / "manifest.jsonl"
    if not manifest.is_file(): raise ManifestError("manifest.jsonl is missing")
    rows = [json.loads(line) for line in manifest.read_text().splitlines() if line]
    if digest(manifest) != (root / "manifest.sha256").read_text().split()[0]: raise ManifestError("manifest hash mismatch")
    selected = [row for row in rows if row.get("fixture_id") == fixture_id]
    if not selected: raise ManifestError(f"unknown fixture: {fixture_id}")
    _verify_rows(root, rows)
    return selected


def _verify_rows(root: Path, rows: list[dict]) -> None:
    ids: set[str] = set(); paths: set[str] = set()
    for row in rows:
        fixture_id, relative = row.get("fixture_id"), row.get("relative_path")
        if not isinstance(fixture_id, str) or not isinstance(relative, str): raise ManifestError("fixture_id and relative_path are required")
        if fixture_id in ids: raise ManifestError(f"duplicate fixture_id: {fixture_id}")
        if relative in paths: raise ManifestError(f"duplicate relative_path: {relative}")
        ids.add(fixture_id); paths.add(relative)
        source = _confined(root, relative); expected = _confined(root, row.get("expected_answer", ""))
        if source.is_symlink() or expected.is_symlink(): raise ManifestError(f"symlink is not allowed: {relative}")
        if not source.is_file() or not expected.is_file(): raise ManifestError(f"missing release member: {relative}")
        if source.stat().st_size != row.get("size_bytes"): raise ManifestError(f"size mismatch: {relative}")
        if digest(source) != row.get("sha256"): raise ManifestError(f"sha256 mismatch: {relative}")
        text = expected.read_text(errors="strict")
        if any(token in text.lower() for token in ("password=", "api_key", "bearer ", "client evidence")): raise ManifestError(f"prohibited content: {expected}")


def verify_release(root: str | Path) -> dict:
    root = Path(root).resolve(); manifest = root / "manifest.jsonl"
    if not manifest.is_file(): raise ManifestError("manifest.jsonl is missing")
    rows = [json.loads(line) for line in manifest.read_text().splitlines() if line]
    expected_hash = (root / "manifest.sha256").read_text().split()[0]
    if digest(manifest) != expected_hash: raise ManifestError("manifest hash mismatch")
    _verify_rows(root, rows)
    return {"status": "verified", "release_root": str(root), "fixture_count": len(rows), "manifest_sha256": expected_hash}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--root", type=Path, required=True); args = parser.parse_args()
    print(json.dumps(verify_release(args.root), sort_keys=True))

if __name__ == "__main__": main()
