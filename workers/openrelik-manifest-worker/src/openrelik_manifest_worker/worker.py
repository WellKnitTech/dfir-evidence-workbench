"""Standalone metadata-only worker with an OpenRelik task-shaped CLI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST: dict[str, Any] = {
    "name": "dfir.openrelik.manifest",
    "version": "0.1.0",
    "task_type": "evidence.metadata_manifest",
    "input_types": ["file", "directory"],
    "capabilities": ["sha256", "metadata_inventory", "provenance"],
    "safety": {
        "read_only_inputs": True,
        "staged_inputs_only": True,
        "host_device_access": False,
        "privileged_access": False,
    },
}


class WorkerError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "retryable": False}


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _safe_id(value: str, field: str) -> str:
    if not value or len(value) > 128 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in value):
        raise WorkerError("INVALID_ID", f"{field} is invalid")
    return value


def _source_inventory(source: Path) -> tuple[str, int, list[dict[str, Any]]]:
    if source.is_file() and not source.is_symlink():
        digest, size = _hash_file(source)
        return digest, size, [{"path": source.name, "size": size, "sha256": digest, "mtime": _utc(source.stat().st_mtime), "kind": "file"}]
    if not source.is_dir() or source.is_symlink():
        raise WorkerError("SOURCE_INVALID", "input must be a regular file or directory")

    entries: list[dict[str, Any]] = []
    aggregate = hashlib.sha256()
    total = 0
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise WorkerError("SYMLINK_REJECTED", "input contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise WorkerError("SPECIAL_FILE_REJECTED", "input contains a special file")
        digest, size = _hash_file(path)
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(bytes.fromhex(digest))
        total += size
        entries.append({"path": relative, "size": size, "sha256": digest, "mtime": _utc(info.st_mtime), "kind": "file"})
    return aggregate.hexdigest(), total, entries


def run_task(
    *,
    source_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    task_id: str,
    evidence_id: str,
    artifact_id: str | None = None,
    report_id: str | None = None,
) -> dict[str, Any]:
    """Hash and inventory staged input without writing anywhere under it."""
    task_id = _safe_id(task_id, "task_id")
    evidence_id = _safe_id(evidence_id, "evidence_id")
    source = Path(source_path).expanduser().resolve(strict=False)
    output = Path(output_dir).expanduser().resolve(strict=False)
    if not source.exists():
        raise WorkerError("SOURCE_NOT_FOUND", "staged input does not exist")
    if output == source or source in output.parents:
        raise WorkerError("OUTPUT_INSIDE_SOURCE", "output directory must be separate from staged input")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    source_hash, total_size, inventory = _source_inventory(source)
    artifact_id = _safe_id(artifact_id, "artifact_id") if artifact_id else "artifact-" + source_hash[:24]
    report_id = _safe_id(report_id, "report_id") if report_id else "report-" + source_hash[:24]
    metadata_path = output / f"{task_id}.metadata.json"
    metadata = {
        "schema_version": "1.0",
        "worker": MANIFEST["name"],
        "worker_version": MANIFEST["version"],
        "task_id": task_id,
        "status": "completed",
        "artifact_id": artifact_id,
        "report_id": report_id,
        "sha256": source_hash,
        "size": total_size,
        "inventory": inventory,
        "provenance": {
            "evidence_id": evidence_id,
            "source_uri": source.as_uri(),
            "staged_input": True,
            "read_only": True,
            "generated_at_utc": _utc(datetime.now(timezone.utc).timestamp()),
        },
    }
    metadata_path.write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(metadata_path, stat.S_IRUSR | stat.S_IWUSR)
    return {
        "schema_version": "1.0",
        "task_id": task_id,
        "status": "completed",
        "artifacts": [{"artifact_id": artifact_id, "task_id": task_id, "sha256": source_hash, "metadata_uri": metadata_path.as_uri()}],
        "reports": [{"report_id": report_id, "task_id": task_id, "sha256": source_hash, "metadata_uri": metadata_path.as_uri()}],
        "metadata_uri": metadata_path.as_uri(),
        "sha256": source_hash,
        "provenance": {"evidence_id": evidence_id, "source_uri": source.as_uri(), "worker": MANIFEST["name"]},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=MANIFEST["name"])
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--evidence-id", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run_task(source_path=args.input, output_dir=args.output, task_id=args.task_id, evidence_id=args.evidence_id), sort_keys=True))
    except WorkerError as exc:
        print(json.dumps({"status": "failed", "error": exc.as_dict()}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
