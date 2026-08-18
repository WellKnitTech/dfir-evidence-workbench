"""Evidence-safe fixture staging and processing harness.

The harness owns the read-only boundary: sources are hashed and inspected before
processing, derived bytes are written below a separate analysis root, and the
source is hashed and metadata-checked again afterwards.  Manifests contain
provenance only; source bytes never enter them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable


class StagingError(Exception):
    """Fail-closed staging or processing error."""

    def __init__(self, code: str, message: str, path: str | None = None) -> None:
        super().__init__(message)
        self.code, self.message, self.path = code, message, path


@dataclass(frozen=True)
class SafetyLimits:
    max_file_bytes: int = 512 * 1024 * 1024
    max_total_bytes: int = 4 * 1024 * 1024 * 1024
    max_archive_members: int = 100_000


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_member(name: str) -> str:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ":" in path.parts[0] or any(part in ("", ".", "..") for part in path.parts):
        raise StagingError("PATH_TRAVERSAL_REJECTED", "unsafe archive member path", name)
    return path.as_posix()


def _regular_source(path: Path) -> None:
    if path.is_symlink() or not path.exists() or not (path.is_file() or path.is_dir()):
        raise StagingError("SOURCE_INVALID", "source must be a regular file or directory", str(path))


class EvidenceStager:
    """Stage one source into an analysis root and run a bounded processor."""

    def __init__(self, source: str | os.PathLike[str], analysis_root: str | os.PathLike[str], *, limits: SafetyLimits | None = None) -> None:
        self.source = Path(source).expanduser()
        self.analysis_root = Path(analysis_root).expanduser().resolve()
        self.limits = limits or SafetyLimits()
        self.manifest: dict[str, Any] | None = None
        self.events: list[dict[str, Any]] = []

    def _snapshot(self) -> tuple[dict[str, Any], dict[str, int]]:
        _regular_source(self.source)
        if self.source.is_file():
            stat_result = self.source.stat()
            if stat_result.st_size > self.limits.max_file_bytes:
                raise StagingError("FILE_LIMIT_EXCEEDED", "source exceeds configured file limit", str(self.source))
            return ({"path": str(self.source), "name": self.source.name, "kind": "file", "size": stat_result.st_size,
                     "sha256": _sha256(self.source), "mode": stat.S_IMODE(stat_result.st_mode), "mtime_utc": _utc(stat_result.st_mtime)},
                    {".": stat.S_IMODE(stat_result.st_mode)})
        total = 0
        entries: list[dict[str, Any]] = []
        modes: dict[str, int] = {}
        for path in sorted(self.source.rglob("*")):
            relative = path.relative_to(self.source).as_posix()
            if path.is_symlink():
                raise StagingError("SYMLINK_REJECTED", "source trees may not contain symlinks", relative)
            result = path.stat()
            modes[relative] = stat.S_IMODE(result.st_mode)
            if path.is_dir():
                entries.append({"path": relative, "kind": "directory", "size": 0, "sha256": None,
                                "mode": modes[relative], "mtime_utc": _utc(result.st_mtime)})
                continue
            if not path.is_file():
                raise StagingError("SOURCE_INVALID", "source tree contains a special file", relative)
            if result.st_size > self.limits.max_file_bytes or total + result.st_size > self.limits.max_total_bytes:
                raise StagingError("FILE_LIMIT_EXCEEDED", "source tree exceeds configured size limit", relative)
            total += result.st_size
            entries.append({"path": relative, "kind": "file", "size": result.st_size, "sha256": _sha256(path),
                            "mode": modes[relative], "mtime_utc": _utc(result.st_mtime)})
        tree_digest = hashlib.sha256()
        for entry in entries:
            tree_digest.update(json.dumps(
                {"path": entry["path"], "kind": entry["kind"], "size": entry["size"], "sha256": entry["sha256"]},
                sort_keys=True, separators=(",", ":"),
            ).encode())
        return ({"path": str(self.source), "name": self.source.name, "kind": "directory", "size": total,
                 "sha256": tree_digest.hexdigest(), "entries": entries}, modes)

    def _validate_archive(self, snapshot: dict[str, Any]) -> None:
        if snapshot["kind"] != "file":
            return
        path = self.source
        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as archive:
                    members = archive.infolist()
                    if len(members) > self.limits.max_archive_members:
                        raise StagingError("ARCHIVE_LIMIT_EXCEEDED", "archive has too many members", str(path))
                    total = 0
                    for member in members:
                        name = _safe_member(member.filename)
                        mode = (member.external_attr >> 16) & 0xFFFF
                        if stat.S_ISLNK(mode) or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                            raise StagingError("SYMLINK_REJECTED", "archive contains a non-regular member", name)
                        if not member.is_dir():
                            if member.file_size > self.limits.max_file_bytes or total + member.file_size > self.limits.max_total_bytes:
                                raise StagingError("ARCHIVE_LIMIT_EXCEEDED", "archive expands beyond configured limits", name)
                            total += member.file_size
                    if archive.testzip() is not None:
                        raise StagingError("ARCHIVE_INVALID", "archive CRC validation failed", str(path))
            except zipfile.BadZipFile as exc:
                raise StagingError("ARCHIVE_INVALID", "invalid ZIP archive", str(path)) from exc
            return
        if tarfile.is_tarfile(path):
            try:
                with tarfile.open(path, "r:*") as archive:
                    members = archive.getmembers()
                    if len(members) > self.limits.max_archive_members:
                        raise StagingError("ARCHIVE_LIMIT_EXCEEDED", "archive has too many members", str(path))
                    total = 0
                    for member in members:
                        name = _safe_member(member.name)
                        if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                            raise StagingError("SYMLINK_REJECTED", "archive contains a link or special member", name)
                        if member.isfile():
                            if member.size > self.limits.max_file_bytes or total + member.size > self.limits.max_total_bytes:
                                raise StagingError("ARCHIVE_LIMIT_EXCEEDED", "archive expands beyond configured limits", name)
                            total += member.size
            except tarfile.TarError as exc:
                raise StagingError("ARCHIVE_INVALID", "invalid TAR archive", str(path)) from exc
            return
        if path.name.lower().endswith(".zip"):
            raise StagingError("ARCHIVE_INVALID", "invalid ZIP archive", str(path))
        if path.name.lower().endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz")):
            raise StagingError("ARCHIVE_INVALID", "invalid TAR archive", str(path))

    def stage(self, *, copy_source: bool = True) -> Path:
        before, modes = self._snapshot()
        self._validate_archive(before)
        if self.analysis_root == self.source.resolve() or self.analysis_root.is_relative_to(self.source.resolve()):
            raise StagingError("ANALYSIS_ROOT_INVALID", "analysis root must not be inside source", str(self.analysis_root))
        self.analysis_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        staged = self.analysis_root / "source"
        if staged.exists() or staged.is_symlink():
            raise StagingError("ANALYSIS_ROOT_NOT_EMPTY", "staged source already exists", str(staged))
        if copy_source:
            if before["kind"] == "file":
                shutil.copyfile(self.source, staged)
                os.chmod(staged, 0o600)
            else:
                shutil.copytree(self.source, staged, symlinks=False, copy_function=shutil.copyfile)
                for path in staged.rglob("*"):
                    if path.is_file(): os.chmod(path, 0o600)
                    elif path.is_dir(): os.chmod(path, 0o700)
        else:
            staged = self.source
        self.manifest = {"schema_version": "1.0", "source": before, "staged_path": str(staged),
                         "copied": copy_source, "limits": self.limits.__dict__.copy()}
        self._event("staged", {"sha256": self._source_sha256()})
        self._write_records()
        return staged

    def _source_sha256(self) -> str | None:
        if self.source.is_file():
            return _sha256(self.source)
        return None

    def _event(self, event: str, details: dict[str, Any] | None = None) -> None:
        self.events.append({"event": event, "at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **(details or {})})

    def run(self, processor: Callable[[Path], Any] | None = None, *, copy_source: bool = True) -> dict[str, Any]:
        staged = self.stage(copy_source=copy_source)
        self._event("processing_started", {"staged_path": str(staged)})
        result = processor(staged) if processor else {"status": "staged"}
        self._event("processing_completed", {"result_type": type(result).__name__})
        after, modes_after = self._snapshot()
        manifest = self.manifest
        assert manifest is not None
        before = manifest["source"]
        if before["sha256"] != after["sha256"]:
            raise StagingError("SOURCE_CHANGED", "source SHA-256 changed during processing", str(self.source))
        if before.get("kind") == "directory":
            before_modes = {entry["path"]: entry["mode"] for entry in before["entries"]}
            if before_modes != modes_after:
                raise StagingError("SOURCE_CHANGED", "source permissions changed during processing", str(self.source))
        self._event("source_verified", {"sha256": after.get("sha256"), "unchanged": True})
        manifest["verification"] = {"after": after, "source_unchanged": True}
        self._write_records()
        return {"manifest": self.manifest, "events": self.events, "result": result, "analysis_root": str(self.analysis_root)}

    def _write_records(self) -> None:
        if self.manifest is None:
            return
        (self.analysis_root / "evidence-manifest.json").write_text(json.dumps(self.manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (self.analysis_root / "custody-events.jsonl").write_text("\n".join(json.dumps(event, sort_keys=True) for event in self.events) + "\n", encoding="utf-8")


def run_fixture(source: str | os.PathLike[str], processor: Callable[[Path], Any] | None = None, *, limits: SafetyLimits | None = None) -> dict[str, Any]:
    """Run a fixture in a temporary analysis root and remove it afterwards."""
    with tempfile.TemporaryDirectory(prefix="dfir-analysis-") as root:
        return EvidenceStager(source, root, limits=limits).run(processor)


def adapter_processor(name: str, analysis_root: Path, source_type: str = "disk_image") -> Callable[[Path], Any]:
    """Return a small adapter callback for the reproducible module command."""
    def process(staged: Path) -> Any:
        output = analysis_root / "adapter-output"
        if name == "uac":
            from .adapters.uac_adapter import UACAdapter
            return UACAdapter(staged, output).report()
        if name == "velociraptor":
            from .adapters.velociraptor_adapter import VelociraptorAdapter
            return VelociraptorAdapter(staged, output).collect()
        if name == "disk-memory":
            from .adapters.disk_memory_adapter import DiskMemoryAdapter
            return DiskMemoryAdapter(staged, output).normalized_record(source_type)
        raise StagingError("UNSUPPORTED_ADAPTER", "unknown adapter", name)
    return process


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one fixture through the evidence-safe staging harness")
    parser.add_argument("source", type=Path)
    parser.add_argument("--analysis-root", type=Path, help="writable root; omitted means temporary and cleaned")
    parser.add_argument("--adapter", choices=("uac", "velociraptor", "disk-memory"))
    parser.add_argument("--source-type", choices=("disk_image", "memory_dump"), default="disk_image")
    args = parser.parse_args()
    def processor(root: Path) -> Any:
        if not args.adapter:
            return {"status": "staged"}
        return adapter_processor(args.adapter, root.parent, args.source_type)(root)
    if args.analysis_root:
        result = EvidenceStager(args.source, args.analysis_root).run(processor)
        print(json.dumps({"analysis_root": result["analysis_root"], "source_unchanged": result["manifest"]["verification"]["source_unchanged"]}, sort_keys=True))
    else:
        with tempfile.TemporaryDirectory(prefix="dfir-analysis-") as root:
            result = EvidenceStager(args.source, root).run(processor)
            print(json.dumps({"analysis_root": root, "source_unchanged": result["manifest"]["verification"]["source_unchanged"]}, sort_keys=True))


if __name__ == "__main__":
    main()
