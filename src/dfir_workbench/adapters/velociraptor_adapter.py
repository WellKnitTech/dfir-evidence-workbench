"""Velociraptor triage bundle adapter.

Read-only ingestion of Velociraptor ZIP exports and unpacked collection roots.
No recovered content is executed.  The public ``collect`` helper emits the
normalized evidence record consumed by coverage reporting.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

ZERO_SHA256 = "0" * 64
POLICY_VERSION = "safe-extraction-1"
DEFAULT_MAX_FILE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024


class AdapterError(Exception):
    def __init__(self, code: str, message: str, path: str | None = None, retryable: bool = False):
        super().__init__(message)
        self.code, self.message, self.path, self.retryable = code, message, path, retryable

    def as_dict(self) -> dict[str, Any]:
        d = {"code": self.code, "message": self.message, "retryable": self.retryable}
        if self.path:
            d["path"] = self.path
        return d


@dataclass
class SafetyLimits:
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES


@dataclass
class VelociraptorAdapter:
    source: str | os.PathLike[str]
    analysis_root: str | os.PathLike[str]
    limits: SafetyLimits = field(default_factory=SafetyLimits)

    def __post_init__(self) -> None:
        self.source_path = Path(self.source).expanduser().resolve(strict=False)
        self.analysis_path = Path(self.analysis_root).expanduser().resolve()
        self.analysis_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.source_path.exists():
            raise AdapterError("SOURCE_NOT_FOUND", "Evidence source does not exist")
        if not (self.source_path.is_file() or self.source_path.is_dir()):
            raise AdapterError("SOURCE_UNREADABLE", "Evidence source is not a regular file or directory")
        self._metadata = self._discover_metadata()

    @property
    def is_zip(self) -> bool:
        return self.source_path.is_file() and zipfile.is_zipfile(self.source_path)

    def validate(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source_type": "velociraptor_triage", "format": "velociraptor", "status": "valid",
            "warnings": [], "errors": [], "metadata": self._metadata,
        }
        if self.source_path.is_file() and not self.is_zip:
            result["status"] = "unsupported"
            result["errors"].append(AdapterError("UNSUPPORTED_FORMAT", "Source is not a Velociraptor ZIP bundle").as_dict())
            return result
        if self.is_zip:
            try:
                with zipfile.ZipFile(self.source_path) as zf:
                    bad = zf.testzip()
                    result["member_count"] = len(zf.infolist())
                    if bad:
                        raise AdapterError("ARCHIVE_INVALID", "ZIP integrity check failed", bad)
            except zipfile.BadZipFile:
                result["status"] = "invalid"
                result["errors"].append(AdapterError("ARCHIVE_INVALID", "Invalid ZIP archive").as_dict())
        elif self.source_path.is_dir():
            result["format"] = "velociraptor_directory"
            result["archive_validation"] = "not_applicable"
        return result

    def inventory(self) -> list[dict[str, Any]]:
        if self.is_zip:
            return self._inventory_zip()
        if self.source_path.is_dir():
            return self._inventory_directory()
        raise AdapterError("UNSUPPORTED_FORMAT", "Cannot inventory unsupported source")

    def extract(self, paths: Iterable[str] = ()) -> dict[str, Any]:
        root = (self.analysis_path / "extracted").resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        requested = list(paths)
        if not requested:
            return {"root": str(root), "status": "not_requested", "extracted": [], "errors": []}
        inventory = {x["path"]: x for x in self.inventory()}
        extracted: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        total = 0
        for rel in requested:
            try:
                rel = self._safe_member_path(rel)
                entry = inventory.get(rel)
                if not entry or entry["kind"] != "file":
                    raise AdapterError("ARCHIVE_MEMBER_INVALID", "Requested path is not a regular file", rel)
                if entry["size"] > self.limits.max_file_bytes or total + entry["size"] > self.limits.max_total_bytes:
                    raise AdapterError("FILE_LIMIT_EXCEEDED", "Extraction size limit exceeded", rel)
                destination = self._contained(root, rel)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd, temp_name = tempfile.mkstemp(prefix=".extract-", dir=destination.parent, text=False)
                try:
                    with os.fdopen(fd, "wb") as out:
                        with self._open_member(rel) as src:
                            digest = hashlib.sha256()
                            copied = 0
                            while True:
                                block = src.read(1024 * 1024)
                                if not block: break
                                copied += len(block)
                                if copied > self.limits.max_file_bytes or total + copied > self.limits.max_total_bytes:
                                    raise AdapterError("TOTAL_LIMIT_EXCEEDED", "Extraction size limit exceeded", rel)
                                out.write(block); digest.update(block)
                            out.flush(); os.fsync(out.fileno())
                    os.chmod(temp_name, 0o600)
                    if digest.hexdigest() != entry["sha256"] or copied != entry["size"]:
                        raise AdapterError("HASH_FAILED", "Extracted bytes do not match inventory", rel)
                    os.replace(temp_name, destination)
                finally:
                    if os.path.exists(temp_name): os.unlink(temp_name)
                total += entry["size"]
                extracted.append({"path": rel, "output_path": str(destination), "sha256": entry["sha256"], "size": entry["size"]})
            except AdapterError as exc:
                errors.append(exc.as_dict())
        return {"root": str(root), "status": "completed" if not errors else ("partial" if extracted else "failed"), "extracted": extracted, "errors": errors}

    def collect(self, extract_paths: Iterable[str] = ()) -> dict[str, Any]:
        validation = self.validate()
        if validation["status"] not in ("valid",):
            raise AdapterError("UNSUPPORTED_FORMAT", "Validation failed")
        entries = self.inventory()
        extraction = self.extract(extract_paths)
        archive_status = {"kind": "zip", "status": "valid", "member_count": len(entries)} if self.is_zip else {"kind": "none", "status": "not_applicable"}
        evidence_id = "vr-" + hashlib.sha256(str(self.source_path).encode()).hexdigest()[:24]
        return {"schema_version": "1.0", "evidence_id": evidence_id, "source_type": "velociraptor_triage",
                "original_uri": self.source_path.as_uri(), "archive_validation": archive_status, "inventory": entries,
                "safe_extraction": {"root": extraction["root"], "status": extraction["status"], "policy_version": POLICY_VERSION,
                                    "max_file_bytes": self.limits.max_file_bytes, "max_total_bytes": self.limits.max_total_bytes,
                                    "extracted_count": len(extraction["extracted"]), "rejected_count": len(extraction["errors"]), "errors": extraction["errors"]},
                "collection_coverage": self._coverage(entries), "adapter_metadata": self._metadata}

    def _inventory_zip(self) -> list[dict[str, Any]]:
        result = []
        with zipfile.ZipFile(self.source_path) as zf:
            for info in zf.infolist():
                rel = self._safe_member_path(info.filename)
                is_dir = info.is_dir() or info.filename.endswith("/")
                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if file_type == stat.S_IFLNK or (file_type and file_type not in (stat.S_IFREG, stat.S_IFDIR)):
                    kind = "symlink" if file_type == stat.S_IFLNK else "special"
                    result.append(self._entry(rel, 0, info.date_time, ZERO_SHA256, kind, source_id=info.header_offset)); continue
                if is_dir:
                    result.append(self._entry(rel, 0, info.date_time, ZERO_SHA256, "directory", source_id=info.header_offset)); continue
                if info.file_size > self.limits.max_file_bytes:
                    raise AdapterError("FILE_LIMIT_EXCEEDED", "Archive member exceeds size limit", rel)
                with zf.open(info) as fh:
                    digest, size = self._hash_stream(fh)
                result.append(self._entry(rel, size, info.date_time, digest, "file", source_id=info.header_offset))
        return result

    def _inventory_directory(self) -> list[dict[str, Any]]:
        result = []
        for path in sorted(self.source_path.rglob("*")):
            rel = path.relative_to(self.source_path).as_posix()
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                result.append(self._entry(rel, 0, st.st_mtime, ZERO_SHA256, "symlink", link_target=os.readlink(path))); continue
            if path.is_dir(): result.append(self._entry(rel, 0, st.st_mtime, ZERO_SHA256, "directory")); continue
            if not path.is_file(): result.append(self._entry(rel, st.st_size, st.st_mtime, ZERO_SHA256, "special")); continue
            if st.st_size > self.limits.max_file_bytes: raise AdapterError("FILE_LIMIT_EXCEEDED", "File exceeds size limit", rel)
            with path.open("rb") as fh: digest, size = self._hash_stream(fh)
            result.append(self._entry(rel, size, st.st_mtime, digest, "file"))
        return result

    def _entry(self, path: str, size: int, mtime: Any, digest: str, kind: str, **extra: Any) -> dict[str, Any]:
        if isinstance(mtime, tuple): dt = datetime(*mtime, tzinfo=timezone.utc)
        elif isinstance(mtime, (int, float)): dt = datetime.fromtimestamp(mtime, timezone.utc)
        else: dt = datetime.now(timezone.utc)
        entry = {"path": path, "size": size, "mtime": dt.isoformat().replace("+00:00", "Z"), "sha256": digest, "kind": kind}
        entry.update({k: str(v) for k, v in extra.items() if v is not None})
        return entry

    def _hash_stream(self, fh: Any) -> tuple[str, int]:
        h, n = hashlib.sha256(), 0
        while block := fh.read(1024 * 1024): h.update(block); n += len(block)
        return h.hexdigest(), n

    def _safe_member_path(self, name: str) -> str:
        name = name.replace("\\", "/")
        p = PurePosixPath(name)
        if not name or p.is_absolute() or any(part in ("", ".", "..") for part in p.parts) or ":" in p.parts[0]:
            raise AdapterError("PATH_TRAVERSAL_REJECTED", "Unsafe archive member path")
        return p.as_posix()

    def _contained(self, root: Path, rel: str) -> Path:
        target = (root / rel).resolve(strict=False)
        if target != root and root not in target.parents: raise AdapterError("PATH_TRAVERSAL_REJECTED", "Destination escapes extraction root", rel)
        return target

    @contextmanager
    def _open_member(self, rel: str):
        if self.is_zip:
            with zipfile.ZipFile(self.source_path) as zf:
                with zf.open(rel) as fh:
                    yield fh
        else:
            with self.source_path.joinpath(*PurePosixPath(rel).parts).open("rb") as fh:
                yield fh

    def _discover_metadata(self) -> dict[str, Any]:
        text = self.source_path.name
        if self.is_zip:
            with zipfile.ZipFile(self.source_path) as zf:
                names = zf.namelist()
                text += " " + " ".join(names[:100])
                for name in names:
                    if name.lower().endswith((".json", ".jsonl")) and zf.getinfo(name).file_size < 2_000_000:
                        try: text += " " + zf.read(name).decode("utf-8", "ignore")[:200_000]
                        except Exception: pass
        out: dict[str, Any] = {}
        patterns = {"client_id": r"(?:client[_ -]?id|clientid)[\"' :=]+([A-Za-z0-9._-]+)", "flow_id": r"(?:flow[_ -]?id|flowid)[\"' :=]+([A-Za-z0-9._-]+)", "hunt_id": r"(?:hunt[_ -]?id|huntid)[\"' :=]+([A-Za-z0-9._-]+)"}
        for key, pat in patterns.items():
            m = re.search(pat, text, re.I)
            if m: out[key] = m.group(1)
        return {"bundle_format": "Velociraptor", "identifiers": out}

    def _coverage(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        names = " ".join(x["path"].lower() for x in entries)
        return {"status": "substantial" if entries else "unknown", "filesystem_metadata": bool(entries), "allocated_files": bool(entries),
                "deleted_files": False, "unallocated_space": False, "memory_artifacts": any(x in names for x in ("memory", "pslist")),
                "network_artifacts": any(x in names for x in ("network", "netstat", "connections")),
                "notes": ["Velociraptor collection coverage reflects supplied artifacts; archive validity alone does not establish complete coverage."]}
