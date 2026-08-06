"""Evidence-safe adapter for UAC archive collections and directories.

The adapter is deliberately stdlib-first and returns the normalized evidence
record defined by normalized-evidence.schema.json. It never mutates its source.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ZERO_SHA256 = "0" * 64
POLICY = "safe-extraction-1"

@dataclass
class AdapterError(Exception):
    code: str
    message: str
    path: str | None = None
    retryable: bool = False
    details: dict[str, Any] | None = None
    def as_dict(self) -> dict[str, Any]:
        d = {"code": self.code, "message": self.message, "retryable": self.retryable}
        if self.path is not None: d["path"] = self.path
        if self.details: d["details"] = self.details
        return d

@dataclass
class SafetyLimits:
    max_file_bytes: int = 512 * 1024 * 1024
    max_total_bytes: int = 4 * 1024 * 1024 * 1024

@dataclass
class UACAdapter:
    source: str | os.PathLike[str]
    analysis_root: str | os.PathLike[str]
    limits: SafetyLimits = field(default_factory=SafetyLimits)
    _validation: dict[str, Any] | None = field(default=None, init=False)
    _inventory: list[dict[str, Any]] | None = field(default=None, init=False)
    _record: dict[str, Any] | None = field(default=None, init=False)
    _inventory_errors: list[dict[str, Any]] = field(default_factory=list, init=False)
    _encrypted: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.source_path = Path(self.source).expanduser()
        self.analysis_path = Path(self.analysis_root).expanduser().resolve()
        self.analysis_path.mkdir(parents=True, exist_ok=True)
        self.source_type = "uac_directory" if self.source_path.is_dir() else "uac_archive"

    @staticmethod
    def _utc(ts: float) -> str:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _sha_stream(stream, limit: int | None = None) -> tuple[str, int]:
        h, n = hashlib.sha256(), 0
        while True:
            b = stream.read(1024 * 1024)
            if not b: break
            n += len(b)
            if limit is not None and n > limit:
                raise AdapterError("FILE_LIMIT_EXCEEDED", "file exceeds configured limit", retryable=False)
            h.update(b)
        return h.hexdigest(), n

    @staticmethod
    def _safe_member(name: str) -> str:
        # Archive names are POSIX paths even on Windows. Backslashes are separators.
        n = name.replace("\\", "/")
        if n.startswith("/") or (len(n) >= 2 and n[1] == ":"):
            raise AdapterError("PATH_TRAVERSAL_REJECTED", "absolute archive member rejected", name)
        n = posixpath.normpath(n)
        if n in ("", "."):
            raise AdapterError("ARCHIVE_MEMBER_INVALID", "empty archive member rejected", name)
        if n == ".." or n.startswith("../"):
            raise AdapterError("PATH_TRAVERSAL_REJECTED", "parent traversal archive member rejected", name)
        return n

    def validate(self) -> dict[str, Any]:
        if not self.source_path.exists():
            raise AdapterError("SOURCE_NOT_FOUND", "evidence source does not exist", str(self.source_path))
        if self.source_path.is_dir():
            result = {"kind": "none", "status": "not_applicable"}
        else:
            kind = self._archive_kind()
            if kind == "7z": result = self._validate_7z()
            elif kind == "zip": result = self._validate_zip()
            elif kind.startswith("tar"): result = self._validate_tar()
            else: raise AdapterError("UNSUPPORTED_FORMAT", "unsupported UAC archive format", str(self.source_path))
        self._validation = result
        return result

    def _archive_kind(self) -> str:
        n = self.source_path.name.lower()
        if n.endswith(".zip"): return "zip"
        if n.endswith((".tar.gz", ".tgz")): return "tar_gz"
        if n.endswith((".tar.xz", ".txz")): return "tar_xz"
        if n.endswith(".tar"): return "tar"
        if n.endswith(".7z"): return "7z"
        # signatures allow archives without conventional names
        with self.source_path.open("rb") as f: sig = f.read(8)
        if sig.startswith(b"PK"): return "zip"
        if sig.startswith(b"7z\xbc\xaf\x27\x1c"): return "7z"
        return "other"

    def _validate_zip(self) -> dict[str, Any]:
        try:
            with zipfile.ZipFile(self.source_path) as z:
                infos = z.infolist()
                self._encrypted = any(i.flag_bits & 1 for i in infos)
                bad = z.testzip() if not self._encrypted else None
                return {"kind": "zip", "status": "invalid" if bad else "valid", "member_count": len(infos), "error": AdapterError("ARCHIVE_INVALID", "CRC check failed", bad).as_dict() if bad else None}
        except (OSError, zipfile.BadZipFile) as e:
            return {"kind": "zip", "status": "invalid", "error": AdapterError("ARCHIVE_INVALID", "archive integrity check failed").as_dict()}

    def _validate_tar(self) -> dict[str, Any]:
        kind = self._archive_kind()
        try:
            with tarfile.open(self.source_path, "r:*", errorlevel=2) as t: count = len(t.getmembers())
            return {"kind": kind, "status": "valid", "member_count": count}
        except (OSError, tarfile.TarError):
            return {"kind": kind, "status": "invalid", "error": AdapterError("ARCHIVE_INVALID", "tar integrity check failed").as_dict()}

    def _validate_7z(self) -> dict[str, Any]:
        p = subprocess.run(["7z", "t", "-y", str(self.source_path)], capture_output=True, text=True)
        return {"kind": "7z", "status": "valid" if p.returncode == 0 else "invalid", "error": None if p.returncode == 0 else AdapterError("ARCHIVE_INVALID", "7z integrity check failed").as_dict()}

    def inventory(self) -> list[dict[str, Any]]:
        if self._inventory is not None: return self._inventory
        if self._validation is None: self.validate()
        if self._validation["status"] == "invalid": raise AdapterError("ARCHIVE_INVALID", "cannot inventory invalid archive")
        self._inventory = self._inventory_dir() if self.source_path.is_dir() else self._inventory_archive()
        return self._inventory

    def _entry(self, path: str, size: int, mtime: str, digest: str, kind: str, **extra) -> dict[str, Any]:
        d = {"path": path, "size": size, "mtime": mtime, "sha256": digest, "kind": kind, "allocated": True}
        d.update({k: v for k, v in extra.items() if v is not None})
        return d

    def _inventory_dir(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.source_path.rglob("*"), key=lambda x: x.relative_to(self.source_path).as_posix()):
            rel = p.relative_to(self.source_path).as_posix()
            st = p.lstat()
            if stat.S_ISREG(st.st_mode):
                try:
                    with p.open("rb") as f: digest, size = self._sha_stream(f, self.limits.max_file_bytes)
                    out.append(self._entry(rel, size, self._utc(st.st_mtime), digest, "file"))
                except (OSError, AdapterError) as e:
                    out.append(self._entry(rel, st.st_size, self._utc(st.st_mtime), ZERO_SHA256, "file"))
            elif stat.S_ISDIR(st.st_mode): out.append(self._entry(rel, 0, self._utc(st.st_mtime), ZERO_SHA256, "directory"))
            elif stat.S_ISLNK(st.st_mode): out.append(self._entry(rel, 0, self._utc(st.st_mtime), ZERO_SHA256, "symlink", link_target=os.readlink(p)))
            else: out.append(self._entry(rel, 0, self._utc(st.st_mtime), ZERO_SHA256, "special"))
        return out

    def _inventory_archive(self) -> list[dict[str, Any]]:
        out = []
        if self._archive_kind() == "7z": return self._inventory_7z()
        if self._archive_kind() == "zip":
            with zipfile.ZipFile(self.source_path) as z:
                for i in z.infolist():
                    try: rel = self._safe_member(i.filename)
                    except AdapterError as e:
                        self._inventory_errors.append(e.as_dict())
                        rel = i.filename.replace("\\", "/")
                    isdir = i.is_dir() or i.filename.endswith("/")
                    if isdir: out.append(self._entry(rel, 0, self._zip_time(i), ZERO_SHA256, "directory", source_id=str(i.header_offset))); continue
                    try:
                        with z.open(i) as f: digest, size = self._sha_stream(f, self.limits.max_file_bytes)
                        out.append(self._entry(rel, size, self._zip_time(i), digest, "file", source_id=str(i.header_offset)))
                    except (OSError, RuntimeError, ValueError, AdapterError): out.append(self._entry(rel, i.file_size, self._zip_time(i), ZERO_SHA256, "file", source_id=str(i.header_offset)))
        else:
            with tarfile.open(self.source_path, "r:*") as t:
                for i in t.getmembers():
                    try: rel = self._safe_member(i.name)
                    except AdapterError as e:
                        self._inventory_errors.append(e.as_dict())
                        rel = i.name.replace("\\", "/")
                    kind = "directory" if i.isdir() else "symlink" if i.issym() or i.islnk() else "file" if i.isfile() else "special"
                    digest, size = ZERO_SHA256, 0
                    if kind == "file":
                        f = t.extractfile(i)
                        if f: digest, size = self._sha_stream(f, self.limits.max_file_bytes)
                    out.append(self._entry(rel, size if kind == "file" else 0, self._utc(i.mtime), digest, kind, source_id=str(i.offset), link_target=i.linkname if kind == "symlink" else None))
        return out

    @staticmethod
    def _zip_time(i: zipfile.ZipInfo) -> str:
        return datetime(*i.date_time, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

    def _inventory_7z(self) -> list[dict[str, Any]]:
        # 7z -slt is a stable machine-readable listing format.
        p = subprocess.run(["7z", "l", "-slt", str(self.source_path)], capture_output=True, text=True, check=True)
        out, cur = [], {}
        for line in p.stdout.splitlines() + [""]:
            if not line.strip():
                if "Path" in cur and cur["Path"] != str(self.source_path):
                    rel = self._safe_member(cur["Path"])
                    isdir = "D" in cur.get("Attributes", "")
                    size = int(cur.get("Size", "0") or 0)
                    digest = ZERO_SHA256
                    if not isdir:
                        q = subprocess.run(["7z", "x", "-so", "-y", str(self.source_path), cur["Path"]], capture_output=True, check=True)
                        digest, size = self._sha_stream(__import__("io").BytesIO(q.stdout), self.limits.max_file_bytes)
                    out.append(self._entry(rel, 0 if isdir else size, cur.get("Modified", "1970-01-01T00:00:00").replace(" ", "T") + "Z", digest, "directory" if isdir else "file"))
                cur = {}
            elif " = " in line:
                k, v = line.split(" = ", 1); cur[k] = v
        return out

    def extract(self, allowlist: Iterable[str]) -> dict[str, Any]:
        selected = list(allowlist)
        root = (self.analysis_path / "extracted").resolve(); root.mkdir(parents=True, exist_ok=True)
        result = {"root": str(root), "status": "not_requested" if not selected else "completed", "policy_version": POLICY, "max_file_bytes": self.limits.max_file_bytes, "max_total_bytes": self.limits.max_total_bytes, "extracted_count": 0, "rejected_count": 0, "errors": []}
        if not selected: return result
        if self._validation is None: self.validate()
        if self._validation["status"] == "invalid": raise AdapterError("ARCHIVE_INVALID", "cannot extract invalid archive")
        total = 0
        wanted = set()
        for raw in selected:
            try: wanted.add(self._safe_member(raw))
            except AdapterError as e: result["rejected_count"] += 1; result["errors"].append(e.as_dict())
        if self.source_path.is_dir():
            for rel in sorted(wanted):
                p = self.source_path / rel
                if not p.exists() and not p.is_symlink(): result["errors"].append(AdapterError("SOURCE_UNREADABLE", "requested path not found", rel).as_dict()); continue
                if p.is_symlink() or not p.is_file(): result["rejected_count"] += 1; result["errors"].append(AdapterError("SYMLINK_REJECTED", "only regular files may be extracted", rel).as_dict()); continue
                total = self._copy_one(p, rel, root, total, result)
        elif self._archive_kind() == "zip":
            with zipfile.ZipFile(self.source_path) as z:
                for i in z.infolist():
                    try: rel = self._safe_member(i.filename)
                    except AdapterError as e: result["rejected_count"] += 1; result["errors"].append(e.as_dict()); continue
                    if rel in wanted and not i.is_dir():
                        if i.flag_bits & 1: result["rejected_count"] += 1; result["errors"].append(AdapterError("ARCHIVE_MEMBER_INVALID", "encrypted archive member cannot be extracted", rel).as_dict()); continue
                        with z.open(i) as f: total = self._copy_stream(f, rel, root, total, result)
        elif self._archive_kind() == "7z":
            for rel in sorted(wanted):
                try:
                    self._safe_member(rel)
                    p = subprocess.run(["7z", "x", "-so", "-y", str(self.source_path), rel], capture_output=True, check=True)
                    total = self._copy_stream(__import__("io").BytesIO(p.stdout), rel, root, total, result)
                except subprocess.CalledProcessError:
                    result["rejected_count"] += 1
                    result["errors"].append(AdapterError("EXTRACTION_FAILED", "7z member extraction failed", rel).as_dict())
        else:
            with tarfile.open(self.source_path, "r:*") as t:
                for i in t.getmembers():
                    try: rel = self._safe_member(i.name)
                    except AdapterError as e: result["rejected_count"] += 1; result["errors"].append(e.as_dict()); continue
                    if rel in wanted:
                        if not i.isfile(): result["rejected_count"] += 1; result["errors"].append(AdapterError("SYMLINK_REJECTED", "non-regular archive member rejected", rel).as_dict()); continue
                        f = t.extractfile(i)
                        if f: total = self._copy_stream(f, rel, root, total, result)
        if result["errors"]: result["status"] = "partial" if result["extracted_count"] else "rejected"
        return result

    def _destination(self, rel: str, root: Path) -> Path:
        dest = (root / rel).resolve()
        if os.path.commonpath([str(root), str(dest)]) != str(root): raise AdapterError("PATH_TRAVERSAL_REJECTED", "destination escapes extraction root", rel)
        return dest

    def _copy_one(self, src: Path, rel: str, root: Path, total: int, result: dict[str, Any]) -> int:
        with src.open("rb") as f: return self._copy_stream(f, rel, root, total, result)

    def _copy_stream(self, stream, rel: str, root: Path, total: int, result: dict[str, Any]) -> int:
        dest = self._destination(rel, root); dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if dest.exists(): raise AdapterError("ARCHIVE_MEMBER_INVALID", "duplicate extraction destination", rel)
        tmp = dest.with_name("." + dest.name + ".tmp-" + next(tempfile._get_candidate_names()))
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                h, n = hashlib.sha256(), 0
                while True:
                    b = stream.read(1024 * 1024)
                    if not b: break
                    n += len(b)
                    if n > self.limits.max_file_bytes or total + n > self.limits.max_total_bytes: raise AdapterError("TOTAL_LIMIT_EXCEEDED", "extraction size limit exceeded", rel)
                    h.update(b); out.write(b)
                out.flush(); os.fsync(out.fileno())
            if dest.exists(): raise AdapterError("ARCHIVE_MEMBER_INVALID", "duplicate extraction destination", rel)
            os.replace(tmp, dest); result["extracted_count"] += 1
            return total + n
        except AdapterError as e:
            result["rejected_count"] += 1; result["errors"].append(e.as_dict())
            try: tmp.unlink()
            except FileNotFoundError: pass
            return total

    def report(self) -> dict[str, Any]:
        inv = self.inventory()
        validation = self._validation or self.validate()
        record = {"schema_version": "1.0", "evidence_id": hashlib.sha256(str(self.source_path).encode()).hexdigest()[:32], "source_type": self.source_type, "original_uri": self.source_path.as_uri(), "archive_validation": {k:v for k,v in validation.items() if v is not None}, "inventory": inv, "safe_extraction": {"root": str((self.analysis_path / "extracted").resolve()), "status": "not_requested", "policy_version": POLICY, "max_file_bytes": self.limits.max_file_bytes, "max_total_bytes": self.limits.max_total_bytes, "extracted_count": 0, "rejected_count": 0, "errors": []}, "collection_coverage": {"status": "substantial", "filesystem_metadata": True, "allocated_files": any(x["kind"] == "file" for x in inv), "deleted_files": False, "unallocated_space": False, "memory_artifacts": False, "network_artifacts": False, "notes": ["Archive/directory inventory does not establish complete collection coverage."]}, "adapter_metadata": {"adapter": "uac_adapter", "policy_version": POLICY, "inventory_file_count": sum(x["kind"] == "file" for x in inv), "inventory_hashed_count": sum(x["kind"] == "file" and x["sha256"] != ZERO_SHA256 for x in inv), "encryption_detected": self._encrypted, "inventory_errors": self._inventory_errors}}
        self._record = record
        return record

    def json(self) -> str: return json.dumps(self.report(), indent=2, sort_keys=True)
