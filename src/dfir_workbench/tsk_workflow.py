"""Read-only Sleuth Kit workflow for raw/IMG evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

class TSKWorkflowError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message); self.code = code; self.message = message; self.retryable = retryable
    def as_dict(self) -> dict[str, Any]: return {"code": self.code, "message": self.message, "retryable": self.retryable}

TSK_TOOLS = ("img_stat", "mmls", "fsstat", "fls", "istat", "icat", "tsk_recover")

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()

def _utc(timestamp: float) -> str: return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")

def _safe_source(path: str | Path) -> Path:
    source = Path(path).expanduser().resolve()
    if Path("/dev") == source or Path("/dev") in source.parents: raise TSKWorkflowError("HOST_DEVICE_REJECTED", "normal mode does not accept host /dev devices")
    if source.is_symlink() or not source.is_file(): raise TSKWorkflowError("SOURCE_INVALID", "image must be a regular, non-symlink file")
    return source

def _safe_root(path: str | Path) -> Path:
    root = Path(path).expanduser().resolve(); root.mkdir(mode=0o700, parents=True, exist_ok=True); return root

def _run(tool: str, args: list[str], *, input_path: Path | None = None, text: bool = True) -> subprocess.CompletedProcess[Any]:
    command = shutil.which(tool)
    if not command: raise TSKWorkflowError("TOOL_UNAVAILABLE", f"required Sleuth Kit tool is unavailable: {tool}")
    argv = [command, *args] + ([str(input_path)] if input_path is not None else [])
    try: return subprocess.run(argv, capture_output=True, text=text, check=False, timeout=120)
    except subprocess.TimeoutExpired as exc: raise TSKWorkflowError("TOOL_TIMEOUT", f"Sleuth Kit tool timed out: {tool}", retryable=True) from exc
    except OSError as exc: raise TSKWorkflowError("TOOL_FAILED", f"could not execute Sleuth Kit tool: {tool}", retryable=True) from exc

def _tool_record(tool: str) -> dict[str, Any]:
    path = shutil.which(tool)
    if not path: return {"name": tool, "available": False, "license": "unknown"}
    result = _run(tool, ["-V"]); output = (result.stdout or result.stderr).strip(); executable = Path(path).resolve()
    return {"name": tool, "available": result.returncode == 0, "path": str(executable), "version": output.splitlines()[0] if output else "unknown", "sha256": _sha256(executable), "license": "GPL-2.0-or-later (verify package notice before redistribution)"}

def tool_manifest() -> dict[str, Any]: return {"schema_version": "1.0", "captured_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "tools": [_tool_record(tool) for tool in TSK_TOOLS]}

def _require_success(result: subprocess.CompletedProcess[Any], tool: str) -> str:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip().splitlines()[0]; raise TSKWorkflowError("TOOL_FAILED", f"{tool} failed: {detail}")
    return result.stdout or ""

def _parse_mmls(output: str) -> list[dict[str, Any]]:
    partitions = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+):\s+(?:\S+\s+)?(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$", line)
        if match:
            index, start, end, length, description = match.groups()
            if not description.lower().startswith(("unallocated", "metadata")): partitions.append({"index": int(index), "start_sector": int(start), "end_sector": int(end), "length_sectors": int(length), "description": description, "raw": line.rstrip()})
    return partitions

def _parse_fls(output: str) -> list[dict[str, Any]]:
    entries = []
    for line in output.splitlines():
        match = re.match(r"^\s*([^:]+):\s+(.*)$", line)
        if match and line.lstrip().startswith(("d/d", "r/r", "-/")):
            source_id, path = match.groups(); inode_match = re.search(r"(\d+)", source_id)
            if inode_match: entries.append({"path": path.strip(), "source_id": inode_match.group(1), "tsk_type": source_id.strip(), "raw": line.rstrip()})
    return entries

@dataclass
class TSKRawImageWorkflow:
    source: Path
    analysis_root: Path
    max_file_bytes: int = 512 * 1024 * 1024
    max_total_bytes: int = 4 * 1024 * 1024 * 1024
    def __post_init__(self) -> None: self.source = _safe_source(self.source); self.analysis_root = _safe_root(self.analysis_root)
    def inspect(self, *, partition_index: int | None = None) -> dict[str, Any]:
        manifest = tool_manifest()
        try:
            image_stat = _require_success(_run("img_stat", [], input_path=self.source), "img_stat")
            mmls = _require_success(_run("mmls", ["-B"], input_path=self.source), "mmls")
            partitions = _parse_mmls(mmls); selected = [p for p in partitions if partition_index is None or p["index"] == partition_index]; filesystems = []
            for partition in selected:
                offset = str(partition["start_sector"]); fs_result = _run("fsstat", ["-o", offset], input_path=self.source)
                if fs_result.returncode != 0: raise TSKWorkflowError("UNSUPPORTED_FILESYSTEM", f"fsstat could not read partition {partition['index']}: {(fs_result.stderr or 'filesystem is not supported').strip().splitlines()[0]}")
                entries = _parse_fls(_require_success(_run("fls", ["-o", offset, "-r", "-p", "-m", "/"], input_path=self.source), "fls"))
                for entry in entries: entry.update(partition_index=partition["index"], partition_offset_sectors=partition["start_sector"])
                filesystems.append({"partition": partition, "fsstat": fs_result.stdout or "", "entries": entries})
            record = self._record(manifest, image_stat, partitions, filesystems); (self.analysis_root / "normalized-evidence.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"); (self.analysis_root / "tool-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"); return record
        except TSKWorkflowError as exc:
            (self.analysis_root / "tool-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            status = "unavailable" if exc.code == "TOOL_UNAVAILABLE" else "unsupported" if exc.code == "UNSUPPORTED_FILESYSTEM" else "failed"
            return {"schema_version": "1.0", "status": status, "error": exc.as_dict(), "evidence_id": self.source.name, "source_type": "disk_image", "original_uri": self.source.as_uri(), "tool_manifest": manifest}
    def extract(self, selections: Iterable[dict[str, Any]], *, partition_index: int, offset_sectors: int) -> dict[str, Any]:
        root = _safe_root(self.analysis_root / "extracted"); extracted = []; errors = []; total = 0
        for selection in selections:
            inode, relative = str(selection.get("source_id", "")), str(selection.get("path", ""))
            if not inode.isdigit() or not relative.startswith("/"): errors.append({"code": "INVALID_SELECTION", "path": relative}); continue
            destination = root / relative.lstrip("/")
            if not destination.resolve().is_relative_to(root): errors.append({"code": "PATH_TRAVERSAL_REJECTED", "path": relative}); continue
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True); fd, temp_name = tempfile.mkstemp(prefix=".partial-", dir=root); os.close(fd); temp = Path(temp_name)
            try:
                istat = _run("istat", ["-o", str(offset_sectors), str(self.source), inode]); result = _run("icat", ["-o", str(offset_sectors), str(self.source), inode], text=False)
                if istat.returncode or result.returncode: errors.append({"code": "EXTRACTION_FAILED", "path": relative}); continue
                data = result.stdout
                if len(data) > self.max_file_bytes or total + len(data) > self.max_total_bytes: errors.append({"code": "FILE_LIMIT_EXCEEDED", "path": relative}); continue
                temp.write_bytes(data); os.replace(temp, destination); os.chmod(destination, 0o600); total += len(data); extracted.append({"path": str(destination), "source_id": inode, "source_path": relative, "partition_index": partition_index, "size": len(data), "sha256": _sha256(destination), "istat": istat.stdout})
            finally: temp.unlink(missing_ok=True)
        return {"status": "completed" if not errors else ("partial" if extracted else "rejected"), "root": str(root), "extracted": extracted, "errors": errors}

    def recover_all(self, *, partition_index: int, offset_sectors: int) -> dict[str, Any]:
        """Recover allocated/deleted files into a fresh, contained root."""
        root = _safe_root(self.analysis_root / "recovered")
        if any(root.iterdir()):
            raise TSKWorkflowError("ANALYSIS_ROOT_NOT_EMPTY", "recovery root must be empty")
        result = _run("tsk_recover", ["-a", "-o", str(offset_sectors), str(self.source), str(root)])
        if result.returncode:
            return {"status": "failed", "root": str(root), "errors": [{"code": "RECOVERY_FAILED", "message": (result.stderr or "tsk_recover failed")[:200]}]}
        return {"status": "completed", "root": str(root), "stdout": result.stdout}
    def _record(self, manifest: dict[str, Any], image_stat: str, partitions: list[dict[str, Any]], filesystems: list[dict[str, Any]]) -> dict[str, Any]:
        stat = self.source.stat(); inventory = [{"path": self.source.name, "size": stat.st_size, "mtime": _utc(stat.st_mtime), "sha256": _sha256(self.source), "kind": "file", "allocated": True, "source_id": "image"}]
        for fs in filesystems:
            for entry in fs["entries"]: inventory.append({"path": entry["path"], "size": 0, "mtime": "1970-01-01T00:00:00Z", "sha256": "0" * 64, "kind": "directory" if entry["tsk_type"].startswith("d/") else "file", "allocated": True, "source_id": f"partition:{entry['partition_index']}:inode:{entry['source_id']}"})
        return {"schema_version": "1.0", "evidence_id": self.source.name, "source_type": "disk_image", "original_uri": self.source.as_uri(), "archive_validation": {"kind": "none", "status": "not_applicable"}, "inventory": inventory, "safe_extraction": {"root": str(self.analysis_root / "extracted"), "status": "not_requested", "policy_version": "tsk-safe-extraction-1", "extracted_count": 0, "rejected_count": 0, "errors": []}, "collection_coverage": {"status": "substantial", "filesystem_metadata": bool(filesystems), "allocated_files": bool(filesystems), "deleted_files": False, "unallocated_space": False, "memory_artifacts": False, "network_artifacts": False, "notes": ["TSK output is read-only; deleted and unallocated artifacts require explicit recovery/analysis steps"]}, "partition_filesystem": {"image_format": "raw", "partitions": partitions}, "adapter_metadata": {"img_stat": image_stat, "filesystems": filesystems, "tool_manifest": manifest}}

def run_tsk_raw_image(source: str | Path, analysis_root: str | Path, *, partition_index: int | None = None) -> dict[str, Any]: return TSKRawImageWorkflow(Path(source), Path(analysis_root)).inspect(partition_index=partition_index)
