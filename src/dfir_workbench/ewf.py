"""Evidence-safe optional EWF/libewf capability."""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

EWF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
_SEGMENT = re.compile(r"^(?P<stem>.+?)(?P<segment>(?:e|ex)\d{2,})$", re.IGNORECASE)


def _sha256(path: Path, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def _segment_paths(source: Path) -> list[Path]:
    match = _SEGMENT.match(source.name)
    if not match:
        return [source]
    stem = match.group("stem").lower()
    try:
        candidates = [p for p in source.parent.iterdir() if p.is_file() and not p.is_symlink()]
    except OSError:
        candidates = [source]
    selected = []
    for candidate in candidates:
        other = _SEGMENT.match(candidate.name)
        if other and other.group("stem").lower() == stem:
            selected.append(candidate)
    return sorted(selected or [source], key=lambda p: p.name.lower())


def detect(source: Path) -> tuple[bool, str]:
    try:
        with source.open("rb") as handle:
            signature = handle.read(len(EWF_SIGNATURE))
    except OSError:
        return False, "source unreadable"
    if signature == EWF_SIGNATURE:
        return True, "EWF signature"
    if source.suffix.lower() in {".e01", ".ex01"}:
        return False, "EWF segment extension without a valid signature"
    return False, "not an EWF segment"


def inventory(source: Path, *, max_total_bytes: int) -> dict[str, Any]:
    segments = _segment_paths(source)
    total = 0
    entries = []
    errors = []
    for segment in segments:
        try:
            size = segment.stat().st_size
            total += size
            if total > max_total_bytes:
                errors.append({"code": "FILE_LIMIT_EXCEEDED", "path": segment.name})
                break
            entries.append({"path": segment.name, "size": size, "sha256": _sha256(segment), "source_id": f"ewf-segment:{len(entries) + 1}", "kind": "ewf_segment", "allocated": True})
        except OSError as exc:
            errors.append({"code": "SEGMENT_UNREADABLE", "path": segment.name, "message": str(exc)})
    return {"format": "ewf", "segment_count": len(entries), "segments": entries, "total_bytes": total, "status": "valid" if entries and not errors else ("degraded" if entries else "unsupported"), "errors": errors, "provenance": {"source_path": str(source), "segment_order": [e["path"] for e in entries]}}


def tool_info() -> dict[str, Any]:
    tool = shutil.which("ewfmount")
    if not tool:
        return {"name": "libewf", "status": "unavailable", "capability": "raw_view", "tool": None}
    try:
        result = subprocess.run([tool, "-V"], capture_output=True, text=True, timeout=10, check=False)
        output = (result.stdout or result.stderr).strip()
        version = output.splitlines()[0] if output else "unknown"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"name": "libewf", "status": "degraded", "capability": "raw_view", "tool": tool, "error": str(exc)}
    return {"name": "libewf", "status": "available", "capability": "raw_view", "tool": tool, "version": version}


@contextmanager
def raw_view(source: Path, output_root: Path, *, max_total_bytes: int) -> Iterator[dict[str, Any]]:
    info = tool_info()
    if info["status"] != "available":
        yield {"status": "degraded", "reason": "libewf/ewfmount unavailable", "tool": info}
        return
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    mount_dir = Path(tempfile.mkdtemp(prefix="ewf-", dir=output_root))
    try:
        details = inventory(source, max_total_bytes=max_total_bytes)
        if details["status"] == "unsupported":
            yield {"status": "unsupported", "reason": "EWF segments exceed configured limits"}
            return
        result = subprocess.run([info["tool"], "-f", "encase7", str(source), str(mount_dir)], capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            yield {"status": "degraded", "reason": "libewf raw view failed", "stderr": result.stderr[-1000:], "tool": info}
            return
        views = [p for p in mount_dir.iterdir() if p.is_file()]
        yield {"status": "ready", "path": str(views[0]) if views else None, "root": str(mount_dir), "tool": info}
    finally:
        shutil.rmtree(mount_dir, ignore_errors=True)


def limits_ok(source: Path, *, max_file_bytes: int, max_total_bytes: int) -> tuple[bool, str | None]:
    for segment in _segment_paths(source):
        if segment.stat().st_size > max_file_bytes:
            return False, "FILE_LIMIT_EXCEEDED: source segment exceeds max_file_bytes"
    details = inventory(source, max_total_bytes=max_total_bytes)
    if details["total_bytes"] > max_total_bytes:
        return False, "FILE_LIMIT_EXCEEDED: EWF segment set exceeds max_total_bytes"
    return True, None
