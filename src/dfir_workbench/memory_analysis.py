"""Fail-closed memory-dump capability and analysis boundary."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

MEMORY_CAPABILITY_MATRIX: dict[str, dict[str, Any]] = {
    "windows-crash-dump": {"formats": ["windows-crash-dump"], "profiles": ["windows-x86", "windows-x64"], "parser": "volatility3", "structured_checks": ["pslist", "psscan", "dlllist", "netscan"]},
    "linux-elf": {"formats": ["elf-memory"], "profiles": ["linux-x86_64", "linux-arm64"], "parser": "volatility3", "structured_checks": ["linux.pslist", "linux.pstree", "linux.lsmod", "linux.sockstat"]},
    "linux-vmcore": {"formats": ["vmcore"], "profiles": ["linux-x86_64", "linux-arm64"], "parser": "volatility3", "structured_checks": ["linux.pslist", "linux.pstree", "linux.lsmod", "linux.sockstat"]},
    "linux-crash": {"formats": ["linux-crash"], "profiles": ["linux-x86_64", "linux-arm64"], "parser": "volatility3", "structured_checks": ["linux.pslist", "linux.pstree", "linux.lsmod", "linux.sockstat"]},
}

class MemoryAnalysisError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024): digest.update(block)
    return digest.hexdigest()


def _elf_details(path: Path) -> dict[str, Any]:
    header = path.read_bytes()[:64]
    if len(header) < 20 or header[:4] != b"\x7fELF": return {}
    endian = "little" if header[5] == 1 else "big"
    machine = int.from_bytes(header[18:20], endian)
    return {"elf_class": {1: "32-bit", 2: "64-bit"}.get(header[4], "unknown"), "endianness": endian, "machine": machine, "architecture": {62: "x86_64", 183: "arm64", 3: "x86", 40: "arm"}.get(machine, "unknown"), "elf_type": int.from_bytes(header[16:18], endian), "os_abi": header[7]}


def detect_memory_profile(path: str | os.PathLike[str]) -> dict[str, Any]:
    source = Path(path)
    with source.open("rb") as handle: head = handle.read(4096)
    if head[:4] == b"\x7fELF":
        details = _elf_details(source)
        return {"format": "elf-memory", "platform": "linux-elf", "reason": "ELF header", "header": details, "detected_architecture": details.get("architecture")}
    if head[:4] in (b"DUMP", b"DU64") or b"PAGE" in head[:64]: return {"format": "windows-crash-dump", "platform": "windows-crash-dump", "reason": "Windows dump marker"}
    if head[:8] == b"VMCORE\x00": return {"format": "vmcore", "platform": "linux-vmcore", "reason": "vmcore marker"}
    if head[:8] in (b"KDUMP\x00\x00", b"CRASH\x00\x00"): return {"format": "linux-crash", "platform": "linux-crash", "reason": "Linux crash marker"}
    return {"format": "raw-memory", "platform": None, "reason": "unrecognized memory header"}


def validate_profile(detection: dict[str, Any], requested: str | None = None) -> dict[str, Any]:
    capability = MEMORY_CAPABILITY_MATRIX.get(detection.get("platform") or "")
    if not capability: return {"status": "unsupported", "requested": requested, "reason": "memory format is not supported"}
    if requested and requested not in capability["profiles"]: return {"status": "unsupported", "requested": requested, "reason": "profile is not supported for detected format", "supported": capability["profiles"]}
    arch = detection.get("detected_architecture")
    if arch and not any(arch in profile for profile in capability["profiles"]): return {"status": "unsupported", "requested": requested, "reason": "detected architecture has no supported profile", "detected_architecture": arch}
    selected = requested or next((p for p in capability["profiles"] if arch and arch in p), None)
    if not selected: return {"status": "unsupported", "requested": requested, "reason": "profile must be selected explicitly for this dump"}
    return {"status": "valid", "requested": requested, "selected": selected, "detected_architecture": arch}


def discover_tools() -> list[dict[str, Any]]:
    tools = []
    for name in ("volatility3", "vol.py", "volatility", "strings"):
        executable = shutil.which(name)
        item: dict[str, Any] = {"name": name, "available": bool(executable), "path": executable, "license": "GPL-2.0-or-later" if name.startswith("vol") else "binutils license"}
        if executable:
            try:
                result = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=10)
                item["version"] = (result.stdout or result.stderr).strip().splitlines()[0] if result.returncode == 0 else "unknown"
            except (OSError, subprocess.TimeoutExpired): item["version"] = "unknown"
        tools.append(item)
    podman = shutil.which("podman")
    tools.append({"name": "reviewed-parser-container", "available": bool(podman), "path": podman, "isolated": bool(podman), "pinned": False, "version": "unknown", "license": "not established", "reason": "no pinned parser image is bundled or configured"})
    return tools


def bounded_strings(path: str | os.PathLike[str], *, limit: int = 200, max_bytes: int = 2 * 1024 * 1024) -> list[str]:
    if limit < 0 or max_bytes < 0: raise ValueError("limits must be non-negative")
    values = re.findall(rb"[ -~]{4,}", Path(path).read_bytes()[:max_bytes])
    return [value.decode("ascii", "replace") for value in values[:limit]]


def analyze_memory(path: str | os.PathLike[str], *, requested_profile: str | None = None, string_limit: int = 200) -> dict[str, Any]:
    source = Path(path)
    if source.is_symlink() or not source.is_file(): raise MemoryAnalysisError("memory source must be a regular file")
    before = _sha256(source); detection = detect_memory_profile(source); profile = validate_profile(detection, requested_profile); tools = discover_tools()
    report: dict[str, Any] = {"source": {"path": str(source), "size": source.stat().st_size, "sha256": before}, "detection": detection, "profile_validation": profile, "tools": tools, "capabilities": {"status": "unsupported" if profile["status"] != "valid" else "unavailable", "structured_checks": [], "findings": [], "limitations": []}}
    if profile["status"] != "valid": report["capabilities"]["limitations"].append("No parser or structured process/module/network claims are permitted without a valid profile")
    else:
        report["capabilities"]["structured_checks"] = MEMORY_CAPABILITY_MATRIX[detection["platform"]]["structured_checks"]
        report["capabilities"]["limitations"].append("Volatility execution is unavailable unless a reviewed pinned tool container is configured")
    report["residue"] = {"type": "bounded-strings", "values": bounded_strings(source, limit=string_limit), "interpretation": "residue only; not evidence of a running process, loaded module, or network connection"}
    after = _sha256(source); report["custody"] = {"sha256_before": before, "sha256_after": after, "unchanged": before == after}
    if before != after: raise MemoryAnalysisError("memory source changed during analysis")
    return report


def capability_report() -> dict[str, Any]:
    return {"schema_version": "1.0", "capabilities": MEMORY_CAPABILITY_MATRIX, "tools": discover_tools(), "policy": {"unsupported_profiles_fail_closed": True, "strings_are_residue": True, "native_parser_claims_require_pinned_tool": True}}


def write_capability_report(path: str | os.PathLike[str]) -> Path:
    destination = Path(path); destination.parent.mkdir(parents=True, exist_ok=True); destination.write_text(json.dumps(capability_report(), indent=2, sort_keys=True) + "\n", encoding="utf-8"); return destination
