#!/usr/bin/env python3
"""Validate the forensic-tool lifecycle and fail closed for unavailable tools."""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools" / "forensic-tools.json"
STATUSES = {"available", "unavailable-unpinned", "excluded-license-review"}

def load() -> dict:
    data=json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("tools"), list): raise ValueError("invalid forensic-tool manifest schema")
    names=set()
    for tool in data["tools"]:
        required={"name","status","source","artifact_sha256","license_notice","container_image","capabilities","network_policy","mounts","golden_smoke_test"}; missing=required-tool.keys()
        if missing: raise ValueError(f"{tool.get('name','<unnamed>')}: missing {sorted(missing)}")
        if tool["name"] in names: raise ValueError(f"duplicate tool: {tool['name']}")
        names.add(tool["name"])
        if tool["status"] not in STATUSES: raise ValueError(f"{tool['name']}: unsupported status {tool['status']!r}")
        if tool["network_policy"] != "none": raise ValueError(f"{tool['name']}: forensic tools must use network_policy=none")
        if tool["mounts"].get("input") != "/input:ro" or tool["mounts"].get("output") != "/output:rw": raise ValueError(f"{tool['name']}: invalid evidence mount policy")
        digest=tool["artifact_sha256"]
        if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest): raise ValueError(f"{tool['name']}: artifact_sha256 must be lowercase SHA-256")
        if tool["status"] == "available" and (not tool.get("version") or not tool.get("artifact") or not digest or "@sha256:" not in (tool.get("container_image") or "")): raise ValueError(f"{tool['name']}: available tool is not pinned")
    return data

def verify_artifact(tool: dict, artifact: Path) -> None:
    expected=tool.get("artifact_sha256")
    if tool["status"] != "available" or not expected: raise RuntimeError(f"{tool['name']}: unsupported ({tool['status']}); no executable artifact is approved")
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != expected: raise RuntimeError(f"{tool['name']}: artifact SHA-256 mismatch")

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--tool"); parser.add_argument("--artifact", type=Path); args=parser.parse_args()
    try:
        data=load()
        if args.tool:
            tool=next((item for item in data["tools"] if item["name"] == args.tool), None)
            if tool is None: raise RuntimeError(f"unknown forensic tool: {args.tool}")
            if args.artifact is None: raise RuntimeError(f"{args.tool}: unsupported ({tool['status']}); no executable artifact is approved")
            verify_artifact(tool,args.artifact)
        print(f"forensic-tool manifest: PASS ({len(data['tools'])} tools; unavailable tools fail closed)")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc: print(f"forensic-tool manifest: FAIL: {exc}", file=sys.stderr); return 1
    return 0
if __name__ == "__main__": raise SystemExit(main())
