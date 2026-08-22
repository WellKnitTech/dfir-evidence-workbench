"""Evidence-safe disk-image and memory-dump adapter.

Stdlib-only implementation with optional native tools. It never mounts evidence and
writes only derived output below the caller supplied staging root.
"""
from __future__ import annotations
import hashlib, json, os, re, shutil, struct, subprocess, tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import ewf

ZERO_SHA256 = "0" * 64
SUPPORTED_IMAGES = {"raw", "img", "vhd", "vhdx", "vmdk", "qcow2", "ewf"}

class AdapterError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False, path: str | None = None):
        super().__init__(message); self.code, self.message, self.retryable, self.path = code, message, retryable, path
    def as_dict(self):
        d = {"code": self.code, "message": self.message, "retryable": self.retryable}
        if self.path: d["path"] = self.path
        return d

def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")

def sha256(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while b := f.read(chunk): h.update(b)
    return h.hexdigest()

def _read(path: Path, offset: int, size: int) -> bytes:
    with path.open("rb") as f:
        f.seek(offset); return f.read(size)

def _file_type(path: Path) -> str:
    try:
        p = subprocess.run(["file", "-b", "--", str(path)], text=True, capture_output=True, timeout=10)
        return p.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired): return "unknown"

def detect_image(path: Path) -> tuple[str, str]:
    head = _read(path, 0, 4096); size = path.stat().st_size
    # VHD footer is at EOF and begins with 'conectix'.
    if size >= 512 and _read(path, size - 512, 8) == b"conectix": return "vhd", "VHD footer (conectix)"
    if head[:8] == b"vmdk\x00\x00\x00\x00" or b"# Disk DescriptorFile" in head[:1024]: return "vmdk", "VMDK signature/descriptor"
    if head[:4] == b"QFI\xfb": return "qcow2", "QCOW2 magic"
    if head[:8] == b"EVF\x09\x0d\x0a\xff\x00": return "ewf", "Expert Witness Format"
    return "raw", "raw byte stream"

def detect_memory(path: Path) -> tuple[str, str]:
    h = _read(path, 0, 4096)
    suffix = path.suffix.lower()
    # Acquisition tooling may rename ETL files to memdump.mem; classify these
    # before any memory markers and never claim memory findings for them.
    if suffix == ".evtx" or (h[:8] == b"ElfFile\x00" and b"ElfChnk" in _read(path, 4096, 4096)):
        return "windows-event-log", "Windows event-log header/chunk"
    if suffix == ".etl" or h[:8] == b"ElfFile\x00" or h[:4] == b"ETL\x00":
        return "windows-etl", "Windows ETL/event-trace marker"
    if h[:4] == b"\x7fELF": return "elf-memory", "ELF header"
    if h[:4] in (b"DUMP", b"DU64") or b"PAGE" in h[:64]: return "windows-crash-dump", "Windows dump marker"
    if h[:7] == b"VMCORE\x00": return "vmcore", "vmcore marker"
    return "raw-memory", "no recognized dump header; treated as opaque bytes"


def _event_log_result(path: Path, fmt: str, reason: str, limit: int = 1024 * 1024) -> dict[str, Any]:
    return {"format": fmt, "detection": reason, "parser": "bounded-timeline", "status": "unavailable",
            "records": [], "scanned_bytes": min(path.stat().st_size, limit), "scan_limit_bytes": limit,
            "limitations": ["ETL/event-log binary parser is not bundled; no events inferred"]}

def _parse_mbr(path: Path) -> tuple[int, list[dict[str, Any]]]:
    b = _read(path, 0, 512)
    if len(b) < 512 or b[510:512] != b"\x55\xaa": return 512, []
    parts=[]
    for i in range(4):
        e=b[446+i*16:462+i*16]; typ=e[4]; first, count=struct.unpack_from("<II", e, 8)
        if typ and count: parts.append({"index":i, "offset_bytes":first*512, "length_bytes":count*512, "type":f"mbr-0x{typ:02x}"})
    return 512, parts

def _parse_gpt(path: Path) -> tuple[int, list[dict[str, Any]]]:
    h=_read(path,512,96)
    if len(h) < 96 or h[:8] != b"EFI PART": return 512, []
    sector=512; first,last,nent,esz=struct.unpack_from("<QQII", h, 72)
    parts=[]
    for i in range(min(nent, 4096)):
        e=_read(path, 2*sector+i*esz, esz)
        if len(e)<esz or not any(e[:16]): continue
        a,z=struct.unpack_from("<QQ",e,32); typ=e[:16].hex()
        if z>=a: parts.append({"index":i, "offset_bytes":a*sector, "length_bytes":(z-a+1)*sector, "type":f"gpt-{typ}"})
    return sector,parts

def fs_at(path: Path, off: int) -> str | None:
    b=_read(path,off,4096)
    if len(b)>=3 and b[:3] in (b"NTFS",): return "ntfs"
    if len(b)>=90 and b[3:11] == b"EXFAT   ": return "exfat"
    if len(b)>=90 and b[54:62] in (b"FAT12   ", b"FAT16   ", b"FAT32   "): return "fat"
    if len(b)>=0x43 and _read(path,off+0x38,2)==b"\x53\xef": return "ext"
    if len(b)>=4 and b[:4] == b"XFSB": return "xfs"
    return None

def _partitions(path: Path) -> tuple[int,list[dict[str,Any]]]:
    sector, parts = _parse_gpt(path)
    if not parts: sector, parts = _parse_mbr(path)
    for p in parts: p["filesystem"] = fs_at(path,p["offset_bytes"])
    return sector, parts

@dataclass
class DiskMemoryAdapter:
    evidence: str | Path
    staging_root: str | Path
    evidence_id: str | None = None
    max_file_bytes: int = 4*1024*1024*1024
    max_total_bytes: int = 8*1024*1024*1024

    def __post_init__(self):
        self.evidence=Path(self.evidence)
        self.root=Path(self.staging_root).resolve()
        if not self.evidence.is_file() or self.evidence.is_symlink(): raise AdapterError("SOURCE_NOT_FOUND", "evidence must be a regular file")
        self.evidence=self.evidence.resolve()
        self.evidence_id=self.evidence_id or re.sub(r"[^A-Za-z0-9._-]", "_", self.evidence.name)[:120]

    def validate(self, source_type: str) -> dict[str,Any]:
        if source_type not in ("disk_image", "memory_dump"): raise AdapterError("UNSUPPORTED_FORMAT", "source_type must be disk_image or memory_dump")
        kind, signature=(detect_image(self.evidence) if source_type=="disk_image" else detect_memory(self.evidence))
        warnings=[]
        if source_type=="disk_image" and kind not in SUPPORTED_IMAGES: raise AdapterError("UNSUPPORTED_FORMAT", "unsupported disk image format")
        if source_type=="disk_image" and kind in ("vmdk","qcow2"): warnings.append("container recognized; partition parsing requires a readable raw view or native image tool")
        if source_type=="disk_image" and kind=="ewf":
            ok, reason = ewf.limits_ok(self.evidence, max_file_bytes=self.max_file_bytes, max_total_bytes=self.max_total_bytes)
            if not ok: raise AdapterError("FILE_LIMIT_EXCEEDED", reason or "EWF limits exceeded")
            warnings.append("EWF metadata is available; raw view requires optional libewf/ewfmount")
        return {"source_type":source_type,"detected_format":kind,"signature":signature,"status":"valid","warnings":warnings,"sha256":sha256(self.evidence),"size":self.evidence.stat().st_size}

    def inventory(self, source_type: str) -> dict[str,Any]:
        v=self.validate(source_type); st=self.evidence.stat()
        entries=[{"path":self.evidence.name,"size":st.st_size,"mtime":utc(st.st_mtime),"sha256":v["sha256"],"kind":"file","allocated":True,"source_id":"source"}]
        out={"validation":v,"inventory":entries,"coverage":{"status":"substantial","filesystem_metadata":False,"allocated_files":False,"deleted_files":False,"unallocated_space":False,"memory_artifacts":source_type=="memory_dump","network_artifacts":False,"notes":[]}}
        if source_type=="memory_dump":
            fmt,reason=detect_memory(Path(self.evidence)); out["memory_dump"]={"format":fmt,"detection":reason,"size_bytes":st.st_size,"sha256":v["sha256"],"workflow":"header-and-profile-validation","profile_required":True,"structured_findings":"not_claimed"}; out["coverage"]["notes"].append("memory is represented as one opaque evidence artifact; no process/profile claims are made")
            if fmt in ("windows-etl", "windows-event-log"):
                out.pop("memory_dump")
                out["event_log"] = _event_log_result(Path(self.evidence), fmt, reason)
                out["coverage"]["memory_artifacts"] = False
                out["coverage"]["event_log_artifacts"] = True
                out["coverage"]["notes"][-1] = "event log routed to bounded timeline parsing; no memory findings are claimed"
        else:
            if v["detected_format"] == "ewf":
                out["ewf"] = ewf.inventory(self.evidence, max_total_bytes=self.max_total_bytes)
                out["tool"] = ewf.tool_info()
                out["partition_filesystem"] = {"image_format":"ewf","sector_size":512,"partitions":[]}
                out["coverage"]["notes"].append("EWF segment metadata is inventoried; filesystem inventory requires a readable libewf raw view")
            else:
                sector,parts=_partitions(Path(self.evidence)); out["partition_filesystem"]={"image_format":v["detected_format"],"sector_size":sector,"partitions":parts}
                out["coverage"]["filesystem_metadata"]=bool(parts); out["coverage"]["notes"].append("file inventory is limited to source/container bytes unless a filesystem reader is available")
        return out

    def extract(self, relative_paths: list[str], output_root: str | Path | None = None) -> dict[str,Any]:
        root=(Path(output_root) if output_root else self.root).resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        extracted=[]; errors=[]; total=0
        for rel in relative_paths:
            p=Path(rel)
            if p.is_absolute() or ".." in p.parts or not rel or rel in (".",): errors.append({"code":"PATH_TRAVERSAL_REJECTED","message":"extraction path must be a non-empty relative path","retryable":False,"path":rel}); continue
            if p.name != self.evidence.name or len(p.parts)!=1: errors.append({"code":"EXTRACTION_FAILED","message":"only the source artifact is extractable by this adapter","retryable":False,"path":rel}); continue
            if self.evidence.stat().st_size>self.max_file_bytes or total+self.evidence.stat().st_size>self.max_total_bytes: errors.append({"code":"FILE_LIMIT_EXCEEDED","message":"configured extraction limit exceeded","retryable":False,"path":rel}); continue
            dest=root/p.name
            if dest.exists(): errors.append({"code":"EXTRACTION_FAILED","message":"destination already exists","retryable":False,"path":rel}); continue
            tmp=Path(tempfile.mkstemp(prefix=".partial-",dir=root)[1]); os.chmod(tmp,0o600)
            try:
                shutil.copyfile(self.evidence,tmp); os.replace(tmp,dest); total+=dest.stat().st_size
                if not dest.resolve().is_relative_to(root): raise AdapterError("EXTRACTION_FAILED","output containment check failed")
                extracted.append({"path":str(dest),"size":dest.stat().st_size,"sha256":sha256(dest)})
            finally:
                if tmp.exists(): tmp.unlink()
        return {"root":str(root),"status":"completed" if not errors else ("partial" if extracted else "rejected"),"extracted":extracted,"errors":errors}

    def report(self, source_type: str) -> dict[str,Any]:
        inv=self.inventory(source_type)
        result={"source_type":source_type,"evidence_id":self.evidence_id,"validation":inv["validation"],"inventory_count":len(inv["inventory"]),"coverage":inv["coverage"],"partition_filesystem":inv.get("partition_filesystem"),"memory_dump":inv.get("memory_dump"),"event_log":inv.get("event_log"),"limitations":inv["coverage"]["notes"]}
        if source_type == "memory_dump":
            from ..memory_analysis import capability_report
            result["memory_capabilities"] = capability_report()
        return result

    def normalized_record(self, source_type: str) -> dict[str,Any]:
        inv=self.inventory(source_type); root=str(self.root)
        r={"schema_version":"1.0","evidence_id":self.evidence_id,"source_type":source_type,"original_uri":self.evidence.as_uri(),"archive_validation":{"kind":"none","status":"not_applicable"},"inventory":inv["inventory"],"safe_extraction":{"root":root,"status":"not_requested","policy_version":"safe-extraction-1","max_file_bytes":self.max_file_bytes,"max_total_bytes":self.max_total_bytes,"extracted_count":0,"rejected_count":0,"errors":[]},"collection_coverage":inv["coverage"],"adapter_metadata":{"validation":inv["validation"]}}
        if source_type=="disk_image":
            r["partition_filesystem"]=inv["partition_filesystem"]
            if "ewf" in inv:
                r["adapter_metadata"]["ewf"] = inv["ewf"]
                r["adapter_metadata"]["libewf"] = inv["tool"]
        else:
            if "event_log" in inv:
                r["adapter_metadata"]["event_log"] = inv["event_log"]
                r["source_type"] = "event_log"
            else: r["adapter_metadata"]["memory_dump"]=inv["memory_dump"]
        return r

def main():
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument("evidence"); ap.add_argument("--source-type",choices=["disk_image","memory_dump"],required=True); ap.add_argument("--staging-root",required=True); ap.add_argument("--extract",action="store_true")
    a=ap.parse_args(); ad=DiskMemoryAdapter(a.evidence,a.staging_root); record=ad.normalized_record(a.source_type)
    if a.extract: record["safe_extraction"]=ad.extract([ad.evidence.name])
    print(json.dumps(record,indent=2,sort_keys=True))
if __name__=="__main__": main()
