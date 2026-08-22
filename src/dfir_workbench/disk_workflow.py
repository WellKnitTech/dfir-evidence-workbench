"""Small, evidence-safe disk-image workflow used by the prototype tests."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .adapters.disk_memory_adapter import DiskMemoryAdapter
from .staging import EvidenceStager
from .tsk_workflow import run_tsk_raw_image


def run_disk_fixture(source: str | Path, analysis_root: str | Path, *, extract: bool = False) -> dict[str, Any]:
    """Stage, inspect, and optionally extract one disk image without mounting it."""
    source = Path(source).expanduser().resolve()
    analysis_root = Path(analysis_root).expanduser().resolve()
    adapter_record: dict[str, Any] = {}

    def process(staged: Path) -> dict[str, Any]:
        adapter_record.update(DiskMemoryAdapter(staged, analysis_root).normalized_record("disk_image"))
        return adapter_record

    run = EvidenceStager(source, analysis_root).run(process)
    record = dict(adapter_record)
    # The staged copy is the processing input; preserve the acquisition identifier.
    record["original_uri"] = source.as_uri()
    extraction: dict[str, Any] | None = None
    if extract:
        staged_path = Path(run["manifest"]["staged_path"])
        extraction = DiskMemoryAdapter(staged_path, analysis_root).extract(
            [staged_path.name], analysis_root / "extracted"
        )
        safe = dict(record["safe_extraction"])
        safe.update(
            extracted_count=len(extraction["extracted"]),
            rejected_count=len(extraction["errors"]),
            status=extraction["status"],
            errors=extraction["errors"],
        )
        record["safe_extraction"] = safe
    (analysis_root / "normalized-evidence.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "analysis_root": str(analysis_root),
        "source_unchanged": run["manifest"]["verification"]["source_unchanged"],
        "record": record,
        "extraction": extraction,
    }


def run_tsk_fixture(source: str | Path, analysis_root: str | Path, *, partition_index: int | None = None) -> dict[str, Any]:
    """Run the optional native Sleuth Kit path; missing tools are explicit."""
    return run_tsk_raw_image(source, analysis_root, partition_index=partition_index)
