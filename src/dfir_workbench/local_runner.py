"""Dev-only local prototype runner over the real evidence workflows.

It is deliberately process-local and synthetic: it proves the browser/API seam
without pretending to be durable job orchestration or production evidence storage.
"""
from __future__ import annotations

import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

import json

from corpus.generate import GROUPS, build
from corpus.verify import load_and_verify_manifest
from .artifact_timeline import process_artifact
from .disk_workflow import run_disk_fixture
from .adapters.disk_memory_adapter import DiskMemoryAdapter


class LocalRunner:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or (Path(tempfile.gettempdir()) / "dfir-evidence-workbench-dev")).resolve()
        self.corpus_root = self.root / "corpus-v1"
        self.jobs: dict[str, dict[str, Any]] = {}
        self.registrations: dict[str, list[dict[str, Any]]] = {}

    def _ensure_corpus(self) -> Path:
        if not (self.corpus_root / "manifest.jsonl").is_file():
            build("corpus-v1", 41001, self.corpus_root)
        return self.corpus_root

    def catalog(self) -> list[dict[str, Any]]:
        root = self._ensure_corpus()
        rows = []
        all_rows = [json.loads(line) for line in (root / "manifest.jsonl").read_text(encoding="utf-8").splitlines() if line]
        for group in GROUPS:
            row = next(item for item in all_rows if item["class"] == group)
            rows.append({"fixture_id": row["fixture_id"], "class": row["class"], "scenario": row["scenario"], "format": row["format"], "synthetic": True})
        return rows

    def _manifest_row(self, fixture_id: str) -> dict[str, Any]:
        root = self._ensure_corpus()
        rows = [r for group in GROUPS for r in load_and_verify_manifest(fixture_id, root)]
        return rows[0]

    def register(self, tenant_id: str, fixture_id: str) -> dict[str, Any]:
        row = self._manifest_row(fixture_id)
        item = {"registration_id": "reg-" + uuid.uuid4().hex[:12], "fixture_id": fixture_id, "class": row["class"], "scenario": row["scenario"], "sha256": row["sha256"], "status": "registered", "synthetic": True}
        self.registrations.setdefault(tenant_id, []).append(item)
        return item

    def submit(self, tenant_id: str, fixture_id: str) -> dict[str, Any]:
        row = self._manifest_row(fixture_id)
        job_id = "job-" + uuid.uuid4().hex[:12]
        work = self.root / "tenants" / tenant_id / job_id
        source = self.corpus_root / row["relative_path"]
        work.mkdir(mode=0o700, parents=True, exist_ok=True)
        job = {"job_id": job_id, "tenant_id": tenant_id, "fixture_id": fixture_id, "status": "processing", "progress": 10, "attempt": 1, "synthetic": True, "provenance": {"tenant_id": tenant_id, "source_sha256": row["sha256"], "source_path": row["relative_path"], "manifest": str(self.corpus_root / "manifest.jsonl")}, "work_root": str(work)}
        self.jobs[job_id] = job
        try:
            if row["class"] == "disk":
                result = run_disk_fixture(source, work, extract=False)
            elif row["class"] == "memory":
                result = DiskMemoryAdapter(source, work).normalized_record("memory_dump")
                (work / "normalized-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            else:
                result = process_artifact(source)
                (work / "artifact-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            job.update({"status": "ready_for_review", "progress": 100, "result": result, "manifest_path": str(work / "evidence-manifest.json" if (work / "evidence-manifest.json").is_file() else work / "artifact-result.json")})
        except Exception as exc:
            job.update({"status": "error", "progress": 100, "error": {"code": type(exc).__name__, "message": str(exc), "retryable": True}})
        return self.public(job)

    def public(self, job: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in job.items() if k not in {"work_root", "tenant_id"}}

    def get(self, tenant_id: str, job_id: str) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if not job or job.get("tenant_id", tenant_id) != tenant_id:
            raise KeyError(job_id)
        return self.public(job)

    def review(self, tenant_id: str, job_id: str, decision: str) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if not job or job.get("tenant_id", tenant_id) != tenant_id:
            raise KeyError(job_id)
        if decision not in {"approve", "quarantine"}:
            raise ValueError("decision must be approve or quarantine")
        job["status"] = "approved" if decision == "approve" else "quarantined"
        job["review"] = {"decision": decision, "analyst": "trusted-principal"}
        return self.public(job)

    def retry(self, tenant_id: str, job_id: str) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if (
            not job
            or job.get("tenant_id") != tenant_id
            or job.get("status") not in {"error", "quarantined"}
        ):
            raise KeyError(job_id)
        job["attempt"] += 1
        return self.submit(tenant_id, job["fixture_id"])

    def teardown(self, tenant_id: str) -> dict[str, Any]:
        tenant_jobs = [
            job_id
            for job_id, job in self.jobs.items()
            if job.get("provenance", {}).get("tenant_id") == tenant_id
        ]
        count = len(tenant_jobs)
        shutil.rmtree(self.root / "tenants" / tenant_id, ignore_errors=True)
        self.registrations.pop(tenant_id, None)
        for job_id in tenant_jobs:
            self.jobs.pop(job_id, None)
        return {"status": "torn_down", "synthetic": True, "jobs_removed": count}


runner = LocalRunner()
