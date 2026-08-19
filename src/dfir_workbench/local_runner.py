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
        work.mkdir(mode=0o700, parents=True, exist_ok=True)
        job = {"job_id": job_id, "tenant_id": tenant_id, "fixture_id": fixture_id, "status": "processing", "progress": 10, "attempt": 1, "synthetic": True, "provenance": {"tenant_id": tenant_id, "source_sha256": row["sha256"], "source_path": row["relative_path"], "manifest": str(self.corpus_root / "manifest.jsonl")}, "work_root": str(work)}
        self.jobs[job_id] = job
        self._run_job(job, row)
        return self.public(job)

    def _run_job(self, job: dict[str, Any], row: dict[str, Any]) -> None:
        source = self.corpus_root / row["relative_path"]
        work = Path(job["work_root"])
        try:
            if row["class"] == "disk":
                result = run_disk_fixture(source, work, extract=False)
                manifest_path = work / "evidence-manifest.json"
            else:
                from .staging import EvidenceStager

                def process(staged: Path) -> dict[str, Any]:
                    if row["class"] == "memory":
                        result = DiskMemoryAdapter(staged, work).normalized_record("memory_dump")
                        (work / "normalized-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                        return result
                    result = process_artifact(staged)
                    (work / "artifact-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    return result

                staged = EvidenceStager(source, work / "staging").run(process)
                result = staged["result"]
                manifest_path = work / "staging" / "evidence-manifest.json"
            job.update({"status": "ready_for_review", "progress": 100, "result": result, "manifest_path": str(manifest_path)})
        except Exception as exc:
            job.update({"status": "error", "progress": 100, "error": {"code": type(exc).__name__, "message": str(exc), "retryable": True}})

    def public(self, job: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in job.items() if k not in {"work_root", "tenant_id"}}

    def get(self, tenant_id: str, job_id: str) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if not job or job.get("tenant_id") != tenant_id:
            raise KeyError(job_id)
        return self.public(job)

    def review(self, tenant_id: str, job_id: str, decision: str) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if not job or job.get("tenant_id") != tenant_id:
            raise KeyError(job_id)
        if decision not in {"approve", "quarantine"}:
            raise ValueError("decision must be approve or quarantine")
        if job.get("status") != "ready_for_review":
            raise ValueError("job is not ready for review")
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
        row = self._manifest_row(job["fixture_id"])
        shutil.rmtree(job["work_root"], ignore_errors=True)
        Path(job["work_root"]).mkdir(mode=0o700, parents=True, exist_ok=True)
        job.pop("result", None)
        job.pop("error", None)
        job.pop("review", None)
        job.update({"status": "processing", "progress": 10})
        self._run_job(job, row)
        return self.public(job)

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
