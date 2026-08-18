from pathlib import Path

from dfir_workbench.local_runner import LocalRunner


def test_local_runner_catalog_register_process_review_and_teardown(tmp_path: Path):
    runner = LocalRunner(tmp_path)
    catalog = runner.catalog()
    assert {row["class"] for row in catalog} == {"disk", "memory", "uac", "velociraptor", "artifacts"}
    fixture = next(row["fixture_id"] for row in catalog if row["class"] == "disk")
    registered = runner.register("tenant-a", fixture)
    job = runner.submit("tenant-a", fixture)
    assert registered["sha256"] == job["provenance"]["source_sha256"]
    assert job["status"] == "ready_for_review"
    assert job["result"]["source_unchanged"] is True
    approved = runner.review("tenant-a", job["job_id"], "approve")
    assert approved["status"] == "approved"
    assert runner.teardown("tenant-a")["status"] == "torn_down"
