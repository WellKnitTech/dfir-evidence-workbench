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


def test_local_runner_fails_closed_and_gates_review(tmp_path: Path):
    runner = LocalRunner(tmp_path)
    fixture = runner.catalog()[0]["fixture_id"]
    job = runner.submit("tenant-a", fixture)
    stored = runner.jobs[job["job_id"]]
    stored.pop("tenant_id")
    try:
        runner.get("tenant-b", job["job_id"])
    except KeyError:
        pass
    else:
        raise AssertionError("missing tenant ownership must fail closed")
    stored["tenant_id"] = "tenant-a"
    stored["status"] = "error"
    try:
        runner.review("tenant-a", job["job_id"], "approve")
    except ValueError:
        pass
    else:
        raise AssertionError("review must require ready_for_review")


def test_local_runner_retry_updates_attempt_in_place(tmp_path: Path):
    runner = LocalRunner(tmp_path)
    fixture = runner.catalog()[0]["fixture_id"]
    job = runner.submit("tenant-a", fixture)
    runner.jobs[job["job_id"]]["status"] = "error"
    retried = runner.retry("tenant-a", job["job_id"])
    assert retried["job_id"] == job["job_id"]
    assert retried["attempt"] == 2
