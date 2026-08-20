import os

from fastapi.testclient import TestClient

os.environ.setdefault("DFIRWB_ENV", "test")
os.environ.setdefault("DFIRWB_SYNTHETIC_TENANT", "synthetic-test-tenant")

from dfir_workbench.api import app


def test_mxray_browser_safe_review_gate():
    client = TestClient(app)
    evidence = client.get("/__dev__/mxray/evidence")
    assert evidence.status_code == 200
    item = evidence.json()["items"][0]
    submitted = client.post("/__dev__/mxray/analyze", json={"evidence_id": item["evidence_id"]})
    assert submitted.status_code == 200
    job = submitted.json()
    assert job["status"] == "ready_for_review"
    assert "raw_message" not in str(job)
    assert "source_path" not in str(job)
    assert job["result"]["capabilities"] == ["message_metadata", "authentication", "routing", "attachments", "archives", "reports"]
    repeated = client.post("/__dev__/mxray/analyze", json={"evidence_id": item["evidence_id"]})
    assert repeated.status_code == 200
    assert repeated.json()["job_id"] == job["job_id"]
    approved = client.post(f"/__dev__/mxray/jobs/{job['job_id']}/review", json={"decision": "approve"})
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
