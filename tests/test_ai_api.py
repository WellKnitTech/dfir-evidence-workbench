import os

from fastapi.testclient import TestClient

os.environ.setdefault("DFIRWB_ENV", "test")
os.environ.setdefault("DFIRWB_SYNTHETIC_TENANT", "synthetic-test-tenant")
os.environ.setdefault("DFIRWB_AI_ENABLED", "true")

from dfir_workbench.api import app


def test_ask_ai_redacts_context_and_requires_explicit_approval():
    client = TestClient(app)
    response = client.post("/api/v1/ai/requests", json={
        "case_id": "case-demo",
        "question": "Summarize this metadata",
        "selection": {
            "resource_class": "artifact", "resource_id": "artifact-1",
            "tenant_id": "synthetic-test-tenant", "case_id": "case-demo",
            "data": {"id": "artifact-1", "case_id": "case-demo", "description": "synthetic", "path": "/secret/file"},
        },
    })
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["provider"] == "local-mock"
    assert body["approval"] is None
    assert "path" not in body["context_manifest"]["included_fields"]
    request_id = body["request_id"]
    assert client.post(f"/api/v1/ai/requests/{request_id}/approve", json={"target": "report"}).status_code == 200
    assert client.get(f"/api/v1/ai/requests/{request_id}").json()["approval"]["target"] == "report"


def test_ask_ai_denies_cross_tenant_selection():
    client = TestClient(app)
    response = client.post("/api/v1/ai/requests", json={
        "case_id": "case-demo", "question": "x",
        "selection": {"resource_class": "artifact", "resource_id": "artifact-1", "tenant_id": "other-tenant", "case_id": "case-demo", "data": {}},
    })
    assert response.status_code == 400


def test_ask_ai_requires_case_scope():
    client = TestClient(app)
    response = client.post("/api/v1/ai/requests", json={
        "question": "x",
        "selection": {"resource_class": "artifact", "resource_id": "artifact-1"},
    })
    assert response.status_code == 400


def test_ask_ai_uses_server_resource_not_client_data():
    client = TestClient(app)
    response = client.post("/api/v1/ai/requests", json={
        "case_id": "case-demo", "question": "x",
        "selection": {
            "resource_class": "artifact", "resource_id": "artifact-1",
            "tenant_id": "synthetic-test-tenant", "case_id": "case-demo",
            "data": {"description": "forged client content"},
        },
    })
    assert response.status_code == 200
    assert "forged client content" not in response.json()["answer"]


def test_ask_ai_is_disabled_by_default(monkeypatch):
    from dfir_workbench import api

    monkeypatch.setattr(api.settings, "ai_enabled", False)
    client = TestClient(app)
    response = client.post("/api/v1/ai/requests", json={"case_id": "case-demo", "question": "x", "selection": {"resource_class": "artifact", "resource_id": "artifact-1"}})
    assert response.status_code == 503


def test_ask_ai_rate_limits_each_analyst_after_twenty_requests():
    from dfir_workbench import api

    api._ai_rate_state.clear()
    client = TestClient(app)
    payload = {
        "case_id": "case-demo", "question": "x",
        "selection": {"resource_class": "artifact", "resource_id": "artifact-1"},
    }
    responses = [client.post("/api/v1/ai/requests", json=payload) for _ in range(21)]
    assert [response.status_code for response in responses[:20]] == [200] * 20
    assert responses[20].status_code == 429
    assert responses[20].json()["error"]["retryable"] is True
    api._ai_rate_state.clear()


def test_ai_routes_fail_closed_when_disabled(monkeypatch):
    from dfir_workbench import api

    client = TestClient(app)
    response = client.post("/api/v1/ai/requests", json={
        "case_id": "case-demo", "question": "x",
        "selection": {"resource_class": "artifact", "resource_id": "artifact-1"},
    })
    request_id = response.json()["request_id"]
    monkeypatch.setattr(api.settings, "ai_enabled", False)
    assert client.get(f"/api/v1/ai/requests/{request_id}").status_code == 503
    assert client.post(f"/api/v1/ai/requests/{request_id}/approve", json={"target": "report"}).status_code == 503


def test_ai_context_denials_are_not_retryable():
    client = TestClient(app)
    response = client.post("/api/v1/ai/requests", json={
        "case_id": "case-demo", "question": "x",
        "selection": {"resource_class": "artifact", "resource_id": "unknown"},
    })
    assert response.status_code == 400
    assert response.json()["error"]["retryable"] is False
