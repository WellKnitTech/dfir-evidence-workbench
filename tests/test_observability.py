"""Observability and audit sink acceptance tests (t_97aa7f13).

Verifies:
- audit events are durably written and queryable via the repository and the
  authenticated /api/v1/audit-events route (synthetic requests -> queryable records)
- audit sink degrades to structured logging (never silently drops) when no pool
- readyz reports degraded/503 when configured DB is unreachable (dependency check)
- metrics/audit are emitted end-to-end for real HTTP requests through the app
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from dfir_workbench.api import Principal, Settings, app, get_current_principal
from dfir_workbench.audit import AuditRepository
from dfir_workbench.db import apply_migrations, disposable_postgres, setup_clean_test_schema, temp_async_pool
from dfir_workbench import alerts, metrics


@pytest.mark.asyncio
async def test_audit_repository_records_and_queries_are_tenant_scoped():
    async with disposable_postgres() as db_url:
        async with temp_async_pool(db_url) as pool:
            await setup_clean_test_schema(pool)
            await apply_migrations(pool)
            repo = AuditRepository(pool)
            tid = "aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
            other_tid = "bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb"
            corr = str(uuid.uuid4())

            event = await repo.record(
                action="case.create",
                result="success",
                correlation_id=corr,
                actor_type="user",
                actor_id="analyst-1",
                tenant_id=tid,
                case_id="case-1",
                object_type="case",
                object_id="case-1",
                metadata={"title": "synthetic case"},
            )
            assert event.recorded_at is not None

            result = await repo.query(tenant_id=tid)
            assert result["count"] == 1
            assert result["items"][0]["action"] == "case.create"
            assert result["items"][0]["correlation_id"] == corr

            # foreign tenant sees nothing (no cross-tenant leak)
            foreign = await repo.query(tenant_id=other_tid)
            assert foreign["count"] == 0


@pytest.mark.asyncio
async def test_audit_repository_rejects_invalid_enum_values():
    repo = AuditRepository(pool=None)
    with pytest.raises(ValueError):
        await repo.record(action="x", result="not-a-real-result", correlation_id="c1")
    with pytest.raises(ValueError):
        await repo.record(action="x", result="success", correlation_id="c1", actor_type="not-a-real-actor")


@pytest.mark.asyncio
async def test_audit_repository_degrades_to_logging_without_pool(caplog):
    import logging

    repo = AuditRepository(pool=None)
    with caplog.at_level(logging.WARNING, logger="dfir_workbench.audit"):
        event = await repo.record(action="evidence.access", result="success", correlation_id="c2")
    assert event.recorded_at is None
    assert any("audit_sink_unavailable" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_synthetic_http_requests_generate_queryable_audit_records():
    """Acceptance: synthetic requests generate queryable audit records and metrics."""
    async with disposable_postgres() as db_url:
        async with temp_async_pool(db_url) as pool:
            await setup_clean_test_schema(pool)
            await apply_migrations(pool)
            tid = "cccccccc-3333-3333-3333-cccccccccccc"
            aid = "dddddddd-4444-4444-4444-dddddddddddd"
            from dfir_workbench.db import ensure_test_analyst

            p = Principal(tenant_id=tid, analyst_id=aid, is_synthetic=True, scopes=frozenset({"cases:read", "cases:write"}))
            await ensure_test_analyst(pool, p)

            app.state.db_pool = pool
            app.dependency_overrides[get_current_principal] = lambda: p
            try:
                client = TestClient(app)
                resp = client.post("/api/v1/cases", json={"title": "synthetic audit case"})
                assert resp.status_code == 200
                corr = resp.headers.get("x-correlation-id")
                assert corr

                audit_resp = client.get("/api/v1/audit-events")
                assert audit_resp.status_code == 200
                items = audit_resp.json()["items"]
                match = next((i for i in items if i["correlation_id"] == corr and i["action"] == "http.post"), None)
                assert match is not None
                # Acceptance: audit records carry actor + tenant + object + provenance, not just a bare HTTP log line.
                assert match["actor_id"] == aid
                assert match["actor_type"] == "user"

                metrics_resp = client.get("/metrics")
                assert 'path="/api/v1/cases"' in metrics_resp.text
            finally:
                app.dependency_overrides.clear()
                app.state.db_pool = None


def test_readyz_reports_degraded_when_db_unreachable():
    """Acceptance: readiness/dependency checks actually probe the DB, not just pool presence."""
    from unittest.mock import AsyncMock, MagicMock

    bad_pool = MagicMock()
    bad_conn_cm = MagicMock()
    bad_conn_cm.__aenter__ = AsyncMock(side_effect=RuntimeError("connection refused"))
    bad_conn_cm.__aexit__ = AsyncMock(return_value=False)
    bad_pool.connection = MagicMock(return_value=bad_conn_cm)

    prev_pool = getattr(app.state, "db_pool", None)
    prev_db_url = Settings.model_fields["database_url"].default
    from dfir_workbench import api as api_mod

    original_settings = api_mod.settings
    try:
        api_mod.settings = Settings(env="test", database_url="postgresql://u:p@localhost/db")
        app.state.db_pool = bad_pool
        client = TestClient(app)
        resp = client.get("/readyz")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "degraded"
        assert body["dependencies"]["database"] == "unreachable"
    finally:
        api_mod.settings = original_settings
        app.state.db_pool = prev_pool


def test_alert_conditions_fire_on_synthetic_metric_state():
    """Acceptance: alert conditions are tested (not just declared as prose in the runbook)."""
    metrics.reset()
    try:
        # Neither rule fires with a clean slate.
        assert alerts.firing_alerts() == []

        # Audit sink degraded: at least one write failure recorded.
        metrics.inc_counter("audit_write_failures_total")
        firing_names = {r.name for r in alerts.firing_alerts()}
        assert "audit_sink_degraded" in firing_names

        # Elevated error rate: >=5% of requests are 5xx.
        metrics.reset()
        for _ in range(19):
            metrics.inc_counter("http_requests_total", {"path": "/api/v1/cases", "method": "GET", "status": "200"})
        metrics.inc_counter("http_requests_total", {"path": "/api/v1/cases", "method": "GET", "status": "500"})
        firing_names = {r.name for r in alerts.firing_alerts()}
        assert "elevated_http_error_rate" in firing_names
    finally:
        metrics.reset()


def test_alerts_endpoint_reports_firing_state_over_http():
    metrics.reset()
    try:
        client = TestClient(app)
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert resp.json()["any_firing"] is False

        metrics.inc_counter("audit_write_failures_total")
        resp = client.get("/alerts")
        body = resp.json()
        assert body["any_firing"] is True
        assert any(a["name"] == "audit_sink_degraded" and a["firing"] for a in body["alerts"])
    finally:
        metrics.reset()
