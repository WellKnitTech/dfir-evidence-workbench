# API and deployment acceptance gate

Status: CONDITIONAL PASS for the durable repository/deployment slice; NOT production ready.

Verification timestamp: 2026-08-07 (host-local run; exact command output recorded in task run)
Repository: `/var/home/jwellnitz/projects/dfir-evidence-workbench`
Scope: isolated localhost Podman Compose deployment, FastAPI health/auth seam, synthetic tenant-scoped mutation, and PostgreSQL-backed repository tests. No real evidence, credentials, vendor deployment, or public exposure used.

## Commands and results

All commands ran from the repository root.

- `.venv/bin/python -m pytest -q` — PASS, 69 passed in 27.92s.
- `python -m compileall -q src tests` — PASS.
- `git diff --check` — PASS.
- `podman compose -f compose.yaml config --quiet` — PASS (warning only when the required database URL was intentionally unset during config inspection).
- `podman compose -f compose.lan.yaml config --quiet` — PASS (same intentional unset-variable warning).
- `podman compose -f compose.prod.yaml config --quiet` — PASS.
- Isolated runtime command: `API_PUBLISH=127.0.0.1:18080 POSTGRES_PUBLISH=127.0.0.1:15432 DFIRWB_DATABASE_URL=... podman compose -p dfir-acceptance -f compose.yaml up -d --build` — PASS. Image built, PostgreSQL became healthy, API started, and both services were reachable on the requested localhost bindings.
- Host network inspection: active interface `wlp2s0` at `10.254.0.158/24`; firewalld active in zone `FedoraWorkstation`. Existing policy exposes `1025-65535/tcp` and `1025-65535/udp` broadly; this gate made no firewall changes and did not expose the acceptance stack on LAN.

## Live endpoint checks

- `GET /healthz` — HTTP 200, deterministic healthy response.
- `GET /readyz` — HTTP 200; config, adapter wiring, ingest boundary, psycopg, and persistence reported wired.
- `GET /api/v1/whoami` without a scope — HTTP 403 with generic structured error (`insufficient scope`). This confirms the protected endpoint is not anonymously usable in the dev container, although the container uses synthetic context by default.
- `GET /__dev__/principal` — HTTP 200, explicitly marked synthetic.
- `GET /__dev__/synthetic/whoami` — HTTP 200, tenant/analyst taken from the server-side synthetic principal.
- `POST /__dev__/synthetic/ingest-preview` with a synthetic payload — HTTP 200; SHA-256 and deterministic idempotency key returned.
- The same preview with `api_key` — HTTP 400; secret-bearing field rejected before serialization.
- `POST /__dev__/synthetic/cases` with body `tenant_id=attacker-supplied` — HTTP 200; persisted response scope remained `synthetic-dev-org`, demonstrating body tenant is ignored.
- `GET /api/v1/flags`, `/api/v1/ingest/preview`, `/api/v1/ingest/approve`, `/api/v1/ingest/commit` — HTTP 404. These routes are not yet exposed by the live API surface.

The route inventory contains health, whoami, and explicitly dev-only synthetic routes; it does not contain public analyst-flag or ingest lifecycle routes.

## PostgreSQL evidence

The running API created the `dfir` schema and tables `analyst`, `ingest_envelope`, and `timeline_entry_flag` in PostgreSQL. Direct query after startup showed zero rows in both durable work tables, as expected because the live API has no public flag/ingest mutation routes. The repository-level disposable PostgreSQL tests passed the durable preview -> approve -> apply-commit flow, duplicate handling, conflict/key-reuse behavior, quarantine states, and tenant isolation.

## Coverage gaps and blockers

1. HIGH / release blocker: live API route surface is incomplete. Analyst flagging and ingest preview/approval/commit/idempotency/rejection/quarantine are implemented at repository/domain seams and tested directly, but are not reachable through authenticated HTTP endpoints. Add route DTOs, principal dependencies, status-preserving errors, and end-to-end HTTP tests before calling the API slice complete.
2. HIGH / production blocker: the Compose dev stack intentionally enables synthetic principal context and dev-only routes. Production requires real Entra/OIDC validation, tenant directory mapping, scope/role policy, and a prod-specific deployment with dev routes absent.
3. HIGH / production blocker: default Compose is plain HTTP and localhost development configuration. Production requires TLS termination, hardened secret injection, network policy, backups/restore drills, monitoring, and an operational deployment target.
4. MEDIUM: live API authentication was not exercised with a real Entra/JWKS issuer. Deterministic JWT validation fixtures are covered by tests; external key rotation, issuer availability, clock skew, and directory authorization remain unverified.
5. MEDIUM: no live TheHive or DFIR-IRIS installation was exercised; current adapters are synthetic projection/intake boundaries, not vendor transport compatibility evidence.
6. MEDIUM: the active firewall has a broad pre-existing high-port allow range. This gate did not alter it; a production deployment must narrow ingress to the intended service ports.

## Gate conclusion

The repository, migrations, container build, health checks, synthetic tenant boundary, and durable repository workflows pass independent verification. The deployment is acceptable as a localhost synthetic development acceptance artifact only. It is not production ready, and the missing authenticated HTTP mutation routes are the concrete next implementation gate.
