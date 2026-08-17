# Authenticated HTTP API and PostgreSQL round-trip gate

Status: CONDITIONAL PASS for the synthetic localhost development stack; not production ready.

Verification date: 2026-08-08
Repository: `/var/home/jwellnitz/projects/dfir-evidence-workbench`

## Implemented HTTP surface

All routes below use the trusted `Principal` dependency and PostgreSQL pool. Tenant scope is taken from the principal, never from request body/query values.

- `POST /api/v1/ingest/preview`
- `POST /api/v1/ingest/{envelope_id}/approve`
- `POST /api/v1/ingest/{envelope_id}/commit`
- `POST /api/v1/ingest/{envelope_id}/quarantine`
- `POST|GET /api/v1/timeline/flags`
- `POST|GET /api/v1/cases`
- `POST|GET /api/v1/evidence` (metadata only; bytes rejected)
- `POST|GET /api/v1/findings`

Resource list routes support `limit`, `offset`, `q`, and case filtering where applicable. JSON request bodies over 1 MiB return structured HTTP 413 errors.

## Exact verification commands and results

Run from the repository root:

- `.venv/bin/python -m pytest -q` — PASS, 69 passed in 27.90s.
- `.venv/bin/python -m compileall -q src tests` — PASS.
- `git diff --check` — PASS.
- `podman compose -f compose.yaml config --quiet` — PASS (intentional warning when `DFIRWB_DATABASE_URL` is unset for config inspection).
- `podman compose -f compose.lan.yaml config --quiet` — PASS.
- `podman compose -f compose.prod.yaml config --quiet` — PASS.
- Clean isolated stack: `API_PUBLISH=127.0.0.1:18081 POSTGRES_PUBLISH=127.0.0.1:15433 DFIRWB_SYNTHETIC_TENANT=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa DFIRWB_DATABASE_URL='postgresql://dfir:***@postgres:5432/dfir_dev' podman compose -p dfir-http-gate -f compose.yaml up -d --build` — PASS. Image built, PostgreSQL became healthy, API started, migrations bootstrapped, and the API was reachable only on localhost.

## Live HTTP and persistence evidence

- `GET /healthz` — HTTP 200.
- `GET /readyz` — HTTP 200; persistence and ingest reported wired.
- `POST /api/v1/cases` then `GET /api/v1/cases?limit=1&q=live` — HTTP 200; row persisted and returned with count/limit/offset.
- `POST /api/v1/evidence` — HTTP 200; metadata row persisted with `content_transferred:false`.
- `POST /api/v1/findings` then filtered `GET /api/v1/findings?case_id=...` — HTTP 200; filtered row returned.
- Oversized case body (~1.1 MiB) — HTTP 413 with `{error:{code:"REQUEST_TOO_LARGE",...}}`.
- `POST /api/v1/ingest/preview` using `tests/fixtures/thehive/alert_minimal.json` — HTTP 200, `accepted:1`, `status:preview`, SHA-256 and deterministic idempotency key returned.
- `POST /api/v1/ingest/{id}/approve` — HTTP 200, `processing_status:approved`.
- `POST /api/v1/ingest/{id}/commit` — HTTP 200, `processing_status:applied`, target ID persisted.
- Repeated preview — HTTP 200 and existing applied envelope returned idempotently.
- `POST /api/v1/timeline/flags` then `GET /api/v1/timeline/flags?timeline_entry_id=...` — HTTP 200; PostgreSQL-backed flag returned.
- Direct PostgreSQL query confirmed the synthetic analyst row and all six `dfir` tables (`analyst`, `ingest_envelope`, `timeline_entry_flag`, `case_record`, `evidence_metadata`, `finding`).

The stack was stopped with the project Compose cleanup command after verification; unrelated containers were not touched.

## Remaining release blockers

1. This gate uses a synthetic dev principal and a local PostgreSQL stack. Production still requires real Entra/OIDC/JWKS validation, directory-backed tenant mapping, role policy, and dev routes disabled.
2. Resource tables are intentionally metadata-only JSONB prototypes. Production requires reviewed domain schemas, audit/event retention, foreign-key policy to the project case schema, and operational migrations.
3. The API is plain HTTP localhost development configuration. Production requires TLS termination, external secret injection, network policy, monitoring, backups/restore drills, and narrowed ingress.
4. No live TheHive or DFIR-IRIS installation was exercised; the current integration remains projection/intake compatibility, not vendor transport certification.
5. Evidence content transfer is deliberately rejected. Originals must remain read-only and be handled by a separately reviewed acquisition/object-storage boundary.

Conclusion: the requested authenticated HTTP-to-PostgreSQL prototype slice is reachable and independently exercised end-to-end with synthetic data. It is suitable for the next security/review gate, not for client evidence or production deployment.
