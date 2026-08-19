# Observability and Incident Operations

Status: prototype operational runbook. Covers what is actually implemented in
this codebase today (structured audit events, Prometheus-text metrics,
readiness dependency checks, alert-rule evaluation) plus the incident
procedures and upgrade/rollback discipline built on top of it. Retention
periods and legal-hold mechanics are defined in the retention/backup policy
(t_349fa125); this document is the *operational* companion — what an on-call
operator does when something breaks.

## 1. Structured audit events

Every non-health HTTP request produces one append-only row in
`dfir.audit_event` (`migrations/0004_create_audit_events.sql`, `audit.py`),
carrying: `event_id`, `tenant_id`, `case_id`, `actor_type`/`actor_id`,
`object_type`/`object_id`, `action`, `result`, `correlation_id`, `source`,
`occurred_at`/`recorded_at`, `metadata`. The request middleware
(`api.py::_observability`) resolves the authenticated principal for every
request (respecting test overrides the same way FastAPI's own DI would) so
audit rows are tenant- and actor-attributed, not just a bare method/path log
line — this is what makes `/api/v1/audit-events` a *queryable* record, not a
grep target. Route handlers doing sensitive mutations may add their own
richer `audit.record(...)` calls with case/object detail.

**Fail-visible, never silent**: if the DB pool is unavailable, `audit.py`
logs the full event as structured JSON at WARNING (`audit_sink_unavailable`)
and increments `audit_write_failures_total` — it never drops the event with
no trace. Real WORM/object-lock storage (see
`audit-logging-and-safe-development-mode.md`, t_a6ee24b4) is the production
hardening step; this migration gives the prototype a queryable,
append-only-by-convention Postgres sink (no UPDATE/DELETE code path exists in
`AuditRepository`).

## 2. Metrics

`metrics.py` is a stdlib-only in-process registry exposed as Prometheus text
at `GET /metrics` (no auth — aggregate counters only, no tenant data).
Recorded series:
- `http_requests_total{path,method,status}` — every request, all statuses.
- `http_request_duration_seconds{path}` — latency histogram.
- `audit_write_failures_total` — incremented whenever the audit write itself
  fails (the fail-visible fallback above still logs the event; this counter
  is what should page someone).

Each app instance owns its own registry (correct for per-instance scraping,
e.g. Prometheus federation or a sidecar scraper per uvicorn worker); nothing
here aggregates across instances.

## 3. Health and readiness

- `GET /healthz` — liveness only, no dependency checks, always 200 if the
  process is up.
- `GET /readyz` — **actually probes the DB** with `SELECT 1` when
  `DFIRWB_DATABASE_URL` is configured (not just "was a pool object
  constructed"); returns HTTP 503 and `status: degraded` with
  `dependencies.database: unreachable` when the probe fails
  (`tests/test_observability.py::test_readyz_reports_degraded_when_db_unreachable`
  exercises this without a real outage).

The endpoint also checks the configured evidence filesystem with `statvfs`,
reports `storage: low_space` below `DFIRWB_STORAGE_MIN_FREE_BYTES`, and in
production verifies that issuer, audience, and a JWT verification key are
configured. It does not make a network call to the issuer (JWT validation is
per-request); upstream reachability remains an external monitor concern.

## 4. Alert rules

`alerts.py` implements the alert conditions as executable Python
(`evaluate_all()`, `firing_alerts()`) and exposes them at `GET /alerts` (no
auth, aggregate-only, excluded from audit logging like the other health
endpoints). Rules:

| Rule | Condition | Rationale |
|---|---|---|
| `audit_sink_degraded` | `audit_write_failures_total >= 1` | Any audit write failure means an event was only logged, not durably recorded — page immediately; see §6 evidence-tampering runbook. |
| `elevated_http_error_rate` | 5xx / total `http_requests_total` >= 5% | Generic service-health signal (DB down, auth outage, code regression). |

`tests/test_observability.py::test_alert_conditions_fire_on_synthetic_metric_state`
and `::test_alerts_endpoint_reports_firing_state_over_http` prove both rules
actually fire against synthetic metric state (reset → inject failure/error →
assert firing), satisfying the "alert conditions are tested" acceptance
criterion without standing up a real Alertmanager.

**Production wiring**: point Prometheus at `/metrics` and translate the same
two conditions into PromQL rules feeding Alertmanager, e.g.:

```yaml
- alert: AuditSinkDegraded
  expr: audit_write_failures_total > 0
  for: 0m
  labels: {severity: critical}
- alert: ElevatedHttpErrorRate
  expr: sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) >= 0.05
  for: 5m
  labels: {severity: warning}
```

`docs/grafana-observability-dashboard.json` is an importable starter dashboard
covering request rate, 5xx ratio, p95 latency, audit failures, and availability.

## 5. Log retention and redaction

- Application logs (uvicorn/structlog stdout) contain **no secrets**:
  `Settings` never logs `database_url`, `oidc_hs256_secret`, or
  `oidc_jwks_json` (all `repr=False` or excluded by construction); the JWT
  verifier (`api.py::_jwt_error`) never surfaces token contents or claims in
  error responses or logs.
- The `audit_sink_unavailable` fallback log line contains the *full* audit
  event as JSON, including `actor_id` and `metadata`. Treat process logs as
  in-scope for the same retention/redaction rules as the audit table itself
  when the fallback path has been exercised — this is the operational reason
  `audit_sink_degraded` is a critical alert, not a warning.
- Retention periods for logs (as a storage category) are governed by the
  retention/backup policy matrix (t_349fa125); this doc does not restate
  periods, only the mechanics of what ends up in a log line.
- No raw PII, emails, or object IDs are carried in `Principal` or JWT claim
  mapping (`api.py::_principal_from_claims`) — nothing to redact there by
  construction.

## 6. Incident runbook

Every entry: **detect** (what page/alert/symptom fires) → **triage** (first
commands) → **contain** → **recover** → **postmortem trigger**.

### 6.1 Database failure

- **Detect**: `/readyz` returns 503 (`dependencies.database: unreachable`);
  `ElevatedHttpErrorRate` alert fires as writes start failing.
- **Triage**: `curl -s $HOST/readyz | jq '.dependencies'`; check Postgres
  container/service health (`podman compose ps`, `podman logs dfir-postgres`
  in dev; managed-Postgres console in prod).
- **Contain**: the app does not crash on pool-open failure
  (`api.py::lifespan` swallows the exception and leaves `db_pool = None`);
  protected DB routes fail closed with 503 rather than serving stale/partial
  data. No action needed to "stop the bleeding" beyond confirming this
  fail-closed behavior is actually happening (check for 5xx on
  `/api/v1/*`, not 200s with empty data).
- **Recover**: restart/restore Postgres per `docs/backup-and-restore.md`;
  once reachable, `/readyz` self-heals on the next probe (no app restart
  required — the pool is long-lived and psycopg reconnects). Confirm with
  `GET /readyz` → `status: ready`.
- **Postmortem trigger**: any DB outage exceeding the RTO in §7.

### 6.2 Storage exhaustion

- **Detect**: `/readyz` returns 503 with `dependencies.storage: low_space` or
  `unreachable` when the configured evidence filesystem crosses its threshold;
  `ElevatedHttpErrorRate` may also fire as evidence/object writes start failing
  with disk-full errors. Host/volume monitoring remains the earlier signal and
  should be the primary trigger in practice.
- **Triage**: check the object-storage volume/bucket free space; check
  Postgres data volume free space separately (metadata vs. evidence bytes
  are different storage categories per `evidence-storage-layout.md`).
- **Contain**: evidence ingest write paths must fail closed (reject new
  writes with a clear 5xx) rather than partially write or silently truncate;
  this is a hard requirement even under storage pressure — never let an
  evidence write "succeed" with truncated bytes.
- **Recover**: expand the volume or provision additional storage per the
  storage layout's capacity plan; do not delete evidence/derivative objects
  under pressure — that is a legal-hold and chain-of-custody violation
  (retention/backup policy, t_349fa125). Log rotation/retention (per §5) is
  the only thing safe to prune under pressure.
- **Postmortem trigger**: any incident that caused a write rejection for a
  real (non-synthetic) tenant.

### 6.3 Auth outage (Entra ID / OIDC issuer unreachable)

- **Detect**: spike in 401s in `http_requests_total{status="401"}`;
  `ElevatedHttpErrorRate` alert fires once 401s cross the 5% threshold
  (401 counts toward "error" result in the audit middleware, and toward the
  5xx-only alert only if the app itself starts erroring — track 401 rate via
  `/metrics` directly as the earlier signal since the alert rule only covers
  5xx).
- **Triage**: confirm this is upstream (Entra/OIDC issuer) and not a local
  misconfiguration — check `oidc_issuer`/`oidc_audience`/JWKS reachability;
  the app never falls back to synthetic auth in `prod`
  (`get_current_principal` raises `authentication required` with no
  bearer token when `env == "prod"` — fail-closed by construction, not a
  toggle that can be silently flipped).
- **Contain**: nothing to contain server-side; the fail-closed behavior
  *is* the correct containment (no unauthenticated access is possible even
  during the outage).
- **Recover**: no app action required once the issuer/JWKS endpoint recovers
  — tokens are verified per-request, no cached "auth is down" state to
  reset.
- **Postmortem trigger**: any auth outage exceeding the RTO in §7, since it
  is a full read/write outage for real tenants even though it is not a data
  risk.

### 6.4 Suspected evidence tampering

This is the highest-severity runbook entry: a mismatch between an evidence
object's recorded hash and its current bytes, or an audit-chain gap,
indicates either a bug or an active integrity compromise. Treat as an
incident, not a data-quality ticket.

- **Detect**: hash-verification mismatch on an evidence object (chain-of-
  custody verification job, see `security-defensibility-requirements.md`);
  or `audit_sink_degraded` firing during a window when sensitive
  mutations occurred (a write could have happened without a corresponding
  audit row).
- **Triage**:
  1. Freeze: do not delete or "fix" the affected object or its metadata row.
     `AuditRepository` has no UPDATE/DELETE path by construction — the audit
     trail itself cannot be tampered with through the application, so any
     gap or mismatch must be explained by data or infrastructure, not an
     app-level cover-up path.
  2. Pull every audit row for the affected `object_id`/`case_id` via
     `GET /api/v1/audit-events?case_id=...` and compare against the object's
     version/manifest history.
  3. Identify the actor/correlation_id of the last known-good write and the
     first anomalous state.
- **Contain**: place the case/evidence item on legal hold immediately
  (retention/backup policy hold mechanism, t_349fa125) — hold state blocks
  deletion/disposition regardless of retention expiry — and revoke access
  for any principal implicated pending investigation (access-review control
  in `governance-privacy-retention-release-operations.md`).
- **Recover**: restore the affected object from the most recent verified
  backup per §7 RPO if bytes are confirmed corrupted/tampered; never restore
  over live evidence without a documented two-person approval
  (governance matrix, "Deletion / disposition approval" row) — a restore
  that overwrites evidence is itself a destructive action.
- **Postmortem trigger**: always. This class of incident requires a written
  postmortem, Security Owner sign-off, and an access-review cycle regardless
  of whether tampering is confirmed or the mismatch turns out to be benign
  (e.g. a legitimate versioned update misrecorded).

## 7. RPO / RTO

Aligned with the backup/restore mechanics in `docs/backup-and-restore.md`
and the schedule owned by the retention/backup policy (t_349fa125); no new
numbers are invented here beyond what those exercised procedures can
actually deliver in this prototype:

| Component | RPO | RTO | Basis |
|---|---|---|---|
| Postgres metadata (cases, evidence metadata, findings, audit events) | At most one scheduled interval after the timer is deployed and verified; until then, time since last manual dump | Time to provision a fresh Postgres instance + `pg_restore` + smoke test (`healthz`/`readyz`/one authenticated round trip) — exercised at ~minutes for the synthetic single-row dataset in `backup-and-restore.md`; scales with data volume | `backup-and-restore.md` §"Exercise verification" (real restore run, row count verified post-restore) |
| Evidence objects (raw bytes, derivatives) | Per object-storage provider's replication/versioning SLA (bucket versioning + cross-region replication per `evidence-storage-layout.md`); not exercised end-to-end in this repo yet | Time to fail over to replica/restore versioned object — not exercised end-to-end in this repo yet | `evidence-storage-layout.md` (design only, documented gap) |

The repository now includes `tools/backup-postgres.sh` plus a hardened
systemd service/timer in `ops/`. Operators must supply an encrypted/off-host
`DFIRWB_BACKUP_DIR` and inject `DFIRWB_DATABASE_URL` through
`/etc/dfir-workbench/backup.env`; the timer is a deployment artifact, not an
assumption that a developer checkout is protected. Verify the timer and run a
restore drill before claiming the one-day schedule as an RPO.

## 8. Upgrade and rollback

- **Upgrade**: migrations in `migrations/*.sql` apply in strict lexical
  order (`db.py::apply_migrations`) and are additive-only by convention (no
  migration in this repo drops or alters existing columns); `deploy` =
  apply new migrations, then roll the API image. `ensure_dev_schema_and_migrations`
  demonstrates the idempotent-probe pattern (checks `to_regclass` before
  applying) that a production migration runner should follow so a re-run
  after partial failure does not double-apply.
- **Rollback**: because migrations are additive-only, rolling back the
  **application** image to the previous version is safe without a DB
  rollback — old code does not depend on new columns being absent. Rolling
  back a **migration** itself is not automated (no `down` scripts exist);
  a schema rollback is a manual, reviewed SQL change following the same
  change-management control as any other schema change
  (`governance-privacy-retention-release-operations.md`, "Change
  management" row) — never an automated `migrate down`.
- **Verification gate**: no rollback or upgrade ships without the full test
  suite passing first (`python -m pytest -q`) and, for API/deployment
  changes, the compose config validating for every variant
  (`compose.yaml`, `compose.lan.yaml`, `compose.prod.yaml`) — see
  `docs/release-checklist.md` and `docs/release-readiness-report-api-deployment.md`
  for the exercised precedent.
- **Post-upgrade smoke test**: `GET /healthz` (200), `GET /readyz` (200,
  `status: ready`), one authenticated round trip
  (`POST /api/v1/cases` → `GET /api/v1/audit-events` shows the matching
  correlation ID) — exactly what
  `tests/test_observability.py::test_synthetic_http_requests_generate_queryable_audit_records`
  exercises, so the smoke test and the acceptance test are the same
  procedure by design.

## 9. Acceptance verification (this task)

Run from a clean checkout:

```bash
python -m pytest -q tests/test_observability.py
```

This exercises, end to end, against a disposable Postgres container:
- synthetic HTTP requests generating queryable, tenant/actor-attributed
  audit records (§1, §9 acceptance target 1)
- metrics emitted for the same requests (§2)
- alert conditions firing against synthetic metric state, both directly and
  over `GET /alerts` (§4, acceptance target 2)
- `/readyz` reporting `degraded`/503 when the DB is unreachable, without a
  real outage (§3)

The runbook scenarios in §6 (DB failure, storage exhaustion, auth outage,
suspected evidence tampering) are procedural — validated by the fail-closed
behaviors above being exercised by the automated tests, and by the linked
governance/retention controls being independently verified in their own
tasks (t_349fa125, `governance-privacy-retention-release-operations.md`).
