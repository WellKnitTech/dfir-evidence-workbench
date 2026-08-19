# Database lifecycle gate

Date: 2026-08-18
Status: NOT CLEARED for controlled beta
Scope: synthetic PostgreSQL metadata only; no client evidence or production credentials
Source checkout: `/var/home/jwellnitz/projects/dfir-evidence-workbench`
Source commit: `6a5e39982a5c06d435737657a332b941a34c979c`

## Runtime and artifact identity

- Host PostgreSQL container: `docker.io/library/postgres:15`
- Running server: PostgreSQL `15.18 (Debian 15.18-1.pgdg13+1)`
- Compose image digest in `compose.yaml`: `sha256:2c64f6d1be50ea37f722d27b936abc6557e5fb95c995514bd9c43490ef8160ef`
- Podman: `5.8.4`; Compose provider: Docker Compose `v5.1.4`
- Python test runtime reported by the host: `3.14.6` (project requires >=3.11)
- Migration SHA-256:
  - `0001_create_timeline_entry_flags.sql`: `182b62df1af2ad19134ded98f0656cd6f13cc99cf236ece12ac43f999b48e10e`
  - `0002_create_ingest_envelopes.sql`: `a60f9cf202353d9df93460e158700893231841bc40e0eef805db01b2d50285d4`
  - `0003_create_api_resources.sql`: `9370c32910c4f45d7aa1533333fe639da4815799b31a184a1eca8da717ef2e48`
  - `0004_create_audit_events.sql`: `388a24cfc894e45fdb690bb8ef21696c4aec6c0e8d558858a34258aa4259328c`
- `compose.yaml`: `8b926cba29ef9f33cb13843beb34ae73e7126fd4a6cb47fdcf7fa1bfe173dca6`
- `pyproject.toml`: `8dede24e1da4c6e1cdef73e673f1f489bbb166d8300a7eae959abebb971ea61a`

## Verification performed

All databases used names prefixed `dfir_qual_20260818` and contained synthetic rows only.

1. Clean install: created `dfir_qual_clean_20260818`, created the minimal `dfir` schema and `dfir.analyst` prerequisite, then applied all four migrations in lexical order with `psql -v ON_ERROR_STOP=1`. Result: PASS. Tables present: analyst, audit_event, case_record, evidence_metadata, finding, ingest_envelope, timeline_entry_flag.
2. Upgrade: created `dfir_qual_upgrade_20260818`, applied migrations 0001 through 0003, then applied 0004. Result: PASS; `dfir.audit_event` was created. The already-running `dfir_dev` instance had the older 0001-0003 shape and also lacked `audit_event`, confirming that an existing deployment needs an explicit upgrade step.
3. Migration failure recovery: in `dfir_qual_fail_20260818`, ran a transaction that created `dfir.migration_failure_probe`, then deliberately raised `division by zero`. PostgreSQL rolled back the transaction; `to_regclass('dfir.migration_failure_probe')` returned `absent`. Result: PASS for transactional rollback. Recovery was then demonstrated by successfully applying the valid migration set in the clean database.
4. Backup/restore: inserted one synthetic analyst, case, evidence metadata row, finding, timeline flag, ingest envelope, and audit event. `pg_dump -Fc` completed in `0.18s`; dump SHA-256 was `31238c46a8b7ecc79228b7baf5ac5c97596eb1d954ff6d2d2ce9fa20143f7135`. Restored to fresh `dfir_qual_restore_20260818` with `pg_restore --exit-on-error` in `0.30s`. All six metadata tables restored with count 1 and the case row retained tenant `11111111-1111-1111-1111-111111111111`.
5. Rollback/restore drill: the restored database was usable for readback after restore. A full application stop/start and traffic cutover were not measured, so the database-only timing is not an application RTO.
6. Baseline verification: `python3 -m pytest -q` -> `119 passed in 42.75s`; focused database/repository tests -> `5 passed, 28 deselected in 17.17s`; observability/PostgreSQL tests -> `7 passed in 12.12s`; `python3 -m compileall -q src tests` -> PASS; `git diff --check` -> PASS; `podman compose -f compose.yaml config -q` -> PASS with an expected warning that `DFIRWB_DATABASE_URL` was unset in this synthetic config check.

## Compatibility and policy findings

- Forward compatibility from the current 0001-0003 shape to 0004 was demonstrated.
- Backward compatibility was not demonstrated. There are no down migrations, and the application does not advertise a tested downgrade path. Treat migration rollback as restore/redeploy, not SQL reversal.
- `apply_migrations()` executes every `*.sql` file and has no migration ledger; rerunning it against an already migrated database will fail on migrations that lack `IF NOT EXISTS` (notably 0001, 0002, and 0004). `ensure_dev_schema_and_migrations()` uses table probes for the dev path, but this is not a general production migration mechanism.
- The composite foreign key from timeline flags and ingest envelopes to `(tenant_id, analyst_id)` is enforced. An attempted flag insert with a tenant different from the analyst failed with `timeline_entry_flag_analyst_fk`.
- `case_record`, `evidence_metadata`, and `finding` only carry an application-level `case_id`; no database foreign key links them. A synthetic evidence row referencing `case-does-not-exist` inserted successfully. Deleting the case left the evidence row in place. This is a referential-integrity and tenant/case lifecycle gap, not a passing policy result.
- No retention table, retention job, legal-hold column, disposition record, or database deletion policy exists in the migrations. The audit table is append-only by repository convention only; the database role is not constrained from deleting rows. Retention/deletion behavior is therefore NOT ESTABLISHED and must not be represented as implemented.
- PostgreSQL dumps contain metadata only. Evidence bytes and object storage are outside this backup and require a separately tested, tenant/case-scoped backup and restore drill.

## RPO/RTO and downtime

- Measured database dump time: `0.18s` for the synthetic dataset.
- Measured database restore time: `0.30s` for the synthetic dataset.
- Database-only restore RTO observed: `0.30s`; application restart, connection-pool recovery, health checks, and traffic cutover were not included.
- RPO is not a measured service guarantee. The prototype has no WAL archiving/PITR or automated backup schedule. With logical dumps, the maximum loss is the interval since the last verified dump; that interval is currently unspecified.
- Known downtime: a restore/redeploy requires taking the application/database target out of service for the restore and cutover. The duration is unknown beyond the database-only `0.30s` measurement.

## Gate decision

NOT CLEARED. The migration and synthetic metadata backup mechanics pass the limited checks above, but controlled-beta qualification remains blocked by: no durable migration ledger or tested backward/rollback path; absent case foreign keys and retention/legal-hold/disposition enforcement; unmeasured application-level RTO and unspecified RPO; no WAL/PITR or automated backup schedule; and no separately verified evidence-object-store restore.

Required before approval: add a production-safe migration ledger/runner with explicit compatibility policy; define and test case/tenant foreign-key and deletion/hold semantics; implement or explicitly gate retention/disposition controls; establish encrypted scheduled backups plus WAL/PITR or document an accepted RPO; and run an end-to-end restore including evidence storage, API startup, readiness, authorization, and synthetic case readback.
