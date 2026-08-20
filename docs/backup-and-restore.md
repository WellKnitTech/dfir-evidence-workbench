# PostgreSQL Backup and Restore for DFIR Evidence Workbench

**Status**: prototype guidance. Production requires encrypted, offsite, tested, versioned backups + point-in-time recovery + retention policy.

## Principles (from security-defensibility-requirements.md)
- Append-only / immutable where possible for evidence metadata.
- Tenant isolation preserved in dumps (never mix tenants).
- Backups must not contain unredacted secrets; DB creds separate.
- Exercise restore regularly against synthetic data; retain verification artifacts.
- Original evidence bytes are NOT in the PG DB (only metadata, hashes, references); separate object/evidence storage has its own backup strategy.

## Dev / Local Stack (compose)

1. Ensure .env from .env.example (dev passwords only).
2. Start stack (localhost):
   ```bash
   podman compose up -d --build
   podman compose ps
   curl -s http://127.0.0.1:8080/readyz | jq
   ```
3. (Optional) Seed synthetic data via dev-only endpoint (tenant-scoped ingest envelope):
   ```bash
   # example synthetic envelope (use real interop schema in practice)
   curl -s -X POST http://127.0.0.1:8080/__dev__/synthetic/ingest-preview \
     -H 'content-type: application/json' \
     -d '{"source":{"system":"thehive","entity":"alert","id":"syn-001","scope":"case-xyz","revision":"1"},"payload":{"title":"synthetic test"}}' | jq
   ```
   Note: dev synthetic tenant from DFIRWB_SYNTHETIC_TENANT (non-UUID for demo; real tenants use UUIDs per schema).

4. Backup (from inside or host; prefer container for consistency):
   ```bash
   # Dump full DB (or per-tenant schema if multi-tenant isolation at DB level)
   podman exec -t dfir-postgres pg_dump -U dfir -d dfir_dev --no-owner --no-acl --clean --if-exists > backup-dev-$(date +%Y%m%d-%H%M%S).sql

   # Or compressed
   podman exec dfir-postgres pg_dump -U dfir -d dfir_dev -Fc > backup-dev.dump
   ```

5. Restore to fresh or test instance:
   ```bash
   # Example: restore to a new DB name on same or different container
   podman exec -i dfir-postgres psql -U dfir -d postgres -c "CREATE DATABASE dfir_restore OWNER dfir;"
   podman exec -i dfir-postgres pg_restore -U dfir -d dfir_restore --clean --if-exists < backup-dev.dump

   # Verify
   podman exec dfir-postgres psql -U dfir -d dfir_restore -c "\dt dfir.*"
   ```

6. Stop:
   ```bash
   podman compose down -v   # -v removes volumes (for clean test)
   ```

## Production notes
- Use managed PostgreSQL (Cloud SQL, Azure PG, Crunchy, etc.) with automated PITR, encryption, IAM auth.
- Logical backups (pg_dump) for schema+data portability; physical (pg_basebackup) for fast large restores.
- Encrypt dumps at rest (gpg, age, S3 SSE + bucket policy).
- Never restore prod dump into dev without redaction / tenant filtering.
- Test full restore + application smoke (health, ingest preview, queries under principal scope) in CI or quarterly.
- Retain backup manifests with: timestamp, DFIRWB git SHA, migration versions, image digests, synthetic fixture hashes, restore verification output.
- Separate strategy for evidence object storage (versioned buckets, WORM, cross-region replication).

### Scheduled logical backup artifact

This repository provides `tools/backup-postgres.sh` and the example
`ops/dfir-postgres-backup.service`/`.timer`. Install the units on a dedicated
backup host (or equivalent scheduler), create `/etc/dfir-workbench/backup.env`
with mode 0600, and set only secret-manager-provided values:

```ini
DFIRWB_DATABASE_URL=postgresql://backup-user@db.example/dfir
DFIRWB_BACKUP_DIR=/srv/dfir-backups
DFIRWB_BACKUP_RETENTION_DAYS=30
```

The script writes a custom-format dump and SHA-256 sidecar atomically, removes
expired dumps, and never prints the connection string. The destination must be
encrypted and off-host; a local directory alone is not a disaster-recovery
backup. Verify installation with `systemctl list-timers dfir-postgres-backup`
and perform a restore drill before treating the daily timer as an RPO.

## Exercise verification (synthetic data)
See below for commands run during this task's verification. Restore must succeed and data (envelopes, flags) must be queryable under correct tenant scope.

### Verification run (2026-08-07 during t_2e0301c2 hardening)
Stack launched with variable publish ports (API_PUBLISH/POSTGRES_PUBLISH) to coexist with host listeners; used .env.example derived config; hardened image (fixed build order for pip -e layout).

Seeded 1 envelope row (status=preview) + matching analyst (using generated UUIDs to satisfy FK; note synthetic-dev-org string tenant used only for non-pg seams).

```bash
# launch (with publish overrides for this env)
API_PUBLISH=127.0.0.1:18080 POSTGRES_PUBLISH=127.0.0.1:15432 \
  podman compose -f compose.yaml --env-file .env up -d --build

curl -s http://127.0.0.1:18080/healthz
curl -s http://127.0.0.1:18080/readyz | jq '.persistence, .principal.tenant_id'

# seed (psql + psycopg for controlled uuid tenant/analyst)
# ... 1 row insert ...

TS=...; podman exec -t dfir-postgres pg_dump -U dfir -d dfir_dev --no-owner --no-acl --clean --if-exists > /tmp/.../backup-$TS.sql
podman exec dfir-postgres pg_dump -U dfir -d dfir_dev -Fc > /tmp/.../backup-$TS.dump

podman exec dfir-postgres psql -U dfir -d postgres -c "DROP DATABASE IF EXISTS dfir_restore;"
podman exec dfir-postgres psql -U dfir -d postgres -c "CREATE DATABASE dfir_restore OWNER dfir;"
podman exec -i dfir-postgres pg_restore -U dfir -d dfir_restore --clean --if-exists < backup.dump

podman exec dfir-postgres psql -U dfir -d dfir_restore -c '\dt dfir.*'
podman exec dfir-postgres psql -U dfir -d dfir_restore -c "SELECT processing_status, count(*) FROM dfir.ingest_envelope GROUP BY processing_status;"
# preview | 1
```

Artifacts: 8k sql + 9k dump; restore recreated 3 tables + 1 data row under correct tenant scope. All under hardened container config.

See kanban task log for full trace.

## Limitations
- Current stack is single-tenant synthetic for dev; real multi-tenant backup/restore must preserve row-level tenant_id filters and analyst FKs.
- No WAL archiving / PITR in prototype compose.
- Evidence content lives outside PG; coordinate backup with evidence volume/object store snapshots.
