# Storage boundary qualification

Status: **FAIL / remediation required for production**

Scope reviewed: the clean post-merge baseline at `aec70c7`, plus the filesystem evidence boundary in `src/dfir_workbench/evidence_store.py`.

## What is qualified

The current adapter is a useful local, evidence-safe boundary, not a production object-storage implementation:

| Control | Result | Evidence |
|---|---|---|
| Tenant prefix and cross-tenant denial | PASS (local adapter) | `tenants/<trusted principal tenant>/...`; `tests/test_evidence_store_boundary.py::test_tenant_prefix_denies_cross_tenant_lookup` |
| Case/evidence path containment | PASS (local adapter) | Strict slug validation and resolved containment; traversal test |
| Source hash preservation | PASS (local adapter) | Quarantine SHA-256 is rechecked before promotion and written to manifest |
| Immutable original | PASS against ordinary process writes | Original is read-only, evidence directory is locked, conflicts are rejected; immutability test |
| Retention/legal hold/delete controls | PASS (local adapter) | Delete fails while retention is active or legal hold is set |
| Upload/storage exhaustion | PASS for configured pre-admission byte limit | Oversized source is rejected before quarantine admission |
| Custody records | PARTIAL | Quarantine metadata and manifests exist; no append-only custody/audit chain is coupled to storage mutations |
| Durable object storage | FAIL | Adapter is local filesystem only; no S3-compatible backend, object versioning, object lock, replication, or provider-side authorization |
| Encryption at rest/in transit and KMS | NOT ESTABLISHED | Explicitly deployment concerns; no code or deployment verification proves them |
| Backup/restore of evidence objects | FAIL | `tools/backup-postgres.sh` covers PostgreSQL metadata only; evidence-object backup/restore is documented but unexercised |
| Storage pressure during copy/promotion | PARTIAL | Pre-admission limit exists, but no quota reservation/atomic capacity contract or exhaustion integration test exists for a full promotion |

## Gate decision

Do not claim REQ-ISO-001/004/005 or REQ-UPL-003 are production-complete solely from this adapter. The filesystem implementation is suitable for isolated development and synthetic evidence qualification only. It cannot prove provider durability, TLS, KMS encryption, version/hold semantics, off-host backup/restore, or append-only custody durability. A production release must use an approved S3-compatible/object-storage implementation with server-side policy enforcement and an independent restore drill.

## Required remediation

Implement one production object-storage boundary behind a narrow interface. It must:

1. derive keys from trusted tenant and case scope, never caller-selected prefixes;
2. upload originals with SHA-256 and size verification, no overwrite, provider-side versioning and immutable/object-lock retention;
3. enforce legal hold and retention through provider policy plus application authorization;
4. use TLS with certificate verification and KMS-managed encryption, with least-privilege service credentials;
5. emit durable custody/audit records for admission, read/export, hold, retention, delete denial, and deletion;
6. define bounded/quota-aware failure behavior and remove incomplete multipart uploads;
7. provide encrypted off-host backup/replication and a verified restore test that preserves bytes, versions, hashes, and custody records.

The implementation should be tested against a local S3-compatible service or a provider test account using synthetic tenants/cases only. Until those tests and deployment checks exist, the gate remains FAIL rather than INCONCLUSIVE-as-pass.

## Verification run

The boundary probes are intentionally local and deterministic:

```text
python -m pytest -q tests/test_evidence_store_boundary.py
```

They cover tenant denial, traversal rejection, hash preservation, ordinary write protection, legal hold/retention denial, and pre-admission size exhaustion. They do not substitute for a deployed object-store, TLS/KMS, or backup/restore test.
