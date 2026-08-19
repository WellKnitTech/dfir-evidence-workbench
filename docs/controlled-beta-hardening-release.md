# Controlled-beta hardening release package

**Verification date:** 2026-08-19
**Repository state:** `origin/main` at `6a5e399`
**Decision:** not cleared for controlled beta; internal synthetic-only evaluation remains the maximum supported scope until the outstanding release gates are completed.

This document is the index for the hardening PR. It records what was verified, what is intentionally not claimed, and which artifacts must accompany a future promotion. It does not authorize client evidence, production deployment, or redistribution of third-party forensic tools.

## Compatibility matrix

| Surface | Verified here | Not verified / limitation |
|---|---|---|
| Python 3.11 package and synthetic fixtures | Full pytest suite and compilation pass | Other Python versions are outside this gate |
| FastAPI API shell and tenant/auth boundaries | Unit/API tests cover fail-closed auth, tenant scoping, audit, readiness, and synthetic runner paths | No production traffic profile or multi-instance soak test |
| PostgreSQL metadata store | Disposable PostgreSQL-backed tests and documented synthetic dump/restore exercise | No PITR/WAL exercise; evidence object storage is separate |
| TheHive / DFIR-IRIS projections | Synthetic fixtures, schema validation, provenance and metadata-only evidence boundary | No live vendor server, authentication handshake, pagination, rate-limit, or write/read-back test |
| OpenRelik / Velociraptor worker boundary | Contract and connector regression tests; same-origin pagination protection | No live pinned OpenRelik or Velociraptor deployment |
| Disk and memory adapters | Approved synthetic fixtures and safety tests | Native TSK/VHD/VMDK/EWF/QCOW2/VHDX coverage is not claimed |
| Browser analyst workflow | Frontend acceptance coverage is present in CI configuration | No claim of production queue, durable evidence store, or client-data readiness |
| Compose deployment | Local config validation for available Podman variants and static supply-chain checks | Docker, fresh image build, registry promotion, and production infrastructure are not reproduced here |

## Verification gates

The following checks are expected from a clean checkout and were run by the upstream hardening task where noted:

- `python -m pytest -q` — 126 passed.
- `python -m compileall -q src tests` — passed.
- `git diff --check` — passed.
- `bash tools/verify-supply-chain.sh` — passed for static checks.
- `podman compose -f compose.lan.yaml config --quiet` — passed.
- Frontend Playwright acceptance is wired into CI; a browser run is not represented as a production readiness claim.

The fresh pinned-image SBOM and HIGH/CRITICAL vulnerability/license scan remain release prerequisites. The local host does not provide Docker, Trivy, or Grype, so no scan result is invented here.

## Evidence-safety result

The repository remains synthetic-only. Tests and documentation enforce that evidence projections carry metadata such as filename, size, SHA-256, and restricted references while `content_transferred` remains false. Secret-bearing keys are rejected before persistence, source timestamps require explicit timezone information, tenant scope comes from the authenticated principal, and extraction is bounded to caller-provided staging roots.

Do not add client evidence, raw images, credentials, proprietary rules, client-derived indicators, or generated case output to this branch or PR. The release checklist, `.gitignore`, and tests are safeguards—not permission to relax that rule.

## Operational runbooks and recovery evidence

- `docs/backup-and-restore.md` documents the synthetic PostgreSQL dump/restore procedure and a prior exercised restore that recreated three tables and one row under tenant scope.
- `docs/observability-and-incident-operations.md` covers database failure, storage exhaustion, Entra/OIDC outage, suspected tampering, audit fallback, alerting, upgrade, and rollback.
- `docs/reproducible-builds.md` defines digest-pinned image, SBOM, signing/attestation, and rollback requirements.
- `docs/release-checklist.md` is the final source, license, secret, schema, scan, and manual evidence-handling checklist.

The prior restore result is a synthetic functional measurement, not a general DR SLA: it was observed at approximately minutes for a one-row database. No representative load test, production-scale restore benchmark, WAL/PITR test, object-storage failover test, or multi-region DR exercise has been completed. Future evidence must record dataset size, image/database digests, elapsed time, RPO/RTO observed, and post-restore authenticated tenant-scoped smoke results.

## Auth and deployment assumptions

Production must set `DFIRWB_ENV=prod`, configure Entra/OIDC issuer and audience, and inject RS256 JWKS or another approved verifier configuration through the deployment secret mechanism. Synthetic principals and fixture secrets are dev/test-only and must not be available as a production fallback. Production compose must use an immutable API image digest, no source bind mount, read-only evidence mounts, least-privilege containers, external logging/audit controls, and host-managed secret injection.

These controls assume a trusted deployment operator, a protected secret store, tenant/case isolation in metadata and object storage, and an independent backup/retention process. Those assumptions are not substitutes for live Entra, registry, storage, or infrastructure acceptance tests.

## Explicit limitations and promotion gate

This PR documents and packages the approved hardening changes; it does not claim controlled-beta authorization. Promotion requires, at minimum:

1. Fresh SBOM plus pinned image HIGH/CRITICAL and secret-scan artifacts.
2. Post-merge backup/restore, readiness/health, and authenticated tenant-scoped smoke evidence.
3. A representative load/latency run with dataset and concurrency recorded.
4. A reviewed DR exercise covering metadata and evidence-object recovery, with observed RPO/RTO.
5. Live compatibility evidence against pinned vendor/OpenRelik versions where those integrations are in scope.
6. Security and evidence-handling sign-off confirming that only synthetic fixtures were used.

Until all six gates are attached to the release record, the supported decision is internal synthetic evaluation only; client evidence and production deployment remain prohibited.
