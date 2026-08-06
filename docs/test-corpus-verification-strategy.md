# DFIR Evidence Workbench: Test Corpus and Verification Strategy

Status: implementation-ready synthesis
Corpus release: `corpus-v1` / `dfir-golden/v1`
Scope: synthetic fixtures, golden outputs, adapter/API/CSV/UI verification, degraded operation, and evidence integrity

## 1. Purpose and release posture

This document is the verification baseline for the Evidence Workbench. It joins the corpus design, golden-output matrix, adapter contract tests, API/CSV/browser acceptance tests, and availability/degraded-mode tests into one executable gate sequence.

The corpus is synthetic and legally safe by construction. It contains no live workstation image, live memory, customer collection, real credential, real endpoint, executable payload, or unlicensed proprietary sample. Names, users, hosts, paths, dates, domains, and network values are generated; network values use `example.test`, `example.invalid`, RFC 5737 IPv4, or TEST-NET IPv6.

Evidence rules are mandatory even for tests:

- Corpus releases are immutable and read-only during every run.
- Every physical input is resolved by fixture ID through `manifest.jsonl`, then verified against `manifest.sha256` and its per-file SHA-256.
- Adapter output, extracted files, logs, reports, and temporary state are written beneath a separate disposable analysis root.
- Sources are hashed before and after each invocation; any change is a hard failure.
- No recovered binary, script, document, macro, or payload is executed; images are never mounted read-write.
- A missing tool or incomplete input is an explicit unavailable/partial/error state, never an empty successful result or a negative conclusion.

## 2. Normative source documents

The following documents are the detailed oracles and must be versioned together with implementation changes:

| Concern | Normative source |
|---|---|
| Fixture generation, legal safety, manifest, tamper checks | `synthetic-corpus-design.md` |
| Per-fixture semantic expected output and schemas | `golden-output-matrix.md` |
| Adapter contracts and end-to-end flows | `adapter-contract-integration-test-plan.md` |
| HTTP routes, CSV interoperability, browser smoke | `api-csv-browser-test-plan.md` |
| Tool masking, crash/timeout behavior, custody assertions | `availability-degraded-mode-tests.md` |

A mismatch must be classified before changing a golden: adapter defect, fixture/manifest defect, schema/contract change, or intentional new corpus release. `corpus-v1` is never silently rewritten; a changed contract creates a new corpus release.

## 3. Corpus inventory and coverage

The baseline contains 40 fixture groups, approximately 105 files, with normal CI inputs below 100 MiB and stress fixtures opt-in. The complete required group inventory is:

- UAC (8): `uac-normal`, `uac-denied`, `uac-empty`, `uac-malformed-evtx`, `uac-fragmented-records`, `uac-encrypted-wrapper`, `uac-duplicates`, `uac-clock-skew`.
- Velociraptor (10): `vr-normal`, `vr-empty`, `vr-malformed-json`, `vr-malformed-csv`, `vr-missing-columns`, `vr-duplicates`, `vr-partial-zip`, `vr-encrypted-zip`, `vr-fragmented-parts`, `vr-schema-v2`.
- Memory (8): `mem-win-normal`, `mem-linux-normal`, `mem-empty`, `mem-truncated`, `mem-bad-page-map`, `mem-fragmented`, `mem-encrypted-wrapper`, `mem-high-entropy`.
- Disk (14): `disk-ntfs-normal`, `disk-ext4-normal`, `disk-fat32-normal`, `disk-gpt-mbr`, `disk-empty`, `disk-malformed-partition`, `disk-truncated`, `disk-encrypted-wrapper`, `disk-fragmented`, `disk-deleted`, `disk-slack`, `disk-zero-byte`, `disk-duplicate`, `disk-offset-variation`.

Every group must represent one or more of these standardized scenarios: normal, malformed, empty, encrypted, and fragmented. Each member has a stable ID, generated provenance, format, size bound, expected-answer path, and SHA-256. Expected answers contain parser-visible facts only, with no unnecessary raw sensitive data.

## 4. Required harness architecture

The test harness must provide these primitives:

1. `load_and_verify_manifest(fixture_id, release="corpus-v1")`: resolves a named group, rejects unknown IDs, path traversal, absolute paths, symlinks, duplicate paths, duplicate IDs, and hash/size mismatches.
2. `load_golden(fixture_id)`: loads expected JSON plus referenced event and artifact CSV; validates all schemas and input references.
3. `run_with_timeout(adapter, inputs, timeout_s, capabilities, fault_plan)`: runs the adapter in a subprocess boundary with process-tree cleanup, bounded stdout/stderr, isolated output, and deterministic fault injection.
4. `canonical_json()` and `canonical_csv()`: apply only declared ordering/serialization rules; never discard fields to hide a mismatch.
5. `scan_prohibited_content(output_root)`: rejects real-PII markers, secrets, keys/passwords, live endpoints, uncontrolled tracebacks, and unsafe path escapes.
6. `assert_evidence_unchanged(source, before_sha256, custody_event)`: verifies source bytes, permissions, manifest, and custody linkage after execution.
7. `assert_degraded_contract(result)`: requires status, observations, unresolved items, errors, evidence hashes, provenance, and stable reason codes whenever analysis is incomplete.
8. `write_run_report()`: records fixture ID, adapter/contract version, corpus release, input hashes, golden path, capabilities, duration, timeout/resource result, status, error code/offset, recovered counts, output hash, and cleanup result.

A missing fixture, missing golden, or manifest mismatch is test-infrastructure failure. It must not be reported as an adapter parse failure.

## 5. Test layers and gate order

Run gates in this order; later layers are blocked by failures in earlier integrity or contract layers.

### Gate 0: corpus release and legal-safety validation

- Verify the canonical manifest hash and every member size/hash.
- Require all 40 groups, all four adapter classes, and all five scenario labels.
- Validate expected-answer existence, schema validity, path confinement, and prohibited-content scan.
- Run deliberate mutation tests: one-byte change, rename, deletion, and manifest-field edit. Each must fail with an object path and reason.
- Confirm release metadata contains generator version, deterministic seed, tool versions, license/provenance, size limits, and known limitations.

### Gate 1: tool capability preflight

Probe each invocation, not just the host globally. Record command path, version, executable status, parser profile, optional dependencies, and masked-tool state. Capabilities are scoped to the adapter and fixture.

Required states include available, missing, not executable, license/feature unavailable, profile unavailable, optional dependency missing, permission denied, and intentionally masked. A preflight failure must produce structured `unavailable` output with an unresolved scope and remediation.

### Gate 2: adapter contract tests

For every one of the 40 groups:

- Run twice in isolated temporary directories.
- Validate result envelope and nested schemas.
- Compare canonical JSON and both canonical CSVs exactly to the golden.
- Compare stable output hashes across runs.
- Assert exact counts, IDs, timestamps, warnings, findings, error codes, offsets, and provenance.
- Assert no uncaught exception, fabricated record, secret, real PII, or unbounded traceback.

Required adapter contracts are `uac-adapter/v1`, `velociraptor-adapter/v1`, `memory-adapter/v1`, and `disk-adapter/v1`. Negative cases are results (`partial`, `degraded`, or `error`), not test-process crashes.

### Gate 3: fault and degraded-mode tests

Inject, through a controlled shim or subprocess hook only: missing executable, non-executable executable, non-zero exit, signal termination, timeout, malformed stdout, malformed input, missing archive part, unsupported schema/profile, permission denial, and missing encryption key.

Assertions for every injected run:

- status is explicit (`complete`, `partial`, `unavailable`, `invalid_input`, or `failed`);
- only independently validated observations are present;
- every skipped scope appears in `unresolved[]` with stable reason code and remediation;
- partial output has its own hash and is marked incomplete;
- no “no events,” “no processes,” “no files,” “not present,” or equivalent negative claim when coverage is incomplete;
- source and manifest hashes remain unchanged;
- custody event is append-only and records operation, tool/version, UTC times, actor, status, and error code;
- adapter failure does not suppress other adapter results.

### Gate 4: API contract and security tests

Start the service against the same verified release and disposable workspace. Exercise health, workspace creation, ingest, list/filter, complete results, events, artifacts, findings, CSV exports, CSV import, and import status routes. Use a documented one-to-one route map if implementation prefixes differ.

Positive coverage includes all 40 groups and class/filter/pagination behavior. Negative coverage includes malformed inputs, missing parameters, wrong content type, unknown adapter/class, invalid cursor, path traversal, nonexistent IDs, manifest hash mutation, conflicting idempotency key reuse, unsupported capability, encrypted input without key, and every malformed fixture.

Every response must validate schema/content type, stable request ID, exact counts and hashes, UTC timestamps, corpus-relative paths, allowed finding severity/status, and absence of secrets. Repeating an idempotent request must not create duplicate evidence or records.

### Gate 5: CSV export/import interoperability

For all 40 groups, compare event and artifact exports byte-for-byte with canonical goldens. Enforce UTF-8, LF endings, schema header order, RFC 4180 quoting, deterministic row order, no BOM/trailing spaces, and header-only output for valid empty sets.

Round-trip both exports through import and re-export. Require preservation of schema, counts, hashes, provenance, warnings, findings, partial/error state, and cross-references. Test events-only and artifacts-only imports as incomplete rather than fabricating the missing collection.

Mutation tests cover commas/quotes/newlines/spaces, Unicode and invalid UTF-8, null/empty distinctions, reordered columns/rows, altered hashes, non-UTC/invalid timestamps, missing zero-byte row, unknown/required columns, duplicate rows, BOM/CRLF/NUL, oversized fields, and row limits. Invalid input is rejected or explicitly degraded; it must never become golden-equivalent by accident.

### Gate 6: integration scenarios

Run the seven traceable scenarios from the adapter plan:

- I-01 complete four-source correlation;
- I-02 malformed-input triage;
- I-03 fragment reassembly and provenance;
- I-04 encrypted-evidence stop condition;
- I-05 duplicate and normalization consistency;
- I-06 empty and valid edge cases;
- I-07 compatibility and degraded capability.

Intermediate results are immutable typed envelopes, not reparsed display text. The final report preserves source references, UTC ordering, confidence/status, limitations, and deterministic final output hash.

### Gate 7: browser smoke acceptance

Run against the same API/release and a disposable workspace. Before and after each state-changing action, capture a fresh accessibility/DOM snapshot. Capture URL, UTC times, fixture IDs, screenshot/evidence path, console output, failed request status, and download hash.

Required scenarios: health/empty shell, corpus load, UAC normal/malformed, memory structured/entropy, disk filesystem/deleted/offset, populated and empty CSV export, CSV import, malformed/encrypted diagnostics, filter/pagination, and direct-link/refresh. A scenario is PASS, FAIL, or BLOCKED with an explicit environment reason; blocked backend/tool availability must never be mislabeled as pass.

## 6. Golden comparison and evidence assertions

Canonical JSON uses UTF-8, lexicographically sorted object keys, declared array ordering, and a final newline. Canonical CSV uses UTF-8, LF, schema-defined headers, required quoting only, and rows sorted by `(time_utc, source_artifact_id, record_key)`.

Every material observation must carry provenance appropriate to its source: source path/member and hash; byte/line offset where applicable; inode/MFT reference for disk artifacts; page/range for memory; extraction hash for recovered content. Findings must cite evidence references and use only `info|low|medium|high` with `confirmed|possible|not_established`.

Special interpretation guards:

- String residue is diagnostic only; it is not a live process, socket, credential, or execution claim.
- Deleted or slack data is not proof of execution or user action.
- Encrypted input proves detection/key-required state only; no key guessing or bypass.
- A timeout/crash proves an unresolved scope, not absence of artifacts.
- An empty valid container is a valid empty result, not “no evidence.”
- Disk partition offsets must be derived from metadata; sector 2048 is never assumed.
- All report-facing timestamps are UTC RFC3339 `Z`, while original value and source timezone remain auditable.

## 7. CI jobs and artifacts

Run in a pinned Linux x86_64 container with Python 3.11, lockfile dependencies, pytest, JSON Schema validation, and only declared local forensic tools. The corpus is fetched as an immutable artifact and read-only. No job accesses production evidence, external decryption, network endpoints, or real credentials.

Suggested jobs:

- `corpus-integrity`: manifest, legal-safety, schema, mutation, prohibited-content checks;
- `adapter-contract`: `pytest -m contract --junitxml=reports/contract-junit.xml --json-report --json-report-file=reports/contract.json`;
- `degraded-mode`: masked tools, crash, timeout, malformed output, missing parts, key-required tests;
- `api-csv`: API positive/negative, exports, imports, mutations, idempotency/security;
- `integration`: seven end-to-end scenarios;
- `browser-smoke`: UI scenarios, console/network/download evidence;
- `final-integrity`: source/manifest rehash, custody audit, cleanup/process/mount sweep.

Publish JUnit, machine-readable JSON, semantic diffs, capability matrix, custody audit, and browser evidence as CI artifacts. Do not publish raw sensitive fixture contents or uncontrolled tracebacks.

## 8. Release acceptance checklist

- [ ] Manifest and every member hash verify before and after all tests.
- [ ] All 40 fixture groups and all four adapter families execute at least one positive or controlled negative test.
- [ ] Golden JSON, schemas, and canonical CSV comparisons pass without discarded fields.
- [ ] Deterministic reruns produce identical canonical output hashes.
- [ ] Malformed, truncated, encrypted, fragmented, empty, duplicate, and compatibility cases have explicit outcomes.
- [ ] Tool-missing, crash, timeout, permission, optional-dependency, and profile-unavailable tests are exercised.
- [ ] API routes, negative/security cases, idempotency, and path confinement pass.
- [ ] CSV export/import round trips and edge mutations pass.
- [ ] Seven integration scenarios pass with typed provenance-preserving handoffs.
- [ ] Browser scenarios are PASS or explicitly BLOCKED with evidence; zero unexplained console/API errors.
- [ ] No source is modified, mounted read-write, or executed; no secrets/PII/live endpoints appear in output.
- [ ] Custody records are append-only, UTC-normalized, hash-linked, and degraded events remain preserved.
- [ ] Reports include limitations and say “not established” where coverage is incomplete.
- [ ] Any golden change is reviewed and released under a new immutable corpus version.

## 9. Traceability summary

| Requirement | Verification layer | Oracle/evidence |
|---|---|---|
| Synthetic/legal-safe fixtures | Gate 0 | corpus manifest, provenance, prohibited scan |
| Exact parser semantics | Gate 2 | golden JSON/schema/CSV |
| Missing tools and degraded behavior | Gate 1 + 3 | capability matrix, structured unresolved/errors |
| Evidence integrity | every gate + 7 | before/after hashes, custody audit, read-only checks |
| API correctness/security | Gate 4 | route responses, schemas, negative tests |
| CSV interoperability | Gate 5 | byte comparison, round-trip and mutation reports |
| Cross-source workflow | Gate 6 | seven scenario reports and final hashes |
| UI usability/observability | Gate 7 | browser snapshots, console/network/download evidence |
| Release reproducibility | Gate 0 + CI | pinned generator/seed/tool versions and immutable release |
