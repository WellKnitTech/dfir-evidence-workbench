# Release-readiness report: TheHive / DFIR-IRIS ingest boundary

Status: PASS for the repository acceptance gate, with the limitations below.

Verification timestamp: 2026-08-08T03:52:30Z
Repository: `/var/home/jwellnitz/projects/dfir-evidence-workbench`
Scope: vendor-neutral schemas, synthetic TheHive and DFIR-IRIS projections, and the durable ingest/API boundary. No live vendor deployment or credentials were used.

## Commands and results

All commands were run from the repository root with the pinned project virtualenv where applicable.

1. JSON Schema Draft 2020-12 meta-validation:

   ```text
   .venv/bin/python - <<'PY'
   import json
   from pathlib import Path
   from jsonschema import Draft202012Validator
   for p in (Path('schemas')/'ingest-envelope.schema.json', Path('schemas')/'interop-entity.schema.json'):
       schema=json.loads(p.read_text())
       Draft202012Validator.check_schema(schema)
       print(f'{p}: valid Draft 2020-12 schema')
   PY
   ```

   Result: PASS. Both `schemas/ingest-envelope.schema.json` and `schemas/interop-entity.schema.json` passed `Draft202012Validator.check_schema`.

2. Full test suite:

   ```text
   .venv/bin/python -m pytest -q
   ```

   Result: PASS — `65 passed in 27.80s`.

3. Python compilation:

   ```text
   .venv/bin/python -m compileall -q src tests
   ```

   Result: PASS — no compiler output or errors.

## Acceptance coverage confirmed by the passing suite

- TheHive synthetic fixtures project case, alert, observable/IOC, task/log timeline events, and quarantine cases through `TheHiveIngestAdapter`; projections validate against the interop schema.
- DFIR-IRIS synthetic fixtures project case, alert, IOC, asset, timeline event, note/finding, and evidence reference through `DFIRIRISIngestAdapter`; projections validate against the interop schema.
- Duplicate suppression is exercised at the durable repository layer using repeated idempotency keys.
- Idempotency-key reuse with a different payload hash is detected as `conflict`, not silently accepted as a duplicate.
- Obvious secret-bearing keys are rejected before serialization/storage, including nested/list forms and API-key/token/password variants.
- Source timestamps retain the raw value and normalize to UTC (`Z`); timezone-less timestamps are rejected.
- Provenance assertions cover source system/entity, opaque source ID and scope, source revision, mapping version, idempotency key, redaction flags, and lossy transformations.
- Evidence projection is metadata-only: filename, size, SHA-256, and restricted URI metadata are allowed; `content_transferred` is enforced as `false`, and evidence bytes are not transferred.
- Unsupported vendor-specific types are quarantined and recorded as lossy rather than silently mapped.
- Durable preview/approval/commit/quarantine paths and tenant-scoped repository behavior are covered by disposable PostgreSQL tests in the suite.

Relevant tests include:

- `tests/test_interop_schema.py`
- `tests/test_thehive_ingest_adapter.py`
- `tests/test_dfir_iris_ingest_adapter.py`
- `tests/test_api_shell.py`

## Limitations and release caveats

- This gate uses synthetic JSON fixtures only. It does not establish compatibility with a running TheHive or DFIR-IRIS installation.
- No live vendor API calls, authentication handshake, pagination behavior, rate limits, retries, server-version negotiation, or vendor-side write/read-back were tested. Live compatibility requires a pinned test installation and versioned API contract.
- The adapters are projection/intake code, not complete vendor transport connectors. Vendor-specific status/ownership transitions, permissions, Cortex/MISP workflows, IRIS task semantics, and destructive operations remain explicit non-mappings or require a separately reviewed connector.
- Secret rejection is a fail-closed heuristic over key names. It cannot detect secrets hidden in values under innocuous keys, obfuscated keys, or arbitrary binary content; transport-time redaction and deployment policy remain required.
- Timestamp parsing is limited to supported ISO-8601-like values with an explicit timezone; epoch/custom formats and leap seconds are outside this baseline.
- The working tree contains preceding implementation/deployment changes from the parent task graph. This report is an acceptance record, not a claim that the checkout is a clean Git worktree or that every deployment environment has been reproduced.

## Gate conclusion

The repository passes the requested schema, projection, safety-boundary, persistence, duplicate/conflict, and compilation checks. It is release-ready only for the reviewed vendor-neutral synthetic boundary; live TheHive/DFIR-IRIS compatibility remains unverified until tested against pinned vendor installations.
