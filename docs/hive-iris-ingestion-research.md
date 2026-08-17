# TheHive and DFIR-IRIS ingestion research

Status: implementation baseline, 2026-08-07; schemas + TheHive (t_1b5bc750) + DFIR-IRIS ingest projection adapter (t_c83aea45) implemented+verified

## Findings

TheHive's investigation unit is the case/alert plus observable model. Observables represent directly observed data points such as IP addresses, domains, file hashes, and system artifacts; an observable can be marked as an IOC or sighted, and observables support correlation across cases and alerts.[1] TheHive can automatically retrieve filtered MISP events as alerts, while case observables can be exported to MISP as IOCs.[2]

DFIR-IRIS exposes a broader incident record through its v2 API: cases, IOCs, assets, timeline events, tasks, notes, evidence records, alerts, and comments are distinct API resources. The published v2.1 reference lists case-scoped create/read/update routes for IOCs, assets, events, notes, evidences, tasks, and alerts, plus API-key authentication and server-version discovery.[3] The upstream OpenAPI source is the version-pinned contract to use at deployment.[4]

## Common denominator

The safest shared ingest model is not vendor database replication. It is an append-only intake envelope plus a normalized entity projection:

- `case`: incident container and human-readable context
- `alert`: incoming detection/notification context; preserve it separately from a case
- `observable`/`ioc`: exact indicator value plus type, description, tags, TLP/PAP, and classification
- `asset`: host/system identity and bounded identifiers
- `timeline_event`: occurred-at timestamp, original timezone, category, title, description, and actor reference
- `finding`: analyst-authored conclusion; approval is required and it must never be downgraded into an IOC
- `evidence_reference`: filename, size, SHA-256, and restricted URI only; never ingest evidence bytes into the interoperability payload

The normalized model uses opaque source IDs and source scopes, retains raw and UTC timestamps, and records source revision, mapping version, idempotency key, redaction decisions, and lossy transformations. This supports both TheHive and IRIS while acknowledging that alerts, sightings, case assets, task state, ownership, and evidence-record semantics are not equivalent across products.

## Ingestion lifecycle

1. Receive an `ingest-envelope` containing the source object, scope, revision, timestamps, payload hash, and raw payload.
2. Reject obvious secrets before serialization; do not transmit credentials, API keys, session cookies, or binary evidence.
3. Validate and map into one `interop-entity` projection.
4. Produce preview counts: accepted, duplicate, rejected, conflict, and quarantined.
5. Require analyst approval for findings and destructive/conflicting operations.
6. Commit only through a configured vendor adapter, then read back target IDs/counts before marking applied.

The schemas in this repository intentionally stop at steps 1–3. They are the durable contract for future JSON API and CSV adapters, not a claim that vendor transport is implemented.

## Verified contract artifacts

Exact paths in durable workbench checkout (as of this task t_40769699):

- `schemas/ingest-envelope.schema.json`: append-only intake envelope. Enforces `schema_version`, `envelope_id`, `received_at_utc`, `source` (with `system`, `entity`, opaque `id`+`scope`+`revision`, `updated_at_raw` + `updated_at_utc`, `timezone`), `payload_sha256`, raw `payload` (object), and `processing` (status enum, `mapping_version` semver, optional idempotency/target/error).

- `schemas/interop-entity.schema.json`: vendor-neutral entity projection. Covers `case`, `alert`, `observable`/`ioc` (as indicator), `asset`, `timeline_event`, `finding`, `evidence_reference`. Enforces:
  - `provenance` with `integration_id`, `source_system`/`source_entity`, opaque `source_id`+`source_scope`, `source_revision`, raw+UTC timestamps + timezone, `mapping_version`, `idempotency_key`, `redaction_flags` (decisions: passed/masked/dropped/quarantined with policy), `lossy_transformations` (array).
  - `finding` requires `approval_required: true` (const; downgrades rejected).
  - `evidence_reference` is metadata-only: requires `filename`, `size_bytes`, `sha256`, `content_transferred: false` (const); no data/bytes; optional `restricted_uri`.
  - `oneOf` discrimination on `entity_type` + matching provenance `source_entity`.
  - `additionalProperties: false` throughout; no evidence bytes in any payload.

- Helpers (for contract use, not transport): `src/dfir_workbench/interop.py` (canonical_json, payload_sha256, idempotency_key, utc_timestamp, reject_secret_keys)
- Tests: `tests/test_interop_schema.py`
- TheHive ingest projection adapter: `src/dfir_workbench/adapters/thehive_ingest_adapter.py` (TheHiveIngestAdapter with project_case / project_alert / project_observable / project_timeline_event + helpers). Maps TLP/PAP, drops forbidden fields (status/owner/Cortex/MISP/bytes), records lossy_transformations, quarantines unsupported observable types, rejects secrets via interop. Produces schema-compliant interop-entities only.
- Synthetic fixtures: `tests/fixtures/thehive/*.json` (good + quarantine secret/attachment/cortex/misp cases)
- Tests: `tests/test_api_shell.py` (updated wiring), `tests/test_thehive_ingest_adapter.py` (new,  schema roundtrips + quarantine)


Schema validation + tests executed:
- `python -m pytest tests/test_interop_schema.py -q` → 7 passed
- Manual + code verifications: canonical determinism, idempotency over integration/direction/source_* tuple, payload_sha256 64-hex, utc raw+UTCZ with tz rejection, fail-closed secret key detection on multiple forms (top/nested/list, password/token/apikey/private-key variants).
- Envelope uses raw vendor `payload` (preserved verbatim for sha256); interop-entity uses separate normalized projection `payload`.
- Schemas themselves are valid Draft 2020-12.
- Full suite: 48 passed (added 12+ from thehive_ingest_adapter + wiring).

These artifacts were reviewed against preceding adapter/normalized-evidence work and the parent kanban graph (per serialized comment: "use the preceding artifact and parent review evidence before editing. Do not dispatch concurrent writers.") before finalization in the durable checkout. API/CSV transport kept out of scope.

## Helper implementation and limitations

The `src/dfir_workbench/interop.py` provides the minimal stdlib-only (json, hashlib, base64, datetime) layer:

- `canonical_json(value)`: stable sort_keys + compact separators for hashing/identity.
- `payload_sha256(payload)`: sha256 over canonical of the raw vendor dict.
- `idempotency_key(*, integration_id, direction, source_system, source_entity, source_id, source_revision)`: v1: + urlsafe_b64(sha256("|".join(6-tuple))) [43 chars]; deterministic identity for dedup.
- `utc_timestamp(raw) -> (raw, utc_z)`: preserves original, produces Z-normalized; rejects missing tz or invalid.
- `reject_secret_keys(value, path="payload")`: recursive fail-closed on heuristic secret key names (password, token, api_key, secret, private_key, cookie, apikey variants). Raises IngestValidationError.

**Documented limitations (do not overclaim):**
- Secret detection is heuristic string match on lowercased key names only; will not catch obfuscated keys, values containing secrets in safe keys, or binary. Always layer with transport-time redaction and policy.
- No normalization/mapping logic here: raw vendor payloads stay in ingest-envelope.payload; mapping to interop-entity.payload (with redaction/lossy flags) happens in higher adapters (see child t_1b5bc750).
- Idempotency is over the provided tuple; caller must supply consistent integration/direction/source for same logical item.
- Timestamps assume ISO-8601-ish with tz; no support for epoch, custom formats, or leap seconds.
- All functions are pure and side-effect free; they do not fetch, mutate, or transport.
- Intended for preview/ingest boundary only; never for production evidence mutating paths without review.
- AdditionalProperties: false and consts in schemas are the enforcement; helpers assist construction but do not replace validation.

## Deliberate non-mappings

The baseline does not automatically propagate delete, close/reopen, status, ownership, permissions, alerts-to-cases, Cortex jobs, MISP events, IRIS task directories, IRIS evidence records, attachment bytes, or vendor-specific custom fields. These require a separate connector or explicit mapping policy. Unknown fields must be quarantined rather than silently discarded.

## Source references

[1] TheHive 5 documentation, About Observables: https://docs.strangebee.com/thehive/user-guides/analyst-corner/cases/observables/about-observables/

[2] TheHive 5 documentation, Connect a MISP Server: https://docs.strangebee.com/thehive/administration/misp-integration/connect-a-misp-server/

[3] DFIR-IRIS API v2.1.0 reference: https://docs.dfir-iris.org/latest/_static/iris_api_reference_v2.1.0.html

[4] DFIR-IRIS v2.1.0 OpenAPI source: https://github.com/dfir-iris/iris-doc-src/blob/master/docs/api_reference/reference/iris.v2.1.0.yaml

## Sources

[1] https://docs.strangebee.com/thehive/user-guides/analyst-corner/cases/observables/about-observables — TheHive 5 About Observables
[2] https://docs.strangebee.com/thehive/administration/misp-integration/connect-a-misp-server — TheHive 5 MISP Integration
[3] https://docs.dfir-iris.org/latest/_static/iris_api_reference_v2.1.0.html — DFIR-IRIS API v2.1.0
[4] https://github.com/dfir-iris/iris-doc-src/blob/master/docs/api_reference/reference/iris.v2.1.0.yaml — DFIR-IRIS v2.1 OpenAPI source
- DFIR-IRIS ingest projection adapter: `src/dfir_workbench/adapters/dfir_iris_ingest_adapter.py` (DFIRIRISIngestAdapter with project_case / project_alert / project_ioc / project_asset / project_timeline_event / project_finding / project_evidence_reference + project() dispatch + helpers). Maps tlp_name strings, splits comma tags, preserves uuids, handles IRIS date forms in ts, drops ownership/MISP links/state, quarantines attachment iocs, forces approval_required for findings, metadata-only evidence with lossy for weak hashes. Synthetic only.
- Synthetic fixtures: `tests/fixtures/iris/*.json` (case, alert, ioc_*, asset, timeline, note, evidence + quarantine secret/attachment/misp)
- Tests: `tests/test_dfir_iris_ingest_adapter.py` (new, schema roundtrips + quarantine + idempotency)

## DFIR-IRIS adapter verification (t_c83aea45)
- python -m pytest tests/test_dfir_iris_ingest_adapter.py -q → 10 passed
- Full suite: python -m pytest -q → 58 passed
- All projections (case/ioc/asset/timeline/finding/evidence/alert) validate against interop-entity.schema.json
- Quarantine: secrets raise IngestValidationError; unsupported ioc types set quarantined redaction; misp links recorded lossy
- Idempotency deterministic; UTC preserved; customer/case scope via source_scope; exact values/types; no bytes
- Synthetic fixtures only; no transport or live calls
- Wired: adapters/__init__, api.py import+readyz, test_api_shell updated
