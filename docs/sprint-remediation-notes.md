# Sprint review remediation notes

This checkout uses the versioned OpenRelik contract (`1.0.0`) and its JSON Schemas as the sole local adapter boundary. The Velociraptor fast path validates that contract before claiming a job; case scope comes from the request while tenant and analyst scope come from the authenticated principal. The adapter and evidence store are local/mock components only: no live OpenRelik service, queue, authentication, or vendor API was exercised.

## Addressed findings

- H1: incomplete claims resume side effects on retry; only completed jobs with outputs are reused. Interrupted quarantine promotion can reuse the matching staged object.
- H2: the flat contract was not retained; adapter and fast path use the schema-backed `1.0.0` request/result boundary.
- H3: an idempotency-key collision compares canonical stored request data and rejects changed payloads.
- M1: fast-path requests pass schema and identifier validation before persistence.
- M2: case scope is explicit request data; `Principal` supplies tenant and analyst identity only.
- M3: evidence-directory creation is an exclusive filesystem claim; a race winner's verified manifest is reused by losers.
- M4: approve and output writes require tenant and case scope; no caller-side private database mutation is used.

## Accepted non-blocking items

- L1: the unused evidence registration alias remains as a compatibility name until callers migrate.
- L2: normalized output retains source paths for provenance; analysis roots remain controlled temporary directories.
- L3: this checkout does not claim a registry digest for locally built worker images.
- L4: regression coverage now includes failure/resume and payload-conflict paths; live OpenRelik integration remains out of scope.

Verification: focused OpenRelik/fast-path tests 9 passed; full pytest 86 passed; `tools/verify-supply-chain.sh` passed.
