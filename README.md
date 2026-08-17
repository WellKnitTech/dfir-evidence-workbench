# DFIR Evidence Workbench

Evidence-safe building blocks for a containerized digital-forensics triage and
analysis workbench.

Status: **0.1.0-alpha / research prototype**

This initial public snapshot contains reviewed, recoverable adapter code and
schemas from the project Kanban work. It is not yet a complete production
Workbench. Incomplete capabilities are documented instead of being presented
as implemented.

## Included in this snapshot

- Safe UAC archive/directory inventory and allowlisted extraction
- Safe Velociraptor ZIP/directory inventory and allowlisted extraction
- Experimental disk/memory evidence metadata adapter
- Normalized evidence schema
- TheHive/DFIR-IRIS-shaped ingest envelope and interoperable entity schemas
- Additive PostgreSQL timeline-flag migration (requires live-schema review)
- Tool and commercial-use screening documentation
- Synthetic, non-client test fixtures generated during tests
- Minimal FastAPI API service shell (/healthz, /readyz, env-only config without secrets, DI wiring seams; dev-only synthetic context explicitly labeled)

## Explicit limitations

- The disk/memory adapter does not yet provide verified native TSK access for
  VHD/VMDK/EWF or full QCOW2/VHDX coverage. It must not be represented as a
  complete forensic image processor.
- The resumable multi-run processing model is specified but not yet integrated.
- The provenance domain implementation is being re-integrated after its
  Kanban scratch workspace was garbage-collected; no unverified reconstruction
  is included here.
- The PostgreSQL migration has not been applied against the project schema in
  this snapshot.
- Volatility 3 and Sigma rules are intentionally excluded pending a separate
  license review.
- The API shell provides health/config seams plus validated production authentication:
  bearer JWTs are verified against configured issuer, audience, expiry, and either
  an injected HS256 fixture secret or RS256 JWKS. Tenant/analyst identity comes
  only from validated `tid` plus a server-side `analyst_id` mapping or opaque `sub`, never
  request headers/body. Missing/invalid tokens return 401; missing scopes/roles
  return 403; responses never include tokens or raw provider claims.
- Synthetic routes are registered only outside `DFIRWB_ENV=prod`. Production has
  no synthetic principal fallback; configure `DFIRWB_OIDC_ISSUER`,
  `DFIRWB_OIDC_AUDIENCE`, and an injected `DFIRWB_OIDC_JWKS_JSON` (Entra RS256)
  or `DFIRWB_OIDC_HS256_SECRET` (deterministic fixture only).

The interoperability boundary is documented in
`docs/hive-iris-ingestion-research.md`. It models append-only intake and
provenance-preserving projections for cases, alerts, observables/IOCs, assets,
timeline events, findings, and metadata-only evidence references. It does not
claim that vendor API transport is implemented.

## Safety boundary

The adapters do not execute recovered files, modify evidence sources, or mount
client images read-write. Extraction is restricted to caller-provided staging
roots and bounded by size limits. Treat all evidence as hostile input.

Do not commit client evidence, raw images, credentials, proprietary rules,
client-derived indicators, or generated analysis output. The `.gitignore` is a
backstop, not a substitute for review.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'  # add ,api when running service: '.[test,api]'
python -m pytest -q
```

The project has no bundled forensic tools. See `docs/tooling-handoff.md` and
`docs/approved-tools-commercial-use.md` for the reviewed tool list and the
rules for fetching tools from official sources.

## API service shell

The durable HTTP API service boundary (smallest runnable FastAPI module) lives in
`src/dfir_workbench/api.py`.

- Configuration loading: exclusively from `DFIRWB_*` environment variables via
  pydantic-settings. No secrets, tokens, or credentials may ever appear in
  source, defaults, or committed files. Invalid configuration fails closed
  (ValidationError at construction / import).
- Endpoints: `GET /healthz` and `GET /readyz` return deterministic JSON.
- Structured error responses: `{ \"error\": { \"code\": \"...\", \"message\": \"...\", \"retryable\": bool } }`
- Dependency wiring seams: `get_settings()`, `get_current_principal()` (trusted
  analyst+tenant context boundary). The Principal returned is the sole source of
  tenant/analyst scope for protected routes; caller-supplied values are never
  trusted for authorization.
- Dev-only synthetic routes (explicitly labeled, excluded from prod schema and
  responses): e.g. `/__dev__/synthetic/ingest-preview`, `/__dev__/principal`,
  `/__dev__/synthetic/whoami`, and tenant-scoped demo `/__dev__/synthetic/cases*`
  used to verify authorization boundary.
- Tenant scope is server-enforced from the Principal. Cross-tenant reads/mutations
  and unauthenticated access are denied (see tests).
- Use synthetic context **only** where explicitly labeled dev-only. Never feed
  real evidence or tenants.
- Future Entra/OIDC seam: `get_current_principal` will be replaced by validated
  OIDC/JWT handling (Entra ID) that populates the same Principal interface without
  leaking sensitive claims. See source docstrings.

### Native launch

```bash
python -m pip install -e '.[api]'
DFIRWB_ENV=dev uvicorn dfir_workbench.api:app --host 127.0.0.1 --port 8080
# or with reload for dev
DFIRWB_ENV=dev uvicorn dfir_workbench.api:app --reload
```

Smoke:

```bash
curl -s http://127.0.0.1:8080/healthz | jq .
curl -s http://127.0.0.1:8080/readyz | jq .
```

### Podman launch path (rootless, dev)

Example using bind mount (source changes visible; for real use build image):

```bash
podman run --rm -p 8080:8080 \
  -e DFIRWB_ENV=dev \
  -v "$PWD:/app:Z" -w /app \
  python:3.11 \
  bash -c 'pip install --no-cache-dir -e \".[api]\" && \
           uvicorn dfir_workbench.api:app --host 0.0.0.0 --port 8080'
```

For full local stack with PostgreSQL see the container card (compose using health
checks, synthetic data only).

See also child Kanban tasks for wiring auth context, Postgres repos, ingest
routes, and the compose stack.

## Container deployment (compose)

The stack is defined in `compose.yaml` (default: localhost-only 127.0.0.1 bindings, using variable publish for flexibility).

- `podman compose up -d --build` (after `cp .env.example .env`)
- Health: `curl http://127.0.0.1:8080/healthz` and `/readyz`
- Stop: `podman compose down -v`

**Explicit separation (per lan-development-exposure skill and security policy):**
- Default (`compose.yaml`): always 127.0.0.1 (localhost). Safe default. Use `API_PUBLISH=127.0.0.1:18080 POSTGRES_PUBLISH=...` env to change published host port without editing yaml.
- Opt-in LAN prototype ONLY: `podman compose -f compose.lan.yaml up -d` (binds 0.0.0.0; plain HTTP; synthetic only; trusted LAN testing ONLY. No TLS, no real auth, no prod data. You control host firewall; do not claim narrow exposure).
- Production-shaped reference: `compose.prod.yaml` (no published ports in template, secrets via _FILE/external injection, DFIRWB_ENV=prod, image digest + scan guidance, read-only evidence mounts, resource limits, external logging/audit).

**Hardening applied during this task:**
- Least-privilege containers (non-root, read_only fs + explicit tmpfs, dropped caps + no-new-privileges, cpu/mem/pids limits, log rotation).
- Secrets: exclusively DFIRWB_DATABASE_URL from host env/.env (gitignored) or secret manager; no values or broken interpolation in committed templates; .env.example documents the rule.
- Storage boundaries documented: case-scoped scratch volume; prod must use read-only source + tenant/case isolation (prefixes or object store).
- PostgreSQL backup/restore procedure + exercised with synthetic data (pg_dump, restore to fresh db, query verification under tenant scope). Full log + artifacts in docs/backup-and-restore.md.
- Config checks, secret scans (grep patterns), compose validation, and full test suite (77 pass) clean.
- No public exposure, no modification of host firewall policy.

See compose.*.yaml comments, .env.example, `docs/backup-and-restore.md`, `SECURITY.md`, and `docs/security-defensibility-requirements.md` (REQ-*) .

For the reproducible production build, pinned dependency locks, SBOM/scanning gates,
signing, and digest-based rollback procedure, see `docs/reproducible-builds.md`.

## Tool distribution model

The repository publishes code, manifests, and documentation—not third-party
forensic binaries. An explicit setup step may download pinned releases or
build tools from official sources into an isolated container/Distrobox.
A future setup implementation must verify checksums, record versions, preserve
licenses/notices, and generate an SBOM. Publishing a prebuilt image containing
GPL/AGPL or mixed-license tools is redistribution and requires its own
compliance package.

## License

Project-authored code is Apache-2.0. Third-party components are not relicensed
by this notice; see `NOTICE.third-party.md` and the upstream references in
`docs/`.
