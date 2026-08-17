# Reproducible release path

The production compose file is a deployment manifest, not a development build. It has no `build:` stanza and no source bind mount. `DFIRWB_API_IMAGE` must be supplied by the deployment system as a registry reference containing `@sha256:<digest>`. PostgreSQL and the Dockerfile base image are committed by digest.

## Local gates

From a clean checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-api.lock -r requirements-test.lock
python -m pytest -q
python -m compileall -q src tests
python -m pip check
DFIRWB_DATABASE_URL='postgresql://dfir:ci-placeholder@postgres:5432/dfir_dev' \
  DFIRWB_API_IMAGE='registry.example/dfir-api@sha256:<64 hex characters>' \
  podman compose -f compose.prod.yaml config --quiet
./tools/verify-supply-chain.sh
```

The lock files contain direct and transitive Python versions. Refreshing either lock is a deliberate supply-chain change: use a clean Python 3.11 environment, review the complete diff, then rerun the gates.

## Image, SBOM, and scans

Build with the pinned Dockerfile base:

```bash
docker build --pull=false --tag registry.example/dfir-api:$GIT_SHA .
```

CI runs Syft (SPDX JSON), Trivy vulnerability/license scanning, and Trivy secret scanning using digest-pinned tool images. High and critical image findings fail the job. The generated `sbom.spdx.json` is a build artifact and is not part of the runtime image.

A release image must be signed or attested after it is pushed. The tag workflow enables Sigstore keyless identity and runs `cosign sign --yes`; deployments must verify the signature and the SBOM attestation before promotion.

## Publishing and rollback

Publish only an immutable digest, never a mutable `latest` or version tag in `compose.prod.yaml`:

1. Build and scan the image in CI.
2. Push it to the registry and record the resulting digest.
3. Sign/attest that exact digest and publish the SBOM alongside it.
4. Render production compose with `DFIRWB_API_IMAGE=registry.example/dfir-api@sha256:<digest>` and run migration checks before rollout.
5. Keep the prior known-good digest in deployment metadata. Roll back by restoring that exact digest and redeploying; never rebuild from a tag during rollback.

This repository does not contain registry credentials or perform a production push from a developer checkout. The existing backup/restore procedure remains the database rollback safety net; schema migrations must be forward-compatible before image promotion.
