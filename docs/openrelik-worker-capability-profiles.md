# OpenRelik worker capability profiles

The first OpenRelik-compatible worker is an opt-in `worker.normal` profile for metadata-only inventory of staged evidence. It is not enabled by the default Workbench compose stack.

## Normal profile guarantees

`compose.openrelik.yaml` runs `dfir.openrelik.manifest` with:

- a digest-pinned Python base image;
- no `devices`, host `/dev`, `privileged`, host namespaces, or published ports;
- an internal-only bridge network;
- `cap_drop: ALL`, `no-new-privileges`, read-only root filesystem, and UID/GID `65532:65532`;
- a read-only `/input` bind mount and separate job-scoped writable `/output` bind mount;
- bounded CPU, memory, and PID resources.

The worker only hashes and inventories staged files/directories. It must not be used for raw devices, disk-image acquisition, carving, or other tasks requiring host device access. Those remain disabled pending a separately reviewed privileged capability profile.

## Build and smoke test with Podman

Run from the repository root with synthetic data only:

```bash
mkdir -p /tmp/dfir-openrelik-input /tmp/dfir-openrelik-output
chmod 0777 /tmp/dfir-openrelik-output  # or podman unshare chown 65532:65532 ...
printf 'synthetic evidence\n' > /tmp/dfir-openrelik-input/sample.bin
podman build --pull=never -t dfir-openrelik-manifest-worker:smoke \
  workers/openrelik-manifest-worker
STAGED_INPUT=/tmp/dfir-openrelik-input \
JOB_OUTPUT=/tmp/dfir-openrelik-output \
OPENRELIK_TASK_ID=task-smoke \
OPENRELIK_EVIDENCE_ID=evidence-smoke \
podman compose -f compose.openrelik.yaml --profile worker.normal run --rm \
  openrelik-manifest-worker
```

If the Podman Compose plugin is unavailable, the equivalent direct smoke run is:

```bash
podman run --rm --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --network none \
  -v /tmp/dfir-openrelik-input:/input:ro,Z \
  -v /tmp/dfir-openrelik-output:/output:rw,Z \
  dfir-openrelik-manifest-worker:smoke \
  --input /input --output /output --task-id task-smoke --evidence-id evidence-smoke
```

The direct command uses `--network none`; the compose profile uses an internal-only network. In both cases, inspect the output JSON and verify the input remains unchanged. Do not mount original evidence read-write and do not add a device or privileged flag.

## Verification

Run the static supply-chain gate and worker tests:

```bash
tools/verify-supply-chain.sh
python -m pytest -q tests/test_openrelik_manifest_worker.py
```

Image digest policy covers every Dockerfile under `workers/`; update the digest and its comment together when intentionally changing the base image.
