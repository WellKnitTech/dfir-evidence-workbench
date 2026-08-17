#!/usr/bin/env bash
set -euo pipefail

# Static gate is intentionally runnable without privileged container tooling.
root=$(git rev-parse --show-toplevel)
cd "$root"

python - <<'PY'
from pathlib import Path
import re

for path in (Path('Dockerfile'), Path('compose.yaml'), Path('compose.lan.yaml'), Path('compose.prod.yaml')):
    text = path.read_text()
    refs = re.findall(r'(?m)^\s*(?:FROM|image:)\s+([^\s#]+)', text)
    for ref in refs:
        if '@sha256:' not in ref and not ref.startswith('${'):
            raise SystemExit(f'{path}: unpinned image reference: {ref}')

prod = Path('compose.prod.yaml').read_text()
if 'build:' in prod or re.search(r'(?m)^\s*-\s*\.\:/', prod):
    raise SystemExit('compose.prod.yaml must not build from or mount editable source')
if 'image: ${DFIRWB_API_IMAGE}' not in prod:
    raise SystemExit('production API image must be an explicitly supplied immutable reference')
api_image = __import__('os').environ.get('DFIRWB_API_IMAGE')
if api_image and '@sha256:' not in api_image:
    raise SystemExit('DFIRWB_API_IMAGE must include an immutable sha256 digest')

lock = Path('requirements-api.lock').read_text().splitlines()
if not lock or any(line and not line.startswith(('#', '-')) and '==' not in line for line in lock):
    raise SystemExit('requirements-api.lock contains an unpinned requirement')
print('static supply-chain checks: PASS')
PY

if [[ "${1:-}" == "--container" ]]; then
  : "${IMAGE:?IMAGE must name the built image}"
  : "${TRIVY_IMAGE:?TRIVY_IMAGE must be a pinned trivy image reference}"
  : "${SYFT_IMAGE:?SYFT_IMAGE must be a pinned syft image reference}"
  docker run --rm -v "$PWD:/src:ro" "$SYFT_IMAGE" dir:/src -o spdx-json=/dev/stdout > sbom.spdx.json
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" image --scanners vuln,license --exit-code 1 --severity HIGH,CRITICAL "$IMAGE"
  docker run --rm -v "$PWD:/src:ro" "$TRIVY_IMAGE" fs --scanners secret --exit-code 1 /src
fi
