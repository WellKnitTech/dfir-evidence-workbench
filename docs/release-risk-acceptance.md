# Release risk disposition: pinned API base image

This record documents the base-image refresh that cleared the release vulnerability gate. It is not a vulnerability waiver.

- **Image:** `docker.io/library/python@sha256:cc19a3e1085aba7d26690cf0725d9a3e083cbea0feec34ba8133d40a8ac1d399`
- **Resolved base:** Python 3.11.16 Alpine 3.24.1
- **Scan:** Trivy 0.69.1, vulnerability and license scanners, 2026-08-19
- **Vulnerability database:** Trivy DB downloaded 2026-08-19 during verification
- **Result:** 0 HIGH, 0 CRITICAL findings in the built application image
- **Disposition:** vulnerability gate **PASSED**; no risk acceptance or production exception is required.

## Findings resolved

The prior Debian slim digest produced 26 HIGH/CRITICAL findings (22 HIGH, 4 CRITICAL), all inherited from the base image. The refreshed Alpine digest removed those OS-package findings. Trivy also identified two HIGH Python packaging findings in the unmodified Alpine base (`jaraco.context==5.3.0`, `wheel==0.45.1`); the Dockerfile installs the fixed versions `jaraco.context==6.1.0` and `wheel==0.46.2` before the application lock, and the final image scan reports zero HIGH/CRITICAL findings.

The final image scan covered both OS and language-specific packages. No vulnerability was suppressed, ignored, or accepted. License results remain available in the complete Trivy JSON output generated during the verification run.

## Residual exposure and controls

No release-blocking vulnerability remains in the scanned image. The image still runs as UID 10001, uses a read-only root filesystem in the production compose template, drops capabilities, enables `no-new-privileges`, has no source bind mount, and has no direct published API port. These controls remain defense in depth and are not being used to override a scanner result.

## Required maintenance

1. Re-run the pinned Trivy vulnerability, license, and secret scans whenever the base digest or dependency lock changes.
2. Refresh the pinned Python Alpine digest before expiry of the organization's normal dependency-refresh interval and whenever Trivy reports a new HIGH/CRITICAL finding.
3. Keep the release gate configured to fail on HIGH and CRITICAL findings; do not add ignore rules without a separately approved, time-bounded exception naming each finding, owner, compensating controls, and expiry.

## Verification record

- `podman build --pull=false --no-cache --tag dfirwb-refresh:test .`: passed.
- Final image Trivy vulnerability/license scan: passed; 0 HIGH, 0 CRITICAL.
- Trivy secret scan of the repository: required and recorded by the release verification command.
- Syft SPDX JSON SBOM: generated as `sbom.spdx.json`, SHA-256 `592be0fc3537021cc4167edde6617a3189eaf3e7c7014f073743981f0b11fb6d`; it is a build artifact and is not part of the runtime image.
- Python tests, compile checks, pip checks, compose validation, static supply-chain checks, and diff checks are independent gates and do not override the vulnerability result.
