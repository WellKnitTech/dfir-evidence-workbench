# MXRay supply-chain evidence

Acceptance was run from this checkout with the following results:

- `npm ci` completed and installed the locked frontend dependency graph.
- `npm audit --audit-level=high` reported `found 0 vulnerabilities`.
- `npm sbom --sbom-format cyclonedx` generated a CycloneDX 1.5 document with 33 frontend components. The committed `frontend/package-lock.json` is the reproducible input; regenerate the SBOM in CI rather than committing a machine-specific absolute-path report.
- `podman compose config --quiet` completed successfully. Compose emitted only the expected unset-development-variable warning for `DFIRWB_DATABASE_URL`; no secret value was supplied or written.
- `syft`, `trivy`, `cyclonedx`, and `pip-audit` were not installed in the acceptance environment, so no claim is made that those scanners ran.

MXRay itself remains stdlib-only and does not vendor or execute ExifTool, YARA Forge rules, or other forensic engines. See `docs/mxray-licensing-boundary.md` for the integration boundary and requirements for any future dependency.
