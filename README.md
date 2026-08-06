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
- Additive PostgreSQL timeline-flag migration (requires live-schema review)
- Tool and commercial-use screening documentation
- Synthetic, non-client test fixtures generated during tests

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
python -m pip install -e '.[test]'  # or install pytest separately
python -m pytest -q
```

The project has no bundled forensic tools. See `docs/tooling-handoff.md` and
`docs/approved-tools-commercial-use.md` for the reviewed tool list and the
rules for fetching tools from official sources.

## Tool distribution model

The repository publishes code, manifests, and documentation—not third-party
forensic binaries. An explicit setup step may download pinned releases or
build tools from official upstream sources into an isolated container/Distrobox.
A future setup implementation must verify checksums, record versions, preserve
licenses/notices, and generate an SBOM. Publishing a prebuilt image containing
GPL/AGPL or mixed-license tools is redistribution and requires its own
compliance package.

## License

Project-authored code is Apache-2.0. Third-party components are not relicensed
by this notice; see `NOTICE.third-party.md` and the upstream references in
`docs/`.
