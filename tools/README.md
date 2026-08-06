# Tool bootstrap policy

The Workbench does not silently download forensic tools during normal startup.
Tool installation is an explicit operator action and must run in an isolated
container or Distrobox.

A production installer must:

1. Read `manifest.yaml`.
2. Resolve an exact upstream release artifact from the official source.
3. Verify a pinned SHA-256 or upstream signature before execution.
4. Refuse missing or changed checksums.
5. Preserve upstream LICENSE/NOTICE files.
6. Generate an SBOM and installed-tools record.
7. Keep the installed tool environment separate from the core application.
8. Avoid installing excluded tools without a separate license review.

This directory intentionally does not ship a downloader that guesses release
URLs or executes unverified binaries. That is a supply-chain control, not a
missing feature. The current Kanban work must add the implementation only after
format-specific artifact URLs and checksums are pinned.
