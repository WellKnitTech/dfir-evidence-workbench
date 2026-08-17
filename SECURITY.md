# Security policy

This is an alpha research prototype. Do not use it as the sole control for
production evidence handling.

Do not report client evidence, credentials, or sensitive indicators in public
issues. Use a private channel with the maintainers instead. Reproduction cases
must be synthetic or sanitized.

The project treats evidence as hostile input and does not execute recovered
files. Security fixes should include a regression test and provenance/coverage
impact notes.

## Deployment hardening notes (t_2e0301c2)
- Default exposure is localhost-only; LAN is explicit opt-in compose file + documented limitations (no TLS/auth/prod).
- Secrets never in templates or layers; least-privilege runtime enforced in compose.
- Backup/restore exercised; storage boundaries called out for evidence vs metadata.
- See README "Container deployment" and docs/backup-and-restore.md for current state vs production requirements.
