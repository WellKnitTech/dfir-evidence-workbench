# Release and redistribution checklist

Before publishing a source release:

- [ ] Run the full test suite and syntax checks.
- [ ] Scan the tree for secrets, client evidence, raw images, and credentials.
- [ ] Confirm only synthetic fixtures are present.
- [ ] Recheck every upstream tool version, URL, checksum, license, and NOTICE.
- [ ] Generate an SBOM for the source and runtime dependencies.
- [ ] Keep tool downloads out of normal application startup.
- [ ] Do not publish a prebuilt tool image without a separate redistribution review.
- [ ] For GPL/AGPL tools, verify source/notice obligations before conveying binaries.
- [ ] Verify migrations against the actual supported database schema.
- [ ] Tag the release only after CI and manual evidence-handling review pass.

This checklist is operational guidance, not legal advice.
