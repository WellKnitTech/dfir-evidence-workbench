# Third-party software notice

This repository does not redistribute forensic tool binaries, client evidence,
proprietary detection content, or prebuilt tool images.

The tools documented under `docs/` are fetched from their official upstream
sources only when a user explicitly installs them. Their licenses, notices,
dependencies, and source-availability obligations remain applicable. The
commercial-use survey is an operational screening record, not legal advice.

Before distributing a container image or binary bundle, generate a fresh SBOM,
copy every upstream license/NOTICE file into `third_party/licenses/`, and run a
separate redistribution review. In particular, TSK has mixed component terms,
and Velociraptor and MISP modules are AGPL-licensed. Volatility 3 and Sigma
rules are intentionally not included in the approved install set.
For optional forensic tooling, `tools/forensic-tools.json` is the authoritative
lifecycle record. It intentionally marks artifacts without independently verified
checksums as unavailable and does not bundle binaries, rules, or client evidence.
