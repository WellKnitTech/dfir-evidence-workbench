# DFIR Evidence Workbench — tooling handoff

Date: 2026-08-06 UTC

## Result

The approved free-for-commercial-consulting tool set was installed and independently smoke-tested in the persistent Arch Distrobox named `arch`, using user-local binaries and the pinned Python virtual environment. The immutable Bazzite host was not modified.

Installed and verified:

- The Sleuth Kit / `fls` 4.15.0
- Autopsy 4.23.1 (pre-existing official installation; verified, not replaced)
- YARA 4.5.8
- bulk_extractor 2.1.1
- Plaso / `log2timeline` 20260512
- dfVFS 20260717
- Velociraptor 0.77.1
- FLARE-FLOSS 3.1.1
- CyberChef 11.3.0
- MISP modules 3.0.9

Fresh checks covered version/help/import checks and harmless fixture processing. All ten approved tools passed. During verification, bulk_extractor was rebuilt from the official 2.1.1 source against the current Distrobox Abseil ABI; the recorded `<cstdint>` compatibility patch was required by current GCC and is not a licensing exception.

## Reproduction

Installer: `/var/home/jwellnitz/.hermes/kanban/boards/dfir-evidence-workbench/workspaces/t_548292d2/install-approved-tools.sh`

Installation record: `/var/home/jwellnitz/.hermes/kanban/boards/dfir-evidence-workbench/workspaces/t_548292d2/installed-tools.md`

Run the installer from the host with the existing `arch` Distrobox. The supported runtime is inside that Distrobox; do not invoke the user-local bulk_extractor binary directly on the immutable host because its shared-library environment is not present there.

## Commercial-use screening

The ten tools are eligible for internal commercial consulting and analysis use under their documented upstream licenses. This is an operational screening result, not legal advice. Apache/BSD tools require preservation of licenses/notices; GPL/AGPL tools remain commercially usable for consulting and services, but conveying binaries, modified builds, or modified network-accessible services can trigger source, notice, and other copyleft obligations. Dependencies and bundled components require their own inventory.

License/compliance report: `/var/home/jwellnitz/.hermes/kanban/boards/dfir-evidence-workbench/attachments/t_14545012/tool-compliance-report.md`

## Exclusions

Volatility 3 and Sigma rules were intentionally not installed. The survey found licensing evidence insufficiently unambiguous for the project's no-ambiguous-license gate (Volatility Software License for Volatility 3; no SPDX license reported for the Sigma rules corpus). They require a separate legal/compliance review before approval.

Survey: `/var/home/jwellnitz/.hermes/kanban/boards/dfir-evidence-workbench/attachments/t_b93596e8/approved-tools-commercial-use.md`

## Operational controls

1. Keep upstream LICENSE/NOTICE files with any redistributed bundle, binary, or image.
2. Maintain an SBOM/dependency inventory.
3. Keep client evidence, proprietary rules, and client-derived indicators out of redistributed tool packages unless separately cleared.
4. Re-check release tags, package metadata, bundled notices, and dependency terms before production redistribution.
5. Use read-only evidence workflows; do not mount client images read-write or execute recovered files.
