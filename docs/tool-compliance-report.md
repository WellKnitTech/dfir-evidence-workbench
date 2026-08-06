# DFIR Evidence Workbench Tool Verification and License Compliance

Verification date: 2026-08-06 UTC
Environment: persistent Arch Distrobox named `arch`, with user-local binaries and the approved Python virtual environment. The immutable Bazzite host was not modified.

## Decision rule

Commercial consulting and analysis use is considered eligible when the upstream license permits commercial use. This is an operational screening result, not legal advice. Redistributing binaries, modified copies, container images, or hosted modified services requires preserving license/NOTICE files and satisfying the applicable copyleft/source obligations. Dependency and bundled-component terms still apply.

## Verification results

All ten approved tools passed a fresh smoke test in the supported Arch Distrobox/user-local environment. The tests used version/help/import checks and, where practical, a harmless fixture. No tool was found to require removal on licensing grounds.

| Tool | Version observed | Smoke test | Result | License / commercial-use screening | Official source and license evidence |
|---|---:|---|---|---|---|
| The Sleuth Kit (`fls`) | 4.15.0 | `fls -V` | PASS | Mixed component licensing (Apache-2.0, GPL-2.0/GPL-3.0, BSD, MIT, CPL and third-party terms); commercial consulting/tool use eligible. Preserve component inventory/notices for redistribution. | https://github.com/sleuthkit/sleuthkit · https://github.com/sleuthkit/sleuthkit/blob/develop-4.1x/licenses/README.md |
| Autopsy | 4.23.1 | Executable exists and is executable; `file` identifies the installed launcher script. GUI launch was not performed by this headless smoke test. | PASS (installation/launcher) | Apache-2.0 for project code; commercial use and service delivery eligible, subject to bundled dependency notices and Apache terms. | https://github.com/sleuthkit/autopsy · https://github.com/sleuthkit/autopsy/blob/develop/LICENSE-2.0.txt |
| YARA | 4.5.8 | `yara --version`; compiled rule matched `test@example.com` in a fixture | PASS | BSD-3-Clause; commercial use eligible. Retain copyright, license, disclaimer, and no-endorsement notices. | https://github.com/VirusTotal/yara · https://github.com/VirusTotal/yara/blob/master/COPYING |
| bulk_extractor | 2.1.1 | `bulk_extractor -V`; processed a fixture and produced domain/email/URL feature files | PASS | GPL-3.0-or-later for project-authored post-NPS code, with separately identified original NPS and third-party material; commercial consulting/tool use eligible. Distribution of binaries or modified builds requires GPLv3 compliance and component inventory. | https://github.com/simsong/bulk_extractor · https://github.com/simsong/bulk_extractor/blob/main/LICENSE.md |
| Plaso / `log2timeline` | 20260512 | `log2timeline --version` | PASS | Apache-2.0 for project code; commercial use eligible, with dependency notices when redistributing. | https://github.com/log2timeline/plaso · https://github.com/log2timeline/plaso/blob/main/LICENSE |
| dfVFS | 20260717 | Python import succeeded (`dfvfs import OK`) | PASS | Apache-2.0; commercial use eligible, with dependency notices and patent terms when applicable. | https://github.com/log2timeline/dfvfs · https://github.com/log2timeline/dfvfs/blob/main/LICENSE |
| Velociraptor | 0.77.1 | `velociraptor version` returned version/build/system metadata | PASS | AGPL-3.0; commercial consulting and internal use eligible. Conveyed/modified binaries and modified network-accessible services must satisfy AGPL source and notice obligations. | https://github.com/Velocidex/velociraptor · https://github.com/Velocidex/velociraptor/blob/master/LICENSE |
| FLARE-FLOSS | 3.1.1 | `floss --version` | PASS | Apache-2.0; commercial use eligible, subject to license and bundled dependency notices. | https://github.com/mandiant/flare-floss · https://github.com/mandiant/flare-floss/blob/master/LICENSE.txt |
| CyberChef | 11.3.0 | Release HTML artifact exists and is non-empty (77,533 bytes); bundled `*.LICENSE.txt` files present | PASS (artifact integrity) | Apache-2.0 for project code; commercial use eligible, subject to bundled dependency notices. | https://github.com/gchq/CyberChef · https://github.com/gchq/CyberChef/blob/master/LICENSE |
| MISP modules | 3.0.9 | `misp-modules --help` returned usage successfully | PASS | AGPL-3.0; commercial consulting and internal use eligible. Conveyed/modified binaries and modified network functionality require AGPL source and notice compliance. | https://github.com/MISP/misp-modules · https://github.com/MISP/misp-modules/blob/main/LICENSE |

## Package and license metadata observed

- Arch package metadata: `sleuthkit 4.15.0-1`, URL `https://www.sleuthkit.org/sleuthkit`, licenses `CPL-1.0 GPL-2.0-or-later IPL-1.0`. Installed license files include Apache, GNUv2/GNUv3, IBM, BSD, CPL, MIT, and README inventory files under `/usr/share/licenses/sleuthkit/`.
- Arch package metadata also reports `yara 4.5.7-1` with BSD-3-Clause. This is the distro package, not the approved user-local build. The approved executable was explicitly invoked as `~/.local/bin/yara` and reported 4.5.8.
- Python package metadata: `plaso 20260512` and `dfVFS 20260717` report `License-Expression: Apache-2.0`; `misp-modules 3.0.9` reports `License-Expression: AGPL-3.0-only`. All point to the official GitHub project pages.
- Autopsy installation contains `/home/jwellnitz/Applications/autopsy-4.23.1/autopsy-4.23.1/LICENSE-2.0.txt` plus bundled dependency license files.
- CyberChef release contains multiple component license files, including `assets/main.js.LICENSE.txt`, worker licenses, and module licenses.

## Remediation performed during verification

The first runtime check found that the previously built bulk_extractor binary referenced an older Abseil ABI (`2601`) while the current Arch Distrobox provided `2605`, so it failed before startup. The official 2.1.1 source in `~/src/bulk_extractor-2.1.1` was rebuilt against the current Distrobox libraries (retaining the recorded `<cstdint>` compatibility patch), installed to `~/.local/bin`, and then passed both version and fixture-processing tests. This was a runtime compatibility issue, not a license non-compliance finding.

The supported invocation is the Arch Distrobox/user-local environment. Running the same user-local bulk_extractor binary directly on the immutable host does not have the Distrobox shared-library environment; do not treat host-direct invocation as the supported installation path.

## Exclusions

Volatility 3 and Sigma rules were not installed. They remain outside this approved set because the prior survey found licensing evidence insufficiently unambiguous for the no-ambiguous-license gate (Volatility Software License for Volatility 3; no SPDX license reported for the Sigma rules corpus). They were neither tested nor removed.

## Evidence artifacts

- Smoke logs: `smoke/final-smoke.txt`, `smoke/installed-tools-smoke.txt`, `smoke/distrobox-smoke.txt`, `smoke/bulk-rebuild.txt`
- Harmless fixture: `smoke/sample.txt`; YARA rule: `smoke/test.yar`
- bulk_extractor fixture output: `bulk-out/`
- Parent installation record: `/var/home/jwellnitz/.hermes/kanban/boards/dfir-evidence-workbench/workspaces/t_548292d2/installed-tools.md`
- Parent licensing survey: `/var/home/jwellnitz/.hermes/kanban/boards/dfir-evidence-workbench/workspaces/t_b93596e8/approved-tools-commercial-use.md`

## Operational controls

1. Keep each upstream LICENSE/NOTICE file with any redistributed tool bundle or image.
2. Maintain an SBOM/dependency inventory; top-level licenses do not replace dependency obligations.
3. For GPL/AGPL tools, charge for consulting, support, training, and analysis services without removing copyleft obligations from conveyed copies.
4. Re-check release tags, package metadata, and bundled notices before production redistribution.
5. Do not put client evidence, proprietary rules, or client-derived indicators into a redistributed tool package without a separate ownership/licensing review.
