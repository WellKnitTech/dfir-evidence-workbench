# PUBLIC-REFERENCE P0 capability report

Independent review: 2026-08-22T18:05:00Z (task `t_45bad142`)
Code base at packaging: `origin/main` @ `523e1f5` (MXRay #10 and Ask-AI #9 included)
Related open work: PR #11 `feat: reconcile native forensic capabilities` (not merged at review time)
Registry: `docs/public-reference-p0-registry.json`
Validation: `docs/public-reference-p0-validation.md`

## Executive summary

P0 public-reference intake is custody-sound for **9** external evidence objects: local SHA-256, signatures, and non-extractive archive tests all match. Workbench **analysis** capability against this set is intentionally degraded on the review host and on `origin/main`:

- Intake/hash/provenance packaging is ready (this document set).
- Native EWF raw-view, Sleuth Kit filesystem, and Volatility structured memory paths are **unavailable** on the host and are not shipped as pinned artifacts in `tools/manifest.yaml`.
- PR #11 adds fail-closed EWF/TSK/memory modules and a forensic-tool lifecycle gate; until it merges and tools are pinned, reports must not claim full filesystem or process-level coverage of P0 images.
- No public evidence binaries are packaged into the repository, CI, or `corpus-v1`.

## Scope checked

| Gate | Result |
|---|---|
| Source manifest SHA-256 | Confirmed `79be847d08ae555a16e098cdc8cb0e77a214174c1c7953f1798483650a4e6893` |
| Local item SHA-256 | 9/9 match |
| Inventory unexpected/partials | 0 / 0 |
| File signatures | EWF×4, ZIP×3, RAR×1, 7z×1 |
| Archive integrity (test-only) | ZIP/RAR/7z passed |
| Publisher digest verification | Not established (flags only; no digests/sidecars) |
| Expected-size fields | Not present in source manifest |
| Source immutability after review | Rehash OK; modes 644; mtimes unchanged |
| Extraction / mount / execution | Not performed |
| Licensing/terms recorded | Yes, per-item from acquisition manifest |
| Host native DFIR tools | libewf/TSK/Volatility unavailable |
| Tool packaging policy | Official-source metadata only; redistribution disabled by default |

## Tool and license boundary

From `tools/manifest.yaml` and `docs/tool-compliance-report.md` on main:

- Approved commercial-use screening covers Sleuth Kit, Autopsy, YARA, bulk_extractor, Plaso/dfVFS, Velociraptor, FLOSS, CyberChef, MISP modules when installed in the supported Distrobox path.
- Volatility 3 and Sigma rules remain **excluded pending license review** and must not be treated as available capability.
- The application does not silently download tools. Missing tools must surface as `unavailable` / degraded structured results, never as empty success or negative forensic conclusions.
- PR #11’s `tools/forensic-tools.json` (when merged) records libewf/TSK/plaso/yara as `unavailable-unpinned` and volatility/exiftool as excluded — fail-closed until artifacts and checksums are pinned.

Host probe during this review:

- Available: `file`, `sha256sum`, `unzip`, `unrar`, `7z`, `python3`, `podman`, `yara` (user-local), `npm`/`node`.
- Unavailable: `ewfinfo`/`ewfmount`/`ewfverify`, `mmls`/`fsstat`/`fls`/`img_stat`/`icat`, `log2timeline`/`plaso`, `volatility3`, `docker`, host `playwright` CLI.
- `bulk_extractor` binary present but broken on host ABI (`libabsl_base` missing); Distrobox path remains the supported install.

## Per-item capability matrix

Statuses are fail-closed for analysis depth. “Ready” means intake/custody only unless noted.

| Item | Lane | Custody | Analysis on origin/main + this host | Resource notes |
|---|---|---|---|---|
| SQLite corpus v1/v2 ZIP | sqlite-corpus | Ready | Archive integrity only. No dedicated SQLite anti-forensics adapter is claimed on main. Controlled extract to analysis root is a follow-on test lane (`t_f0820277`). | Small; safe for local analysis roots |
| nps-2010-emails.E01 | ewf-email-disk | Ready | EWF signature detectable by `DiskMemoryAdapter` / `file`. Partition/FS inventory and mailbox extraction **unavailable** without libewf raw-view + TSK/MXRay path. MXRay email path on main is for staged email jobs, not E01 containers. | 0.5 MiB |
| ntfs1-gen2.E01 | ewf-ntfs | Ready | Same EWF boundary. NTFS listing/extract not established without TSK. | ~34 MiB |
| ubnist1.casper-rw.gen3.E01 | ewf-linux-rw | Ready | Same EWF boundary. Largest E01 in set; enforce staging size ceilings before any extract. | ~161 MiB |
| nps-2009-canon2-gen6.E01 | ewf-camera | Ready | Same EWF boundary. | ~30 MiB |
| DFTT 1-extend-part.zip | partition-extended | Ready | ZIP integrity only until controlled extract. Extended-partition parsing requires raw image + TSK/`mmls`; tools unavailable → degraded. Terms: DFTT GPL — redistribution needs GPL compliance review. | ~164 KiB |
| CFReDS memory-images.rar | memory-images | Ready | RAR integrity only. Member inventory/hash after controlled extract is follow-on (`t_5b2f13e6`). Structured memory analysis unavailable (Volatility excluded/unpinned). Residue-only strings, if ever used, must be labeled non-process evidence. | ~494 MiB; largest object — bound CPU/RAM/disk for any extract |
| CFReDS winreg 7z | windows-registry | Ready | 7z integrity only (146 files / 29 folders listed, not extracted). Hive normalize/parse path not established on main. | ~5.9 MiB |

## Degraded-mode claims (normative for P0)

1. Missing native tool ⇒ structured `unavailable` / `degraded`, with unresolved scope and remediation. Never invent partitions, processes, or “no findings.”
2. Container formats (EWF, archives) recognized by signature/extension are **not** proof of successful filesystem or memory parse.
3. Publisher `publisher_hash: true` without a digest value is **not** a verified publisher hash.
4. Archive `t`/`list` success is integrity of the container, not validation of every member’s semantic content.
5. MXRay and Ask-AI gates on main remain offline/bounded by their own docs; they do not authorize executing recovered content from P0 or uploading P0 binaries to external services.
6. OpenRelik normal worker remains metadata inventory only (`docs/openrelik-worker-capability-profiles.md`); it is not a disk/memory parser for P0 E01/RAR payloads.
7. Resource limits: prefer separate analysis roots under mode 0700; refuse uncontrolled extract of the 494 MiB memory RAR into CI; keep max file/total ceilings as implemented in adapters (for example `DiskMemoryAdapter` defaults) and fail closed on overflow.

## Provenance packaging rules

Every derived artifact from P0 must carry:

- source relative path from the acquisition manifest
- source SHA-256
- source manifest SHA-256 `79be847d…6893`
- registration class `public-reference`
- analysis-root path distinct from the acquisition directory
- tool name/version or explicit `tool_unavailable`
- UTC timestamps

Do not place P0 paths under `corpus-v1` manifests. Synthetic corpus gates remain separate and immutable.

## Downstream test lanes (not executed by this review)

Sibling cards own execution against verified intake:

- `t_1076e40d` — EWF/TSK workflows on the four E01 images
- `t_5b2f13e6` — memory RAR capability/profile gates
- `t_f0820277` — SQLite, registry, email artifact paths
- `t_002a77b7` — negative/custody/safety regressions

This review only certifies intake truthfulness and packages capability/limit metadata for those lanes.

## Verdict

| Question | Answer |
|---|---|
| Is P0 custody baseline trustworthy? | **Yes**, after correcting item counts to 9 evidence objects |
| May binaries enter git/CI/corpus-v1? | **No** |
| Are publisher hashes independently verified? | **No** |
| Is full disk/memory analysis claimed on main + this host? | **No** — degraded/unavailable |
| Is packaging of metadata/docs required? | **Yes** — this PR |
| Merge PR #11 before claiming native EWF/TSK paths? | **Yes** |
