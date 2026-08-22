# PUBLIC-REFERENCE P0 validation report

Independent review timestamp: 2026-08-22T18:05:00Z
Upstream validation task: `t_b40858cd`
Independent review task: `t_45bad142`
Source manifest (operator-local, not in git): `AgenticForensicsTesting/ForensicsTestImage/PublicReference/P0/acquisition-manifest.json`
Source manifest SHA-256: `79be847d08ae555a16e098cdc8cb0e77a214174c1c7953f1798483650a4e6893`
Acquisition manifest `retrieved_utc`: `2026-08-20`
Machine-readable registry: `docs/public-reference-p0-registry.json`

## Disposition

The P0 directory contains **exactly 9 evidence files** named by the acquisition manifest, plus the acquisition manifest itself (10 files total on disk). All **9** local SHA-256 values match the manifest. File signatures match the declared extensions and intended roles: four EWF images, three ZIP archives, one RAR archive, and one 7z archive. ZIP, RAR, and 7z integrity tests completed successfully without extracting members.

The set is **conditionally registered for read-only analysis**. The manifest records `publisher_hash: true` for **six** Digital Corpora entries, but does not contain publisher digest values or detached publisher checksum files. Those publisher claims are therefore recorded but not independently verified here. The manifest also has no expected-size fields; observed byte sizes below are the intake baseline, not publisher-provided expected sizes.

### Correction to upstream validation prose

The upstream `t_b40858cd` handoff and draft report stated “10” evidence items and “five” Digital Corpora `publisher_hash` flags. Independent recount against the source manifest shows **9 evidence items** and **6** `publisher_hash: true` flags. Per-item hashes, sizes, URLs, terms, signatures, and archive integrity results from that upstream pass re-verified successfully; only the summary counts were wrong.

## File inventory and verification

| Manifest path | Observed bytes | Local SHA-256 | Signature / integrity | Source URL | Terms from manifest |
|---|---:|---|---|---|---|
| `digital-corpora/sqlite/sqlite_forensic_corpus_v1.0.zip` | 1,423,067 | `cfe9bdb9c88f78b5410dc25ad36cf0b36e1baaec6094c8945c91f8aea2b358f4` | ZIP; `unzip -t` passed | `https://downloads.digitalcorpora.org/corpora/sql/sqlite_forensic_corpus_v1.0.zip` | Digital Corpora public-domain/open corpus terms per acquisition matrix |
| `digital-corpora/sqlite/sqlite_forensic_corpus_v2.0.zip` | 5,370,116 | `8d71ff0ca595716b60ca7b6e9f0c7789e4612383f230e3742c9fc06ad39e95d8` | ZIP; `unzip -t` passed | `https://downloads.digitalcorpora.org/corpora/sql/sqlite_forensic_corpus_v2.0.zip` | Digital Corpora public-domain/open corpus terms per acquisition matrix |
| `digital-corpora/nps-2010-emails/nps-2010-emails.E01` | 518,680 | `c9ffd969954c2f9b9f97f459916c3d2e8755f596eda952c306ab3f9bc0d43bf1` | EWF/Expert Witness/EnCase signature | `https://downloads.digitalcorpora.org/corpora/drives/nps-2010-emails/nps-2010-emails.E01` | Digital Corpora NPS test image terms |
| `digital-corpora/nps-2009-ntfs1/ntfs1-gen2.E01` | 36,083,007 | `2badead91bef56c80155d7731671ad1d93c08f32cd4ce17566fdf02d5769feea` | EWF/Expert Witness/EnCase signature | `https://downloads.digitalcorpora.org/corpora/drives/nps-2009-ntfs1/ntfs1-gen2.E01` | Digital Corpora NPS test image terms |
| `digital-corpora/nps-2009-casper-rw/ubnist1.casper-rw.gen3.E01` | 168,365,166 | `f2ad970ab2c8ed41e2d26d0c7e821aaee0bb6fe71063ae17bea894306a8e55ff` | EWF/Expert Witness/EnCase signature | `https://downloads.digitalcorpora.org/corpora/drives/nps-2009-casper-rw/ubnist1.casper-rw.gen3.E01` | Digital Corpora NPS test image terms |
| `digital-corpora/nps-2009-canon2/nps-2009-canon2-gen6.E01` | 31,144,390 | `10483722d84e0cefcb693b11dea2d32dbd3ad2f06f8c9656688c8c730fe41579` | EWF/Expert Witness/EnCase signature | `https://downloads.digitalcorpora.org/corpora/drives/nps-2009-canon2/nps-2009-canon2-gen6.E01` | Digital Corpora NPS test image terms |
| `dftt/1-extend-part.zip` | 167,678 | `771cc763798ed23d85f6362de4adff503bf83c33c56c5ac8dea689a3996c8ce3` | ZIP; `unzip -t` passed | `https://downloads.sourceforge.net/project/dftt/Test%20Images/1_%20Extended%20Partition/1-extend-part.zip` | DFTT GPL per acquisition matrix; local SHA-256 baseline |
| `cfreds/memory-images.rar` | 518,372,568 | `9e1ba0de296a21fa606763e6bd207d741f06e3f23a19d2b6d507678ea516b5f8` | RAR v4; `unrar t` passed | `https://cfreds-archive.nist.gov/mem/memory-images.rar` | NIST/CFReDS public reference terms; local SHA-256 baseline |
| `cfreds/cfreds-2017-winreg_ugrd-nr.7z` | 6,151,857 | `7b68bc00c1c12744377e5a429d3e839a597ab228e94b5c2f8bfdd02abd779b67` | 7z; `7z t` passed; 146 files / 29 folders | `https://cfreds-archive.nist.gov/winreg/cfreds-2017-winreg/cfreds-2017-winreg_ugrd-nr.7z` | NIST/CFReDS public reference terms; local SHA-256 baseline |

## Safety and handling controls

- Originals were treated as read-only. No source bytes, manifest bytes, permissions, or timestamps were changed by this validation or the independent review.
- No archive member was extracted. Archive checks used test/list operations only.
- No disk image was mounted, and no recovered or archived content was executed.
- The files remain outside the repository and outside `corpus-v1`; this report contains metadata and hashes only and does not redistribute evidence.
- The material may contain personal data, mailbox content, registry data, or malware-like/test content. Treat all members as untrusted evidence; do not open by double-click, execute, or submit to external scanning services without explicit authorization. Keep raw exports restricted and redact report-facing PII.
- Derived artifacts must retain source manifest path and source SHA-256. Reconfirm license/terms before redistribution.

## Unexpected files and partials

Inventory found no unexpected files, detached partials, temporary downloads, or sidecar checksum files under the P0 acquisition directory. The only non-evidence file is the acquisition manifest itself. Because no publisher checksum sidecars are present, the six `publisher_hash: true` flags remain unverified claims rather than verified digest comparisons.

## Recommended registration state

Register all **9** evidence entries as `public-reference`, `read_only=true`, `execution_prohibited=true`, `redistribution_review_required=true`, and `publisher_hash_status=not_independently_verified`. Use the observed byte counts and local SHA-256 values above as the intake custody baseline. Do not copy these files into CI or `corpus-v1`.

## Verification commands

```text
sha256sum <each manifest item>
file <each manifest item>
unzip -t <each ZIP>
unrar t -idq <memory-images.rar>
7z t -bb0 <cfreds-2017-winreg_ugrd-nr.7z>
```

All independent review commands completed successfully. No evidence was modified.
