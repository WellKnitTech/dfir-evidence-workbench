# Disk-image prototype workflow

`dfir_workbench.disk_workflow.run_disk_fixture()` is the supported test harness for
small synthetic disk images. It stages a source into a separate mode-0700 analysis
root, hashes it before and after processing, derives partition offsets from the
image metadata, emits a normalized evidence record, and optionally extracts only
the staged image artifact. It never mounts an image and never writes to the source.

The corpus-backed regression tests cover:

- a raw MBR image with an ext filesystem marker (`disk-ext4-normal-001`);
- a partition-table/reference image with a deliberately incomplete GPT header
  (`disk-gpt-mbr-001`); and
- containment, source-integrity, golden-output, and normalized-schema checks.

The current adapter provides metadata-level coverage only. File inventory is the
source/container artifact, not a filesystem file listing, and deleted/orphan,
slack, and unallocated records are explicitly reported as unavailable. Native
TSK tools (`mmls`, `fsstat`, `fls`, `icat`, `tsk_recover`) are not bundled or
assumed. VHD/VMDK/EWF/QCOW2 containers are recognized only when their signatures
are detectable; parsing their contained filesystem requires a future readable
raw-view/native-tool adapter. E01 is not guessed as EWF from its filename.

Run the focused workflow gate with:

```text
python -m pytest -q tests/test_disk_workflow.py
```
