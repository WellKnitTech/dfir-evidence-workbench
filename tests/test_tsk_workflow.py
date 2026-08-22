from subprocess import CompletedProcess
from dfir_workbench import tsk_workflow

def test_tsk_inspection_normalizes_partition_and_inode_provenance(tmp_path, monkeypatch):
    image = tmp_path / "evidence.img"; image.write_bytes(b"synthetic image")
    def fake_run(tool, args, **kwargs):
        if args == ["-V"]: return CompletedProcess(tool, 0, stdout="Sleuth Kit 4.15.0\n", stderr="")
        outputs = {"img_stat": "Image type: raw\n", "mmls": " 0:      0      0      0  Primary Table\n 1:      1   4096   4096  NTFS\n", "fsstat": "FILE SYSTEM INFORMATION\n", "fls": "r/r 128: /Users/alice/notes.txt\nd/d 5: /Users/alice\n"}
        return CompletedProcess(tool, 0, stdout=outputs[tool], stderr="")
    monkeypatch.setattr(tsk_workflow.shutil, "which", lambda tool: "/bin/true")
    monkeypatch.setattr(tsk_workflow, "_run", fake_run)
    record = tsk_workflow.run_tsk_raw_image(image, tmp_path / "analysis", partition_index=1)
    partition = next(p for p in record["partition_filesystem"]["partitions"] if p["index"] == 1)
    assert partition["start_sector"] == 1
    entry = next(item for item in record["inventory"] if item["path"].endswith("notes.txt"))
    assert entry["source_id"] == "partition:1:inode:128"
    assert (tmp_path / "analysis" / "tool-manifest.json").is_file()

def test_tsk_missing_binary_is_explicit(tmp_path, monkeypatch):
    image = tmp_path / "evidence.img"; image.write_bytes(b"x")
    monkeypatch.setattr(tsk_workflow.shutil, "which", lambda tool: None)
    result = tsk_workflow.run_tsk_raw_image(image, tmp_path / "analysis")
    assert result["status"] == "unavailable"; assert result["error"]["code"] == "TOOL_UNAVAILABLE"
    try: tsk_workflow.TSKRawImageWorkflow(__import__("pathlib").Path("/dev/null"), tmp_path / "other")
    except tsk_workflow.TSKWorkflowError as exc: assert exc.code == "HOST_DEVICE_REJECTED"
    else: raise AssertionError("host device was accepted")
