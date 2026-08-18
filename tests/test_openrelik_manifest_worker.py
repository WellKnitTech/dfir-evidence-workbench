import hashlib
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


WORKER_ROOT = Path(__file__).parents[1] / "workers" / "openrelik-manifest-worker"
SRC = WORKER_ROOT / "src"


def test_worker_hashes_read_only_source_and_emits_provenance(tmp_path):
    source = tmp_path / "staged.evtx"
    source.write_bytes(b"synthetic-evtx")
    original = source.read_bytes()
    output = tmp_path / "output"

    sys.path.insert(0, str(SRC))
    try:
        from openrelik_manifest_worker.worker import run_task

        result = run_task(
            source_path=source,
            output_dir=output,
            task_id="task-123",
            evidence_id="evidence-123",
            artifact_id="artifact-123",
        )
    finally:
        sys.path.remove(str(SRC))

    assert source.read_bytes() == original
    assert result["status"] == "completed"
    assert result["task_id"] == "task-123"
    assert result["artifacts"][0]["artifact_id"] == "artifact-123"
    assert result["artifacts"][0]["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["provenance"]["evidence_id"] == "evidence-123"
    metadata_path = Path(urlparse(result["metadata_uri"]).path)
    assert metadata_path.is_file()
    assert b"synthetic-evtx" not in metadata_path.read_bytes()


def test_worker_rejects_output_inside_source_directory(tmp_path):
    source = tmp_path / "staged"
    source.mkdir()
    (source / "event.evtx").write_bytes(b"event")
    sys.path.insert(0, str(SRC))
    try:
        from openrelik_manifest_worker.worker import WorkerError, run_task

        try:
            run_task(source_path=source, output_dir=source / "output", task_id="t", evidence_id="e")
        except WorkerError as exc:
            assert exc.code == "OUTPUT_INSIDE_SOURCE"
        else:
            raise AssertionError("worker accepted output inside source")
    finally:
        sys.path.remove(str(SRC))


def test_worker_cli_smoke_has_no_privileged_device_access(tmp_path):
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"evidence")
    output = tmp_path / "output"
    completed = subprocess.run(
        [
            sys.executable,
            str(SRC / "openrelik_manifest_worker" / "worker.py"),
            "--input",
            str(source),
            "--output",
            str(output),
            "--task-id",
            "task-cli",
            "--evidence-id",
            "evidence-cli",
        ],
        env={"PYTHONPATH": str(SRC)},
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(completed.stdout)
    assert payload["status"] == "completed"
    assert "dev" not in payload["metadata_uri"]
    assert "/dev" not in completed.stdout
