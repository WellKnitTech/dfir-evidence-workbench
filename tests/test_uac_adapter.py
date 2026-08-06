import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from dfir_workbench.adapters.uac_adapter import AdapterError, UACAdapter


def test_directory_inventory_and_extract(tmp_path):
    src = tmp_path / "uac"
    (src / "nested dir").mkdir(parents=True)
    payload = b"hello UAC\n"
    (src / "nested dir" / "empty file").write_bytes(b"")
    (src / "nested dir" / "a file.txt").write_bytes(payload)
    a = UACAdapter(src, tmp_path / "analysis")
    assert a.validate()["status"] == "not_applicable"
    inv = a.inventory()
    f = next(x for x in inv if x["path"] == "nested dir/a file.txt")
    assert f["sha256"] == hashlib.sha256(payload).hexdigest()
    report = a.report()
    assert report["collection_coverage"]["status"] == "substantial"
    extracted = a.extract(["nested dir/a file.txt"])
    assert extracted["extracted_count"] == 1
    assert (Path(extracted["root"]) / "nested dir/a file.txt").read_bytes() == payload


def test_zip_hashes_and_safe_extract(tmp_path):
    archive = tmp_path / "collection.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("Windows/System32/log.txt", b"log")
        z.writestr("../escape.txt", b"no")
        z.writestr("/absolute.txt", b"no")
    a = UACAdapter(archive, tmp_path / "analysis")
    assert a.validate()["status"] == "valid"
    inv = a.inventory()
    assert next(x for x in inv if x["path"] == "Windows/System32/log.txt")["sha256"] == hashlib.sha256(b"log").hexdigest()
    out = a.extract(["Windows/System32/log.txt", "../escape.txt"])
    assert out["extracted_count"] == 1
    assert out["rejected_count"] >= 2
    assert not (tmp_path / "escape.txt").exists()


def test_tar_symlink_rejected(tmp_path):
    archive = tmp_path / "collection.tar"
    with tarfile.open(archive, "w") as t:
        info = tarfile.TarInfo("good.txt"); data = b"ok"; info.size = len(data)
        t.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("bad-link"); link.type = tarfile.SYMTYPE; link.linkname = "../../outside"
        t.addfile(link)
    a = UACAdapter(archive, tmp_path / "analysis")
    assert a.validate()["status"] == "valid"
    assert next(x for x in a.inventory() if x["path"] == "bad-link")["kind"] == "symlink"
    out = a.extract(["good.txt", "bad-link"])
    assert out["extracted_count"] == 1
    assert any(e["code"] == "SYMLINK_REJECTED" for e in out["errors"])


def test_empty_allowlist_does_not_extract(tmp_path):
    src = tmp_path / "src"; src.mkdir(); (src / "x").write_bytes(b"x")
    out = UACAdapter(src, tmp_path / "analysis").extract([])
    assert out["status"] == "not_requested"
    assert out["extracted_count"] == 0


def test_invalid_archive_fails_closed(tmp_path):
    p = tmp_path / "bad.zip"; p.write_bytes(b"not a zip")
    a = UACAdapter(p, tmp_path / "analysis")
    assert a.validate()["status"] == "invalid"
    with pytest.raises(AdapterError, match="invalid archive"):
        a.inventory()
