import json, struct, tempfile, unittest
from pathlib import Path
from dfir_workbench.adapters.disk_memory_adapter import DiskMemoryAdapter, detect_memory

class AdapterTests(unittest.TestCase):
    def test_raw_mbr_inventory_and_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"sample.img"; b=bytearray(2*1024*1024); e=bytearray(16); e[4]=0x83; struct.pack_into("<II",e,8,1,1024); b[446:462]=e; b[510:512]=b"\x55\xaa"; b[512+0x38:512+0x3a]=b"\x53\xef"; p.write_bytes(b)
            r=DiskMemoryAdapter(p,Path(d)/"stage").normalized_record("disk_image")
            self.assertEqual(r["partition_filesystem"]["partitions"][0]["offset_bytes"],512); self.assertEqual(r["partition_filesystem"]["partitions"][0]["filesystem"],"ext"); self.assertEqual(len(r["inventory"]),1); self.assertEqual(len(r["inventory"][0]["sha256"]),64)
    def test_vhd_signature_and_memory_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            v=Path(d)/"x.vhd"; v.write_bytes(b"x"*1024+b"conectix"+b"y"*504); self.assertEqual(DiskMemoryAdapter(v,Path(d)/"s").validate("disk_image")["detected_format"],"vhd")
            m=Path(d)/"mem.dmp"; m.write_bytes(b"DUMP"+b"\0"*100); r=DiskMemoryAdapter(m,Path(d)/"s2").normalized_record("memory_dump"); self.assertEqual(r["adapter_metadata"]["memory_dump"]["format"],"windows-crash-dump"); self.assertTrue(r["collection_coverage"]["memory_artifacts"])
    def test_safe_extraction_rejects_traversal_and_hashes_copy(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"e.img"; p.write_bytes(b"abc"); ad=DiskMemoryAdapter(p,Path(d)/"stage"); r=ad.extract(["../escape", "/tmp/x", p.name]); self.assertEqual(r["status"],"partial"); self.assertEqual(len(r["extracted"]),1); self.assertTrue(Path(r["extracted"][0]["path"]).is_relative_to(Path(d)/"stage")); self.assertEqual(r["extracted"][0]["sha256"],ad.inventory("disk_image")["inventory"][0]["sha256"])
    def test_event_logs_are_not_labeled_as_memory(self):
        for name, data in {"memdump.mem": b"ElfFile\x00synthetic-etl", "events.evtx": b"ElfFile\x00synthetic-event-log", "trace.etl": b"ETL\x00synthetic-etl"}.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                path=Path(d)/name; path.write_bytes(data); self.assertIn(detect_memory(path)[0], {"windows-etl", "windows-event-log"}); record=DiskMemoryAdapter(path,Path(d)/"stage").normalized_record("memory_dump"); self.assertEqual(record["source_type"],"event_log"); self.assertNotIn("memory_dump",record["adapter_metadata"]); self.assertFalse(record["collection_coverage"]["memory_artifacts"]); self.assertEqual(record["adapter_metadata"]["event_log"]["records"],[])
    def test_memory_headers_remain_format_specific(self):
        for prefix, expected in [(b"\x7fELF","elf-memory"),(b"DUMP","windows-crash-dump"),(b"VMCORE\x00","vmcore"),(b"not-a-known-header","raw-memory")]:
            with tempfile.TemporaryDirectory() as d:
                path=Path(d)/"sample.mem"; path.write_bytes(prefix+b"\0"*32); self.assertEqual(detect_memory(path)[0],expected)
if __name__ == "__main__": unittest.main()
