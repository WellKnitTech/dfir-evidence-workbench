import json, zipfile
from pathlib import Path
from dfir_workbench.adapters.velociraptor_adapter import VelociraptorAdapter, AdapterError, SafetyLimits


def make_bundle(tmp_path):
    bundle = tmp_path / 'vr-client-C. zip'.replace(' ', '')
    with zipfile.ZipFile(bundle, 'w') as z:
        z.writestr('client_id-C.123/metadata.json', '{"client_id":"C.123","flow_id":"F.9","hunt_id":"H.2"}')
        z.writestr('client_id-C.123/Windows/Users/A User/notes.txt', 'triage')
        z.writestr('client_id-C.123/empty.csv', '')
    return bundle


def test_inventory_hash_metadata_extract(tmp_path):
    bundle = make_bundle(tmp_path)
    a = VelociraptorAdapter(bundle, tmp_path / 'analysis')
    record = a.collect(['client_id-C.123/Windows/Users/A User/notes.txt'])
    assert record['source_type'] == 'velociraptor_triage'
    assert len(record['inventory']) == 3
    assert record['adapter_metadata']['identifiers']['client_id'] == 'C.123'
    assert record['safe_extraction']['extracted_count'] == 1
    out = Path(record['safe_extraction']['root']) / 'client_id-C.123/Windows/Users/A User/notes.txt'
    assert out.read_text() == 'triage'


def test_traversal_rejected(tmp_path):
    bundle = tmp_path / 'bad.zip'
    with zipfile.ZipFile(bundle, 'w') as z: z.writestr('../escape.txt', 'x')
    try:
        VelociraptorAdapter(bundle, tmp_path / 'analysis').inventory()
    except AdapterError as e:
        assert e.code == 'PATH_TRAVERSAL_REJECTED'
    else: raise AssertionError('unsafe member accepted')


def test_limits_fail_closed(tmp_path):
    bundle = tmp_path / 'large.zip'
    with zipfile.ZipFile(bundle, 'w') as z: z.writestr('x.bin', '12345')
    try: VelociraptorAdapter(bundle, tmp_path / 'analysis', SafetyLimits(max_file_bytes=3)).inventory()
    except AdapterError as e: assert e.code == 'FILE_LIMIT_EXCEEDED'
    else: raise AssertionError('limit not enforced')
