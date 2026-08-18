from types import SimpleNamespace
import copy, json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from dfir_workbench.openrelik_contract import ContractValidationError, build_idempotency_key, validate_job_request
from dfir_workbench.openrelik_adapter import OpenRelikAdapter, SQLiteJobStore

P = SimpleNamespace(tenant_id="tenant-1", case_id="case-1", analyst_id="analyst-1")
def request():
    r = {"contract_version":"1.0.0","request_id":"req-1","submitted_at_utc":"2026-08-17T19:00:00Z","immutable_context":{"tenant":{"tenant_id":"tenant-1"},"case":{"case_id":"case-1"},"asset":{"asset_id":"asset-1","asset_type":"endpoint"},"evidence":{"evidence_id":"evidence-1","sha256":"a"*64,"metadata_uri":"s3://metadata/evidence-1"},"acquisition":{"acquisition_id":"acq-1","method":"test","acquired_at_utc":"2026-08-17T18:00:00Z"}},"execution":{"read_only":True,"tool_profile":"triage-v1","capability_requirements":["filesystem_read"],"reviewer":{"reviewer_id":"reviewer-1","approval_reference":"approval-1"},"retention":{"policy_id":"case-default","retain_until_utc":"2027-08-17T00:00:00Z"},"expected_outputs":[{"output_type":"report","logical_name":"timeline","required":True}]},"idempotency":{"key":"","scope":"tenant-1:case-1:evidence-1"},"retry_policy":{"max_attempts":3,"backoff_seconds":0},"redaction_policy":{"policy_id":"safe-v1","version":"1.0.0"}}
    r["idempotency"]["key"] = build_idempotency_key("tenant-1","case-1","evidence-1","a"*64,"triage-v1")
    return r

def test_contract_is_validated_against_published_schema():
    value = request(); schema = json.loads((Path(__file__).parents[1]/"schemas/openrelik-job-request.schema.json").read_text())
    assert not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value)); validate_job_request(value)

def test_path_like_identifier_is_rejected():
    value = request(); value["immutable_context"]["evidence"]["evidence_id"] = "../../etc/passwd"
    with pytest.raises(ContractValidationError): validate_job_request(value)

def test_same_key_with_changed_payload_is_rejected():
    adapter = OpenRelikAdapter(_Transport(), SQLiteJobStore())
    value = request(); adapter.submit(P, value)
    changed = copy.deepcopy(value); changed["immutable_context"]["asset"]["asset_id"] = "asset-2"
    with pytest.raises(ValueError, match="IDEMPOTENCY_CONFLICT"):
        adapter.submit(P, changed)

def test_missing_and_foreign_jobs_have_uniform_denial():
    adapter = OpenRelikAdapter(_Transport(), SQLiteJobStore())
    adapter.submit(P, request())
    foreign = SimpleNamespace(tenant_id="tenant-2", case_id="case-2", analyst_id="analyst-2")
    with pytest.raises(PermissionError) as foreign_error: adapter.poll(foreign, "req-1", "case-1")
    with pytest.raises(PermissionError) as missing_error: adapter.poll(P, "missing", "case-1")
    assert str(foreign_error.value) == str(missing_error.value) == "job not found"

def test_submit_poll_retry_and_denial_emit_audit_events():
    events=[]; sink=type("Sink",(),{"emit":lambda self,event,payload: events.append(event)})()
    adapter=OpenRelikAdapter(_Transport(), SQLiteJobStore(), audit_sink=sink)
    adapter.submit(P, request()); adapter.poll(P, "req-1", "case-1"); adapter.retry(P, "req-1", "case-1")
    with pytest.raises(PermissionError): adapter.poll(SimpleNamespace(tenant_id="other",analyst_id="a"),"req-1", "case-1")
    assert events == ["openrelik.submit","openrelik.poll","openrelik.retry","openrelik.deny"]

class _Transport:
    def submit(self, request, *, idempotency_key): return {"workflow_id":"wf-1","task_id":"task-1","status":"queued"}
    def status(self, workflow_id, task_id=None): return {"contract_version":"1.0.0","request_id":"req-1","workflow":{"workflow_id":workflow_id,"status":"succeeded","executor":"harness"},"tasks":[{"task_id":"task-1","status":"succeeded","attempt":1}],"logs":[],"reports":[],"artifacts":[],"provenance":{"tenant_id":"tenant-1","case_id":"case-1","asset_id":"asset-1","evidence_id":"evidence-1","workflow_id":workflow_id,"request_id":"req-1","idempotency_key":build_idempotency_key("tenant-1","case-1","evidence-1","a"*64,"triage-v1")},"terminal_state":"succeeded"}
