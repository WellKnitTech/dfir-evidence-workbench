"""Authoritative validation for the versioned Workbench/OpenRelik schemas."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

CONTRACT_VERSION = "1.0.0"
_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")

class ContractValidationError(ValueError):
    """Raised when a request/result does not satisfy the published schema."""

def _validate(value: dict[str, Any], filename: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractValidationError("contract value must be an object")
    schema = json.loads((_SCHEMA_DIR / filename).read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value), key=lambda e: list(e.path))
    if errors:
        raise ContractValidationError(errors[0].message)
    return copy.deepcopy(value)

def _validate_ids(request: dict[str, Any]) -> None:
    context = request["immutable_context"]
    values = (
        context["tenant"]["tenant_id"], context["case"]["case_id"], context["asset"]["asset_id"],
        context["evidence"]["evidence_id"], context["acquisition"]["acquisition_id"],
    )
    if any(not _SAFE_ID.fullmatch(value) for value in values):
        raise ContractValidationError("identifiers must be safe opaque IDs")

def validate_job_request(value: dict[str, Any]) -> dict[str, Any]:
    result = _validate(value, "openrelik-job-request.schema.json")
    _validate_ids(result)
    return result

def validate_job_result(value: dict[str, Any]) -> dict[str, Any]:
    return _validate(value, "openrelik-job-result.schema.json")

def build_idempotency_key(tenant_id: str, case_id: str, evidence_id: str, evidence_sha256: str, workflow_name: str) -> str:
    material = "|".join((tenant_id, case_id, evidence_id, evidence_sha256, workflow_name))
    return "v1:" + hashlib.sha256(material.encode()).hexdigest()[:43]
