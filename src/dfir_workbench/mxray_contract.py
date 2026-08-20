"""Versioned, metadata-only contract for the MXRay email worker boundary."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

CONTRACT_VERSION = "1.0.0"
_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SECRET_WORDS = ("password", "passwd", "token", "api_key", "apikey", "secret", "private_key", "cookie", "authorization")
_RAW_FIELDS = {"raw_bytes", "raw_message", "message_bytes", "raw_content", "source_bytes"}


class MXRayContractError(ValueError):
    """Raised when an MXRay request/result violates the published boundary."""


def _validate(value: dict[str, Any], filename: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MXRayContractError("contract value must be an object")
    schema = json.loads((_SCHEMA_DIR / filename).read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value), key=lambda e: list(e.path))
    if errors:
        raise MXRayContractError(f"{filename} validation failed: {errors[0].message}")
    return copy.deepcopy(value)


def _reject_unsafe_fields(value: Any, path: str = "contract") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in _RAW_FIELDS:
                raise MXRayContractError(f"raw evidence field is forbidden at {path}.{key}")
            if any(word in normalized for word in _SECRET_WORDS):
                raise MXRayContractError(f"secret field is forbidden at {path}.{key}")
            _reject_unsafe_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_unsafe_fields(child, f"{path}[{index}]")


def build_idempotency_key(*, tenant_id: str, case_id: str, evidence_id: str, source_id: str, sha256: str, worker_version: str) -> str:
    parts = (tenant_id, case_id, evidence_id, source_id, sha256, worker_version)
    if not all(isinstance(part, str) and part for part in parts):
        raise MXRayContractError("idempotency inputs must be non-empty strings")
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    return "v1:" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def validate_job_request(value: dict[str, Any]) -> dict[str, Any]:
    result = _validate(value, "mxray-email-job-request.schema.json")
    _reject_unsafe_fields(result)
    context = result["context"]
    if result["policies"]["enrichment"]["enabled"] and result["policies"]["enrichment"]["network_egress"] == "disabled":
        raise MXRayContractError("enabled enrichment requires an explicitly allowlisted egress policy")
    for field in ("tenant_id", "case_id", "evidence_id", "source_id"):
        if not _SAFE_ID.fullmatch(context[field]):
            raise MXRayContractError(f"unsafe opaque identifier: {field}")
    expected = build_idempotency_key(
        tenant_id=context["tenant_id"], case_id=context["case_id"], evidence_id=context["evidence_id"],
        source_id=context["source_id"], sha256=result["input"]["sha256"], worker_version=result["toolchain"]["worker_version"],
    )
    if result["idempotency"]["key"] != expected:
        raise MXRayContractError("idempotency key mismatch")
    return result


def validate_job_result(value: dict[str, Any]) -> dict[str, Any]:
    result = _validate(value, "mxray-email-job-result.schema.json")
    _reject_unsafe_fields(result)
    if result["terminal_state"] == "quarantined" and "quarantine_reference" not in result["failure"]:
        raise MXRayContractError("quarantined results require a quarantine reference")
    return result
