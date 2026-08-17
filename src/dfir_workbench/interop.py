"""Small, vendor-neutral helpers for TheHive/DFIR-IRIS-shaped ingestion.

This module deliberately stops before HTTP transport. It makes intake identity,
UTC normalization, and payload hashing deterministic so API and CSV adapters can
share the same contract.

Exposed helpers (stdlib only):
- canonical_json: stable serialization for hashing
- payload_sha256: over raw vendor payload
- idempotency_key: v1: over (integration_id, direction, source_system, source_entity, source_id, source_revision) 6-tuple
- utc_timestamp: (raw, utcZ) with tz enforcement
- reject_secret_keys: fail-closed heuristic on credential keys (before any serialization)
- validate_ingest_envelope / validate_interop_entity: use the reviewed JSON schemas (requires jsonschema in api env)
- IngestValidationError: the exception type

Raw vendor payloads are retained verbatim in ingest envelopes; normalized
projections live in separate interop-entity structures. No mapping performed here.

See docs/hive-iris-ingestion-research.md for verified contract, test evidence,
and explicit limitations.
"""
from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as _imp_exc:  # pragma: no cover
    Draft202012Validator = None  # type: ignore
    FormatChecker = None  # type: ignore
    _jsonschema_import_error = _imp_exc
else:
    _jsonschema_import_error = None


class IngestValidationError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def payload_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def idempotency_key(*, integration_id: str, direction: str, source_system: str,
                    source_entity: str, source_id: str, source_revision: str) -> str:
    parts = (integration_id, direction, source_system, source_entity, source_id, source_revision)
    if not all(isinstance(part, str) and part for part in parts):
        raise IngestValidationError("idempotency inputs must be non-empty strings")
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    return "v1:" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def utc_timestamp(raw: str) -> tuple[str, str]:
    """Return `(raw, normalized UTC)` and reject timezone-less source values."""
    if not isinstance(raw, str) or not raw.strip():
        raise IngestValidationError("timestamp must be a non-empty string")
    value = raw.strip()
    parsed_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(parsed_value)
    except ValueError as exc:
        raise IngestValidationError(f"invalid timestamp: {raw!r}") from exc
    if parsed.tzinfo is None:
        raise IngestValidationError("timestamp must include a timezone")
    normalized = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return raw, normalized


def reject_secret_keys(value: Any, path: str = "payload") -> None:
    """Fail closed on obvious credential-bearing keys before serialization."""
    secret_words = ("password", "passwd", "token", "api_key", "apikey", "secret", "private_key", "cookie")
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key).lower().replace("-", "_")
            if any(word in key_text for word in secret_words):
                raise IngestValidationError(f"forbidden secret field at {path}.{key}")
            reject_secret_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_keys(child, f"{path}[{index}]")


# Schema validation wired from reviewed contract files (schemas/*.json)
# These are used by API routes for preview/ingest to enforce the exact reviewed boundaries.
_SCHEMA_CACHE: dict[str, dict] = {}


def _get_schema_root() -> Path:
    """Locate schemas/ relative to project for dev + test pythonpath usage."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "schemas",   # src/dfir_workbench/... -> project root
        here.parents[1] / "schemas",   # if run differently
        Path.cwd() / "schemas",
        here.parent / "schemas",       # fallback
    ]
    for cand in candidates:
        if (cand / "ingest-envelope.schema.json").is_file():
            return cand
    raise RuntimeError(
        "Cannot locate schemas/ directory containing ingest-envelope.schema.json. "
        "Run from project root or ensure pythonpath includes the layout used in tests."
    )


def _load_schema(name: str) -> dict:
    if name in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[name]
    root = _get_schema_root()
    path = root / name
    schema = json.loads(path.read_text(encoding="utf-8"))
    _SCHEMA_CACHE[name] = schema
    return schema


def _validate_against(name: str, value: dict[str, Any]) -> None:
    if Draft202012Validator is None:
        if _jsonschema_import_error:
            raise IngestValidationError(
                f"jsonschema not available for schema validation (install via api extras): {_jsonschema_import_error}"
            )
        raise IngestValidationError("jsonschema validator not importable")
    schema = _load_schema(name)
    if Draft202012Validator is None:
        raise IngestValidationError("jsonschema not available")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=str)
    if errors:
        msgs = "; ".join(e.message for e in errors)
        raise IngestValidationError(f"{name} validation failed: {msgs}")


def validate_ingest_envelope(envelope: dict[str, Any]) -> None:
    """Validate a full ingest-envelope against the reviewed schema. Raises IngestValidationError on failure."""
    _validate_against("ingest-envelope.schema.json", envelope)


def validate_interop_entity(entity: dict[str, Any]) -> None:
    """Validate an interop-entity projection against the reviewed schema. Raises IngestValidationError on failure."""
    _validate_against("interop-entity.schema.json", entity)
