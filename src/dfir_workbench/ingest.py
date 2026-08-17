"""Pre-commit ingestion boundary for DFIR Evidence Workbench.

Wires the reviewed schemas + interop helpers + both vendor projection adapters
(TheHiveIngestAdapter, DFIRIRISIngestAdapter) into a safe intake path that
produces ingest-envelopes for preview storage.

Responsibilities (fail-closed):
- Select adapter by source_system ("hive" | "iris"); unknown -> rejected
- Project raw vendor payload -> interop-entity (adapters enforce reject_secret_keys,
  record lossy_transformations, set quarantined redaction_flags for unsupported)
- Build append-only ingest-envelope preserving *raw* payload + its sha256 +
  mapping_version + idempotency_key from provenance
- Redaction decision "quarantined" or secret failure -> status=quarantined
- Unknown scope, unsupported entity, bad fields -> IngestValidationError (rejected)
- Idempotency key reuse: same key + different sha -> conflict (handled in repo)
- Findings carry approval_required=True (enforced by interop schema)
- Evidence always content_transferred=False (enforced by projection)
- Never transport bytes, never mutate vendor, never silent drop

Preview returns structured counts: accepted | duplicate | rejected | conflict | quarantined
(preview/validated treated as accepted for pre-commit summary).

Use via:
  from dfir_workbench.ingest import preview_vendor_payload, build_envelope_for_preview
  from dfir_workbench.adapters import ...

All operations are pure or use caller-supplied repo+principal (tenant from principal only).

See schemas/, adapters/*_ingest_adapter.py, interop.py, db.py IngestRepository.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from dfir_workbench.adapters import DFIRIRISIngestAdapter, TheHiveIngestAdapter
from dfir_workbench.interop import (
    IngestValidationError,
    payload_sha256,
    validate_ingest_envelope,
    validate_interop_entity,
)

MAPPING_VERSION = "1.0.0"
POLICY_VERSION = "workbench-ingest-boundary-1"


def _get_adapter(source_system: str, integration_id: str) -> Any:
    ss = (source_system or "").lower().strip()
    if ss == "hive":
        return TheHiveIngestAdapter(integration_id)
    if ss == "iris":
        return DFIRIRISIngestAdapter(integration_id)
    raise IngestValidationError(f"unknown source_system for projection: {source_system}")


def project_vendor_payload(
    raw: dict[str, Any],
    *,
    source_system: str,
    entity: str,
    source_scope: str,
    integration_id: str = "default",
    source_id: str | None = None,
    source_revision: str | None = None,
    **kw: Any,
) -> dict[str, Any]:
    """Project raw vendor dict to validated interop-entity.

    Delegates to the correct adapter; adapters raise IngestValidationError on
    secrets or missing requireds. Records lossy + redaction decisions.
    """
    if not isinstance(raw, dict):
        raise IngestValidationError("raw payload must be dict")
    if not source_scope or not str(source_scope).strip():
        raise IngestValidationError("source_scope is required (tenant/customer isolation)")
    adapter = _get_adapter(source_system, integration_id)
    # use the dispatch project() if present (both adapters have it)
    if hasattr(adapter, "project"):
        ent = adapter.project(
            raw,
            entity=entity,
            source_scope=source_scope,
            source_id=source_id,
            source_revision=source_revision,
            **kw,
        )
    else:
        # fallback for specific
        meth = getattr(adapter, f"project_{entity}", None)
        if meth is None:
            raise IngestValidationError(f"unsupported entity {entity} for {source_system}")
        ent = meth(raw, source_scope=source_scope, source_id=source_id, source_revision=source_revision, **kw)
    validate_interop_entity(ent)
    return ent


def build_envelope_for_preview(
    raw_payload: dict[str, Any],
    interop_entity: dict[str, Any],
    *,
    received_at_utc: str | None = None,
) -> dict[str, Any]:
    """Construct a validated ingest-envelope around the raw payload + its projection.

    - payload = verbatim vendor raw (for audit/replay)
    - sha256 over raw
    - status derived from redaction_flags: any quarantined => quarantined else preview
    - preserves mapping_version, idempotency_key from provenance
    - source fields pulled from provenance (authoritative after projection)
    """
    if not isinstance(raw_payload, dict):
        raise IngestValidationError("raw_payload must be dict for envelope")
    if not isinstance(interop_entity, dict):
        raise IngestValidationError("interop_entity required")

    prov = interop_entity.get("provenance", {})
    src = {
        "system": prov.get("source_system"),
        "entity": prov.get("source_entity"),
        "id": prov.get("source_id"),
        "scope": prov.get("source_scope"),
        "revision": prov.get("source_revision"),
        "updated_at_raw": prov.get("source_updated_at_raw"),
        "updated_at_utc": prov.get("source_updated_at_utc"),
        "timezone": prov.get("source_timezone"),
    }
    for k, v in src.items():
        if v is None or (isinstance(v, str) and not v.strip()):
            raise IngestValidationError(f"incomplete source after projection: missing {k}")

    sha = payload_sha256(raw_payload)
    if received_at_utc is None:
        received_at_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    env_id = f"env-{uuid.uuid4().hex[:12]}"
    idem = prov.get("idempotency_key")
    mapping_ver = prov.get("mapping_version") or MAPPING_VERSION

    # redaction -> quarantine status for pre-commit record
    redaction_flags = prov.get("redaction_flags") or {}
    status = "preview"
    qref: str | None = None
    err: str | None = None
    for _k, flag in redaction_flags.items():
        if isinstance(flag, dict) and flag.get("decision") == "quarantined":
            status = "quarantined"
            qref = f"quarantine-{uuid.uuid4().hex[:8]}"
            err = flag.get("reason")
            break

    envelope: dict[str, Any] = {
        "schema_version": "1.0",
        "envelope_id": env_id,
        "received_at_utc": received_at_utc,
        "source": src,
        "payload_sha256": sha,
        "payload": dict(raw_payload),  # copy
        "processing": {
            "status": status,
            "mapping_version": mapping_ver,
            "idempotency_key": idem,
            "target_id": None,
            "error_code": err,
            "quarantine_reference": qref,
        },
    }
    validate_ingest_envelope(envelope)
    # interop already validated by caller
    return envelope


def _is_quarantined(interop: dict[str, Any]) -> bool:
    rf = interop.get("provenance", {}).get("redaction_flags", {}) or {}
    return any(
        isinstance(f, dict) and f.get("decision") == "quarantined" for f in rf.values()
    )


def preview_vendor_payload(
    raw: dict[str, Any],
    *,
    source_system: str,
    entity: str,
    source_scope: str,
    integration_id: str = "default",
    source_id: str | None = None,
    source_revision: str | None = None,
) -> dict[str, Any]:
    """Convenience: project + build envelope in one step. Returns dict with envelope, interop, status.

    Does NOT touch DB or principal. Caller does store_preview + counts.
    Raises IngestValidationError on redaction/secrets/unknowns (fail closed).
    """
    interop = project_vendor_payload(
        raw,
        source_system=source_system,
        entity=entity,
        source_scope=source_scope,
        integration_id=integration_id,
        source_id=source_id,
        source_revision=source_revision,
    )
    envelope = build_envelope_for_preview(raw, interop)
    status = envelope["processing"]["status"]
    return {
        "envelope": envelope,
        "interop": interop,
        "status": status,
        "idempotency_key": envelope["processing"]["idempotency_key"],
        "payload_sha256": envelope["payload_sha256"],
    }


async def ingest_preview_batch(
    repo: Any,  # IngestRepository to avoid circular
    principal: Any,  # Principal
    items: list[dict[str, Any]],
    *,
    source_system: str,
    entity: str | None = None,  # if per-item override in item
    source_scope: str,
    integration_id: str = "default",
) -> dict[str, Any]:
    """Batch pre-commit preview using projections + durable store.

    Each item: {"raw": <vendor dict>, "entity": "..."} or flat with "payload" etc.
    Returns counts + list of results. Tenant/analyst from principal only.
    """
    from dfir_workbench.db import IngestRepository  # local to avoid top import issues

    if not isinstance(repo, IngestRepository):
        # allow duck for tests
        pass

    results: list[dict[str, Any]] = []
    for it in items or []:
        raw = it.get("raw") or it.get("payload") or it
        ent = it.get("entity") or entity
        if not ent:
            raise IngestValidationError("entity required per-item or at batch level")
        sid = it.get("source_id")
        srev = it.get("source_revision")
        try:
            pv = preview_vendor_payload(
                raw,
                source_system=source_system,
                entity=ent,
                source_scope=source_scope,
                integration_id=integration_id,
                source_id=sid,
                source_revision=srev,
            )
            env = pv["envelope"]
            stored = await repo.store_preview(principal, envelope=env)
            # after store, status may be duplicate/conflict/quarantined/preview
            st = stored.processing_status
            results.append(
                {
                    "status": st,
                    "envelope_id": stored.envelope_id,
                    "idempotency_key": stored.idempotency_key,
                    "payload_sha256": stored.payload_sha256,
                    "quarantine_reference": stored.quarantine_reference,
                    "error_code": stored.error_code,
                }
            )
        except IngestValidationError as ve:
            # rejected path; do not store secrets etc.
            results.append(
                {
                    "status": "rejected",
                    "error_code": str(ve)[:200],
                    "idempotency_key": None,
                }
            )
        except Exception as e:  # fail closed
            results.append({"status": "rejected", "error_code": f"internal:{type(e).__name__}"})

    counts = {"accepted": 0, "duplicate": 0, "rejected": 0, "conflict": 0, "quarantined": 0}
    for r in results:
        st = r.get("status", "rejected")
        if st in ("preview", "validated", "received", "approved", "applied"):
            counts["accepted"] += 1
        elif st in counts:
            counts[st] += 1
        else:
            counts["rejected"] += 1
    return {"counts": counts, "results": results, "source_system": source_system}


# module level for parity with adapters
def preview_thehive(raw: dict[str, Any], *, source_scope: str, entity: str = "alert", **kw) -> dict[str, Any]:
    return preview_vendor_payload(raw, source_system="hive", entity=entity, source_scope=source_scope, **kw)


def preview_iris(raw: dict[str, Any], *, source_scope: str, entity: str = "case", **kw) -> dict[str, Any]:
    return preview_vendor_payload(raw, source_system="iris", entity=entity, source_scope=source_scope, **kw)
