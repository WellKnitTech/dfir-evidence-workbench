"""TheHive ingest projection adapter.

Read-only normalization of TheHive case, alert, observable, and task/log timeline
inputs into the vendor-neutral interop-entity schema.

- Preserves: opaque org scope, source IDs/revisions, raw+UTC timestamps, tags,
  TLP/PAP (mapped to names), exact observable value/type.
- Drops (with lossy record): status, ownership, deletion, Cortex jobs, MISP events,
  evidence bytes, attachment content, custom analyzer results.
- Rejects secrets via interop.reject_secret_keys (IngestValidationError) -> quarantine upstream.
- Unsupported types (attachment, file, binary) are quarantined via redaction decision.
- No HTTP, no live vendor calls, no evidence bytes ever loaded.
- Synthetic fixtures only; deterministic output for given inputs.

See docs/hive-iris-ingestion-research.md and schemas/interop-entity.schema.json.
"""

from __future__ import annotations

import uuid
from typing import Any

from dfir_workbench.interop import (
    IngestValidationError,
    idempotency_key,
    reject_secret_keys,
    utc_timestamp,
)

MAPPING_VERSION = "1.0.0"
POLICY_VERSION = "thehive-projection-1"

_TLP_MAP = {0: "white", 1: "green", 2: "amber", 3: "red", -1: "unknown"}
_PAP_MAP = _TLP_MAP.copy()

_UNSUPPORTED_OBSERVABLE_TYPES = {"file", "attachment", "binary", "hash:other"}


def _map_tlp_pap(val: Any) -> str | None:
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return _TLP_MAP.get(int(val), str(int(val)))
    if isinstance(val, str):
        v = val.lower().strip()
        if v in ("white", "green", "amber", "red", "unknown"):
            return v
        try:
            return _TLP_MAP.get(int(v), v)
        except Exception:
            return v
    return str(val)


def _safe_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _choose_ts(raw: dict[str, Any], keys: list[str]) -> tuple[str, str, str]:
    """Return (raw_ts, utc_ts, timezone_str) preferring the listed keys."""
    for k in keys:
        if k in raw and raw[k]:
            ts_raw = _safe_str(raw[k])
            if ts_raw:
                try:
                    r, u = utc_timestamp(ts_raw)
                    # derive tz label conservatively
                    tz = "UTC" if ts_raw.endswith(("Z", "+00:00", "-00:00")) else _safe_str(raw.get("timezone")) or "UTC"
                    return r, u, tz
                except IngestValidationError:
                    continue
    # deterministic fallback for synthetic fixtures
    fb = "2026-08-07T12:00:00Z"
    return fb, fb, "UTC"


def _source_id(raw: dict[str, Any], override: str | None = None) -> str:
    if override:
        return override
    return raw.get("_id") or raw.get("id") or f"syn-{uuid.uuid4().hex[:12]}"


def _source_revision(raw: dict[str, Any], override: str | None = None) -> str:
    if override:
        return override
    return (
        raw.get("updatedAt")
        or raw.get("updated_at")
        or raw.get("createdAt")
        or raw.get("created_at")
        or raw.get("date")
        or "rev-1"
    )


def _base_payload_common(raw: dict[str, Any]) -> dict[str, Any]:
    """Common fields safe to carry for case/alert/indicator."""
    p: dict[str, Any] = {}
    if "title" in raw:
        p["title"] = _safe_str(raw["title"])
    if "description" in raw or "message" in raw:
        p["description"] = _safe_str(raw.get("description") or raw.get("message"))
    if "severity" in raw:
        p["severity"] = raw.get("severity")
    tlp = _map_tlp_pap(raw.get("tlp"))
    if tlp is not None:
        p["tlp"] = tlp
    pap = _map_tlp_pap(raw.get("pap"))
    if pap is not None:
        p["pap"] = pap
    tags = raw.get("tags") or []
    if isinstance(tags, list):
        p["tags"] = [str(t) for t in tags if t]
    else:
        p["tags"] = []
    cf = raw.get("customFields") or raw.get("custom_fields") or {}
    if isinstance(cf, dict):
        p["custom_fields"] = {k: v for k, v in cf.items() if not str(k).lower().startswith(("_", "secret", "token"))}
    else:
        p["custom_fields"] = {}
    return p


class TheHiveIngestAdapter:
    """Projection adapter: raw TheHive -> interop-entity (case/alert/observable/timeline_event)."""

    def __init__(self, integration_id: str = "thehive-default"):
        if not integration_id or not isinstance(integration_id, str):
            raise IngestValidationError("integration_id must be non-empty string")
        self.integration_id = integration_id

    def _provenance(
        self,
        entity: str,
        source_id: str,
        source_revision: str,
        raw_ts: str,
        utc_ts: str,
        tz: str,
        source_scope: str,
        lossy: list[str] | None = None,
        redaction: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        idem = idempotency_key(
            integration_id=self.integration_id,
            direction="in",
            source_system="hive",
            source_entity=entity,
            source_id=source_id,
            source_revision=source_revision,
        )
        prov: dict[str, Any] = {
            "integration_id": self.integration_id,
            "source_system": "hive",
            "source_entity": entity,
            "source_id": source_id,
            "source_scope": source_scope,
            "source_revision": source_revision,
            "source_updated_at_raw": raw_ts,
            "source_updated_at_utc": utc_ts,
            "source_timezone": tz,
            "mapping_version": MAPPING_VERSION,
            "idempotency_key": idem,
            "redaction_flags": redaction or {},
            "lossy_transformations": lossy or [],
        }
        # optional nullables omitted unless set
        return prov

    def project_case(
        self, raw: dict[str, Any], *, source_scope: str, source_id: str | None = None, source_revision: str | None = None
    ) -> dict[str, Any]:
        """Project TheHive case to interop-entity case. Raises on secrets."""
        if not isinstance(raw, dict):
            raise IngestValidationError("raw case must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["updatedAt", "createdAt", "startDate"])
        lossy = []
        if "status" in raw:
            lossy.append("dropped:status")
        if any(k in raw for k in ("owner", "createdBy", "updatedBy")):
            lossy.append("dropped:ownership")
        if "cortexJobs" in raw or "misp" in raw or any("misp" in str(k).lower() for k in raw):
            lossy.append("dropped:misp-cortex")
        payload = _base_payload_common(raw)
        # case requires title
        if not payload.get("title"):
            raise IngestValidationError("case payload must include title")
        prov = self._provenance("case", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy)
        return {
            "schema_version": "1.0",
            "entity_type": "case",
            "provenance": prov,
            "payload": payload,
        }

    def project_alert(
        self, raw: dict[str, Any], *, source_scope: str, source_id: str | None = None, source_revision: str | None = None
    ) -> dict[str, Any]:
        """Project TheHive alert to interop-entity alert. Drops embedded artifacts list (project separately)."""
        if not isinstance(raw, dict):
            raise IngestValidationError("raw alert must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["updatedAt", "createdAt", "date"])
        lossy = ["dropped:embedded-observables"] if "artifacts" in raw or "observables" in raw else []
        if "status" in raw:
            lossy.append("dropped:status")
        if any(k in raw for k in ("owner", "createdBy", "updatedBy")):
            lossy.append("dropped:ownership")
        if "cortex" in str(raw).lower() or "mispEvent" in raw:
            lossy.append("dropped:misp-cortex")
        payload = _base_payload_common(raw)
        if not payload.get("title"):
            raise IngestValidationError("alert payload must include title")
        # do not include status or observables list per spec
        prov = self._provenance("alert", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy)
        return {
            "schema_version": "1.0",
            "entity_type": "alert",
            "provenance": prov,
            "payload": payload,
        }

    def project_observable(
        self, raw: dict[str, Any], *, source_scope: str, source_id: str | None = None, source_revision: str | None = None
    ) -> dict[str, Any]:
        """Project TheHive observable to interop-entity (observable or ioc)."""
        if not isinstance(raw, dict):
            raise IngestValidationError("raw observable must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["updatedAt", "createdAt"])
        otype = _safe_str(raw.get("dataType") or raw.get("type") or raw.get("data_type"))
        ovalue = _safe_str(raw.get("data") or raw.get("value"))
        if not otype or not ovalue:
            raise IngestValidationError("observable requires dataType and data")
        lossy: list[str] = []
        redaction_flags: dict[str, Any] = {}
        entity_type = "ioc" if raw.get("ioc") else "observable"
        if otype in _UNSUPPORTED_OBSERVABLE_TYPES:
            # explicit quarantine for types that could carry bytes
            redaction_flags = {
                "dataType": {
                    "decision": "quarantined",
                    "policy_version": POLICY_VERSION,
                    "reason": f"unsupported observable type for interop: {otype} (no evidence bytes)",
                }
            }
            lossy.append("quarantined:unsupported-type")
        payload: dict[str, Any] = {
            "value": ovalue,
            "type": otype,
        }
        desc = _safe_str(raw.get("message") or raw.get("description"))
        if desc:
            payload["description"] = desc
        tlp = _map_tlp_pap(raw.get("tlp"))
        if tlp:
            payload["tlp"] = tlp
        pap = _map_tlp_pap(raw.get("pap"))
        if pap:
            payload["pap"] = pap
        tags = raw.get("tags") or []
        if isinstance(tags, list) and tags:
            payload["tags"] = [str(t) for t in tags if t]
        if raw.get("ioc") is not None:
            payload["classification"] = "ioc" if raw.get("ioc") else None
        cf = raw.get("customFields") or {}
        if isinstance(cf, dict):
            payload["custom_fields"] = cf
        prov = self._provenance(entity_type, sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy, redaction=redaction_flags)
        return {
            "schema_version": "1.0",
            "entity_type": entity_type,
            "provenance": prov,
            "payload": payload,
        }

    def project_timeline_event(
        self,
        raw: dict[str, Any],
        *,
        source_scope: str,
        category: str = "task",
        source_id: str | None = None,
        source_revision: str | None = None,
    ) -> dict[str, Any]:
        """Project TheHive task or log to interop-entity timeline_event."""
        if not isinstance(raw, dict):
            raise IngestValidationError("raw timeline must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["updatedAt", "createdAt", "startDate", "date", "endDate"])
        title = _safe_str(raw.get("title") or raw.get("message") or category)
        if not title:
            title = "untitled event"
        lossy = []
        if any(k in raw for k in ("status", "owner", "flag")):
            lossy.append("dropped:task-status-ownership")
        payload = {
            "occurred_at_raw": raw_ts,
            "occurred_at_utc": utc_ts,
            "timezone": tz,
            "category": _safe_str(category) or "task",
            "title": title,
        }
        desc = _safe_str(raw.get("description") or raw.get("message"))
        if desc:
            payload["description"] = desc
        tags = raw.get("tags") or []
        if isinstance(tags, list) and tags:
            payload["tags"] = [str(t) for t in tags if t]
        prov = self._provenance("timeline_event", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy)
        return {
            "schema_version": "1.0",
            "entity_type": "timeline_event",
            "provenance": prov,
            "payload": payload,
        }

    def project(
        self, raw: dict[str, Any], *, entity: str, source_scope: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Dispatch by entity kind."""
        entity = entity.lower()
        if entity == "case":
            return self.project_case(raw, source_scope=source_scope, **kwargs)
        if entity == "alert":
            return self.project_alert(raw, source_scope=source_scope, **kwargs)
        if entity in ("observable", "ioc"):
            return self.project_observable(raw, source_scope=source_scope, **kwargs)
        if entity in ("timeline_event", "task", "log"):
            cat = kwargs.pop("category", "task" if entity == "task" else "log")
            return self.project_timeline_event(raw, source_scope=source_scope, category=cat, **kwargs)
        raise IngestValidationError(f"unsupported entity for TheHive projection: {entity}")


# module level convenience for simple use
def project_thehive_case(raw: dict[str, Any], *, integration_id: str = "thehive-default", source_scope: str = "org-default", **kw) -> dict[str, Any]:
    return TheHiveIngestAdapter(integration_id).project_case(raw, source_scope=source_scope, **kw)


def project_thehive_observable(raw: dict[str, Any], *, integration_id: str = "thehive-default", source_scope: str = "org-default", **kw) -> dict[str, Any]:
    return TheHiveIngestAdapter(integration_id).project_observable(raw, source_scope=source_scope, **kw)
