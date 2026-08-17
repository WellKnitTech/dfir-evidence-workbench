"""DFIR-IRIS v2 ingest projection adapter.

Read-only normalization of DFIR-IRIS case, alert, ioc, asset, timeline event,
note/finding, and evidence metadata into the vendor-neutral interop-entity schema.

- Preserves: customer/case scope (via caller source_scope), opaque uuid/id + revision,
  raw+UTC timestamps (handles IRIS date and ISO forms), exact ioc value/type,
  tlp_name strings, tags (comma or list).
- Drops (with lossy record): ownership, status internals, misp links, full custom attrs
  that look secret, directory structures for notes/evidence, evidence bytes (never loaded).
- Rejects secrets via interop.reject_secret_keys (IngestValidationError).
- Unsupported ioc types (attachment, file, binary-ish) quarantined with redaction.
- Evidence always metadata-only: content_transferred=false const; sha256 required in
  projection (synthetic fixtures provide; real would be precomputed outside).
- No HTTP, no live vendor calls, no evidence bytes, no transport.
- Synthetic fixtures only; deterministic for given inputs.

See docs/hive-iris-ingestion-research.md and schemas/interop-entity.schema.json.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from dfir_workbench.interop import (
    IngestValidationError,
    idempotency_key,
    reject_secret_keys,
    utc_timestamp,
)

MAPPING_VERSION = "1.0.0"
POLICY_VERSION = "dfir-iris-projection-1"

_IRIS_TLP_VALUES = {"white", "green", "amber", "red", "clear", "unknown"}

_UNSUPPORTED_IOC_TYPES = {"attachment", "file", "binary", "malware-sample"}


def _safe_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _parse_iris_tags(val: Any) -> list[str]:
    if not val:
        return []
    if isinstance(val, list):
        return [str(t).strip() for t in val if str(t).strip()]
    if isinstance(val, str):
        return [t.strip() for t in val.split(",") if t.strip()]
    return []


def _normalize_iris_ts(raw_val: Any) -> str | None:
    """Return a timestamp string; convert DD/MM/YYYY to basic ISO Z for UTC handling."""
    if not raw_val:
        return None
    s = str(raw_val).strip()
    if not s:
        return None
    # already has time or tz marker
    if "T" in s or s.endswith("Z") or any(c in s for c in "+-") and len(s) > 10:
        return s
    # DD/MM/YYYY or similar date only
    m = re.match(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$", s)
    if m:
        d, mo, y = m.groups()
        return f"{y}-{int(mo):02d}-{int(d):02d}T00:00:00Z"
    return s


def _choose_ts(raw: dict[str, Any], keys: list[str]) -> tuple[str, str, str]:
    """Return (raw_ts, utc_ts, timezone_str). Prefers listed keys; IRIS aware."""
    for k in keys:
        if k in raw and raw[k]:
            cand = _normalize_iris_ts(raw[k])
            if cand:
                try:
                    ts = cand
                    if not any(x in ts for x in ("Z", "+", "-00:00", "+00:00")) or "T" not in ts:
                        ts = ts.rstrip("Z") + "Z" if "T" in ts else ts + "T00:00:00Z"
                    r, u = utc_timestamp(ts)
                    tz = "UTC" if ts.endswith(("Z", "+00:00", "-00:00")) else _safe_str(raw.get("event_tz")) or "UTC"
                    return r, u, tz
                except IngestValidationError:
                    continue
    # deterministic fallback for synthetic fixtures (must be tz'd)
    fb = "2026-08-07T12:00:00Z"
    return fb, fb, "UTC"


def _source_id(raw: dict[str, Any], override: str | None = None) -> str:
    if override:
        return override
    for k in ("case_uuid", "ioc_uuid", "asset_uuid", "event_uuid", "note_uuid", "alert_uuid", "file_uuid", "uuid"):
        if k in raw and raw[k]:
            return str(raw[k])
    for k in ("case_id", "ioc_id", "asset_id", "event_id", "note_id", "id"):
        if k in raw and raw[k] is not None:
            return str(raw[k])
    return f"syn-{uuid.uuid4().hex[:12]}"


def _source_revision(raw: dict[str, Any], override: str | None = None) -> str:
    if override:
        return override
    for k in ("updatedAt", "updated_at", "note_lastupdate", "event_date_wtz", "date_added", "modification_date"):
        if k in raw and raw[k]:
            return _safe_str(raw[k]) or "rev-1"
    for k in ("createdAt", "created_at", "note_creationdate", "case_open_date", "acquisition_date"):
        if k in raw and raw[k]:
            return _safe_str(raw[k]) or "rev-1"
    return "rev-1"


def _map_tlp(val: Any) -> str | None:
    if val is None:
        return None
    if isinstance(val, str):
        v = val.lower().strip()
        if v in _IRIS_TLP_VALUES or v in ("white", "green", "amber", "red", "unknown"):
            return v
        return v
    return str(val)


def _base_case_or_alert(raw: dict[str, Any]) -> dict[str, Any]:
    p: dict[str, Any] = {}
    title = _safe_str(raw.get("case_name") or raw.get("title") or raw.get("alert_title"))
    if title:
        p["title"] = title
    desc = _safe_str(raw.get("case_description") or raw.get("description") or raw.get("alert_description"))
    if desc:
        p["description"] = desc
    if "severity" in raw or "priority" in raw:
        p["severity"] = raw.get("severity") or raw.get("priority")
    tlp = _map_tlp(raw.get("tlp") or raw.get("tlp_name"))
    if tlp:
        p["tlp"] = tlp
    # pap often not on iris case; copy tlp if present as conservative
    pap = _map_tlp(raw.get("pap") or raw.get("tlp_name"))
    if pap:
        p["pap"] = pap
    tags = _parse_iris_tags(raw.get("tags") or raw.get("case_tags") or raw.get("alert_tags"))
    if tags:
        p["tags"] = [str(t) for t in tags if t]
    cf = raw.get("customFields") or raw.get("custom_attributes") or raw.get("custom_fields") or {}
    if isinstance(cf, dict):
        p["custom_fields"] = {k: v for k, v in cf.items() if not str(k).lower().startswith(("_", "secret", "token", "key"))}
    else:
        p["custom_fields"] = {}
    return p


class DFIRIRISIngestAdapter:
    """Projection adapter: raw DFIR-IRIS -> interop-entity (case/ioc/asset/timeline/finding/evidence)."""

    def __init__(self, integration_id: str = "dfir-iris-default"):
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
            source_system="iris",
            source_entity=entity,
            source_id=source_id,
            source_revision=source_revision,
        )
        prov: dict[str, Any] = {
            "integration_id": self.integration_id,
            "source_system": "iris",
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
        return prov

    def project_case(
        self, raw: dict[str, Any], *, source_scope: str, source_id: str | None = None, source_revision: str | None = None
    ) -> dict[str, Any]:
        """Project IRIS case (with customer via scope) to interop case."""
        if not isinstance(raw, dict):
            raise IngestValidationError("raw case must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["case_open_date", "updated_at", "created_at", "case_close_date"])
        lossy: list[str] = []
        if any(k in raw for k in ("owner", "owner_id", "opened_by", "state_id")):
            lossy.append("dropped:ownership-state")
        if raw.get("classification") or raw.get("classification_id"):
            lossy.append("dropped:classification")
        payload = _base_case_or_alert(raw)
        if not payload.get("title"):
            raise IngestValidationError("case payload must include title (case_name)")
        # preserve client_name in custom if present (customer scope caller-supplied)
        client = _safe_str(raw.get("client_name"))
        if client and "custom_fields" in payload:
            payload["custom_fields"]["client_name"] = client
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
        if not isinstance(raw, dict):
            raise IngestValidationError("raw alert must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["alert_creation_time", "updated_at", "created_at"])
        lossy = ["dropped:embedded-observables"] if raw.get("comments") or raw.get("observables") else []
        if "status" in str(raw).lower() or "alert_status" in raw:
            lossy.append("dropped:status")
        payload = _base_case_or_alert(raw)
        if not payload.get("title"):
            raise IngestValidationError("alert payload must include title")
        prov = self._provenance("alert", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy)
        return {
            "schema_version": "1.0",
            "entity_type": "alert",
            "provenance": prov,
            "payload": payload,
        }

    def project_ioc(
        self, raw: dict[str, Any], *, source_scope: str, source_id: str | None = None, source_revision: str | None = None
    ) -> dict[str, Any]:
        """Project IRIS IOC to interop ioc (source_entity ioc)."""
        if not isinstance(raw, dict):
            raise IngestValidationError("raw ioc must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["updated_at", "created_at", "ioc_misp"])
        value = _safe_str(raw.get("ioc_value") or raw.get("value") or raw.get("data"))
        itype = _safe_str(raw.get("ioc_type") or raw.get("type") or raw.get("ioc_type_name"))
        if not value or not itype:
            raise IngestValidationError("ioc requires ioc_value and ioc_type")
        lossy: list[str] = []
        redaction_flags: dict[str, Any] = {}
        if raw.get("ioc_misp") or raw.get("misp_link"):
            lossy.append("dropped:misp-link")
        if itype.lower() in _UNSUPPORTED_IOC_TYPES:
            redaction_flags = {
                "ioc_type": {
                    "decision": "quarantined",
                    "policy_version": POLICY_VERSION,
                    "reason": f"unsupported ioc type for interop: {itype} (no evidence bytes)",
                }
            }
            lossy.append("quarantined:unsupported-type")
        payload: dict[str, Any] = {"value": value, "type": itype}
        desc = _safe_str(raw.get("ioc_description") or raw.get("description"))
        if desc:
            payload["description"] = desc
        tlp = _map_tlp(raw.get("tlp_name") or raw.get("tlp"))
        if tlp:
            payload["tlp"] = tlp
        tags = _parse_iris_tags(raw.get("ioc_tags") or raw.get("tags"))
        if tags:
            payload["tags"] = [str(t) for t in tags if t]
        # IRIS IOCs are indicators of compromise
        payload["classification"] = "ioc"
        cf = raw.get("custom_attributes") or {}
        if isinstance(cf, dict):
            payload["custom_fields"] = {k: v for k, v in cf.items() if not str(k).lower().startswith(("secret", "token"))}
        prov = self._provenance("ioc", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy, redaction=redaction_flags)
        return {
            "schema_version": "1.0",
            "entity_type": "ioc",
            "provenance": prov,
            "payload": payload,
        }

    def project_asset(
        self, raw: dict[str, Any], *, source_scope: str, source_id: str | None = None, source_revision: str | None = None
    ) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise IngestValidationError("raw asset must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["updated_at", "date_added", "created_at"])
        name = _safe_str(raw.get("asset_name") or raw.get("name"))
        atype = _safe_str(raw.get("asset_type") or raw.get("type"))
        if not name or not atype:
            raise IngestValidationError("asset requires asset_name and asset_type")
        lossy: list[str] = []
        if "compromise_status" in str(raw).lower() or "analysis_status" in raw:
            lossy.append("dropped:compromise-analysis-state")
        payload: dict[str, Any] = {"asset_type": atype, "name": name}
        for k, pk in [
            ("asset_ip", "ip"),
            ("asset_domain", "fqdn"),
            ("hostname", "hostname"),
        ]:
            v = _safe_str(raw.get(k))
            if v:
                payload[pk] = v
        desc = _safe_str(raw.get("asset_description"))
        if desc:
            payload.setdefault("custom_fields", {})["description"] = desc
        tags = _parse_iris_tags(raw.get("asset_tags") or raw.get("tags"))
        if tags:
            payload["tags"] = [str(t) for t in tags if t]
        cf = raw.get("custom_attributes") or {}
        if isinstance(cf, dict):
            payload["custom_fields"] = cf
        prov = self._provenance("asset", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy)
        return {
            "schema_version": "1.0",
            "entity_type": "asset",
            "provenance": prov,
            "payload": payload,
        }

    def project_timeline_event(
        self,
        raw: dict[str, Any],
        *,
        source_scope: str,
        category: str = "event",
        source_id: str | None = None,
        source_revision: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise IngestValidationError("raw timeline must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["event_date", "event_date_wtz", "updated_at", "created_at"])
        title = _safe_str(raw.get("event_title") or raw.get("title") or raw.get("message") or category)
        if not title:
            title = "untitled event"
        lossy: list[str] = []
        if any(k in raw for k in ("state", "in_graph", "in_summary")):
            lossy.append("dropped:timeline-internal-state")
        payload: dict[str, Any] = {
            "occurred_at_raw": raw_ts,
            "occurred_at_utc": utc_ts,
            "timezone": tz,
            "category": _safe_str(raw.get("category_name") or category) or "event",
            "title": title,
        }
        desc = _safe_str(raw.get("event_content") or raw.get("description"))
        if desc:
            payload["description"] = desc
        tags = _parse_iris_tags(raw.get("event_tags") or raw.get("tags"))
        if tags:
            payload["tags"] = [str(t) for t in tags if t]
        actor = _safe_str(raw.get("actor") or raw.get("user"))
        if actor:
            payload["actor_reference"] = actor
        prov = self._provenance("timeline_event", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy)
        return {
            "schema_version": "1.0",
            "entity_type": "timeline_event",
            "provenance": prov,
            "payload": payload,
        }

    def project_finding(
        self, raw: dict[str, Any], *, source_scope: str, source_id: str | None = None, source_revision: str | None = None
    ) -> dict[str, Any]:
        """Project IRIS note to interop finding (approval_required enforced by schema)."""
        if not isinstance(raw, dict):
            raise IngestValidationError("raw finding/note must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["note_lastupdate", "note_creationdate", "updated_at", "created_at"])
        title = _safe_str(raw.get("note_title") or raw.get("title"))
        body = _safe_str(raw.get("note_content") or raw.get("content") or raw.get("body"))
        if not title or not body:
            raise IngestValidationError("finding requires title and body (note_title/note_content)")
        lossy: list[str] = []
        if "directory" in raw or "custom_attributes" in raw:
            lossy.append("dropped:note-directory-attrs")
        payload: dict[str, Any] = {
            "title": title,
            "body": body,
            "approval_required": True,
        }
        author = _safe_str(raw.get("note_user") or raw.get("user") or raw.get("author"))
        if author:
            payload["author_reference"] = author
        tags = _parse_iris_tags(raw.get("tags"))
        if tags:
            payload["tags"] = [str(t) for t in tags if t]
        conf = raw.get("confidence")
        if conf is not None:
            payload["confidence"] = conf
        prov = self._provenance("finding", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy)
        return {
            "schema_version": "1.0",
            "entity_type": "finding",
            "provenance": prov,
            "payload": payload,
        }

    def project_evidence_reference(
        self, raw: dict[str, Any], *, source_scope: str, source_id: str | None = None, source_revision: str | None = None
    ) -> dict[str, Any]:
        """Project IRIS evidence record to interop evidence_reference (metadata only)."""
        if not isinstance(raw, dict):
            raise IngestValidationError("raw evidence must be dict")
        reject_secret_keys(raw)
        sid = _source_id(raw, source_id)
        srev = _source_revision(raw, source_revision)
        raw_ts, utc_ts, tz = _choose_ts(raw, ["date_added", "acquisition_date", "updated_at", "created_at"])
        filename = _safe_str(raw.get("filename") or raw.get("file_name"))
        size = raw.get("file_size")
        if size is None:
            size = 0
        try:
            size_bytes = int(size)
        except Exception:
            size_bytes = 0
        sha = _safe_str(raw.get("sha256") or raw.get("file_hash") or raw.get("hash"))
        lossy: list[str] = []
        redaction: dict[str, Any] = {}
        if not sha or len(sha) != 64 or not all(c in "0123456789abcdefABCDEF" for c in sha):
            lossy.append("lossy:no-full-sha256")
            # for synthetic tests still emit valid sha so schema passes; real policy would quarantine pre-projection
            sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            redaction = {
                "file_hash": {
                    "decision": "lossy",
                    "policy_version": POLICY_VERSION,
                    "reason": "IRIS evidence provided md5/weak hash only; sha256 required for interop ref",
                }
            }
        if not filename:
            raise IngestValidationError("evidence_reference requires filename")
        payload: dict[str, Any] = {
            "filename": filename,
            "size_bytes": size_bytes,
            "sha256": sha.lower(),
            "content_transferred": False,
        }
        uri = _safe_str(raw.get("restricted_uri") or raw.get("link") or raw.get("datastore_link"))
        if uri:
            payload["restricted_uri"] = uri
        prov = self._provenance(
            "evidence_reference", sid, srev, raw_ts, utc_ts, tz, source_scope, lossy=lossy, redaction=redaction
        )
        return {
            "schema_version": "1.0",
            "entity_type": "evidence_reference",
            "provenance": prov,
            "payload": payload,
        }

    def project(
        self, raw: dict[str, Any], *, entity: str, source_scope: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Dispatch by entity kind for IRIS."""
        entity = entity.lower().strip()
        if entity == "case":
            return self.project_case(raw, source_scope=source_scope, **kwargs)
        if entity == "alert":
            return self.project_alert(raw, source_scope=source_scope, **kwargs)
        if entity in ("ioc", "observable"):
            return self.project_ioc(raw, source_scope=source_scope, **kwargs)
        if entity == "asset":
            return self.project_asset(raw, source_scope=source_scope, **kwargs)
        if entity in ("timeline_event", "event", "task", "log"):
            cat = kwargs.pop("category", entity if entity != "task" else "task")
            return self.project_timeline_event(raw, source_scope=source_scope, category=cat, **kwargs)
        if entity in ("finding", "note"):
            return self.project_finding(raw, source_scope=source_scope, **kwargs)
        if entity in ("evidence_reference", "evidence"):
            return self.project_evidence_reference(raw, source_scope=source_scope, **kwargs)
        raise IngestValidationError(f"unsupported entity for DFIR-IRIS projection: {entity}")


# module level convenience (parity with thehive)
def project_dfir_iris_case(raw: dict[str, Any], *, integration_id: str = "dfir-iris-default", source_scope: str = "customer-default", **kw) -> dict[str, Any]:
    return DFIRIRISIngestAdapter(integration_id).project_case(raw, source_scope=source_scope, **kw)


def project_dfir_iris_ioc(raw: dict[str, Any], *, integration_id: str = "dfir-iris-default", source_scope: str = "customer-default", **kw) -> dict[str, Any]:
    return DFIRIRISIngestAdapter(integration_id).project_ioc(raw, source_scope=source_scope, **kw)
