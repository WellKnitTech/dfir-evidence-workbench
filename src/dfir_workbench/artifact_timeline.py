"""Deterministic, evidence-safe artifact and timeline fixture workflow.

The parser intentionally uses the standard library. Unsupported binary formats
remain explicit partial results; they are never represented as empty success.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

VERSION = "artifact-timeline/v1"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_output(value: Any) -> str:
    """Stable golden-file representation (UTF-8 JSON plus final newline)."""
    return canonical_json(value) + "\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _timestamp(value: Any, source_timezone: str = "UTC") -> tuple[str | None, str | None, str]:
    """Return raw, UTC Z, and the retained source timezone/assumption."""
    if value is None or value == "":
        return None, None, source_timezone
    raw = str(value).strip()
    try:
        if raw.isdigit() and len(raw) in (10, 13, 16):
            divisor = {10: 1, 13: 1_000, 16: 1_000_000}[len(raw)]
            parsed = datetime.fromtimestamp(int(raw) / divisor, timezone.utc)
        else:
            candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
                source_timezone = f"{source_timezone} (assumed for timezone-less value)"
        return raw, parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), source_timezone
    except (TypeError, ValueError):
        return raw, None, source_timezone


def _record(payload: Mapping[str, Any], *, source_path: str, source_hash: str,
            row: int | None, source_timezone: str) -> dict[str, Any]:
    time_value = next((payload.get(k) for k in ("timestamp", "time", "datetime", "date", "ts", "Timestamp") if payload.get(k) not in (None, "")), None)
    raw, utc, tz = _timestamp(time_value, source_timezone)
    body = dict(payload)
    if raw is not None:
        body["time_raw"], body["time_utc"], body["source_timezone"] = raw, utc, tz
    key_material = {"source_path": source_path, "row": row, "payload": body}
    key = hashlib.sha256(canonical_json(key_material).encode()).hexdigest()[:24]
    return {"record_key": key, "source_path": source_path, "source_row": row,
            "source_sha256": source_hash, "payload": body,
            "provenance": {"source_path": source_path, "source_row": row,
                           "source_sha256": source_hash, "review_state": "unreviewed"}}


def _parse_text(data: bytes, suffix: str, source_path: str, digest: str, tz: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [], [{"code": "INVALID_UTF8", "message": str(exc), "source_path": source_path}]
    rows: list[Mapping[str, Any]] = []
    try:
        if suffix in (".jsonl", ".ndjson"):
            for number, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    value = json.loads(line)
                    rows.append(value if isinstance(value, dict) else {"value": value})
                    if not isinstance(value, dict): errors.append({"code": "NON_OBJECT_ROW", "source_row": number, "source_path": source_path})
        elif suffix == ".json":
            value = json.loads(text)
            values = value if isinstance(value, list) else [value]
            rows = [x if isinstance(x, dict) else {"value": x} for x in values]
        elif suffix in (".csv", ".tsv"):
            reader = csv.DictReader(io.StringIO(text), delimiter="\t" if suffix == ".tsv" else ",")
            if reader.fieldnames is None: raise ValueError("missing header")
            rows = list(reader)
        else:
            rows = [{"line": line} for line in text.splitlines() if line.strip()]
    except (json.JSONDecodeError, csv.Error, ValueError) as exc:
        return [], [{"code": "MALFORMED_INPUT", "message": str(exc), "source_path": source_path}]
    return [_record(row, source_path=source_path, source_hash=digest, row=i, source_timezone=tz) for i, row in enumerate(rows, 1)], errors


def _sqlite_records(path: Path, source_path: str, digest: str, tz: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    try:
        uri = f"file:{path.resolve()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            tables = [r[0] for r in db.execute("select name from sqlite_master where type='table' order by name")]
            for table in tables:
                cols = [r[1] for r in db.execute(f'pragma table_info("{table}")')]
                for row_number, values in enumerate(db.execute(f'select * from "{table}"'), 1):
                    records.append(_record(dict(zip(cols, values)), source_path=f"{source_path}#{table}", source_hash=digest, row=row_number, source_timezone=tz))
    except (sqlite3.Error, OSError) as exc:
        errors.append({"code": "BROWSER_DB_UNREADABLE", "message": str(exc), "source_path": source_path})
    return records, errors


def process_artifact(source: str | Path, *, source_timezone: str = "UTC") -> dict[str, Any]:
    """Parse one artifact or archive into a stable result envelope."""
    path = Path(source).expanduser().resolve()
    if not path.is_file() or path.is_symlink():
        return {"schema_version": "1.0", "workflow": VERSION, "status": "invalid_input", "source": {"path": str(path)}, "records": [], "errors": [{"code": "SOURCE_NOT_FOUND", "source_path": str(path)}], "unresolved": []}
    data = path.read_bytes()
    digest = sha256_bytes(data)
    records: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    if path.suffix.lower() in (".evtx", ".hive", ".regf"):
        unresolved.append({"code": "OPTIONAL_PARSER_UNAVAILABLE", "scope": path.suffix.lower(), "message": "Binary parser is not bundled; no records inferred."})
    elif path.suffix.lower() in (".sqlite", ".db"):
        records, errors = _sqlite_records(path, str(path), digest, source_timezone)
    elif zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                total_member_bytes = 0
                for info in sorted(archive.infolist(), key=lambda item: item.filename):
                    if info.is_dir(): continue
                    member = PurePosixPath(info.filename).as_posix()
                    if (not member or PurePosixPath(member).is_absolute() or
                            any(part in ("", ".", "..") for part in PurePosixPath(member).parts)):
                        errors.append({"code": "PATH_TRAVERSAL_REJECTED", "source_path": member}); continue
                    if info.file_size > 512 * 1024 * 1024 or total_member_bytes + info.file_size > 4 * 1024 * 1024 * 1024:
                        errors.append({"code": "ARCHIVE_MEMBER_LIMIT_EXCEEDED", "source_path": member}); continue
                    member_data = archive.read(info)
                    total_member_bytes += len(member_data)
                    member_digest = sha256_bytes(member_data)
                    parsed, member_errors = _parse_text(member_data, Path(member).suffix.lower(), f"{path}!/{member}", member_digest, source_timezone)
                    records.extend(parsed); errors.extend(member_errors)
        except (zipfile.BadZipFile, OSError) as exc:
            errors.append({"code": "ARCHIVE_INVALID", "message": str(exc), "source_path": str(path)})
    else:
        records, errors = _parse_text(data, path.suffix.lower(), str(path), digest, source_timezone)
    status = "invalid_input" if any(e["code"] in ("MALFORMED_INPUT", "ARCHIVE_INVALID", "INVALID_UTF8") for e in errors) else "partial" if errors or unresolved else "complete"
    return {"schema_version": "1.0", "workflow": VERSION, "status": status,
            "source": {"path": str(path), "sha256": digest, "size": len(data), "source_timezone": source_timezone},
            "records": records, "errors": errors, "unresolved": unresolved,
            "stats": {"record_count": len(records), "error_count": len(errors), "unresolved_count": len(unresolved)}}


normalize_timestamp = _timestamp


@dataclass
class OpenRelikFastPath:
    """Small local seam for Velociraptor -> OpenRelik job submission."""
    jobs: dict[str, dict[str, Any]] = field(default_factory=dict)

    def submit(self, result: Mapping[str, Any], *, case_id: str) -> dict[str, Any]:
        payload = {"case_id": case_id, "source_sha256": result.get("source", {}).get("sha256"), "workflow": VERSION, "records": result.get("records", [])}
        key = "vr-" + hashlib.sha256(canonical_json({"case_id": case_id, "source_sha256": payload["source_sha256"]}).encode()).hexdigest()
        payload_hash = sha256_bytes(canonical_json(payload).encode())
        existing = self.jobs.get(key)
        if existing:
            if existing["payload_sha256"] != payload_hash:
                return {"status": "conflict", "code": "IDEMPOTENCY_CONFLICT", "idempotency_key": key}
            return {**existing, "status": "duplicate"}
        job = {"status": "accepted", "idempotency_key": key, "payload_sha256": sha256_bytes(canonical_json(payload).encode()), "openrelik": {"case_id": case_id, "input_hash": payload["source_sha256"], "records": len(payload["records"])}}
        self.jobs[key] = job
        return job


def submit_velociraptor_to_openrelik(result: Mapping[str, Any], *, case_id: str,
                                     jobs: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Submit through the local seam, allowing callers to persist its job map."""
    return OpenRelikFastPath(jobs if jobs is not None else {}).submit(result, case_id=case_id)
