"""Production evidence storage boundary (filesystem-backed WORM object store).

Implements the tenant/case-scoped evidence boundary described in
docs/security-defensibility-requirements.md (REQ-ISO-004/005/006, REQ-PATH-002/003,
REQ-UPL-003, REQ-AUD-005 retention/legal-hold):

- Tenant scope is derived *exclusively* from the trusted Principal, never from
  caller-supplied ids. Case/evidence ids are caller-supplied but validated
  against a strict slug pattern and always joined under the resolved tenant root
  with a containment check before any filesystem operation (fail closed).
- Uploads land in a bounded, size-checked quarantine area first. Nothing is
  admitted into the immutable case evidence tree until promote_to_evidence()
  re-hashes the quarantined bytes and matches the caller-declared sha256.
- Promoted originals are chmod'd read-only (0o400 file / 0o500 dir) and the
  store never opens them for writing again; corruption/tamper attempts raise.
- Legal hold and retention are enforced on the deletion path only: delete_evidence
  fails closed while a hold is set or retention has not elapsed.
- This module never accepts bytes through the metadata-only ingest boundary
  (dfir_workbench.ingest) and vice versa: ingest envelopes carry vendor JSON only,
  this module carries file bytes only. The two are intentionally not wired together.

Filesystem layout (root is an operator-configured, non-web-served volume):
  <root>/tenants/<tenant_id>/quarantine/<quarantine_id>/blob      (pre-admission)
  <root>/tenants/<tenant_id>/quarantine/<quarantine_id>/meta.json
  <root>/tenants/<tenant_id>/cases/<case_id>/evidence/<evidence_id>/original   (0o400, immutable)
  <root>/tenants/<tenant_id>/cases/<case_id>/evidence/<evidence_id>/manifest.json

Encryption at rest/in transit, KMS-backed key management, and least-privilege
IAM for a remote object-storage backend (S3-compatible) are deployment/
infrastructure concerns outside what a local process can prove; this module
provides the same tenant/case isolation and immutability contract regardless of
backend and documents the production requirements it does not itself implement
(see docs/security-defensibility-requirements.md REQ-SEC-002, REQ-POD-*).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .api import Principal

_ID_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?$")

DEFAULT_MAX_QUARANTINE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GiB, matches REQ-UPL-001 baseline
DEFAULT_RETENTION_DAYS = 365


class EvidenceStoreError(Exception):
    """Fail-closed error for the evidence boundary. Never carries evidence bytes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


def _validate_id(value: str, field: str) -> str:
    """Reject anything that is not a plain, bounded slug.

    This is the single choke point for path-traversal defense (REQ-PATH-002):
    absolute paths, dot-segments, separators, NUL bytes, and empty/oversized
    values are all rejected by construction because only this character class
    is accepted.
    """
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise EvidenceStoreError("INVALID_ID", f"{field} must match {_ID_RE.pattern}")
    return value


def _sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while b := f.read(chunk):
            h.update(b)
    return h.hexdigest()


def _require_contained(path: Path, root: Path) -> Path:
    """Resolve path and assert it is inside root; reject symlink escapes."""
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise EvidenceStoreError("PATH_TRAVERSAL_REJECTED", "resolved path escapes storage root")
    return resolved


def _reject_symlink(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise EvidenceStoreError("SYMLINK_REJECTED", "symlinked evidence paths are not permitted")


@dataclass(frozen=True)
class QuarantineRecord:
    quarantine_id: str
    tenant_id: str
    sha256: str
    size: int
    received_at_utc: str


@dataclass(frozen=True)
class EvidenceManifest:
    tenant_id: str
    case_id: str
    evidence_id: str
    sha256: str
    size: int
    promoted_at_utc: str
    retention_until_utc: str
    legal_hold: bool
    source_quarantine_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "sha256": self.sha256,
            "size": self.size,
            "promoted_at_utc": self.promoted_at_utc,
            "retention_until_utc": self.retention_until_utc,
            "legal_hold": self.legal_hold,
            "source_quarantine_id": self.source_quarantine_id,
        }


class EvidenceStore:
    """Tenant-scoped, case-scoped, WORM-original evidence boundary.

    tenant scope comes exclusively from `principal.tenant_id`; every method
    validates case_id/evidence_id as plain slugs and re-resolves the final
    path under the tenant root before touching the filesystem, so a caller
    from tenant A can never read, overwrite, or delete tenant B's bytes even
    if it guesses B's case/evidence ids.
    """

    def __init__(
        self,
        root: str | Path,
        principal: "Principal",
        *,
        max_quarantine_bytes: int = DEFAULT_MAX_QUARANTINE_BYTES,
        default_retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        tenant_id = _validate_id(str(principal.tenant_id), "tenant_id")
        self._root = Path(root).resolve()
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._tenant_root = (self._root / "tenants" / tenant_id).resolve()
        if not self._tenant_root.is_relative_to(self._root):
            raise EvidenceStoreError("PATH_TRAVERSAL_REJECTED", "tenant root escapes storage root")
        self._tenant_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.tenant_id = tenant_id
        self.max_quarantine_bytes = max_quarantine_bytes
        self.default_retention_days = default_retention_days

    # -- internal path helpers -------------------------------------------------

    def _quarantine_dir(self, quarantine_id: str) -> Path:
        qid = _validate_id(quarantine_id, "quarantine_id")
        d = self._tenant_root / "quarantine" / qid
        return _require_contained(d, self._tenant_root)

    def _case_dir(self, case_id: str) -> Path:
        cid = _validate_id(case_id, "case_id")
        d = self._tenant_root / "cases" / cid
        return _require_contained(d, self._tenant_root)

    def _evidence_dir(self, case_id: str, evidence_id: str) -> Path:
        eid = _validate_id(evidence_id, "evidence_id")
        d = self._case_dir(case_id) / "evidence" / eid
        return _require_contained(d, self._tenant_root)

    # -- quarantine (pre-admission) ---------------------------------------------

    def ingest_to_quarantine(self, source_path: str | Path) -> QuarantineRecord:
        """Copy an already-on-disk source into a fresh bounded quarantine slot.

        Rejects symlinked sources and oversized bytes before any bytes are
        admitted (REQ-UPL-001/003). Does not touch the case tree.
        """
        src = Path(source_path)
        if not src.is_file() or src.is_symlink():
            raise EvidenceStoreError("SOURCE_INVALID", "source must be a regular, non-symlink file")
        size = src.stat().st_size
        if size > self.max_quarantine_bytes:
            raise EvidenceStoreError("QUARANTINE_LIMIT_EXCEEDED", "source exceeds configured quarantine byte limit")

        qid = uuid.uuid4().hex
        qdir = self._quarantine_dir(qid)
        qdir.mkdir(mode=0o700, parents=True, exist_ok=False)
        blob = qdir / "blob"
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=".partial-", dir=qdir)
        os.close(tmp_fd)
        tmp = Path(tmp_name)
        os.chmod(tmp, 0o600)
        try:
            shutil.copyfile(src, tmp)
            os.replace(tmp, blob)
        finally:
            if tmp.exists():
                tmp.unlink()
        _require_contained(blob, self._tenant_root)
        digest = _sha256_file(blob)
        received_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        (qdir / "meta.json").write_text(
            json.dumps({"quarantine_id": qid, "tenant_id": self.tenant_id, "sha256": digest, "size": blob.stat().st_size, "received_at_utc": received_at}),
            encoding="utf-8",
        )
        return QuarantineRecord(quarantine_id=qid, tenant_id=self.tenant_id, sha256=digest, size=blob.stat().st_size, received_at_utc=received_at)

    # -- promotion to immutable case evidence ------------------------------------

    def promote_to_evidence(
        self,
        *,
        case_id: str,
        evidence_id: str,
        quarantine_id: str,
        expected_sha256: str,
        retention_days: int | None = None,
    ) -> EvidenceManifest:
        """Move quarantined bytes into the immutable, case-scoped evidence tree.

        Fails closed (no promotion, quarantine left intact) if the recorded
        quarantine hash does not match `expected_sha256`, or if an evidence
        object already exists at that id (no silent overwrite of originals).
        """
        qdir = self._quarantine_dir(quarantine_id)
        blob = qdir / "blob"
        meta_path = qdir / "meta.json"
        if not blob.is_file() or not meta_path.is_file():
            raise EvidenceStoreError("QUARANTINE_NOT_FOUND", "no quarantined object for that id in this tenant")
        _reject_symlink(blob)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("tenant_id") != self.tenant_id:
            raise EvidenceStoreError("QUARANTINE_NOT_FOUND", "no quarantined object for that id in this tenant")
        actual_sha = _sha256_file(blob)
        if actual_sha != meta.get("sha256") or actual_sha != expected_sha256:
            raise EvidenceStoreError("CHECKSUM_MISMATCH", "quarantined bytes do not match the declared checksum")

        edir = self._evidence_dir(case_id, evidence_id)
        if edir.exists():
            raise EvidenceStoreError("EVIDENCE_EXISTS", "an evidence object already exists at this id; originals are immutable")
        edir.mkdir(mode=0o700, parents=True, exist_ok=False)
        original = edir / "original"
        shutil.copyfile(blob, original)
        _require_contained(original, self._tenant_root)
        # Make the original read-only, then lock the directory down too so the
        # file cannot be replaced, renamed, or deleted through this path either.
        os.chmod(original, stat.S_IRUSR)
        os.chmod(edir, stat.S_IRUSR | stat.S_IXUSR)

        now = datetime.now(timezone.utc)
        retention_until = now + timedelta(days=retention_days if retention_days is not None else self.default_retention_days)
        manifest = EvidenceManifest(
            tenant_id=self.tenant_id,
            case_id=_validate_id(case_id, "case_id"),
            evidence_id=_validate_id(evidence_id, "evidence_id"),
            sha256=actual_sha,
            size=original.stat().st_size,
            promoted_at_utc=now.isoformat().replace("+00:00", "Z"),
            retention_until_utc=retention_until.isoformat().replace("+00:00", "Z"),
            legal_hold=False,
            source_quarantine_id=quarantine_id,
        )
        manifest_path = edir.parent / f"{edir.name}.manifest.json"
        os.chmod(edir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        manifest_path.write_text(json.dumps(manifest.as_dict()), encoding="utf-8")
        os.chmod(manifest_path, stat.S_IRUSR)
        os.chmod(edir, stat.S_IRUSR | stat.S_IXUSR)
        # Quarantine is single-use: remove the staged copy once promoted.
        shutil.rmtree(qdir, ignore_errors=True)
        return manifest

    # -- read / lookup -----------------------------------------------------------

    def _manifest_path(self, case_id: str, evidence_id: str) -> Path:
        edir = self._evidence_dir(case_id, evidence_id)
        return edir.parent / f"{edir.name}.manifest.json"

    def read_manifest(self, case_id: str, evidence_id: str) -> EvidenceManifest:
        mpath = self._manifest_path(case_id, evidence_id)
        if not mpath.is_file():
            raise EvidenceStoreError("EVIDENCE_NOT_FOUND", "no evidence object at that case/evidence id in this tenant")
        data = json.loads(mpath.read_text(encoding="utf-8"))
        if data.get("tenant_id") != self.tenant_id:
            raise EvidenceStoreError("EVIDENCE_NOT_FOUND", "no evidence object at that case/evidence id in this tenant")
        return EvidenceManifest(**data)

    def original_path(self, case_id: str, evidence_id: str) -> Path:
        """Return the read-only path to the original bytes (never opened for write here)."""
        self.read_manifest(case_id, evidence_id)  # enforces tenant scope + existence
        edir = self._evidence_dir(case_id, evidence_id)
        original = edir / "original"
        _reject_symlink(original)
        if not original.is_file():
            raise EvidenceStoreError("EVIDENCE_NOT_FOUND", "evidence original missing on disk")
        return _require_contained(original, self._tenant_root)

    def verify_integrity(self, case_id: str, evidence_id: str) -> bool:
        """Re-hash the original and compare against the manifest (tamper check)."""
        manifest = self.read_manifest(case_id, evidence_id)
        original = self.original_path(case_id, evidence_id)
        return _sha256_file(original) == manifest.sha256

    # -- retention / legal hold / deletion -----------------------------------------

    def set_legal_hold(self, case_id: str, evidence_id: str, hold: bool) -> EvidenceManifest:
        manifest = self.read_manifest(case_id, evidence_id)
        updated = EvidenceManifest(**{**manifest.as_dict(), "legal_hold": hold})
        mpath = self._manifest_path(case_id, evidence_id)
        os.chmod(mpath, stat.S_IRUSR | stat.S_IWUSR)
        mpath.write_text(json.dumps(updated.as_dict()), encoding="utf-8")
        os.chmod(mpath, stat.S_IRUSR)
        return updated

    def delete_evidence(self, case_id: str, evidence_id: str, *, force_after_hold_cleared: bool = False) -> None:
        """Fail-closed delete: refuses while legal hold is set or retention is active.

        force_after_hold_cleared exists only to make the fail-closed check
        explicit at call sites; it never bypasses an active hold or retention.
        """
        manifest = self.read_manifest(case_id, evidence_id)
        if manifest.legal_hold:
            raise EvidenceStoreError("LEGAL_HOLD_ACTIVE", "evidence is under legal hold and cannot be deleted")
        retention_until = datetime.fromisoformat(manifest.retention_until_utc.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) < retention_until:
            raise EvidenceStoreError("RETENTION_ACTIVE", "retention period has not elapsed")
        if not force_after_hold_cleared:
            raise EvidenceStoreError("DELETE_NOT_CONFIRMED", "explicit force_after_hold_cleared=True required to delete evidence")
        edir = self._evidence_dir(case_id, evidence_id)
        os.chmod(edir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        shutil.rmtree(edir)
        self._manifest_path(case_id, evidence_id).unlink(missing_ok=True)
