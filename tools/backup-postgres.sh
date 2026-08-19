#!/usr/bin/env bash
set -euo pipefail

: "${DFIRWB_BACKUP_DIR:?set DFIRWB_BACKUP_DIR to an encrypted/off-host backup directory}"
: "${DFIRWB_DATABASE_URL:?set DFIRWB_DATABASE_URL via a secret manager}"
retention_days="${DFIRWB_BACKUP_RETENTION_DAYS:-30}"
mkdir -p -- "$DFIRWB_BACKUP_DIR"
chmod 700 -- "$DFIRWB_BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp="$(mktemp "$DFIRWB_BACKUP_DIR/.dfir-${timestamp}.XXXXXX.dump")"
trap 'rm -f -- "$tmp"' EXIT

pg_dump --format=custom --no-owner --no-acl --file="$tmp" "$DFIRWB_DATABASE_URL"
sha256sum "$tmp" > "$tmp.sha256"
mv -- "$tmp" "$DFIRWB_BACKUP_DIR/dfir-${timestamp}.dump"
mv -- "$tmp.sha256" "$DFIRWB_BACKUP_DIR/dfir-${timestamp}.dump.sha256"
find "$DFIRWB_BACKUP_DIR" -type f -name 'dfir-*.dump' -mtime "+$retention_days" -delete
find "$DFIRWB_BACKUP_DIR" -type f -name 'dfir-*.dump.sha256' -mtime "+$retention_days" -delete
printf 'created backup %s\n' "$DFIRWB_BACKUP_DIR/dfir-${timestamp}.dump"
