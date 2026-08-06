-- Migration: create analyst flags for processed timeline entries
-- Target: PostgreSQL 15+, applied after metadata-schema.sql
-- This migration is additive: it does not alter or rewrite processed entries.

BEGIN;

CREATE TABLE dfir.timeline_entry_flag (
  tenant_id uuid NOT NULL,
  flag_id uuid NOT NULL DEFAULT gen_random_uuid(),
  timeline_entry_id text NOT NULL,
  analyst_id uuid NOT NULL,
  analyst_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  note text,

  CONSTRAINT timeline_entry_flag_pkey
    PRIMARY KEY (tenant_id, flag_id),
  CONSTRAINT timeline_entry_flag_entry_id_not_blank
    CHECK (btrim(timeline_entry_id) <> ''),
  CONSTRAINT timeline_entry_flag_analyst_name_not_blank
    CHECK (btrim(analyst_name) <> ''),
  CONSTRAINT timeline_entry_flag_entry_analyst_key
    UNIQUE (tenant_id, timeline_entry_id, analyst_id),
  CONSTRAINT timeline_entry_flag_analyst_fk
    FOREIGN KEY (tenant_id, analyst_id)
    REFERENCES dfir.analyst (tenant_id, analyst_id)
);

-- The unique constraint above also supplies an index for duplicate prevention
-- and entry+analyst lookup. These additional indexes match the read paths used
-- by the timeline UI/API without changing existing timeline data.
CREATE INDEX timeline_entry_flag_entry_time_idx
  ON dfir.timeline_entry_flag (tenant_id, timeline_entry_id, created_at DESC);

CREATE INDEX timeline_entry_flag_analyst_time_idx
  ON dfir.timeline_entry_flag (tenant_id, analyst_id, created_at DESC);

CREATE INDEX timeline_entry_flag_created_at_idx
  ON dfir.timeline_entry_flag (tenant_id, created_at DESC);

COMMIT;
