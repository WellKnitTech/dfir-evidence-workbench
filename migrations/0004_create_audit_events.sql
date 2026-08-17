-- Migration: append-only audit event log (queryable, tenant-scoped)
-- Target: PostgreSQL 15+, additive after 0003
-- No UPDATE/DELETE paths exist in the application repository layer for this table.
-- ponytail: real WORM/object-lock storage + a separate insert-only DB role is the
-- production hardening step (see docs/observability-and-incident-operations.md);
-- this migration gives the prototype a queryable, append-only-by-convention sink.

BEGIN;

CREATE TABLE dfir.audit_event (
  event_id uuid NOT NULL,
  tenant_id uuid,
  case_id text,
  actor_type text NOT NULL,
  actor_id text,
  object_type text,
  object_id text,
  action text NOT NULL,
  result text NOT NULL,
  correlation_id text NOT NULL,
  source text NOT NULL,
  occurred_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,

  CONSTRAINT audit_event_pkey PRIMARY KEY (event_id),
  CONSTRAINT audit_event_actor_type_check
    CHECK (actor_type IN ('user', 'service', 'job', 'system')),
  CONSTRAINT audit_event_result_check
    CHECK (result IN ('success', 'denied', 'validation_failed', 'not_found', 'conflict', 'error', 'partial'))
);

CREATE INDEX IF NOT EXISTS audit_event_tenant_recorded_idx
  ON dfir.audit_event (tenant_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS audit_event_correlation_idx
  ON dfir.audit_event (correlation_id);

COMMIT;
