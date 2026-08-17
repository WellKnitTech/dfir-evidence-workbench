-- Migration: create append-only ingest envelopes for preview/approval/commit/quarantine
-- Target: PostgreSQL 15+, additive after 0001
-- Tenant isolation enforced at repo layer (WHERE + insert values from principal only)
-- Idempotency via unique constraint on (tenant_id, idempotency_key)
-- Statuses match reviewed ingest-envelope.schema.json processing.status enum
-- No evidence content bytes stored; payload is the vendor raw object for audit only

BEGIN;

CREATE TABLE dfir.ingest_envelope (
  tenant_id uuid NOT NULL,
  envelope_id text NOT NULL,
  received_at_utc timestamptz NOT NULL,
  source_system text NOT NULL,
  source_entity text NOT NULL,
  source_id text NOT NULL,
  source_scope text NOT NULL,
  source_revision text NOT NULL,
  payload_sha256 text NOT NULL,
  payload jsonb NOT NULL,
  processing_status text NOT NULL,
  mapping_version text NOT NULL,
  idempotency_key text NOT NULL,
  target_id text,
  error_code text,
  quarantine_reference text,
  analyst_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),

  CONSTRAINT ingest_envelope_pkey PRIMARY KEY (tenant_id, envelope_id),
  CONSTRAINT ingest_envelope_idem_key UNIQUE (tenant_id, idempotency_key),
  CONSTRAINT ingest_envelope_status_check
    CHECK (processing_status IN ('received', 'validated', 'preview', 'approved', 'applied', 'duplicate', 'rejected', 'quarantined', 'conflict')),
  CONSTRAINT ingest_envelope_sha_check
    CHECK (payload_sha256 ~ '^[a-fA-F0-9]{64}$'),
  CONSTRAINT ingest_envelope_analyst_fk
    FOREIGN KEY (tenant_id, analyst_id) REFERENCES dfir.analyst (tenant_id, analyst_id)
);

CREATE INDEX IF NOT EXISTS ingest_envelope_tenant_status_idx
  ON dfir.ingest_envelope (tenant_id, processing_status, created_at DESC);

CREATE INDEX IF NOT EXISTS ingest_envelope_idem_idx
  ON dfir.ingest_envelope (tenant_id, idempotency_key);

COMMIT;
