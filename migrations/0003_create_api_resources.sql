-- Authenticated HTTP resource metadata tables. Evidence bytes are never stored.
BEGIN;

CREATE TABLE IF NOT EXISTS dfir.case_record (
  tenant_id uuid NOT NULL,
  case_id text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS dfir.evidence_metadata (
  tenant_id uuid NOT NULL,
  evidence_id text NOT NULL,
  case_id text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS dfir.finding (
  tenant_id uuid NOT NULL,
  finding_id text NOT NULL,
  case_id text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, finding_id)
);
CREATE INDEX IF NOT EXISTS case_record_tenant_created_idx ON dfir.case_record (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS evidence_metadata_tenant_case_idx ON dfir.evidence_metadata (tenant_id, case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS finding_tenant_case_idx ON dfir.finding (tenant_id, case_id, created_at DESC);
COMMIT;
