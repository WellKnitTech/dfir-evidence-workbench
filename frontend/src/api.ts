/**
 * Minimal typed API client for the DFIR Evidence Workbench HTTP API.
 *
 * - Every mutating/read call hits the real backend routes in
 *   src/dfir_workbench/api.py (no mock data, no fallback).
 * - Errors are surfaced as ApiError with the server's structured
 *   {error:{code,message,retryable}} envelope preserved.
 * - Tenant scope is never selected client-side: it is entirely derived
 *   server-side from the bearer token (see api.py get_current_principal).
 *   The UI never sends a tenant id anywhere.
 */

export interface ApiErrorBody {
  code: string;
  message: string;
  retryable: boolean;
}

export class ApiError extends Error {
  status: number;
  code: string;
  retryable: boolean;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message);
    this.status = status;
    this.code = body.code;
    this.retryable = body.retryable;
  }
}

export interface Whoami {
  tenant_id: string;
  analyst_id: string;
  roles: string[];
  scopes: string[];
}

export interface ListResult<T> {
  items: T[];
  count: number;
  limit: number;
  offset: number;
}

export interface CaseRecord {
  id: string;
  title?: string;
  [key: string]: unknown;
}

export interface EvidenceRecord {
  id: string;
  case_id?: string;
  [key: string]: unknown;
}

export interface FindingRecord {
  id: string;
  case_id?: string;
  [key: string]: unknown;
}

export interface IngestEnvelope {
  envelope_id: string;
  processing_status: string;
  payload_sha256: string;
  idempotency_key: string;
  target_id: string | null;
  error_code: string | null;
  quarantine_reference: string | null;
  [key: string]: unknown;
}

export interface TimelineFlag {
  flag_id: string;
  timeline_entry_id: string;
  analyst_name: string;
  created_at: string;
  note: string | null;
}

export interface RunnerFixture {
  fixture_id: string;
  class: string;
  scenario: string[];
  format: string;
  synthetic: boolean;
}

export interface RunnerJob {
  job_id: string;
  fixture_id: string;
  status: string;
  progress: number;
  attempt: number;
  synthetic: boolean;
  provenance: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { code: string; message: string; retryable: boolean };
}

const DEFAULT_BASE_URL = "http://127.0.0.1:8080";

export class ApiClient {
  constructor(
    private baseUrl: string = DEFAULT_BASE_URL,
    private token: string | null = null,
  ) {}

  setToken(token: string | null): void {
    this.token = token;
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body) headers.set("content-type", "application/json");
    if (this.token) headers.set("authorization", `Bearer ${this.token}`);

    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, { ...init, headers });
    } catch {
      throw new ApiError(0, { code: "NETWORK_ERROR", message: "could not reach the API", retryable: true });
    }

    if (res.status === 204) return undefined as T;

    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      // no body / non-JSON
    }

    if (!res.ok) {
      const errBody = (body as { error?: ApiErrorBody } | null)?.error ?? {
        code: `HTTP_${res.status}`,
        message: res.statusText || "request failed",
        retryable: res.status >= 500,
      };
      throw new ApiError(res.status, errBody);
    }
    return body as T;
  }

  whoami(): Promise<Whoami> {
    return this.request("/api/v1/whoami");
  }

  listCases(params: { q?: string; limit?: number; offset?: number } = {}): Promise<ListResult<CaseRecord>> {
    return this.request(`/api/v1/cases${qs(params)}`);
  }

  createCase(payload: { title: string }): Promise<{ case: CaseRecord }> {
    return this.request("/api/v1/cases", { method: "POST", body: JSON.stringify(payload) });
  }

  listEvidence(params: { case_id?: string; q?: string; limit?: number; offset?: number } = {}): Promise<ListResult<EvidenceRecord>> {
    return this.request(`/api/v1/evidence${qs(params)}`);
  }

  createEvidence(payload: Record<string, unknown>): Promise<{ evidence: EvidenceRecord }> {
    return this.request("/api/v1/evidence", { method: "POST", body: JSON.stringify(payload) });
  }

  listFindings(params: { case_id?: string; q?: string; limit?: number; offset?: number } = {}): Promise<ListResult<FindingRecord>> {
    return this.request(`/api/v1/findings${qs(params)}`);
  }

  createFinding(payload: Record<string, unknown>): Promise<{ finding: FindingRecord }> {
    return this.request("/api/v1/findings", { method: "POST", body: JSON.stringify(payload) });
  }

  ingestPreview(payload: Record<string, unknown>): Promise<unknown> {
    return this.request("/api/v1/ingest/preview", { method: "POST", body: JSON.stringify(payload) });
  }

  ingestApprove(envelopeId: string): Promise<IngestEnvelope> {
    return this.request(`/api/v1/ingest/${encodeURIComponent(envelopeId)}/approve`, { method: "POST" });
  }

  ingestCommit(envelopeId: string, targetId?: string): Promise<IngestEnvelope> {
    return this.request(`/api/v1/ingest/${encodeURIComponent(envelopeId)}/commit`, {
      method: "POST",
      body: JSON.stringify(targetId ? { target_id: targetId } : {}),
    });
  }

  ingestQuarantine(envelopeId: string, reason?: string): Promise<IngestEnvelope> {
    return this.request(`/api/v1/ingest/${encodeURIComponent(envelopeId)}/quarantine`, {
      method: "POST",
      body: JSON.stringify(reason ? { reason } : {}),
    });
  }

  createTimelineFlag(payload: { timeline_entry_id: string; note?: string }): Promise<TimelineFlag> {
    return this.request("/api/v1/timeline/flags", { method: "POST", body: JSON.stringify(payload) });
  }

  listTimelineFlags(timelineEntryId: string): Promise<{ items: TimelineFlag[] }> {
    return this.request(`/api/v1/timeline/flags${qs({ timeline_entry_id: timelineEntryId })}`);
  }

  runnerCatalog(): Promise<{ fixtures: RunnerFixture[]; synthetic: boolean }> {
    return this.request("/__dev__/runner/catalog");
  }

  runnerRegister(fixtureId: string): Promise<{ registration: Record<string, unknown> }> {
    return this.request("/__dev__/runner/register", { method: "POST", body: JSON.stringify({ fixture_id: fixtureId }) });
  }

  runnerSubmit(fixtureId: string): Promise<RunnerJob> {
    return this.request("/__dev__/runner/jobs", { method: "POST", body: JSON.stringify({ fixture_id: fixtureId }) });
  }

  runnerReview(jobId: string, decision: "approve" | "quarantine"): Promise<RunnerJob> {
    return this.request(`/__dev__/runner/jobs/${encodeURIComponent(jobId)}/review`, { method: "POST", body: JSON.stringify({ decision }) });
  }

  runnerTeardown(): Promise<Record<string, unknown>> {
    return this.request("/__dev__/runner/teardown", { method: "DELETE" });
  }
}

function qs(params: Record<string, unknown>): string {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== "");
  if (entries.length === 0) return "";
  const sp = new URLSearchParams();
  for (const [k, v] of entries) sp.set(k, String(v));
  return `?${sp.toString()}`;
}
