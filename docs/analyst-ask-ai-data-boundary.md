# Analyst Ask AI data boundary

## Status and operator gate

Ask AI is disabled by default. An operator must set `DFIRWB_AI_ENABLED=true` and review `DFIRWB_AI_POLICY_VERSION` before enabling the routes. External provider egress is a separate provider-registry decision and is never enabled by this flag.

The model output is advisory only. A human analyst must explicitly approve a derived answer for a report or finding. Approval records intent and does not mutate authoritative evidence, findings, or case state.

## Authorized context

`POST /api/v1/ai/requests` accepts a case ID, question, resource class, and opaque resource ID. The API derives tenant and analyst scope from the authenticated `Principal`, then resolves the resource from the tenant-and-case-scoped authoritative store. Client-supplied `selection.data`, tenant IDs, and analyst IDs are not authoritative. Missing, malformed, or cross-scope resources receive a generic denial and never reach the context builder or provider.

Allowed context classes are `case`, `evidence`, `artifact`, `timeline`, `finding`, and `report_section`. The synthetic development principal uses a fixed server-owned artifact fixture only; it is not a production evidence store. UUID principals require the configured PostgreSQL resource store.

## Redaction and prompt-injection policy

The context builder creates a minimum-necessary metadata package. It excludes raw bytes, content/body fields, download links, source mounts, directory listings, filesystem paths, and credential-shaped keys. Credential-shaped values are replaced with `[REDACTED:credential]`. Absolute paths and file/HTTP links in evidence are rejected rather than sent to a provider. Questions are credential-redacted but may contain normal analyst prose.

Evidence is untrusted data, never instructions. Text matching common instruction-hijacking phrases is labeled with `[UNTRUSTED_EVIDENCE:prompt_injection]` and counted in the context manifest. The provider system message explicitly says to treat quoted evidence as data. The UI warns analysts not to follow instructions in evidence. This is defense in depth, not a claim that heuristic detection catches every attack; analysts must still verify citations against source evidence.

## Limits, cost, and retention

The context package is bounded to 4,000 UTF-8 question bytes, 64 KiB serialized input, 16 KiB per field, 200 fields, 100 list records, depth 4, and an estimated 8,000 input tokens. Provider requests cap output at 2,000 tokens, response bodies at 256 KiB, timeouts at 30 seconds, and retries at three. A deployment-wide token/cost budget is reserved before provider egress. The API also limits each tenant/analyst pair to 20 requests per rolling hour and one in-flight request.

Audit metadata contains status, provider, model, policy version, package SHA-256, response SHA-256, and input/output/total token counts. It does not contain the question, rendered prompt, context, or answer. The in-memory derived response cache is TTL-purged after one hour and is not a durable evidence record. Production deployments must pair this with the configured durable audit repository and its retention policy; the in-memory synthetic path is not production retention.

## Audit and provenance example

A successful response exposes safe derived metadata similar to:

```json
{
  "request_id": "uuid",
  "selected_context": {"resource_class": "artifact", "resource_id": "artifact-1"},
  "context_manifest": {
    "policy_version": "analyst-ask-ai/v1",
    "included_fields": ["data.description", "data.sha256"],
    "redactions": [],
    "prompt_injection_count": 0
  },
  "provenance": {
    "selected_resource_id": "artifact-1",
    "source_references": [{"resource_class": "artifact", "resource_id": "artifact-1", "sha256": "..."}],
    "package_sha256": "sha256-of-redacted-package"
  },
  "approval": null
}
```

For a UUID-backed tenant, the durable audit event `ai.request.completed` records the policy, provider, package hash, response hash, and token counts. `ai.answer.approved` records the target and `mutated_authoritative_record: false`.

## Provider compatibility matrix

| Provider mode | Base URL / protocol | Auth | Egress | Intended use |
| --- | --- | --- | --- | --- |
| `local-mock` | `mock://local`; deterministic seam | none | none | tests and synthetic development |
| OpenAI-compatible external | operator-configured `https://` URL | server-side secret reference | explicit external HTTPS only | controlled pilot integration |
| Arbitrary request URL | not supported | n/a | denied | prevents SSRF and client policy bypass |

The gateway resolves external hostnames at request time and rejects loopback, private, link-local, multicast, reserved, unspecified, and unresolved destinations. Standard TLS certificate verification remains enabled. Provider IDs, models, URLs, retry policy, secrets, and egress policy are operator-owned configuration; callers cannot override them.

## Known pilot limitations

Browser automation was unavailable during acceptance, PostgreSQL-backed audit persistence was not exercised, the synthetic resource catalog currently exposes only one artifact fixture, and the synchronous mock does not demonstrate cancellation of an in-flight provider call. These are explicit coverage limitations, not claims of production readiness.
