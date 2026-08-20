# OpenAI-compatible model gateway

`dfir_workbench.model_gateway.ModelGateway` is a server-side seam for the
analyst Ask-AI flow. It accepts an operator-owned `ProviderConfig` registry and
selects providers only by opaque `provider_id`; callers cannot provide or
override a URL, model, key, retry policy, or egress rule.

The default is `ModelGateway.local_mock()`. It makes no network calls and
returns deterministic text. External providers must be explicitly configured
with an `https://` URL, a secret reference, and an operator policy. At request
time the gateway resolves the hostname and rejects loopback, private,
link-local, multicast, reserved, unspecified, or unresolved destinations. TLS
certificate verification remains the standard `urllib` default; no insecure TLS
context or proxy override is accepted.

The request shape is the OpenAI-compatible `POST <base_url>/v1/chat/completions`
body:

```json
{"model":"operator-configured-model","messages":[{"role":"user","content":"..."}]}
```

The compatible response must contain
`choices[0].message.content` and may contain the usual `usage` fields
`prompt_tokens`, `completion_tokens`, and `total_tokens`. Provider responses are
bounded to 256 KiB. Retries are limited to three and occur only for transient
HTTP/transport failures. Timeouts are capped at 30 seconds and the request
sets the operator-owned `max_tokens` output ceiling (2,000 by default).

`TokenCostBudget` reserves estimated input tokens before egress and rejects
requests after the configured token/cost ceiling. The completion metadata is
safe for audit: provider/model/policy/compatibility and local-vs-external mode;
request and response bodies, URLs containing secrets, and API keys are not
returned or logged by this module. Secret values are obtained through the
server-only `secret_resolver` callback.

This seam does not authorize case context, redaction, consent, provenance, or
saving model output. Those controls remain mandatory at the API/service layer
per `docs/analyst-ask-ai-data-boundary.md`.
