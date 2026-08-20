"""Small, server-side OpenAI-compatible model gateway.

Provider selection is by an operator-owned registry ID, never by a request URL.
The default provider is the deterministic local mock; external egress is an
explicit, HTTPS-only configuration decision.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence
from urllib.parse import urlsplit


class GatewayError(Exception):
    """Safe, bounded error suitable for returning without provider details."""


class ProviderConfigurationError(GatewayError):
    pass


class ProviderRequestError(GatewayError):
    pass


class BudgetExceeded(GatewayError):
    pass


@dataclass(frozen=True)
class ProviderConfig:
    """Operator-owned provider policy; secrets are referenced, not stored."""

    provider_id: str
    base_url: str
    model: str
    timeout_seconds: float = 15.0
    max_retries: int = 1
    max_output_tokens: int = 2_000
    secret_ref: str | None = None
    external: bool = False
    cost_per_1k_tokens: float | None = None
    policy_id: str = "default"
    compatibility_version: str = "chat-completions-v1"

    def __post_init__(self) -> None:
        if not self.provider_id or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in self.provider_id):
            raise ProviderConfigurationError("provider_id is invalid")
        if not self.model or len(self.model) > 200:
            raise ProviderConfigurationError("model is invalid")
        if not 0.1 <= self.timeout_seconds <= 30:
            raise ProviderConfigurationError("timeout must be between 0.1 and 30 seconds")
        if not 0 <= self.max_retries <= 3:
            raise ProviderConfigurationError("max_retries must be between 0 and 3")
        if not 1 <= self.max_output_tokens <= 2_000:
            raise ProviderConfigurationError("max_output_tokens must be between 1 and 2000")
        if self.cost_per_1k_tokens is not None and self.cost_per_1k_tokens < 0:
            raise ProviderConfigurationError("cost rate cannot be negative")
        _validate_url(self.base_url, external=self.external)
        if self.external and not self.secret_ref:
            raise ProviderConfigurationError("external providers require a secret reference")


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated: bool = False


@dataclass(frozen=True)
class Completion:
    text: str
    usage: Usage
    metadata: Mapping[str, object]


class TokenCostBudget:
    """Thread-safe bounded deployment budget; reserve before provider egress."""

    def __init__(self, max_tokens: int, max_cost: float | None = None) -> None:
        if max_tokens < 0 or (max_cost is not None and max_cost < 0):
            raise ValueError("budget limits cannot be negative")
        self.max_tokens = max_tokens
        self.max_cost = max_cost
        self._tokens = 0
        self._cost = 0.0
        self._lock = threading.Lock()

    def reserve(self, tokens: int, cost: float | None) -> None:
        with self._lock:
            if self._tokens + tokens > self.max_tokens:
                raise BudgetExceeded("token budget exhausted")
            if self.max_cost is not None and cost is not None and self._cost + cost > self.max_cost:
                raise BudgetExceeded("cost budget exhausted")
            self._tokens += tokens
            if cost is not None:
                self._cost += cost

    @property
    def spent(self) -> tuple[int, float]:
        with self._lock:
            return self._tokens, self._cost


class ModelGateway:
    """Provider registry and minimal `/v1/chat/completions` client seam."""

    def __init__(
        self,
        providers: Sequence[ProviderConfig],
        secret_resolver: Callable[[str], str] | None = None,
        budget: TokenCostBudget | None = None,
        opener: Callable[..., object] | None = None,
        resolver: Callable[[str, int], Sequence[tuple]] | None = None,
    ) -> None:
        self._providers = {p.provider_id: p for p in providers}
        if len(self._providers) != len(providers):
            raise ProviderConfigurationError("duplicate provider_id")
        self._secret_resolver = secret_resolver
        self._budget = budget
        # Ignore ambient HTTP(S)_PROXY settings. A future controlled-proxy
        # policy must inject an explicit opener rather than inherit the host.
        self._opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({})).open
        self._resolver = resolver or socket.getaddrinfo

    @classmethod
    def local_mock(cls, budget: TokenCostBudget | None = None) -> "ModelGateway":
        return cls((ProviderConfig("local-mock", "mock://local", "deterministic-mock"),), budget=budget)

    def provider_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    def complete(self, provider_id: str, messages: Sequence[Mapping[str, str]]) -> Completion:
        config = self._providers.get(provider_id)
        if config is None:
            raise ProviderRequestError("unknown provider")
        if not messages or any(m.get("role") not in {"system", "user", "assistant"} or not isinstance(m.get("content"), str) for m in messages):
            raise ProviderRequestError("invalid messages")
        input_tokens = _estimate_tokens(messages)
        estimated_output = 1
        requested_tokens = input_tokens + estimated_output
        cost = _cost(config, requested_tokens)
        if self._budget:
            self._budget.reserve(requested_tokens, cost)
        started = time.monotonic()
        try:
            if config.base_url.startswith("mock://"):
                text = _mock_response(messages)
                usage = Usage(input_tokens, 1, input_tokens + 1, estimated=True)
            else:
                text, usage = self._request(config, messages)
        except BudgetExceeded:
            raise
        except GatewayError:
            raise
        except Exception as exc:
            raise ProviderRequestError("provider request failed") from exc
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return Completion(text, usage, {
            "provider_id": config.provider_id,
            "model": config.model,
            "policy_id": config.policy_id,
            "compatibility_version": config.compatibility_version,
            "egress": "external" if config.external else "local",
            "elapsed_ms": elapsed_ms,
        })

    def _request(self, config: ProviderConfig, messages: Sequence[Mapping[str, str]]) -> tuple[str, Usage]:
        _validate_resolved_destination(config.base_url, self._resolver)
        api_key = self._secret_resolver(config.secret_ref) if self._secret_resolver and config.secret_ref else None
        if config.external and not api_key:
            raise ProviderRequestError("provider secret unavailable")
        body = json.dumps({"model": config.model, "messages": list(messages), "max_tokens": config.max_output_tokens}).encode()
        request = urllib.request.Request(
            config.base_url.rstrip("/") + "/v1/chat/completions",
            data=body,
            headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {api_key}"} if api_key else {})},
            method="POST",
        )
        for attempt in range(config.max_retries + 1):
            try:
                with self._opener(request, timeout=config.timeout_seconds) as response:
                    raw = response.read(256 * 1024 + 1)
                    if len(raw) > 256 * 1024:
                        raise ProviderRequestError("provider response too large")
                    return _parse_response(raw)
            except urllib.error.HTTPError as exc:
                if exc.code not in {408, 429, 500, 502, 503, 504} or attempt == config.max_retries:
                    raise ProviderRequestError("provider returned an error") from exc
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                if attempt == config.max_retries:
                    raise ProviderRequestError("provider unavailable") from exc
        raise ProviderRequestError("provider unavailable")


def _validate_url(value: str, external: bool) -> None:
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ProviderConfigurationError("provider URL must not contain credentials, query, or fragment")
    if external and parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ProviderConfigurationError("private or special provider destination is not allowed")
    if external and parsed.scheme != "https":
        raise ProviderConfigurationError("external providers require HTTPS")
    if not external and parsed.scheme != "mock":
        raise ProviderConfigurationError("non-external providers must use the local mock scheme")
    if parsed.port and not 1 <= parsed.port <= 65535:
        raise ProviderConfigurationError("provider port is invalid")
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return
    if _blocked_ip(ip):
        raise ProviderConfigurationError("private or special provider destination is not allowed")


def _validate_resolved_destination(url: str, resolver: Callable[[str, int], Sequence[tuple]]) -> None:
    parsed = urlsplit(url)
    try:
        infos = resolver(parsed.hostname or "", parsed.port or 443)
    except (OSError, socket.gaierror) as exc:
        raise ProviderRequestError("provider destination could not be resolved") from exc
    addresses = {item[4][0] for item in infos if len(item) > 4 and item[4]}
    if not addresses or any(_blocked_ip(ipaddress.ip_address(address)) for address in addresses):
        raise ProviderRequestError("provider destination is not allowed")


def _blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def _estimate_tokens(messages: Sequence[Mapping[str, str]]) -> int:
    return max(1, sum(len(m["content"].encode("utf-8")) for m in messages) // 4)


def _cost(config: ProviderConfig, tokens: int) -> float | None:
    return None if config.cost_per_1k_tokens is None else config.cost_per_1k_tokens * tokens / 1000


def _mock_response(messages: Sequence[Mapping[str, str]]) -> str:
    return "[local-mock] Advisory answer generated from redacted context; verify against source evidence."


def _parse_response(raw: bytes) -> tuple[str, Usage]:
    try:
        payload = json.loads(raw)
        text = payload["choices"][0]["message"]["content"]
        if not isinstance(text, str) or not text:
            raise ValueError
        usage_data = payload.get("usage") or {}
        input_tokens = int(usage_data.get("prompt_tokens", 0))
        output_tokens = int(usage_data.get("completion_tokens", 0))
        return text, Usage(input_tokens, output_tokens, int(usage_data.get("total_tokens", input_tokens + output_tokens)))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderRequestError("malformed provider response") from exc
