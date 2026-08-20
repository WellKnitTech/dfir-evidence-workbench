import json
import socket
from types import SimpleNamespace

import pytest

from dfir_workbench.model_gateway import (
    BudgetExceeded,
    ModelGateway,
    ProviderConfigurationError,
    ProviderConfig,
    ProviderRequestError,
    TokenCostBudget,
)


def test_local_mock_is_deterministic_and_never_needs_a_secret():
    gateway = ModelGateway.local_mock()
    result = gateway.complete("local-mock", [{"role": "user", "content": "hello"}])
    assert result.text == "[local-mock] Advisory answer generated from redacted context; verify against source evidence."
    assert result.metadata["egress"] == "local"
    assert result.metadata["provider_id"] == "local-mock"
    assert result.usage.estimated is True


def test_local_mock_does_not_echo_user_package():
    gateway = ModelGateway.local_mock()
    package = '{"question":"secret question","context":{"token":"secret"}}'
    result = gateway.complete("local-mock", [{"role": "user", "content": package}])
    assert "secret question" not in result.text
    assert "secret" not in result.text


@pytest.mark.parametrize("url", ["http://example.com", "https://127.0.0.1", "https://localhost", "https://[::1]"])
def test_external_registry_rejects_non_tls_or_private_destinations(url):
    with pytest.raises(ProviderConfigurationError):
        ProviderConfig("external", url, "model", external=True, secret_ref="secret-ref")


def test_registry_rejects_user_style_arbitrary_non_external_url():
    with pytest.raises(ProviderConfigurationError):
        ProviderConfig("oops", "https://example.com", "model")


def test_external_request_resolves_and_rejects_private_dns_before_opening():
    config = ProviderConfig("external", "https://provider.example", "model", external=True, secret_ref="key")
    opened = []

    def resolver(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", port))]

    gateway = ModelGateway([config], secret_resolver=lambda ref: "not-for-logs", opener=lambda *args, **kwargs: opened.append(args))
    gateway._resolver = resolver
    with pytest.raises(ProviderRequestError, match="not allowed"):
        gateway.complete("external", [{"role": "user", "content": "hello"}])
    assert opened == []


def test_external_request_injects_secret_only_into_transport_and_parses_response():
    config = ProviderConfig("external", "https://provider.example", "model", external=True, secret_ref="key")
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return json.dumps({"choices": [{"message": {"content": "answer"}}], "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}}).encode()

    def opener(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    def resolver(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    gateway = ModelGateway([config], secret_resolver=lambda ref: "super-secret", opener=opener, resolver=resolver)
    result = gateway.complete("external", [{"role": "user", "content": "hello"}])
    assert result.text == "answer"
    assert captured["timeout"] == 15.0
    assert captured["request"].get_header("Authorization") == "Bearer super-secret"
    assert json.loads(captured["request"].data)["max_tokens"] == 2_000
    assert "super-secret" not in str(result.metadata)


def test_budget_is_enforced_before_request():
    gateway = ModelGateway.local_mock(TokenCostBudget(max_tokens=1))
    with pytest.raises(BudgetExceeded):
        gateway.complete("local-mock", [{"role": "user", "content": "a long enough message"}])


def test_provider_response_is_bounded_and_malformed_response_fails_closed():
    config = ProviderConfig("external", "https://provider.example", "model", external=True, secret_ref="key")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return b"{}"

    gateway = ModelGateway([config], secret_resolver=lambda _: "key", opener=lambda *a, **k: Response(), resolver=lambda h, p: [(2, 1, 6, "", ("93.184.216.34", p))])
    with pytest.raises(ProviderRequestError, match="malformed"):
        gateway.complete("external", [{"role": "user", "content": "hello"}])
