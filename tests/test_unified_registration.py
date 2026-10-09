"""Unified registration wire validation and recovery checks."""

from dataclasses import replace
from unittest.mock import patch

import httpx
import pytest

from dnsid import AgentRegistrationInput, RegistryClient, RegistryRequestError
from dnsid.exceptions import ArgumentError, ValidationError, VerificationError
from tests._registry_http import patch_registry_http
from tests.test_registry_client import (
    _DOMAIN,
    _FAKE_API_KEY,
    _PUBLICATION_CONFIG,
    _REGISTER_RESPONSE,
    _FakeResponse,
    _live_key,
    _make_client,
    _post_capturing,
    _registration,
)


@pytest.mark.parametrize(
    "selectors",
    [
        {},
        {"domain": "AGENT.EXAMPLE.COM."},
        {"root_domain": "EXAMPLE.COM."},
        {"governance_domain": "EXAMPLE.COM."},
        {"root_domain": "example.com", "governance_domain": "example.com"},
    ],
)
def test_selectors_without_legacy_defaults(selectors):
    ctx, captured = _post_capturing(_REGISTER_RESPONSE)
    with (
        ctx,
        patch.object(
            RegistryClient, "get_agent_detail", return_value=_registration(authority="registry")
        ),
    ):
        result = _make_client().register_agent(
            AgentRegistrationInput(public_key_jwk=_live_key(), **selectors), "create-1"
        )
    body = captured[0]["body"]
    assert body == {
        "public_key": _live_key().to_dict(),
        **{name: value.lower().rstrip(".") for name, value in selectors.items()},
    }
    assert captured[0]["headers"] == {"Idempotency-Key": "create-1"}
    assert result.id == "agent-123"
    assert result.publication_authority == "registry"
    assert result.publication_config.governance_id == "example.com"
    assert result.publication_config.max_key_age == ""
    assert result.publication_config.capabilities_url == ""


@pytest.mark.parametrize(
    "changes",
    [
        {"domain": _DOMAIN, "root_domain": "example.com"},
        {"root_domain": "bad..example"},
        {"governance_domain": "https://example.com"},
        {"domain": "bad/domain"},
        {"capabilities_url": "http://example.com/card"},
        {"capabilities_url": "https://user:pass@example.com/card"},
        {"name": "x" * 256},
        {"public_key_jwk": None},
        {"public_key_jwk": _live_key(d="private")},
        {"tier": "live"},
        {"idempotency_key": "key\r\nInjected: header"},
    ],
)
def test_invalid_input_never_posts(changes):
    input = AgentRegistrationInput(public_key_jwk=_live_key())
    input = replace(input, **changes)
    with patch.object(RegistryClient, "_post") as post, pytest.raises(ArgumentError):
        _make_client().register_agent(input)
    post.assert_not_called()


def test_nested_private_jwks_never_posts():
    key = _live_key()
    key._raw["keys"] = [{"keys": [{"d": "private"}]}]
    with patch.object(RegistryClient, "_post") as post, pytest.raises(ArgumentError):
        _make_client().register_agent(AgentRegistrationInput(public_key_jwk=key))
    post.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"domain": "other.example.com"},
        {"id": ""},
        {"publication_config": None},
        {"publication_config": {**_PUBLICATION_CONFIG, "governance_id": "other.example"}},
        {"publication_config": {**_PUBLICATION_CONFIG, "publish_profile": "DNSid1"}},
        {"publication_config": {**_PUBLICATION_CONFIG, "ku_url": "https://other.example/key"}},
        {"publication_config": {**_PUBLICATION_CONFIG, "log_ref": "bad"}},
        {"publication_config": {**_PUBLICATION_CONFIG, "max_key_age": "1d"}},
        {"oidc_issuer_url": 42},
    ],
)
def test_invalid_response_retains_creation_facts_without_detail_read(changes):
    response = {**_REGISTER_RESPONSE, **changes}
    ctx, captured = _post_capturing(response)
    with ctx, patch.object(RegistryClient, "get_agent_detail") as detail:
        with pytest.raises((ValidationError, VerificationError)) as caught:
            _make_client().register_agent(AgentRegistrationInput(domain=_DOMAIN), "create-1")
    detail.assert_not_called()
    assert len(captured) == 1
    assert caught.value.registration_request == {"domain": _DOMAIN}
    assert caught.value.registration_response == response
    assert caught.value.registration_idempotency_key == "create-1"


@pytest.mark.parametrize("root", ["agent.example.com", "ample.com", "other.example.com"])
def test_returned_domain_is_strictly_beneath_root(root):
    ctx, _ = _post_capturing(_REGISTER_RESPONSE)
    with ctx, pytest.raises(ValidationError, match="beneath root_domain"):
        _make_client().register_agent(
            AgentRegistrationInput(root_domain=root, public_key_jwk=_live_key())
        )


def test_gi_response_must_match_expected_gi():
    ctx, _ = _post_capturing(_REGISTER_RESPONSE)
    with ctx, pytest.raises(ValidationError, match="different governance"):
        _make_client().register_agent(
            AgentRegistrationInput(governance_domain="other.example", public_key_jwk=_live_key())
        )


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (409, "AMBIGUOUS_ROOT"),
        (409, "MANAGED_GOVERNANCE_UNAVAILABLE"),
        (422, "IDEMPOTENCY_MISMATCH"),
        (403, "GOVERNANCE_NOT_AUTHORIZED"),
        (400, "BAD_REQUEST"),
        (503, "SERVICE_UNAVAILABLE"),
    ],
)
def test_server_errors_preserve_request_and_key_without_fallback(status, code):
    input = AgentRegistrationInput(
        root_domain="example.com",
        governance_domain="example.com",
        public_key_jwk=_live_key(),
        managed=True,
        environment="production",
        zone_id="zone-1",
    )
    with patch_registry_http("httpx.post", return_value=_FakeResponse(status, {"error": code})) as post:
        with pytest.raises(RegistryRequestError) as caught:
            _make_client().register_agent(input, "create-1")
    assert post.call_count == 1
    assert caught.value.status_code == status
    assert caught.value.error_code == code
    assert caught.value.registration_idempotency_key == "create-1"
    assert caught.value.registration_request == post.call_args.kwargs["json"]
    assert caught.value.registration_request["zone_id"] == "zone-1"


def test_keyed_retry_retains_complete_request():
    ctx, captured = _post_capturing(_REGISTER_RESPONSE)
    with ctx, patch.object(RegistryClient, "get_agent_detail", return_value=_registration()):
        input = AgentRegistrationInput(root_domain="example.com", public_key_jwk=_live_key())
        first = _make_client().register_agent(input, "create-1")
        second = _make_client().register_agent(input, "create-1")
    assert first == second
    assert captured[0] == captured[1]
    assert "domain" not in captured[1]["body"]


def test_creation_timeout_does_not_retry_without_key():
    with patch_registry_http("httpx.post", side_effect=httpx.ReadTimeout("timeout")) as post:
        with pytest.raises(VerificationError) as caught:
            _make_client().register_agent(AgentRegistrationInput(domain=_DOMAIN))
    assert post.call_count == 1
    assert caught.value.registration_request == {"domain": _DOMAIN}
    assert caught.value.registration_response is None
    assert caught.value.registration_idempotency_key == ""


@pytest.mark.parametrize("managed", ["dnsid", "self", "unknown"])
def test_creation_uses_authenticated_detail_and_preserves_snapshot_on_failure(managed):
    detail = {"id": "agent-123", "domain": _DOMAIN, "status": "READY", "managed": managed}
    with (
        patch_registry_http("httpx.post", return_value=_FakeResponse(201, _REGISTER_RESPONSE)),
        patch_registry_http("httpx.get", return_value=_FakeResponse(200, detail)) as get,
    ):
        if managed == "unknown":
            with pytest.raises(ValidationError) as caught:
                _make_client().register_agent(AgentRegistrationInput(domain=_DOMAIN), "create-1")
            assert caught.value.registration_response == _REGISTER_RESPONSE
        else:
            result = _make_client().register_agent(AgentRegistrationInput(domain=_DOMAIN))
            assert result.publication_authority == ("registry" if managed == "dnsid" else "client")
        assert get.call_args.args[0] == f"https://registry.example.com/api/v1/agent/{_DOMAIN}/status"
        assert get.call_args.kwargs["headers"] == {"Authorization": f"Bearer {_FAKE_API_KEY}"}
        assert get.call_count == 1


def test_failed_detail_retains_id_domain_config_and_issuer():
    response = {**_REGISTER_RESPONSE, "oidc_issuer_url": "https://issuer.example.com"}
    with (
        patch_registry_http("httpx.post", return_value=_FakeResponse(201, response)),
        patch_registry_http("httpx.get", return_value=_FakeResponse(403, {"error": "FORBIDDEN"})) as get,
        pytest.raises(RegistryRequestError) as caught,
    ):
        _make_client().register_agent(AgentRegistrationInput(domain=_DOMAIN), "create-1")
    assert get.call_count == 1
    assert caught.value.registration_response == response
    assert caught.value.error_code == "FORBIDDEN"
    assert _FAKE_API_KEY not in str(caught.value)


def test_unexpected_creation_status_preserves_facts_and_http_status():
    with patch_registry_http("httpx.post", return_value=_FakeResponse(202, _REGISTER_RESPONSE)) as post:
        with pytest.raises(VerificationError) as caught:
            _make_client().register_agent(AgentRegistrationInput(domain=_DOMAIN), "create-1")
    assert post.call_count == 1
    assert caught.value.status_code == 202
    assert caught.value.registration_response["id"] == "agent-123"
    assert caught.value.registration_response["publication_config"] == _PUBLICATION_CONFIG


def test_creation_snapshot_is_not_replaced_by_detail_defaults():
    response = {**_REGISTER_RESPONSE, "oidc_issuer_url": "https://issuer.example.com"}
    detail = {
        "id": "agent-123",
        "domain": _DOMAIN,
        "managed": "self",
        "status": "READY",
        "publication_config": {**_PUBLICATION_CONFIG, "max_key_age": "30d"},
        "oidc_issuer_url": "https://later.example.com",
    }
    with (
        patch_registry_http("httpx.post", return_value=_FakeResponse(201, response)),
        patch_registry_http("httpx.get", return_value=_FakeResponse(200, detail)),
    ):
        result = _make_client().register_agent(AgentRegistrationInput(domain=_DOMAIN))
    assert result.publication_config.max_key_age == ""
    assert result.oidc_issuer_url == response["oidc_issuer_url"]


@pytest.mark.parametrize("operation", ["get_agent_detail", "get_registration"])
def test_management_reads_require_credentials(operation):
    client = RegistryClient("https://registry.example.com")
    with patch_registry_http("httpx.get") as get, pytest.raises(ArgumentError, match="credentials"):
        getattr(client, operation)(_DOMAIN)
    get.assert_not_called()


def test_legacy_selectors_and_trimmed_name_are_preserved_with_explicit_root():
    ctx, captured = _post_capturing(_REGISTER_RESPONSE)
    with ctx, patch.object(RegistryClient, "get_agent_detail", return_value=_registration()):
        _make_client().register_agent(
            AgentRegistrationInput(
                root_domain="example.com",
                public_key_jwk=_live_key(),
                environment="production",
                managed=True,
                tier="sandbox",
                zone_id="zone-1",
                name="  Agent  ",
            )
        )
    assert captured[0]["body"] == {
        "root_domain": "example.com",
        "public_key": _live_key().to_dict(),
        "environment": "production",
        "managed": True,
        "tier": "sandbox",
        "zone_id": "zone-1",
        "name": "Agent",
    }
