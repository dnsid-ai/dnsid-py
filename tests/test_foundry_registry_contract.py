"""Low-level wire additions needed by named Live and issuance recovery."""

from unittest.mock import patch

import httpx
import pytest

from dnsid import LocalKeyProvider, RegistryClient
from dnsid.exceptions import RegistryRequestError, ValidationError
from dnsid.registry_client import _live_provisioning_from_response
from tests.test_foundry import DOMAIN, FoundryServer


def test_challenge_free_replay_domain_present_absent_or_invalid():
    provider = LocalKeyProvider.generate()
    raw = {
        "request_id": "request-1",
        "agent_id": "id-1",
        "status": "PROVISIONING",
        "challenge": "",
        "challenge_message": "",
    }
    assert _live_provisioning_from_response(raw, provider.signing_key()).domain == ""
    assert (
        _live_provisioning_from_response(
            dict(raw, domain="Agent.Example.COM."), provider.signing_key()
        ).domain
        == DOMAIN
    )
    with pytest.raises(ValidationError):
        _live_provisioning_from_response(
            dict(raw, domain="https://invalid"), provider.signing_key()
        )


def test_wire_domain_must_match_challenge_after_normalization():
    provider = LocalKeyProvider.generate()
    server = FoundryServer(provider)
    raw = server.challenge(provider.signing_key(), "request-1")
    raw["domain"] = "Agent.Example.COM."
    assert _live_provisioning_from_response(raw, provider.signing_key()).domain == DOMAIN
    raw["domain"] = "other.example.com"
    with pytest.raises(ValidationError):
        _live_provisioning_from_response(raw, provider.signing_key())


def test_issuance_prepare_preserves_wire_status_and_code():
    response = httpx.Response(409, json={"error": "TLOG_PREPARATION_MISMATCH"})
    with (
        RegistryClient("https://registry.example", api_key="test-placeholder") as client,
        patch.object(
            client,
            "_http_request",
            return_value=response,
        ),
    ):
        with pytest.raises(RegistryRequestError) as caught:
            client.prepare_issuance(DOMAIN, "issuance-1")
    assert caught.value.status_code == 409
    assert caught.value.error_code == "TLOG_PREPARATION_MISMATCH"


def test_submission_rejection_preserves_http_status_with_normalized_result():
    response = httpx.Response(422, json={"error": "IDEMPOTENCY_MISMATCH"})
    with (
        RegistryClient("https://registry.example", api_key="test-placeholder") as client,
        patch.object(
            client,
            "_http_request",
            return_value=response,
        ),
    ):
        result = client.submit_prepared_event(DOMAIN, b"{}", "issuance-1")
    assert result.state == "rejected" and result.status_code == 422
    assert result.error_code == "IDEMPOTENCY_MISMATCH"
