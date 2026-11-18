"""Low-level wire additions needed by named Live and issuance recovery."""

from unittest.mock import Mock, patch

import httpx
import pytest

from dnsid import RegistryClient, SubmissionResult
from dnsid.exceptions import RegistryRequestError
from dnsid.foundry._issuance import IssuanceRegistry
from tests.test_foundry import DOMAIN


def test_onboarding_without_governance_domain_keeps_proof_but_is_not_ready():
    body = {
        "org_id": "org-1", "ek": {"status": "verified"},
        "gi": {"domain": "example.com", "state": "verified", "gate_authorized": True},
    }
    with RegistryClient("https://registry.example", api_key="test-placeholder") as client:
        with patch.object(client, "_http_request", return_value=httpx.Response(200, json=body)):
            assert client.get_organization_onboarding() == {**body, "bindings_ready": False}


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


def test_pending_202_is_not_a_registry_request_error():
    registry, store = Mock(), Mock()
    registry.submit_prepared_event.return_value = SubmissionResult("pending", status_code=202)
    result = IssuanceRegistry(registry, store).submit_prepared_event(DOMAIN, b"{}", "issuance-1")
    assert result.state == "pending" and result.status_code == 202
    assert store.request_error is None


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
