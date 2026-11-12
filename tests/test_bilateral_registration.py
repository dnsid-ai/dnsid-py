"""Bilateral registration wire and owner-only custody contracts."""

import datetime
import hashlib
from unittest.mock import patch

import httpx
import pytest

from dnsid import (
    AgentRegistrationInput,
    LiveAgentRegistrationInput,
    LocalKeyProvider,
    RegistryClient,
    UnsupportedRegistryResponse,
    VerificationError,
)
from dnsid.c2sp_tlog import (
    C2spSignerRole,
    C2spVerificationContext,
    entry_bytes,
    owner_issuance_bytes,
    prepare_event,
    sign_prepared_event,
    write_prepared_event,
)
from dnsid.c2sp_tlog.errors import C2spTlogError, C2spTlogVerificationError
from dnsid.models import IssuanceEvent
from tests.test_registry_client import _DOMAIN, _REGISTER_RESPONSE, _live_key

LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"


@pytest.mark.parametrize("echo", [None, "other-key", "live-1"])
@pytest.mark.parametrize("detail_status", [200, 503])
def test_live_creation_echo_and_failed_detail_preserve_creation(echo, detail_status):
    calls = []

    def request(method, url, **kwargs):
        calls.append((method, kwargs))
        if method == "POST":
            return httpx.Response(201, json=_REGISTER_RESPONSE,
                                  headers={"Idempotency-Key": echo} if echo else {})
        return httpx.Response(detail_status, json={
            **_REGISTER_RESPONSE, "managed": "dnsid", "dns_published": True,
        })

    with RegistryClient("https://registry.example", api_key="test-placeholder") as client:
        with patch.object(client, "_http_request", side_effect=request):
            if echo == "live-1" and detail_status == 200:
                assert client.register_live_agent(LiveAgentRegistrationInput(_live_key()), "live-1").id == "agent-123"
                return
            with pytest.raises(VerificationError) as caught:
                client.register_live_agent(LiveAgentRegistrationInput(_live_key()), "live-1")
    assert caught.value.registration_idempotency_key == "live-1"
    assert caught.value.registration_response == _REGISTER_RESPONSE
    assert caught.value.registration_request["tier"] == "live"
    assert len(calls) == (2 if echo == "live-1" else 1)


@pytest.mark.parametrize("published", [None, "true", 0, 1, [], {}])
def test_registry_managed_detail_requires_boolean_publication(published):
    facts = {**_REGISTER_RESPONSE, "managed": "dnsid"}
    if published is not None:
        facts["dns_published"] = published
    with RegistryClient("https://registry.example", api_key="test-placeholder") as client:
        with patch.object(client, "_http_request", return_value=httpx.Response(200, json=facts)):
            with pytest.raises(UnsupportedRegistryResponse) as caught:
                client.get_registration(_DOMAIN)
    assert caught.value.registration_response == facts


@pytest.mark.parametrize("code", ["TLOG_PUBLICATION_REQUIRED", "OTHER_ERROR", "INVALID_TRANSITION"])
def test_verify_is_explicit_empty_owner_request_and_live_errors_are_preserved(code):
    with RegistryClient("https://registry.example", api_key="test-placeholder") as client:
        with patch.object(client, "_http_request", return_value=httpx.Response(
            409, json={"error": code},
        )) as request:
            with pytest.raises(VerificationError) as caught:
                client.verify_agent(_DOMAIN)
    assert caught.value.status_code == 409 and caught.value.error_code == code
    assert "json" not in request.call_args.kwargs
    assert request.call_args.kwargs["headers"]["Authorization"] == "Bearer test-placeholder"
    assert request.call_count == 1


def _owner_event(algorithm="EdDSA"):
    entity, operational = LocalKeyProvider.generate(algorithm), LocalKeyProvider.generate(algorithm)
    event = IssuanceEvent(
        domain=_DOMAIN, governance_id="example.com",
        entity_key=entity.signing_key(), operational_key=operational.signing_key(),
        timestamp=datetime.datetime(2026, 11, 1, tzinfo=datetime.UTC),
    )
    prepared = sign_prepared_event(prepare_event(event, LR), C2spSignerRole.ENTITY, entity)
    return prepared, entity, operational


@pytest.mark.parametrize("algorithm", ["EdDSA", "ES256"])
def test_owner_envelope_cannot_be_complete_or_appended_and_replays_exactly(algorithm):
    prepared, entity, operational = _owner_event(algorithm)
    owner = owner_issuance_bytes(prepared)
    with pytest.raises(C2spTlogError):
        entry_bytes(prepared)
    with pytest.raises(C2spTlogError):
        write_prepared_event(prepared, submit=lambda *args: pytest.fail("partial append"),
                             idempotency_key="owner-1")
    completed = sign_prepared_event(prepared, C2spSignerRole.OPERATIONAL_COUNTERSIGNATURE,
                                   operational, C2spVerificationContext(
                                       fqdn=_DOMAIN, gi="example.com",
                                       entity_key=entity.signing_key(),
                                       operational_key=operational.signing_key(),
                                   ))
    with pytest.raises(C2spTlogError):
        owner_issuance_bytes(completed)
    assert completed.signed_bytes == prepared.signed_bytes
    assert completed.envelope["sigs"]["ae"] == prepared.envelope["sigs"]["ae"]
    completed_hash = hashlib.sha256(entry_bytes(completed)).hexdigest()
    assert completed_hash != hashlib.sha256(owner).hexdigest()
    response = httpx.Response(200, json={
        "state": "accepted", "entry_hash": completed_hash, "index": 0, "lr": f"{LR}@0",
    })
    with RegistryClient("https://registry.example", api_key="test-placeholder") as client:
        with patch.object(client, "_http_request", return_value=response) as request:
            for _ in range(2):
                result = client.submit_owner_issuance(_DOMAIN, owner, "owner-1")
                assert result.accepted and result.entry_hash == completed_hash
            assert all(call.kwargs["content"] == owner for call in request.call_args_list)
            assert all(call.kwargs["headers"]["Idempotency-Key"] == "owner-1" for call in request.call_args_list)
            with pytest.raises(VerificationError, match="different prepared-event"):
                client.submit_prepared_event(_DOMAIN, owner, "owner-1")


@pytest.mark.parametrize(("change", "message"), [
    ("bad-signature", "invalid existing Entity signature"),
    ("missing-signature", "owner issuance requires only the entity signature"),
    ("private-key", "owner issuance requires public keys"),
    ("invalid-ku", "invalid owner issuance public key"),
    ("noncanonical-ku", "invalid owner issuance public key"),
    ("missing-ku-coordinate", "invalid owner issuance public key"),
    ("same-key", "entity and operational keys must be distinct"),
])
def test_owner_serialization_validates_signature_and_all_key_material(change, message):
    prepared, entity, _ = _owner_event()
    if change == "bad-signature":
        prepared.envelope["sigs"]["ae"]["sig"] = "AAAA"
    elif change == "missing-signature":
        prepared.envelope.pop("sigs")
    else:
        from dnsid.c2sp_tlog.canonical import canonical_bytes

        if change == "private-key":
            prepared.envelope["ku"]["d"] = "private"
        elif change == "invalid-ku":
            prepared.envelope["ku"]["x"] = "AAAA"
        elif change == "noncanonical-ku":
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            x = prepared.envelope["ku"]["x"]
            prepared.envelope["ku"]["x"] = x[:-1] + alphabet[alphabet.index(x[-1]) + 1]
        elif change == "missing-ku-coordinate":
            prepared.envelope["ku"].pop("x")
        else:
            prepared.envelope["ku"] = entity.signing_key().to_dict()
        prepared.envelope.pop("sigs")
        prepared.signed_bytes = canonical_bytes(prepared.envelope)
        prepared = sign_prepared_event(prepared, C2spSignerRole.ENTITY, entity)
    with pytest.raises(C2spTlogVerificationError, match=message):
        owner_issuance_bytes(prepared)


def test_ordinary_registration_keeps_optional_replay_header():
    with RegistryClient("https://registry.example", api_key="test-placeholder") as client:
        with patch.object(client, "_http_request", return_value=httpx.Response(202, json=_REGISTER_RESPONSE)):
            with pytest.raises(VerificationError) as caught:
                client.register_agent(AgentRegistrationInput(domain=_DOMAIN))
    assert caught.value.registration_idempotency_key == ""
    assert caught.value.registration_response == _REGISTER_RESPONSE


@pytest.mark.parametrize("missing", ["entry_hash", "index", "lr"])
def test_owner_acceptance_without_complete_receipt_stays_pending(missing):
    receipt = {"state": "accepted", "entry_hash": "a" * 64, "index": 0, "lr": f"{LR}@0"}
    receipt.pop(missing)
    with RegistryClient("https://registry.example", api_key="test-placeholder") as client:
        with patch.object(client, "_http_request", return_value=httpx.Response(200, json=receipt)):
            result = client.submit_owner_issuance(_DOMAIN, b"persisted-owner-envelope", "owner-1")
    assert result.state == "pending"
    assert result.error_code == "TLOG_SUBMISSION_INVALID_RESPONSE"
