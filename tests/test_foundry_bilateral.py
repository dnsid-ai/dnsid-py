"""Publication gating and version-two recovery without registration nonces."""

import copy
from unittest.mock import Mock

import pytest

from dnsid import UnsupportedRegistryResponse
from dnsid.c2sp_tlog.canonical import canonical_bytes
from dnsid.exceptions import RegistryRequestError
from dnsid.foundry import (
    FoundryDeadline,
    FoundryError,
    FoundryStateError,
    SigningPaused,
    UnsupportedRegistry,
    WorkflowOutcome,
    create,
)
from tests.test_foundry import DOMAIN, saved
from tests.test_foundry import setup as setup


@pytest.mark.parametrize("published", [False, None, "true", 1])
def test_unpublished_or_unsupported_detail_never_prepares(setup, published):
    server, store, arguments = setup
    server.dns_published = published
    with create("billing-agent", **arguments) as identity:
        error = FoundryDeadline if published is False else UnsupportedRegistry
        with pytest.raises(error):
            identity.active(timeout=0.01)
        with pytest.raises(SigningPaused):
            identity.sign(b"not active")
    assert server.prepare_calls == 0 and not server.submitted
    assert saved(store)["identityId"] == "id-1"
    assert len(server.created) == 1


def test_provisioning_issues_before_ready_without_signing_saved_nonce_metadata(setup):
    server, store, arguments = setup
    prepare = server.prepare_issuance

    def prepare_during_provisioning(*args):
        assert server.status == "PROVISIONING"
        assert server.dns_published
        return prepare(*args)

    server.prepare_issuance = prepare_during_provisioning
    with create("billing-agent", **arguments) as identity:
        document = saved(store)
        document["proof"] = {"challenge": "obsolete", "challengeMessage": "invalid"}
        key = (document["registryUrl"], document["organizationId"], document["name"])
        with store.lock(key):
            store.save(key, document)
        identity.active()
    assert len(server.submitted) == server.prepare_calls == 1
    assert saved(store)["schemaVersion"] == 2
    assert saved(store)["registrationKey"] == server.created[0][1]
    assert saved(store)["issuanceKey"] == server.submitted[0][2]


@pytest.mark.parametrize("phase", ["publication", "issuance", "public"])
def test_each_poll_refreshes_management_and_stops_on_error(setup, monkeypatch, phase):
    import dnsid.foundry._workflow as workflow

    server, store, arguments = setup
    monkeypatch.setattr(workflow.time, "sleep", lambda seconds: None)
    with create("billing-agent", **arguments) as identity:
        if phase == "publication":
            server.dns_published = False
        elif phase == "issuance":
            server.submit_prepared_event = Mock(side_effect=RegistryRequestError(
                "/events", 503, "SERVICE_UNAVAILABLE",
            ))
        else:
            server.public_status = "PENDING"
        get = server.get_registration
        reads = 0

        def registration(domain):
            nonlocal reads
            reads += 1
            if reads == (2 if phase == "publication" else 3 if phase == "issuance" else 4):
                server.status = "ERROR"
            return get(domain)

        server.get_registration = registration
        with pytest.raises(WorkflowOutcome):
            identity.active(timeout=1)
        with pytest.raises(SigningPaused):
            identity.sign(b"stopped")
    assert saved(store)["registryStatus"] == "ERROR"
    assert len(server.created) == 1


@pytest.mark.parametrize("change", [{"schemaVersion": 1}, {"phase": "proof-pending"}])
def test_unsupported_recovery_never_overwrites_or_mutates(setup, change):
    server, store, arguments = setup
    with create("billing-agent", **arguments):
        pass
    before = saved(store)
    corrupt = {**copy.deepcopy(before), **change}
    with pytest.raises(FoundryStateError):
        store.import_operation(canonical_bytes(corrupt))
    assert saved(store) == before
    assert len(server.created) == 1 and server.prepare_calls == 0


def test_unsupported_detail_error_maps_with_known_identity(setup):
    server, _, arguments = setup
    with create("billing-agent", **arguments) as identity:
        server.get_registration = Mock(side_effect=UnsupportedRegistryResponse("missing dns_published"))
        with pytest.raises(UnsupportedRegistry) as caught:
            identity.active()
    assert caught.value.identity_id == "id-1" and caught.value.domain == DOMAIN


def test_failed_detail_retains_creation_facts_and_replays_original_request(setup):
    server, store, arguments = setup
    register = server.register_live_agent

    def lost_detail(request, key):
        result = register(request, key)
        error = RegistryRequestError("/status", 503, "SERVICE_UNAVAILABLE")
        error.registration_response = {
            "id": result.id, "domain": result.domain, "status": result.registry_status,
            "publication_config": vars(result.publication_config),
        }
        raise error

    server.register_live_agent = lost_detail
    with pytest.raises(FoundryError) as caught:
        create("billing-agent", **arguments)
    assert caught.value.identity_id == "id-1" and caught.value.domain == DOMAIN
    assert saved(store)["creationFacts"]["id"] == "id-1"
    server.register_live_agent = register
    with create("billing-agent", **arguments) as identity:
        assert identity.domain == DOMAIN
    assert server.created[0] == server.created[1]
