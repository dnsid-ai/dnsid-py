"""Regression checks for configuration, transport, and rotation recovery."""

import gzip
from dataclasses import replace
from unittest.mock import Mock, patch

import httpx
import pytest

from dnsid import (
    JWKS,
    KeySource,
    LoadedConfig,
    LocalKeyProvider,
    RegistryClient,
    merge_loaded_config,
    verification_budget,
)
from dnsid._crypto import verify_signature
from dnsid.aws_kms_key_provider import AwsKmsConfig, AwsKmsKeyProvider
from dnsid.exceptions import (
    ArgumentError,
    ManagedKeyRotationActivationError,
    VerificationError,
)
from tests.test_aws_kms_key_provider import _make_facade_with_ed25519, _make_facade_with_p256
from tests.test_key_rotation import FakeRotationRegistry, RotationProvider, _hooks, _manager


def test_operational_source_replaces_as_group_and_entity_path_merges_independently():
    base = LoadedConfig(key_source=KeySource(
        cli_directory="/cli", entity_key_path="/entity", settings={"old": "setting"},
    ))
    overlay = LoadedConfig(key_source=KeySource(provider="aws-kms", key_ref="arn:existing"))
    merged = merge_loaded_config(base, overlay)
    assert merged.key_source == KeySource(
        provider="aws-kms", key_ref="arn:existing", entity_key_path="/entity",
    )
    entity_only = LoadedConfig(key_source=KeySource(entity_key_path="/new-entity"))
    assert merge_loaded_config(merged, entity_only).key_source == KeySource(
        provider="aws-kms", key_ref="arn:existing", entity_key_path="/new-entity",
    )
    assert merge_loaded_config(merged, LoadedConfig()).key_source == merged.key_source
    assert merge_loaded_config(merged, LoadedConfig(key_source=KeySource(settings={}))).key_source == (
        KeySource(settings={}, entity_key_path="/entity")
    )


def test_default_registry_transport_decodes_once_reuses_client_and_closes(monkeypatch):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200, content=gzip.compress(b'{"org_id":"org-1"}'),
            headers={"Content-Encoding": "gzip", "X-Registry": "test"},
        )

    transport = httpx.MockTransport(respond)
    factory = Mock(return_value=transport)
    monkeypatch.setattr("dnsid.safe_transport.make_ssrf_safe_transport", factory)
    with RegistryClient("https://registry.test", api_key="test-token") as client:
        with verification_budget(1):
            assert client.get_organization_onboarding() == {"org_id": "org-1"}
        pooled = client._http_client
        response = client._http_request("GET", "https://registry.test/api/v1/org/onboarding")
        assert response.json() == {"org_id": "org-1"}
        assert response.headers["X-Registry"] == "test"
        assert "content-encoding" not in response.headers
        assert int(response.headers["content-length"]) == len(response.content)
        assert client._http_client is pooled
        factory.assert_called_once_with(client._transport_config, allow_loopback_host=None)
        assert pooled.trust_env is False
        assert requests[0].headers["Authorization"] == "Bearer test-token"
        assert 0 < requests[0].extensions["timeout"]["read"] <= 1
    assert pooled.is_closed


def test_default_registry_transport_rejects_private_resolution_without_connecting():
    with (
        patch("dnsid.safe_transport._resolve_addresses", return_value=["127.0.0.1"]),
        patch("httpcore.SyncBackend.connect_tcp") as connect,
        patch("httpx.get", side_effect=AssertionError("unprotected HTTP path")),
        RegistryClient("https://registry.test", api_key="test-token") as client,
    ):
        with pytest.raises(VerificationError, match="dnsid-ssrf-blocked"):
            client.get_organization_onboarding()
        connect.assert_not_called()


def test_default_registry_transport_limits_response_body(monkeypatch):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * (4 * 1024 * 1024 + 1)))
    monkeypatch.setattr("dnsid.safe_transport.make_ssrf_safe_transport", lambda *a, **kw: transport)
    with RegistryClient(api_key="test-token") as client:
        with pytest.raises(VerificationError, match="resource limit exceeded"):
            client.get_organization_onboarding()


def test_activated_recovery_rejects_stale_active_provider_before_unpausing():
    provider = RotationProvider()
    with _manager(provider) as manager:
        hooks, saved, pauses = _hooks()
        result = manager.rotate_operational_key(FakeRotationRegistry(), idempotency_key="rotation", **hooks)
        provider.active_kid = "ku-1"
        provider.pending = ["ku-2"]
        with pytest.raises(ManagedKeyRotationActivationError) as error:
            manager.resume_key_rotation(FakeRotationRegistry(), saved[-2], **hooks)
        assert error.value.rotation.activated
        assert "active target key" in str(error.value.__cause__)
        assert pauses == [True, False]
        provider.active_kid = "ku-2"
        provider.pending = []
        assert manager.resume_key_rotation(FakeRotationRegistry(), result, **hooks).activated


@pytest.mark.parametrize("previous_type", ["file", "aws"])
@pytest.mark.parametrize("activation_saved", [False, True])
def test_cross_provider_crash_restores_signer(tmp_path, previous_type, activation_saved):
    class Crash(BaseException):
        pass

    if previous_type == "file":
        path = tmp_path / "old.json"
        previous = LocalKeyProvider.load(path, create_if_missing=True)
    else:
        facade, kid = _make_facade_with_ed25519()
        previous = AwsKmsKeyProvider.load(facade, AwsKmsConfig(active_key_id=kid, algorithm="ED25519_SHA_512"))
    target = RotationProvider()
    registry = FakeRotationRegistry()
    registry.previous_kid = previous.signing_key().kid
    hooks, saved, pauses = _hooks()

    def persist(rotation):
        if rotation.activated and not activation_saved:
            raise Crash()
        saved.append(rotation)
        if rotation.activated:
            raise Crash()

    providers = dict(
        target_key_provider=target,
        previous_provider_reference="old-provider",
        target_provider_reference="target-provider",
    )
    with _manager(target) as manager:
        manager._key_provider = previous
        with pytest.raises(Crash):
            manager.rotate_operational_key(
                registry, idempotency_key="rotation", **(hooks | {"persist_rotation": persist}), **providers,
            )
        assert manager.key_provider is previous
    if previous_type == "file":
        previous = LocalKeyProvider.load(path)
    else:
        previous = AwsKmsKeyProvider.load(facade, AwsKmsConfig(state=previous.state_snapshot(), algorithm="ED25519_SHA_512"))
    assert not previous.list_key_ids()
    with pytest.raises(ArgumentError, match="no active"):
        previous.sign(b"blocked")
    with _manager(target) as restarted:
        restarted._key_provider = previous
        result = restarted.resume_key_rotation(registry, saved[-1], **hooks, **providers)
        assert result.activated and not result.application_signing_paused
        assert restarted.key_provider is target
        assert target.signing_key().kid == result.new_kid
        assert pauses == ([True, False] if activation_saved else [True, True, False])
        assert len(registry.submit_calls) == 1


@pytest.mark.parametrize(
    "factory,algorithm",
    [(_make_facade_with_ed25519, "ED25519_SHA_512"), (_make_facade_with_p256, "ECDSA_SHA_256")],
)
def test_aws_pending_key_can_sign_rotation_without_becoming_application_signer(factory, algorithm):
    facade, kid = factory()
    provider = AwsKmsKeyProvider.load(facade, AwsKmsConfig(active_key_id=kid, algorithm=algorithm))
    new_kid = provider.generate_key()
    reopened = AwsKmsKeyProvider.load(facade, AwsKmsConfig(state=provider.state_snapshot(), algorithm=algorithm))
    payload = b"rotation proof"
    assert verify_signature(reopened.jwk(new_kid)._raw, payload, reopened.sign_key(new_kid, payload))
    assert reopened.signing_key().kid == kid
    assert reopened.list_key_ids() == [kid]
    reopened.activate(new_kid)
    with pytest.raises(ArgumentError, match="no active or pending"):
        reopened.sign_key(kid, payload)
    with pytest.raises(ArgumentError, match="no active or pending"):
        reopened.sign_key("unknown", payload)


def test_local_to_aws_rotation_activates_only_after_verified_publication():
    previous = LocalKeyProvider.generate()
    facade, kid = _make_facade_with_ed25519()
    target = AwsKmsKeyProvider.load(facade, AwsKmsConfig(active_key_id=kid, algorithm="ED25519_SHA_512"))
    with _manager(RotationProvider()) as manager:
        manager._key_provider = previous

        class Registry(FakeRotationRegistry):
            def prepare_key_rotation(self, domain, request, idempotency_key):
                prepared = super().prepare_key_rotation(domain, request, idempotency_key)
                manager._verify_publication_evidence.return_value.jwks = JWKS([request.public_key])
                return prepared

            def submit_prepared_event(self, domain, entry_bytes, idempotency_key):
                result = super().submit_prepared_event(domain, entry_bytes, idempotency_key)
                return replace(result, key_id=self.prepare_calls[-1][1].public_key.kid)

        registry = Registry()
        registry.previous_kid = previous.signing_key().kid
        hooks, saved, pauses = _hooks()
        result = manager.rotate_operational_key(
            registry, idempotency_key="rotation", **hooks,
            target_key_provider=target,
            previous_provider_reference="local-provider",
            target_provider_reference="aws-provider",
        )
        assert result.activated and manager.key_provider is target
        assert target.signing_key().kid == result.new_kid
        assert not previous.list_key_ids()
        assert pauses == [True, False]
        assert saved[-1] == result


def test_retired_aws_provider_can_activate_pending_key_without_empty_retained_id():
    facade, kid = _make_facade_with_ed25519()
    provider = AwsKmsKeyProvider.load(facade, AwsKmsConfig(active_key_id=kid, algorithm="ED25519_SHA_512"))
    new_kid = provider.generate_key()
    provider.supersede(kid, allow_active=True)
    reopened = AwsKmsKeyProvider.load(facade, AwsKmsConfig(state=provider.state_snapshot(), algorithm="ED25519_SHA_512"))
    reopened.activate(new_kid)
    assert reopened.signing_key().kid == new_kid
    assert reopened.state_snapshot().retained_key_ids == []
