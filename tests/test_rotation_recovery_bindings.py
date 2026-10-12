"""Rotation must validate saved provider bindings before recovery actions."""

import copy
from dataclasses import replace
from unittest.mock import Mock

import pytest

from dnsid import JWKS, LocalKeyProvider, SubmissionResult
from dnsid.aws_kms_key_provider import AwsKmsConfig, AwsKmsKeyProvider
from dnsid.exceptions import ArgumentError, ManagedKeyRotationActivationError, ValidationError
from dnsid.local_key_provider import _generate_stored_key
from tests.test_key_rotation import FakeRotationRegistry, RotationProvider, _hooks, _manager


def _providers(target):
    return dict(
        target_key_provider=target,
        previous_provider_reference="saved-source",
        target_provider_reference="saved-target",
    )


@pytest.mark.parametrize("state", ["pending", "accepted", "activated"])
@pytest.mark.parametrize("source", ["unrelated", "old-retained", "unavailable"])
def test_invalid_source_fails_before_recovery_actions(state, source):
    previous = LocalKeyProvider.generate()
    original_store = copy.deepcopy(previous._store)
    target = RotationProvider()
    registry = FakeRotationRegistry("accepted" if state == "activated" else "pending")
    registry.previous_kid = previous.signing_key().kid
    hooks, saved, pauses = _hooks()
    with _manager(target) as manager:
        manager._key_provider = previous
        rotation = manager.rotate_operational_key(
            registry, idempotency_key="rotation", **hooks, **_providers(target),
        )
    if state == "accepted":
        rotation = replace(rotation, submission=SubmissionResult(
            state="accepted", entry_hash=rotation.entry_hash, key_id=rotation.new_kid,
        ))
    if source == "unrelated":
        previous = LocalKeyProvider.generate()
    else:
        previous._store = original_store
        if source == "old-retained":
            previous.activate(previous.generate_key())
        else:
            previous.jwk = Mock(side_effect=ArgumentError("saved key unavailable"))
    before = (len(registry.submit_calls), len(saved), len(pauses))
    with _manager(target) as restarted:
        restarted._key_provider = previous
        with pytest.raises(ManagedKeyRotationActivationError) as error:
            restarted.resume_key_rotation(registry, rotation, **hooks, **_providers(target))
        assert error.value.rotation.entry_bytes == rotation.entry_bytes
        restarted._verify_publication_evidence.assert_not_called()
    assert (len(registry.submit_calls), len(saved), len(pauses)) == before
    assert target.active_kid == ("ku-2" if state == "activated" else "ku-1")
    if source == "old-retained":
        assert rotation.previous_kid in previous.list_key_ids()


@pytest.mark.parametrize("accepted", [False, True])
def test_absent_source_cannot_activate_pending_target(accepted):
    previous = LocalKeyProvider.generate()
    target = RotationProvider()
    registry = FakeRotationRegistry("pending")
    registry.previous_kid = previous.signing_key().kid
    hooks, saved, pauses = _hooks()
    with _manager(target) as manager:
        manager._key_provider = previous
        rotation = manager.rotate_operational_key(
            registry, idempotency_key="rotation", **hooks, **_providers(target),
        )
        previous.supersede(rotation.previous_kid, allow_active=True)
        if accepted:
            rotation = replace(rotation, submission=SubmissionResult(
                state="accepted", entry_hash=rotation.entry_hash, key_id=rotation.new_kid,
            ))
        before = (len(registry.submit_calls), len(saved), len(pauses))
        with pytest.raises(ManagedKeyRotationActivationError) as error:
            manager.resume_key_rotation(registry, rotation, **hooks, **_providers(target))
        assert "absent previous key" in str(error.value.__cause__)
        assert (len(registry.submit_calls), len(saved), len(pauses)) == before
        assert target.active_kid == "ku-1"


def test_activated_record_requires_saved_acceptance():
    provider = RotationProvider()
    registry = FakeRotationRegistry()
    hooks, _, pauses = _hooks()
    with _manager(provider) as manager:
        rotation = manager.rotate_operational_key(registry, idempotency_key="rotation", **hooks)
        invalid = replace(rotation, submission=None, application_signing_paused=True)
        with pytest.raises(ManagedKeyRotationActivationError):
            manager.resume_key_rotation(registry, invalid, **hooks)
        assert pauses == [True, False]
        assert len(registry.submit_calls) == 1


@pytest.mark.parametrize("entrypoint", ["resume_key_rotation", "activate_rotated_key"])
def test_cross_provider_unpause_failure_recovers_with_explicit_source(entrypoint):
    previous = LocalKeyProvider.generate()
    target = RotationProvider()
    registry = FakeRotationRegistry()
    registry.previous_kid = previous.signing_key().kid
    hooks, saved, pauses = _hooks()

    def fail_unpause(paused):
        if not paused:
            raise RuntimeError("unpause failed")
        pauses.append(paused)

    with _manager(target) as manager:
        manager._key_provider = previous
        with pytest.raises(ManagedKeyRotationActivationError) as error:
            manager.rotate_operational_key(
                registry, idempotency_key="rotation", **_providers(target),
                **(hooks | {"set_application_signing_paused": fail_unpause}),
            )
        rotation = error.value.rotation
        assert rotation.activated and rotation.application_signing_paused
        assert manager.key_provider is target and not previous.list_key_ids()
        kwargs = dict(**hooks, **_providers(target), previous_key_provider=previous)
        if entrypoint == "resume_key_rotation":
            result = manager.resume_key_rotation(registry, rotation, **kwargs)
        else:
            result = manager.activate_rotated_key(rotation, **kwargs)
        assert result.activated and not result.application_signing_paused
        assert manager.key_provider is target and saved[-1] == result
        assert len(registry.prepare_calls) == len(registry.submit_calls) == 1
        assert pauses[-1] is False


@pytest.mark.parametrize("algorithm", [None, "ES256", "unsupported"])
def test_target_algorithm_is_checked_before_generation(algorithm):
    previous = LocalKeyProvider.generate("EdDSA")
    target = LocalKeyProvider.generate("ES256" if algorithm is None else "EdDSA")
    target.generate_key = Mock(side_effect=AssertionError("must not generate"))
    registry = FakeRotationRegistry()
    hooks, saved, pauses = _hooks()
    with _manager(RotationProvider()) as manager:
        manager._key_provider = previous
        with pytest.raises(ArgumentError, match="selected algorithm"):
            manager.rotate_operational_key(
                registry, idempotency_key="rotation", target_algorithm=algorithm,
                **hooks, **_providers(target),
            )
    target.generate_key.assert_not_called()
    assert not registry.prepare_calls and not registry.submit_calls and not saved and not pauses


def test_unexpected_generated_algorithm_is_rejected_before_preparation():
    previous = LocalKeyProvider.generate()
    target = LocalKeyProvider.generate()
    unexpected = _generate_stored_key("ES256")
    target._store.pending.append(unexpected)
    target.generate_key = Mock(return_value=unexpected.kid)
    registry = FakeRotationRegistry()
    hooks, saved, pauses = _hooks()
    with _manager(RotationProvider()) as manager:
        manager._key_provider = previous
        with pytest.raises(ValidationError, match="generated key"):
            manager.rotate_operational_key(
                registry, idempotency_key="rotation", **hooks, **_providers(target),
            )
    assert not registry.prepare_calls and not registry.submit_calls and not saved and not pauses


def test_explicit_cross_algorithm_rotation_and_recovery():
    previous = LocalKeyProvider.generate("EdDSA")
    target = LocalKeyProvider.generate("ES256")
    hooks, _, pauses = _hooks()
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

        registry = Registry("pending")
        registry.previous_kid = previous.signing_key().kid
        rotation = manager.rotate_operational_key(
            registry, idempotency_key="rotation", target_algorithm="ES256",
            **hooks, **_providers(target),
        )
        assert previous.signing_key().signature_alg() == "EdDSA"
        registry.submit_state = "accepted"
        result = manager.resume_key_rotation(registry, rotation, **hooks, **_providers(target))
        assert result.activated and manager.key_provider is target
        assert target.signing_key().signature_alg() == "ES256"
        assert not previous.list_key_ids() and pauses == [True, True, False]
        assert registry.submit_calls[0] == registry.submit_calls[1]


@pytest.mark.parametrize("algorithm,key_spec", [
    ("ECDSA_SHA_256", "ECC_NIST_EDWARDS25519"),
    ("ED25519_SHA_512", "ECC_NIST_P256"),
    ("unsupported", None),
])
def test_invalid_kms_generation_settings_fail_before_network(algorithm, key_spec):
    facade = Mock()
    with pytest.raises(ArgumentError):
        AwsKmsKeyProvider.load(facade, AwsKmsConfig(algorithm=algorithm, key_spec=key_spec))
    assert not facade.mock_calls
