"""A recovered in-memory state is not proof that storage succeeded."""

from dataclasses import replace

import pytest

from dnsid.exceptions import ManagedKeyRotationActivationError, ManagedKeyRotationSubmissionError
from tests.test_key_rotation import FakeRotationRegistry, RotationProvider, _manager


@pytest.mark.parametrize(
    ("phase", "entrypoint"),
    [
        ("prepared", "resume_key_rotation"),
        ("accepted", "resume_key_rotation"),
        ("accepted", "activate_rotated_key"),
    ],
)
def test_recovery_persists_before_submission_or_activation(phase, entrypoint):
    provider = RotationProvider()
    registry = FakeRotationRegistry()
    blocked = True
    durable = []

    def persist(rotation):
        if blocked and (phase == "prepared" or rotation.submission is not None):
            raise OSError("storage unavailable")
        durable.append(rotation)

    hooks = dict(persist_rotation=persist, set_application_signing_paused=lambda _: None)
    with _manager(provider) as manager:
        with pytest.raises(ManagedKeyRotationSubmissionError) as failure:
            manager.rotate_operational_key(registry, idempotency_key="rotation-1", **hooks)
        rotation = failure.value.rotation
        submissions = len(registry.submit_calls)
        recover = getattr(manager, entrypoint)
        args = (registry, rotation) if entrypoint == "resume_key_rotation" else (rotation,)
        with pytest.raises((ManagedKeyRotationSubmissionError, ManagedKeyRotationActivationError)):
            recover(*args, **hooks)
        assert provider.active_kid == rotation.previous_kid
        assert len(registry.submit_calls) == submissions
        manager._verify_publication_evidence.assert_not_called()

        blocked = False
        completed = recover(*args, **hooks)
        assert completed.activated and not completed.application_signing_paused
        assert durable[-1] == completed
        assert len(registry.prepare_calls) == len(registry.submit_calls) == 1
        assert registry.submit_calls[0][1] == rotation.entry_bytes
        assert registry.submit_calls[0][2] == rotation.idempotency_key


@pytest.mark.parametrize("paused", [True, False])
def test_activated_resume_needs_no_network(paused):
    provider = RotationProvider()
    registry = FakeRotationRegistry()
    durable = []
    pauses = []
    hooks = dict(persist_rotation=durable.append, set_application_signing_paused=pauses.append)
    with _manager(provider) as manager:
        completed = manager.rotate_operational_key(registry, idempotency_key="rotation-1", **hooks)
        manager._verify_publication_evidence.assert_called_once_with(completed.domain, refresh=True)
    durable.clear()
    pauses.clear()
    with _manager(provider) as restarted:
        result = restarted.resume_key_rotation(
            registry, replace(completed, application_signing_paused=paused), **hooks
        )
        restarted._verify_publication_evidence.assert_not_called()
        assert restarted._key_provider is provider
    assert result.activated and not result.application_signing_paused
    assert pauses == ([False] if paused else [])
    assert len(durable) == (1 if paused else 0)
    assert len(registry.submit_calls) == 1
