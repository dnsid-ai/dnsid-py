"""Tests for managed operational key rotation.

Covers KeyProvider.supersede, RegistryClient.prepare_key_rotation /
submit_prepared_event, and IdentityManager.rotate_operational_key
(design: 01 §Operational Key Rotation, 05 §RegistryClient, 11 §Submission
and Idempotency).
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from dnsid import (
    JWK,
    IdentityManager,
    IdentityManagerDependencies,
    KeyRotationPreparationRequest,
    PreparedRegistryEvent,
    RegistryClient,
    SubmissionResult,
)
from dnsid._crypto import ed25519_public_jwk_dict, jwk_from_dict
from dnsid.exceptions import (
    ArgumentError,
    ManagedKeyRotationActivationError,
    ManagedKeyRotationSubmissionError,
    ValidationError,
    VerificationError,
)
from dnsid.interfaces import KeyProvider
from tests._config import make_config

_DOMAIN = "agent.example.com"
_LR = "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
_FAKE_API_KEY = "test-key-placeholder"


def _ed25519_jwk(kid: str) -> tuple[dict, ed25519.Ed25519PrivateKey]:
    private = ed25519.Ed25519PrivateKey.generate()
    return ed25519_public_jwk_dict(private, kid), private


class RotationProvider(KeyProvider):
    """Two-key provider: active previous key plus a pre-generated pending key."""

    def __init__(self) -> None:
        self.prev_raw, self.prev_private = _ed25519_jwk("ku-1")
        self.new_raw, self.new_private = _ed25519_jwk("ku-2")
        self._keys = {
            "ku-1": (self.prev_private, jwk_from_dict(self.prev_raw)),
            "ku-2": (self.new_private, jwk_from_dict(self.new_raw)),
        }
        self.active_kid = "ku-1"
        self.pending: list[str] = []
        self.superseded: list[str] = []

    def signing_key(self) -> JWK:
        return self._keys[self.active_kid][1]

    def jwk(self, kid: str) -> JWK:
        return self._keys[kid][1]

    def list_key_ids(self) -> list[str]:
        retained = ["ku-1"] if self.active_kid == "ku-2" and "ku-1" not in self.superseded else []
        return [self.active_kid, *retained]

    def sign(self, payload: bytes) -> bytes:
        return self._keys[self.active_kid][0].sign(payload)

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        return self._keys[kid][0].sign(payload)

    def generate_key(self) -> str:
        self.pending.append("ku-2")
        return "ku-2"

    def activate(self, kid: str) -> None:
        assert kid in self.pending
        self.pending.remove(kid)
        self.active_kid = kid

    def supersede(self, kid: str) -> None:
        if kid == self.active_kid:
            raise ArgumentError("cannot supersede the active key")
        self.superseded.append(kid)


class FakeRotationRegistry:
    """Registry double that prepares a genuine c2sp-tlog KEY_ROTATION envelope."""

    def __init__(self, submit_state: str = "accepted") -> None:
        self.submit_state = submit_state
        self.prepare_calls: list[tuple[str, KeyRotationPreparationRequest, str]] = []
        self.submit_calls: list[tuple[str, bytes, str]] = []

    def prepare_key_rotation(
        self, domain: str, request: KeyRotationPreparationRequest, idempotency_key: str
    ) -> PreparedRegistryEvent:
        from dnsid._utils import b64url_encode
        from dnsid.c2sp_tlog import C2spChain, prepare_event
        from dnsid.c2sp_tlog.canonical import canonical_json
        from dnsid.models import KeyRotationEvent

        self.prepare_calls.append((domain, request, idempotency_key))
        new_key = request.public_key
        event = KeyRotationEvent(
            domain=domain,
            previous_kid="ku-1",
            previous_thumbprint=request.previous_key_id,
            new_kid=new_key.kid,
            new_thumbprint=new_key.thumbprint(),
            new_public_key=new_key,
            timestamp=datetime.datetime(2026, 7, 21, tzinfo=datetime.UTC),
        )
        # Registry double supplies reserved logical-chain metadata in every scope.
        prepared = prepare_event(event, _LR, C2spChain(
            sequence=1, previous_event_id=b64url_encode(bytes(32)),
            previous_state_hash=b64url_encode(bytes(32)),
        ))
        return PreparedRegistryEvent(
            entry_bytes=canonical_json(prepared.envelope).encode(),
            log_reference=_LR,
        )

    def submit_prepared_event(
        self, domain: str, entry_bytes: bytes, idempotency_key: str
    ) -> SubmissionResult:
        import hashlib

        self.submit_calls.append((domain, entry_bytes, idempotency_key))
        entry_hash = (
            hashlib.sha256(entry_bytes).hexdigest()
            if self.submit_state == "accepted"
            else ""
        )
        return SubmissionResult(
            state=self.submit_state,
            entry_hash=entry_hash,
            key_id="ku-2" if self.submit_state == "accepted" else "",
        )


def _manager(provider: RotationProvider) -> IdentityManager:
    config = make_config(
        domain=_DOMAIN,
        governance_id="example.com",
        log_ref=_LR,
        status_url=f"https://{_DOMAIN}/status",
    )
    with patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s):
        return IdentityManager(config, provider, IdentityManagerDependencies())


def _hooks():
    persisted = []
    pauses = []

    def persist(rotation):
        persisted.append(rotation)

    def pause(value):
        pauses.append(value)

    return {
        "persist_rotation": persist,
        "set_application_signing_paused": pause,
    }, persisted, pauses


class TestRotateOperationalKey:
    def test_requires_durability_hooks_before_registry_work(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry()
        manager = _manager(provider)

        with pytest.raises(ArgumentError, match="persistence hook"):
            manager.rotate_operational_key(
                registry,
                idempotency_key="idem-1",
                persist_rotation=None,  # type: ignore[arg-type]
                set_application_signing_paused=lambda _: None,
            )

        assert registry.prepare_calls == []
        assert registry.submit_calls == []

    @pytest.mark.parametrize("failure", ["persist", "pause"])
    def test_hook_failure_prevents_submission(self, failure):
        provider = RotationProvider()
        registry = FakeRotationRegistry()
        manager = _manager(provider)

        def persist(_rotation):
            if failure == "persist":
                raise OSError("store unavailable")

        def pause(_paused):
            if failure == "pause":
                raise OSError("pause unavailable")

        with pytest.raises(ManagedKeyRotationSubmissionError) as excinfo:
            manager.rotate_operational_key(
                registry,
                idempotency_key="idem-1",
                persist_rotation=persist,
                set_application_signing_paused=pause,
            )

        assert excinfo.value.rotation.entry_bytes
        assert registry.submit_calls == []

    def test_accepted_rotation_activates_and_supersedes(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry()
        manager = _manager(provider)
        hooks, persisted, pauses = _hooks()

        result = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )

        assert result.activated is True
        assert provider.active_kid == "ku-2"
        assert provider.superseded == ["ku-1"]
        assert result.submission is not None and result.submission.accepted
        assert pauses == [True, False]
        assert [state.application_signing_paused for state in persisted] == [
            True,
            True,
            True,
            False,
        ]
        # Preparation was keyed by the previous key's RFC 7638 thumbprint and
        # never carried private material.
        _, request, idem = registry.prepare_calls[0]
        assert request.previous_key_id == provider.jwk("ku-1").thumbprint()
        assert "d" not in request.public_key._raw
        assert idem == "idem-1"
        # Submission used the same idempotency key and complete signed bytes.
        _, entry, idem2 = registry.submit_calls[0]
        assert idem2 == "idem-1"
        assert entry == result.entry_bytes

    def test_submitted_bytes_carry_both_rotation_signatures(self):
        from dnsid.c2sp_tlog import parse_c2sp_event_entry

        provider = RotationProvider()
        registry = FakeRotationRegistry()
        manager = _manager(provider)
        hooks, _, _ = _hooks()

        result = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )

        event = parse_c2sp_event_entry(result.entry_bytes)
        # prev_op authorization and new_op proof of possession both present.
        assert event.sig  # PreviousOperational
        assert event.new_operational_proof  # NewOperational

    def test_pending_submission_does_not_activate(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry(submit_state="pending")
        manager = _manager(provider)
        hooks, _, pauses = _hooks()

        result = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )

        assert result.activated is False
        assert provider.active_kid == "ku-1"
        assert provider.superseded == []
        # The exact bytes and idempotency key are retained for retry.
        assert result.entry_bytes
        assert result.idempotency_key == "idem-1"
        assert result.application_signing_paused is True

        # A pending rotation cannot be activated directly — publication and
        # append must converge before local application-key activation.
        with pytest.raises(ArgumentError, match="accepted submission"):
            manager.activate_rotated_key(result, **hooks)
        assert provider.active_kid == "ku-1"
        assert provider.superseded == []

        # resume_key_rotation retries the exact bytes + idempotency key and
        # activates once the registry reports accepted.
        registry.submit_state = "accepted"
        result = manager.resume_key_rotation(registry, result, **hooks)
        assert result.activated is True
        assert provider.active_kid == "ku-2"
        assert provider.superseded == ["ku-1"]
        # The retry reused the identical persisted bytes and key.
        assert registry.submit_calls[1][1] == registry.submit_calls[0][1]
        assert registry.submit_calls[1][2] == "idem-1"
        assert pauses == [True, True, False]

    def test_persists_and_pauses_before_submission_in_strict_order(self):
        provider = RotationProvider()
        events = []

        class OrderingRegistry(FakeRotationRegistry):
            def submit_prepared_event(self, domain, entry_bytes, idempotency_key):
                events.append("submit")
                assert events[:2] == ["persist:prepared", "pause:true"]
                return super().submit_prepared_event(domain, entry_bytes, idempotency_key)

        registry = OrderingRegistry()
        manager = _manager(provider)
        original_activate = provider.activate
        original_supersede = provider.supersede

        def activate(kid):
            events.append("activate")
            original_activate(kid)

        def supersede(kid):
            events.append("supersede")
            original_supersede(kid)

        provider.activate = activate  # type: ignore[method-assign]
        provider.supersede = supersede  # type: ignore[method-assign]

        def persist(rotation):
            if rotation.submission is None:
                state = "prepared"
            else:
                state = rotation.submission.state
            if rotation.activated:
                state = "completed" if not rotation.application_signing_paused else "activated"
            events.append(f"persist:{state}")

        def pause(value):
            events.append(f"pause:{str(value).lower()}")

        manager.rotate_operational_key(
            registry,
            idempotency_key="idem-1",
            persist_rotation=persist,
            set_application_signing_paused=pause,
        )

        assert events == [
            "persist:prepared",
            "pause:true",
            "submit",
            "persist:accepted",
            "activate",
            "supersede",
            "persist:activated",
            "pause:false",
            "persist:completed",
        ]

    def test_transport_failure_carries_and_persists_exact_recovery_state(self):
        provider = RotationProvider()

        class FailingRegistry(FakeRotationRegistry):
            def __init__(self):
                super().__init__()
                self.fail = True

            def submit_prepared_event(self, domain, entry_bytes, idempotency_key):
                if self.fail:
                    self.submit_calls.append((domain, entry_bytes, idempotency_key))
                    raise OSError("connection reset")
                return super().submit_prepared_event(domain, entry_bytes, idempotency_key)

        registry = FailingRegistry()
        manager = _manager(provider)
        hooks, persisted, _ = _hooks()

        with pytest.raises(ManagedKeyRotationSubmissionError) as excinfo:
            manager.rotate_operational_key(
                registry, idempotency_key="idem-1", **hooks
            )

        recovery = excinfo.value.rotation
        assert excinfo.value.retry_same_bytes is True
        assert recovery.submission is not None
        assert recovery.submission.state == "pending"
        assert persisted[-1].entry_bytes == recovery.entry_bytes
        registry.fail = False
        completed = manager.resume_key_rotation(registry, recovery, **hooks)
        assert completed.activated is True
        assert registry.submit_calls[0][1:] == registry.submit_calls[1][1:]

    def test_accepted_persist_failure_carries_latest_state(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry()
        manager = _manager(provider)
        calls = 0

        def persist(rotation):
            nonlocal calls
            calls += 1
            if rotation.submission is not None and rotation.submission.accepted:
                raise OSError("store unavailable")

        with pytest.raises(ManagedKeyRotationSubmissionError) as excinfo:
            manager.rotate_operational_key(
                registry,
                idempotency_key="idem-1",
                persist_rotation=persist,
                set_application_signing_paused=lambda _: None,
            )

        assert calls == 2
        assert excinfo.value.rotation.submission is not None
        assert excinfo.value.rotation.submission.accepted
        assert provider.active_kid == "ku-1"

    def test_restart_from_accepted_state_activates_without_resubmission(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry()
        manager = _manager(provider)
        persisted = []
        fail_activated_persist = True

        def persist(rotation):
            nonlocal fail_activated_persist
            if rotation.activated and fail_activated_persist:
                raise OSError("crash before activation marker")
            persisted.append(rotation)

        with pytest.raises(ManagedKeyRotationActivationError):
            manager.rotate_operational_key(
                registry,
                idempotency_key="idem-1",
                persist_rotation=persist,
                set_application_signing_paused=lambda _: None,
            )

        durable = persisted[-1]
        assert durable.submission is not None and durable.submission.accepted
        assert durable.activated is False
        assert len(registry.submit_calls) == 1
        fail_activated_persist = False
        recovered = _manager(provider).resume_key_rotation(
            registry,
            durable,
            persist_rotation=persist,
            set_application_signing_paused=lambda _: None,
        )
        assert recovered.activated is True
        assert recovered.application_signing_paused is False
        assert len(registry.submit_calls) == 1

    def test_unpause_failure_recovers_without_resubmission_or_key_reactivation(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry()
        manager = _manager(provider)
        persisted = []
        fail_unpause = True

        def persist(rotation):
            persisted.append(rotation)

        def pause(value):
            if not value and fail_unpause:
                raise OSError("signer controller unavailable")

        with pytest.raises(ManagedKeyRotationActivationError) as excinfo:
            manager.rotate_operational_key(
                registry,
                idempotency_key="idem-1",
                persist_rotation=persist,
                set_application_signing_paused=pause,
            )

        recovery = excinfo.value.rotation
        assert recovery.activated is True
        assert recovery.application_signing_paused is True
        assert persisted[-1].activated is True
        assert len(registry.submit_calls) == 1
        fail_unpause = False
        completed = manager.resume_key_rotation(
            registry,
            recovery,
            persist_rotation=persist,
            set_application_signing_paused=pause,
        )
        assert completed.application_signing_paused is False
        assert provider.superseded == ["ku-1"]
        assert len(registry.submit_calls) == 1

    def test_resume_rejects_tampered_bytes_before_pause_or_network(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry(submit_state="pending")
        manager = _manager(provider)
        hooks, _, pauses = _hooks()
        rotation = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )
        rotation.entry_bytes = b"x" + rotation.entry_bytes[1:]
        calls_before = len(registry.submit_calls)
        pauses_before = len(pauses)

        with pytest.raises(ValidationError, match="hash"):
            manager.resume_key_rotation(registry, rotation, **hooks)

        assert len(registry.submit_calls) == calls_before
        assert len(pauses) == pauses_before

    def test_resume_binds_entry_bytes_to_persisted_log_reference(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry(submit_state="pending")
        manager = _manager(provider)
        hooks, _, pauses = _hooks()
        rotation = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )
        swapped = "c2sp-tlog:testnet:https://other.example#instance_BBBBBBBBBBBBBBBBBBBBBB"
        rotation.log_reference = swapped
        manager._identity.log_ref = swapped
        calls_before = len(registry.submit_calls)
        pauses_before = len(pauses)

        with pytest.raises(Exception, match="context|origin|stream|reference"):
            manager.resume_key_rotation(registry, rotation, **hooks)

        assert len(registry.submit_calls) == calls_before
        assert len(pauses) == pauses_before

    def test_accepted_key_id_mismatch_fails_closed_before_activation(self):
        class WrongKeyRegistry(FakeRotationRegistry):
            def submit_prepared_event(self, domain, entry_bytes, idempotency_key):
                result = super().submit_prepared_event(domain, entry_bytes, idempotency_key)
                result.key_id = "foreign-key"
                return result

        provider = RotationProvider()
        hooks, _, _ = _hooks()

        with pytest.raises(ManagedKeyRotationSubmissionError) as excinfo:
            _manager(provider).rotate_operational_key(
                WrongKeyRegistry(), idempotency_key="idem-1", **hooks
            )

        assert excinfo.value.retry_same_bytes is False
        assert provider.active_kid == "ku-1"

    def test_resume_still_pending_keeps_keys_untouched(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry(submit_state="pending")
        manager = _manager(provider)
        hooks, _, _ = _hooks()

        result = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )
        result = manager.resume_key_rotation(registry, result, **hooks)

        assert result.activated is False
        assert provider.active_kid == "ku-1"
        assert provider.superseded == []

    def test_resume_rejected_raises_without_activation(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry(submit_state="pending")
        manager = _manager(provider)
        hooks, _, _ = _hooks()

        result = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )
        registry.submit_state = "rejected"
        with pytest.raises(ManagedKeyRotationSubmissionError, match="rejected"):
            manager.resume_key_rotation(registry, result, **hooks)
        assert provider.active_kid == "ku-1"
        assert provider.superseded == []

    def test_activate_with_explicit_accepted_submission(self):
        import hashlib

        provider = RotationProvider()
        registry = FakeRotationRegistry(submit_state="pending")
        manager = _manager(provider)
        hooks, _, _ = _hooks()

        result = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )
        accepted = SubmissionResult(
            state="accepted",
            entry_hash=hashlib.sha256(result.entry_bytes).hexdigest(),
        )
        result = manager.activate_rotated_key(result, accepted, **hooks)
        assert result.activated is True
        assert provider.active_kid == "ku-2"

    def test_activate_rejects_mismatched_entry_hash(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry(submit_state="pending")
        manager = _manager(provider)
        hooks, _, _ = _hooks()

        result = manager.rotate_operational_key(
            registry, idempotency_key="idem-1", **hooks
        )
        # The pending result carries entry_hash "h"; an accepted result for a
        # DIFFERENT entry must not complete this rotation.
        foreign = SubmissionResult(state="accepted", entry_hash="other-entry")
        with pytest.raises(ValidationError, match="entry hash does not match"):
            manager.activate_rotated_key(result, foreign, **hooks)
        assert provider.active_kid == "ku-1"
        assert provider.superseded == []

    def test_rejected_submission_raises_without_activation(self):
        provider = RotationProvider()
        registry = FakeRotationRegistry(submit_state="rejected")
        manager = _manager(provider)
        hooks, _, _ = _hooks()

        with pytest.raises(ManagedKeyRotationSubmissionError, match="rejected"):
            manager.rotate_operational_key(
                registry, idempotency_key="idem-1", **hooks
            )

        assert provider.active_kid == "ku-1"
        assert provider.superseded == []

    def test_first_accepted_result_must_match_submitted_bytes(self):
        class WrongHashRegistry(FakeRotationRegistry):
            def submit_prepared_event(self, domain, entry_bytes, idempotency_key):
                self.submit_calls.append((domain, entry_bytes, idempotency_key))
                return SubmissionResult(state="accepted", entry_hash="0" * 64)

        provider = RotationProvider()
        manager = _manager(provider)
        hooks, _, _ = _hooks()

        with pytest.raises(ManagedKeyRotationSubmissionError, match="invalid"):
            manager.rotate_operational_key(
                WrongHashRegistry(), idempotency_key="idem-1", **hooks
            )

        assert provider.active_kid == "ku-1"
        assert provider.superseded == []

    def test_tampered_preparation_fails_closed(self):
        """An envelope naming a foreign new key must not obtain our signatures."""

        class TamperingRegistry(FakeRotationRegistry):
            def prepare_key_rotation(self, domain, request, idempotency_key):
                foreign_raw, _ = _ed25519_jwk("ku-2")  # same kid, different key
                tampered = KeyRotationPreparationRequest(
                    previous_key_id=request.previous_key_id,
                    public_key=jwk_from_dict(foreign_raw),
                )
                return super().prepare_key_rotation(domain, tampered, idempotency_key)

        provider = RotationProvider()
        manager = _manager(provider)
        hooks, _, _ = _hooks()

        with pytest.raises(Exception):
            manager.rotate_operational_key(
                TamperingRegistry(), idempotency_key="idem-1", **hooks
            )

        assert provider.active_kid == "ku-1"
        assert provider.superseded == []


class TestRegistryRotationEndpoints:
    def _client(self) -> RegistryClient:
        return RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)

    def _request(self) -> KeyRotationPreparationRequest:
        raw, _ = _ed25519_jwk("ku-2")
        return KeyRotationPreparationRequest(previous_key_id="thumb", public_key=jwk_from_dict(raw))

    def test_prepare_sends_exact_request_and_preserves_untrusted_response(self):
        captured: dict = {}
        response = MagicMock()
        response.is_success = True
        response.status_code = 200
        response.content = b"prepared-bytes"
        response.headers = {"DNSID-Log-Reference": _LR}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured.update(url=url, json=json, headers=headers, timeout=timeout)
            return response

        with patch("httpx.post", fake_post):
            data = self._client().prepare_key_rotation(_DOMAIN, self._request(), "idem-9")

        assert data == PreparedRegistryEvent(b"prepared-bytes", _LR)
        assert captured["url"].endswith("/tlog/key-rotation/prepare")
        assert captured["headers"] == {
            "Authorization": f"Bearer {_FAKE_API_KEY}",
            "Idempotency-Key": "idem-9",
        }
        assert captured["json"]["previous_key_id"] == "thumb"
        assert captured["json"]["public_key"]["kid"] == "ku-2"

    def test_prepare_requires_log_reference(self):
        response = MagicMock()
        response.is_success = True
        response.status_code = 200
        response.content = b"prepared-bytes"
        response.headers = {}
        with patch("httpx.post", return_value=response):
            with pytest.raises(VerificationError, match="DNSID-Log-Reference"):
                self._client().prepare_key_rotation(_DOMAIN, self._request(), "idem-9")

    def test_prepare_rejects_private_jwk_members(self):
        raw, _ = _ed25519_jwk("ku-2")
        raw["d"] = "c2VjcmV0"
        request = KeyRotationPreparationRequest(
            previous_key_id="thumb", public_key=jwk_from_dict(raw)
        )
        with pytest.raises(ArgumentError, match="private JWK members"):
            self._client().prepare_key_rotation(_DOMAIN, request, "idem-9")

    def test_prepare_requires_idempotency_key(self):
        with pytest.raises(ArgumentError, match="idempotency_key"):
            self._client().prepare_key_rotation(_DOMAIN, self._request(), "  ")

    def test_submit_sends_exact_bytes_and_parses_result(self):
        import hashlib

        captured: dict = {}

        response = MagicMock()
        response.is_success = True
        response.status_code = 201
        response.json.return_value = {
            "state": "accepted",
            "entry_hash": hashlib.sha256(b"entry").hexdigest(),
            "index": 7,
            "lr": "c2sp-tlog:entry-ref",
        }

        def fake_post(url, content=None, headers=None, timeout=None):
            captured.update(url=url, content=content, headers=headers, timeout=timeout)
            return response

        with patch("httpx.post", fake_post):
            result = self._client().submit_prepared_event(_DOMAIN, b"entry", "idem-9")

        assert captured["url"].endswith("/tlog/events")
        assert captured["content"] == b"entry"
        assert captured["headers"] == {
            "Authorization": f"Bearer {_FAKE_API_KEY}",
            "Content-Type": "application/json",
            "Idempotency-Key": "idem-9",
        }
        assert result.accepted
        assert result.entry_hash == hashlib.sha256(b"entry").hexdigest()
        assert result.index == 7
        assert result.log_ref is not None and result.log_ref.method == "c2sp-tlog"

    def test_submit_unknown_state_rejected(self):
        response = MagicMock()
        response.is_success = True
        response.status_code = 200
        response.json.return_value = {"state": "weird"}

        with patch("httpx.post", return_value=response):
            result = self._client().submit_prepared_event(_DOMAIN, b"entry", "idem-9")

        assert result.state == "pending"
        assert result.error_code == "TLOG_SUBMISSION_INVALID_RESPONSE"

    def test_submit_transport_failure_remains_pending_for_same_byte_retry(self):
        import httpx

        with patch("httpx.post", side_effect=httpx.ReadTimeout("timed out")):
            result = self._client().submit_prepared_event(
                _DOMAIN, b"exact-entry", "idem-9"
            )

        assert result.state == "pending"
        assert result.error_code == "TLOG_SUBMISSION_TRANSPORT_ERROR"

    @pytest.mark.parametrize(
        "code",
        ["TLOG_SUBMISSION_BUSY", "TLOG_SUBMISSION_INDETERMINATE"],
    )
    def test_submit_preserves_retryable_non_success(self, code):
        response = MagicMock()
        response.is_success = False
        response.status_code = 503
        response.json.return_value = {"error": code, "message": "retry exact bytes"}
        with patch("httpx.post", return_value=response):
            result = self._client().submit_prepared_event(_DOMAIN, b"entry", "idem-9")
        assert result.state == "pending"
        assert result.error_code == code
        assert result.raw["message"] == "retry exact bytes"

    def test_submit_preserves_definitive_rejection(self):
        response = MagicMock()
        response.is_success = False
        response.status_code = 422
        response.json.return_value = {
            "error": "TLOG_PREPARATION_MISMATCH",
            "message": "different bytes",
        }
        with patch("httpx.post", return_value=response):
            result = self._client().submit_prepared_event(_DOMAIN, b"entry", "idem-9")
        assert result.state == "rejected"
        assert result.error_code == "TLOG_PREPARATION_MISMATCH"

    def test_submit_rejects_accepted_result_for_other_bytes(self):
        response = MagicMock()
        response.is_success = True
        response.status_code = 200
        response.json.return_value = {
            "state": "accepted",
            "entry_hash": "0" * 64,
        }
        with patch("httpx.post", return_value=response):
            with pytest.raises(VerificationError, match="different prepared-event"):
                self._client().submit_prepared_event(_DOMAIN, b"entry", "idem-9")

    def test_mutations_require_credentials(self):
        client = RegistryClient("https://registry.example.com")
        with pytest.raises(ArgumentError, match="credentials"):
            client.prepare_key_rotation(_DOMAIN, self._request(), "idem-9")
        with pytest.raises(ArgumentError, match="credentials"):
            client.submit_prepared_event(_DOMAIN, b"entry", "idem-9")


class TestSupersede:
    def test_base_class_purge_alias_delegates(self):
        provider = RotationProvider()
        provider.generate_key()
        provider.activate("ku-2")
        provider.supersede("ku-1")
        assert provider.superseded == ["ku-1"]
