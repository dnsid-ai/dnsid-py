"""Tests for AwsKmsKeyProvider using a local in-process fake KMS facade."""

from __future__ import annotations

from typing import Any, Literal

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dnsid import (
    AwsKmsConfig,
    AwsKmsFacade,
    AwsKmsKeyProvider,
    AwsKmsKeyState,
)
from dnsid._crypto import verify_signature
from dnsid.aws_kms_key_provider import AwsKmsKeySpec, AwsKmsSigningAlgorithm
from dnsid.exceptions import ArgumentError

# ---------------------------------------------------------------------------
# Fake KMS facade
# ---------------------------------------------------------------------------

_KeyPair = ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


class FakeKmsFacade(AwsKmsFacade):
    """In-process KMS fake backed by cryptography — no AWS required."""

    def __init__(self) -> None:
        self._keys: dict[str, _KeyPair] = {}
        self._algorithms: dict[str, AwsKmsSigningAlgorithm] = {}
        self._aliases: dict[str, str] = {}
        self._deleted: list[str] = []
        self._create_inputs: list[dict[str, Any]] = []
        self._counter = 0

    def add_p256_key(self, key_id: str) -> None:
        self._keys[key_id] = ec.generate_private_key(ec.SECP256R1())
        self._algorithms[key_id] = "ECDSA_SHA_256"

    def add_ed25519_key(self, key_id: str) -> None:
        self._keys[key_id] = ed25519.Ed25519PrivateKey.generate()
        self._algorithms[key_id] = "ED25519_SHA_512"

    def add_alias(self, alias: str, key_id: str) -> None:
        self._aliases[alias] = key_id

    def _resolve(self, key_id: str) -> str:
        return self._aliases.get(key_id, key_id)

    def _key(self, key_id: str) -> _KeyPair:
        resolved = self._resolve(key_id)
        k = self._keys.get(resolved)
        if k is None:
            raise KeyError(f"fake KMS: unknown key {key_id!r}")
        return k

    def _algorithm(self, key_id: str) -> AwsKmsSigningAlgorithm:
        resolved = self._resolve(key_id)
        return self._algorithms[resolved]

    def create_signing_key(
        self,
        key_spec: AwsKmsKeySpec,
        description: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> str:
        self._counter += 1
        key_id = f"arn:aws:kms:us-east-1:111122223333:key/generated-{self._counter}"
        self._create_inputs.append({"key_spec": key_spec, "description": description, "tags": tags})
        if key_spec == "ECC_NIST_EDWARDS25519":
            self.add_ed25519_key(key_id)
        else:
            self.add_p256_key(key_id)
        return key_id

    def get_public_key(self, key_id: str) -> dict[str, Any]:
        private = self._key(key_id)
        resolved = self._resolve(key_id)
        alg = self._algorithm(key_id)

        if isinstance(private, ec.EllipticCurvePrivateKey):
            spki = private.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            key_spec: str = "ECC_NIST_P256"
        else:
            spki = private.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            key_spec = "ECC_NIST_EDWARDS25519"

        return {
            "key_id": resolved,
            "public_key": spki,
            "key_spec": key_spec,
            "key_usage": "SIGN_VERIFY",
            "signing_algorithms": [alg],
        }

    def sign(
        self,
        key_id: str,
        message: bytes,
        signing_algorithm: AwsKmsSigningAlgorithm,
        message_type: Literal["RAW", "DIGEST"],
    ) -> dict[str, Any]:
        private = self._key(key_id)
        resolved = self._resolve(key_id)

        if isinstance(private, ec.EllipticCurvePrivateKey):
            # Sign and return DER-encoded ECDSA (what real KMS returns).
            # DIGEST mode means the message is already SHA-256 hashed.
            hash_alg = Prehashed(SHA256()) if message_type == "DIGEST" else SHA256()
            der_sig = private.sign(message, ec.ECDSA(hash_alg))
            signature = der_sig
        else:
            # Ed25519: sign the raw message and return raw bytes (what real KMS returns)
            assert isinstance(private, ed25519.Ed25519PrivateKey)
            signature = private.sign(message)

        return {
            "key_id": resolved,
            "signature": signature,
            "signing_algorithm": signing_algorithm,
        }

    def schedule_key_deletion(self, key_id: str, pending_window_in_days: int) -> None:
        self._deleted.append(key_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_facade_with_p256(key_id: str = "active-key") -> tuple[FakeKmsFacade, str]:
    f = FakeKmsFacade()
    f.add_p256_key(key_id)
    return f, key_id


def _make_facade_with_ed25519(key_id: str = "active-key") -> tuple[FakeKmsFacade, str]:
    f = FakeKmsFacade()
    f.add_ed25519_key(key_id)
    return f, key_id


# ---------------------------------------------------------------------------
# Construction and loading
# ---------------------------------------------------------------------------


class TestLoad:
    def test_loads_active_key_as_jwk(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id=kid,
                algorithm="ECDSA_SHA_256",
            ),
        )
        jwk = provider.signing_key()
        assert jwk.kid == kid
        assert jwk._raw["kty"] == "EC"
        assert jwk._raw["crv"] == "P-256"
        assert jwk._raw["alg"] == "ES256"
        assert jwk._raw["use"] == "sig"

    def test_loads_ed25519_key(self) -> None:
        facade, kid = _make_facade_with_ed25519()
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id=kid,
                algorithm="ED25519_SHA_512",
            ),
        )
        jwk = provider.signing_key()
        assert jwk._raw["kty"] == "OKP"
        assert jwk._raw["crv"] == "Ed25519"
        assert jwk._raw["alg"] == "EdDSA"

    def test_loads_retained_keys(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("active-key")
        facade.add_p256_key("retained-key")

        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id="active-key",
                retained_key_ids=["retained-key"],
                algorithm="ECDSA_SHA_256",
            ),
        )
        assert provider.list_key_ids() == ["active-key", "retained-key"]
        retained_jwk = provider.jwk("retained-key")
        assert retained_jwk.kid == "retained-key"

    def test_active_key_is_first_in_list(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("active")
        facade.add_p256_key("retained")

        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id="active",
                retained_key_ids=["retained"],
                algorithm="ECDSA_SHA_256",
            ),
        )
        ids = provider.list_key_ids()
        assert ids[0] == "active"
        assert ids[1] == "retained"

    def test_resolves_aliases_to_canonical_ids_on_load(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("canonical-key")
        facade.add_p256_key("pending-key")
        facade.add_alias("alias/current", "canonical-key")
        facade.add_alias("alias/pending", "pending-key")

        state = AwsKmsKeyState(
            active_key_id="alias/current",
            pending_key_ids=["alias/pending"],
        )
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                state=state,
                algorithm="ECDSA_SHA_256",
            ),
        )
        # state object is mutated in place with canonical IDs
        assert state.active_key_id == "canonical-key"
        assert state.pending_key_ids == ["pending-key"]
        assert provider.list_key_ids() == ["canonical-key"]

    def test_state_object_takes_precedence_over_top_level_fields(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("state-key")
        facade.add_p256_key("field-key")

        state = AwsKmsKeyState(active_key_id="state-key")
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                state=state,
                active_key_id="field-key",
                algorithm="ECDSA_SHA_256",
            ),
        )
        assert provider.signing_key().kid == "state-key"

    def test_raises_when_no_active_key_id(self) -> None:
        with pytest.raises(ArgumentError, match="requires an active key ID"):
            AwsKmsKeyProvider.load(FakeKmsFacade(), AwsKmsConfig(algorithm="ECDSA_SHA_256"))

    def test_raises_when_kid_contains_hash(self) -> None:
        with pytest.raises(ArgumentError, match="must not contain '#'"):
            AwsKmsKeyProvider.load(
                FakeKmsFacade(),
                AwsKmsConfig(
                    active_key_id="key#bad",
                    algorithm="ECDSA_SHA_256",
                ),
            )

    def test_raises_when_key_is_not_sign_verify(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("k")

        class BadFacade(AwsKmsFacade):
            def create_signing_key(self, key_spec, description=None, tags=None):  # type: ignore[override]
                raise NotImplementedError

            def get_public_key(self, key_id):  # type: ignore[override]
                r = facade.get_public_key(key_id)
                r["key_usage"] = "ENCRYPT_DECRYPT"
                return r

            def sign(self, key_id, message, signing_algorithm, message_type):  # type: ignore[override]
                raise NotImplementedError

        with pytest.raises(ArgumentError, match="is not a SIGN_VERIFY key"):
            AwsKmsKeyProvider.load(
                BadFacade(),
                AwsKmsConfig(
                    active_key_id="k",
                    algorithm="ECDSA_SHA_256",
                ),
            )

    def test_raises_when_key_spec_mismatch(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("k")

        with pytest.raises(ArgumentError, match="spec mismatch"):
            AwsKmsKeyProvider.load(
                facade,
                AwsKmsConfig(
                    active_key_id="k",
                    algorithm="ED25519_SHA_512",  # expects EDWARDS25519, got P256
                    key_spec="ECC_NIST_EDWARDS25519",
                ),
            )

    def test_raises_when_algorithm_not_supported_by_key(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("k")

        class BadFacade(AwsKmsFacade):
            def create_signing_key(self, key_spec, description=None, tags=None):  # type: ignore[override]
                raise NotImplementedError

            def get_public_key(self, key_id):  # type: ignore[override]
                r = facade.get_public_key(key_id)
                r["signing_algorithms"] = ["ECDSA_SHA_384"]
                return r

            def sign(self, key_id, message, signing_algorithm, message_type):  # type: ignore[override]
                raise NotImplementedError

        with pytest.raises(ArgumentError, match="does not support ECDSA_SHA_256"):
            AwsKmsKeyProvider.load(
                BadFacade(),
                AwsKmsConfig(
                    active_key_id="k",
                    algorithm="ECDSA_SHA_256",
                ),
            )


# ---------------------------------------------------------------------------
# jwk() lookup
# ---------------------------------------------------------------------------


class TestJwkLookup:
    def test_jwk_returns_active_key(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        assert provider.jwk(kid).kid == kid

    def test_jwk_returns_retained_key(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("active")
        facade.add_p256_key("retained")
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id="active",
                retained_key_ids=["retained"],
                algorithm="ECDSA_SHA_256",
            ),
        )
        assert provider.jwk("retained").kid == "retained"

    def test_jwk_raises_for_unknown_kid(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        with pytest.raises(ArgumentError, match="key not found"):
            provider.jwk("no-such-key")

    def test_jwk_raises_for_pending_kid(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("active")
        facade.add_p256_key("pending")
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id="active",
                pending_key_ids=["pending"],
                algorithm="ECDSA_SHA_256",
            ),
        )
        with pytest.raises(ArgumentError, match="key not found"):
            provider.jwk("pending")


# ---------------------------------------------------------------------------
# Sign + verify roundtrip
# ---------------------------------------------------------------------------


class TestSign:
    def test_p256_sign_produces_valid_signature(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        payload = b"hello, world"
        sig = provider.sign(payload)
        jwk = provider.signing_key()
        assert verify_signature(jwk._raw, payload, sig)

    def test_ed25519_sign_produces_valid_signature(self) -> None:
        facade, kid = _make_facade_with_ed25519()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ED25519_SHA_512")
        )
        payload = b"hello, world"
        sig = provider.sign(payload)
        jwk = provider.signing_key()
        assert verify_signature(jwk._raw, payload, sig)

    def test_sign_large_payload_uses_digest_mode_for_p256(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        large_payload = b"x" * 5000
        sig = provider.sign(large_payload)
        jwk = provider.signing_key()
        assert verify_signature(jwk._raw, large_payload, sig)

    def test_sign_large_payload_raises_for_ed25519(self) -> None:
        facade, kid = _make_facade_with_ed25519()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ED25519_SHA_512")
        )
        with pytest.raises(ArgumentError, match="exceeds"):
            provider.sign(b"x" * 5000)

    def test_different_payload_produces_different_signature(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        sig1 = provider.sign(b"payload-a")
        sig2 = provider.sign(b"payload-b")
        assert sig1 != sig2


# ---------------------------------------------------------------------------
# Key lifecycle: generate, activate, supersede
# ---------------------------------------------------------------------------


class TestKeyLifecycle:
    def test_generate_key_adds_to_pending(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        new_kid = provider.generate_key()
        snapshot = provider.state_snapshot()
        assert new_kid in snapshot.pending_key_ids
        assert new_kid not in provider.list_key_ids()

    def test_activate_promotes_pending_to_active(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        new_kid = provider.generate_key()
        provider.activate(new_kid)

        snapshot = provider.state_snapshot()
        assert snapshot.active_key_id == new_kid
        assert kid in snapshot.retained_key_ids
        assert new_kid not in snapshot.pending_key_ids

    def test_activate_raises_for_non_pending_key(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        with pytest.raises(ArgumentError, match="no pending key"):
            provider.activate(kid)

    def test_supersede_removes_retained_key(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("active")
        facade.add_p256_key("retained")
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id="active",
                retained_key_ids=["retained"],
                algorithm="ECDSA_SHA_256",
            ),
        )
        provider.supersede("retained")
        assert "retained" not in provider.list_key_ids()

    def test_supersede_raises_for_active_key(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        with pytest.raises(ArgumentError, match="cannot supersede the active key"):
            provider.supersede(kid)

    def test_supersede_raises_for_unknown_key(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        with pytest.raises(ArgumentError, match="no retained key"):
            provider.supersede("nonexistent")

    def test_supersede_calls_schedule_key_deletion_when_configured(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("active")
        facade.add_p256_key("retained")
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id="active",
                retained_key_ids=["retained"],
                algorithm="ECDSA_SHA_256",
                schedule_key_deletion_on_supersede=True,
                deletion_window_in_days=7,
            ),
        )
        provider.supersede("retained")
        assert "retained" in facade._deleted

    def test_supersede_raises_when_facade_lacks_schedule_deletion(self) -> None:
        """Raise ArgumentError when configured deletion is unsupported."""

        class NoDeleteFacade(FakeKmsFacade):
            def schedule_key_deletion(self, key_id: str, pending_window_in_days: int) -> None:
                raise NotImplementedError("This facade does not implement schedule_key_deletion")

        facade = NoDeleteFacade()
        facade.add_p256_key("active")
        facade.add_p256_key("retained")
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id="active",
                retained_key_ids=["retained"],
                algorithm="ECDSA_SHA_256",
                schedule_key_deletion_on_supersede=True,
            ),
        )
        with pytest.raises(ArgumentError, match="schedule_key_deletion"):
            provider.supersede("retained")

    def test_supersede_does_not_schedule_deletion_by_default(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("active")
        facade.add_p256_key("retained")
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id="active",
                retained_key_ids=["retained"],
                algorithm="ECDSA_SHA_256",
            ),
        )
        provider.supersede("retained")
        assert facade._deleted == []

    def test_full_rotation_roundtrip(self) -> None:
        facade, original_kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=original_kid, algorithm="ECDSA_SHA_256")
        )

        # Generate → activate → supersede old
        new_kid = provider.generate_key()
        provider.activate(new_kid)
        provider.supersede(original_kid)

        snapshot = provider.state_snapshot()
        assert snapshot.active_key_id == new_kid
        assert original_kid not in snapshot.retained_key_ids
        assert snapshot.pending_key_ids == []

        # New active key signs correctly
        payload = b"post-rotation payload"
        sig = provider.sign(payload)
        assert verify_signature(provider.signing_key()._raw, payload, sig)


# ---------------------------------------------------------------------------
# state_snapshot
# ---------------------------------------------------------------------------


class TestStateSnapshot:
    def test_snapshot_is_a_copy(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade, AwsKmsConfig(active_key_id=kid, algorithm="ECDSA_SHA_256")
        )
        snap1 = provider.state_snapshot()
        provider.generate_key()
        snap2 = provider.state_snapshot()
        assert snap1.pending_key_ids == []
        assert len(snap2.pending_key_ids) == 1

    def test_state_object_mutated_in_place_during_load(self) -> None:
        facade = FakeKmsFacade()
        facade.add_p256_key("canonical-key")
        facade.add_alias("alias/current", "canonical-key")

        state = AwsKmsKeyState(active_key_id="alias/current")
        AwsKmsKeyProvider.load(facade, AwsKmsConfig(state=state, algorithm="ECDSA_SHA_256"))

        assert state.active_key_id == "canonical-key"


# ---------------------------------------------------------------------------
# generate_key uses configured key spec
# ---------------------------------------------------------------------------


class TestGenerateKey:
    def test_generate_passes_key_spec_to_facade(self) -> None:
        facade, kid = _make_facade_with_ed25519()
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id=kid,
                algorithm="ED25519_SHA_512",
            ),
        )
        provider.generate_key()
        assert facade._create_inputs[-1]["key_spec"] == "ECC_NIST_EDWARDS25519"

    def test_generate_passes_custom_key_spec(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id=kid,
                algorithm="ECDSA_SHA_256",
                key_spec="ECC_NIST_P256",
            ),
        )
        provider.generate_key()
        assert facade._create_inputs[-1]["key_spec"] == "ECC_NIST_P256"

    def test_generate_passes_description_and_tags(self) -> None:
        facade, kid = _make_facade_with_p256()
        provider = AwsKmsKeyProvider.load(
            facade,
            AwsKmsConfig(
                active_key_id=kid,
                algorithm="ECDSA_SHA_256",
                description="dnsid signing key",
                tags={"env": "prod"},
            ),
        )
        provider.generate_key()
        inp = facade._create_inputs[-1]
        assert inp["description"] == "dnsid signing key"
        assert inp["tags"] == {"env": "prod"}
