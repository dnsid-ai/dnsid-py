"""KMS-first resource binding through the real boto adapter, without cloud access.

Shared 01 Initial Setup: validate the created resource before exposing an
immutable reference. Ordinary existing-key alias loading remains supported.
"""

import pytest

from dnsid import ArgumentError, AwsKmsConfig, AwsKmsKeyProvider, AwsKmsKeyState, BotoKmsFacade
from tests.test_kms_first_creation import (
    ARN,
    PAYLOAD,
    RemoteMaterial,
    assert_inactive,
    assert_public,
    forbid_local_custody,
)

UUID = ARN.rsplit("/", 1)[1]
OTHER_ARN = ARN.replace(UUID, "22222222-2222-4222-8222-222222222222")
ALIAS = "alias/dnsid-current"


class NativeKms(RemoteMaterial):
    """Only the AWS service is fake; adapter and provider are unmodified."""

    def __init__(self, metadata, public_binding=ARN, requested=ARN):
        super().__init__()
        self.metadata = metadata
        self.public_binding = public_binding
        self.requested = requested

    def create_key(self, **request):
        self.calls.append(("create", request))
        assert not self.created, "creation must not retry"
        assert request["KeySpec"] == "ECC_NIST_EDWARDS25519"
        assert request["KeyUsage"] == "SIGN_VERIFY"
        self.created = True
        return {"KeyMetadata": self.metadata}

    def get_public_key(self, **request):
        self.calls.append(("public", request))
        assert request == {"KeyId": self.requested}
        response = dict(
            PublicKey=self.der,
            KeySpec="ECC_NIST_EDWARDS25519",
            KeyUsage="SIGN_VERIFY",
            SigningAlgorithms=["ED25519_SHA_512"],
        )
        if self.public_binding is not None:
            response["KeyId"] = self.public_binding
        return response

    def sign(self, **request):
        self.calls.append(("sign", request))
        assert request == dict(
            KeyId=ARN, Message=PAYLOAD, MessageType="RAW", SigningAlgorithm="ED25519_SHA_512",
        )
        return dict(
            KeyId=ARN, Signature=self.private.sign(PAYLOAD), SigningAlgorithm="ED25519_SHA_512",
        )

    def schedule_key_deletion(self, **request):
        self.calls.append(("delete", request))
        pytest.fail("failed creation must not implicitly delete a remote key")


def empty_provider(client):
    return AwsKmsKeyProvider.load(
        BotoKmsFacade(client),
        AwsKmsConfig(algorithm="ED25519_SHA_512", state=AwsKmsKeyState(active_key_id="")),
    )


@pytest.mark.parametrize(
    "metadata,binding,requested",
    [
        pytest.param({"Arn": ARN, "KeyId": UUID}, OTHER_ARN, ARN, id="unrelated-public-arn"),
        pytest.param({"Arn": ARN, "KeyId": UUID}, None, ARN, id="missing-public-binding"),
        pytest.param({"Arn": ALIAS}, ARN, ALIAS, id="mutable-create-alias"),
        pytest.param({"Arn": "not-an-immutable-key"}, ARN, "not-an-immutable-key", id="malformed-create"),
        pytest.param({}, ARN, ARN, id="missing-create-reference"),
    ],
)
def test_given_invalid_binding_when_generated_then_no_candidate_or_handoff(
    metadata, binding, requested, tmp_path, monkeypatch,
):
    """**Mode**: fake-only. Invalid native responses cannot become pending keys."""
    client = NativeKms(metadata, binding, requested)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        provider = empty_provider(client)
        assert client.calls == []
        assert_inactive(provider, client)
        error = None
        try:
            provider.generate_key()
        except ArgumentError as exc:
            error = exc
        # Check the public state even if generation raised after partial mutation.
        state = provider.state_snapshot()
        assert state == AwsKmsKeyState(active_key_id=""), "unvalidated resource became a candidate"
        assert_inactive(provider, client)
        with pytest.raises(ArgumentError):
            provider.activate(assert_public_fixture_kid())
        with pytest.raises(ArgumentError):
            provider.jwk(assert_public_fixture_kid())
        with pytest.raises(ArgumentError):
            provider.sign_key(assert_public_fixture_kid(), PAYLOAD)
        assert error is not None, "native creation/public binding must be rejected"
        assert sum(name == "create" for name, _ in client.calls) == 1
        assert all(name in {"create", "public"} for name, _ in client.calls)
    assert list(tmp_path.iterdir()) == []


def assert_public_fixture_kid():
    """RFC7638 thumbprint independently calculated from the RFC8032 vector."""
    import base64
    import hashlib
    import json

    from tests.test_kms_first_creation import PUBLIC, b64

    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": b64(PUBLIC)},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


@pytest.mark.parametrize(
    "metadata,requested",
    [
        pytest.param({"Arn": ARN, "KeyId": UUID}, ARN, id="matching-arn"),
        pytest.param({"KeyId": UUID}, UUID, id="bare-uuid-to-canonical-arn"),
    ],
)
def test_given_matching_binding_when_generated_then_pending_canonical_arn_activates(
    metadata, requested, tmp_path, monkeypatch,
):
    """**Mode**: real-capable, run fake with custody guards. GWT canonical handoff."""
    client = NativeKms(metadata, requested=requested)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        provider = empty_provider(client)
        assert client.calls == []
        kid = provider.generate_key()
        assert kid == assert_public(provider.jwk(kid)) == assert_public_fixture_kid()
        assert provider.state_snapshot() == AwsKmsKeyState(active_key_id="", pending_key_ids=[ARN])
        assert_inactive(provider, client)
        provider.activate(kid)
        assert provider.state_snapshot() == AwsKmsKeyState(active_key_id=ARN)
        client.public.verify(provider.sign(PAYLOAD), PAYLOAD)
        assert [name for name, _ in client.calls] == ["create", "public", "sign"]
    assert list(tmp_path.iterdir()) == []


def test_given_existing_alias_when_loaded_then_canonical_signer_remains_supported():
    """**Mode**: real-capable, run fake. GWT ordinary loading is not creation."""
    client = NativeKms({}, requested=ALIAS)
    provider = AwsKmsKeyProvider.load(
        BotoKmsFacade(client), AwsKmsConfig(algorithm="ED25519_SHA_512", active_key_id=ALIAS),
    )
    assert assert_public(provider.signing_key()) == assert_public_fixture_kid()
    assert provider.state_snapshot() == AwsKmsKeyState(active_key_id=ARN)
    client.public.verify(provider.sign(PAYLOAD), PAYLOAD)
    assert [name for name, _ in client.calls] == ["public", "sign"]
