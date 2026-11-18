"""#58 explicit KMS-first contracts; no cloud resources or production helpers.

Contract inputs: shared 01 KeyProvider, 12 open-only configuration, and #58
existing-parent bootstrap scope. All dependencies run fake; RFC8032 vector 1
provides independently known public material for the public creation flow.
"""

import base64
import builtins
import hashlib
import io
import json
import os
import tempfile
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dnsid import (
    ArgumentError,
    AwsKmsConfig,
    AwsKmsKeyProvider,
    AwsKmsKeyState,
    GoogleKmsKeyProvider,
    LocalKeyProvider,
    NoActiveSigningKeyError,
)
from tests.test_google_kms_runtime_contract import crc32c

PARENT = "projects/fixture/locations/global/keyRings/first/cryptoKeys/agent"
VERSION = PARENT + "/cryptoKeyVersions/1"
ARN = "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111"
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
PAYLOAD = b"first operational signing, not a prehashed digest"


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def assert_public(jwk):
    """Expected values use RFC8032 and RFC7638, never SDK-generated values."""
    expected = {"crv": "Ed25519", "kty": "OKP", "x": b64(PUBLIC)}
    kid = b64(hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).digest())
    actual = jwk.to_dict()
    assert {name: actual[name] for name in (*expected, "alg", "kid")} == {
        **expected, "alg": "EdDSA", "kid": kid,
    }
    assert "d" not in actual
    return kid


class RemoteMaterial:
    """Private fixture material stays service-side, prepared before custody guards."""

    def __init__(self):
        self.private = Ed25519PrivateKey.from_private_bytes(SEED)
        self.public = self.private.public_key()
        self.pem = self.public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.der = self.public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.calls = []
        self.created = False
        self.closed = False

    def close(self):
        self.closed = True


class AwsService(RemoteMaterial):
    def create_signing_key(self, key_spec, description=None, tags=None):
        self.calls.append(("create", key_spec))
        assert key_spec == "ECC_NIST_EDWARDS25519"
        assert not self.created, "no duplicate remote create"
        self.created = True
        return ARN

    def get_public_key(self, key_id):
        self.calls.append(("public", key_id))
        assert self.created and key_id == ARN
        return dict(key_id=ARN, public_key=self.der, key_spec="ECC_NIST_EDWARDS25519",
                    key_usage="SIGN_VERIFY", signing_algorithms=["ED25519_SHA_512"])

    def sign(self, key_id, message, signing_algorithm, message_type):
        self.calls.append(("sign", key_id))
        assert key_id == ARN and message_type == "RAW"
        assert signing_algorithm == "ED25519_SHA_512" and message == PAYLOAD
        return dict(key_id=ARN, signature=self.private.sign(message),
                    signing_algorithm=signing_algorithm)


class FirstVersionService(RemoteMaterial):
    """Existing compatible parent, initially zero versions; no import/create-parent API."""

    def __init__(self, fault=None):
        super().__init__()
        self.fault = fault

    def get_crypto_key(self, request):
        self.calls.append(("parent", request["name"]))
        assert request["name"] == PARENT
        return SimpleNamespace(
            name=PARENT if self.fault != "parent_name" else PARENT + "-other",
            purpose=1 if self.fault == "parent_purpose" else 5,
            version_template=SimpleNamespace(
                algorithm=12 if self.fault == "parent_algorithm" else 40,
                protection_level=2 if self.fault == "parent_protection" else 1,
            ),
        )

    def create_crypto_key_version(self, request):
        self.calls.append(("create", request["parent"]))
        assert request["parent"] == PARENT
        assert not self.created, "no duplicate remote create"
        if self.fault == "denied":
            raise PermissionError("fixture create denied")
        self.created = True
        fields = dict(name=VERSION, algorithm=40, state=1, protection_level=1)
        if self.fault == "missing_name":
            fields["name"] = ""
        if self.fault == "foreign_parent":
            fields["name"] = VERSION.replace("/agent/", "/foreign/")
        if self.fault == "create_algorithm":
            fields["algorithm"] = 12
        if self.fault == "create_protection":
            fields["protection_level"] = 2
        return SimpleNamespace(**fields)

    def get_public_key(self, request):
        self.calls.append(("public", request["name"]))
        assert self.created, "bootstrap must not open a prior version"
        assert request["name"] == VERSION
        if self.fault == "public_unavailable":
            raise PermissionError("fixture public read denied")
        fields = dict(name=VERSION, pem=self.pem, pem_crc32c=crc32c(self.pem.encode()),
                      algorithm=40, protection_level=1)
        if self.fault == "public_crc":
            fields["pem_crc32c"] = 0
        if self.fault == "public_algorithm":
            fields["algorithm"] = 12
        if self.fault == "public_name":
            fields["name"] = VERSION + "0"
        if self.fault == "public_pem":
            fields.update(pem="not a public key", pem_crc32c=crc32c(b"not a public key"))
        return SimpleNamespace(**fields)

    def asymmetric_sign(self, request):
        self.calls.append(("sign", request["name"]))
        assert self.created and request["name"] == VERSION
        assert "digest" not in request and request["data"] == PAYLOAD
        assert request["data_crc32c"] == crc32c(PAYLOAD)
        signature = self.private.sign(PAYLOAD)
        return SimpleNamespace(name=VERSION, signature=signature,
                               signature_crc32c=crc32c(signature), verified_data_crc32c=True)


def forbid_local_custody(monkeypatch):
    """Narrow invariant: no SDK local key generation/import or file/temp writes."""
    def forbidden(*args, **kwargs):
        pytest.fail("KMS-first operation attempted local key custody or file creation")

    monkeypatch.setattr(Ed25519PrivateKey, "generate", forbidden)
    monkeypatch.setattr(Ed25519PrivateKey, "from_private_bytes", forbidden)
    monkeypatch.setattr(serialization, "load_pem_private_key", forbidden)
    monkeypatch.setattr(serialization, "load_der_private_key", forbidden)
    monkeypatch.setattr(LocalKeyProvider, "__init__", forbidden)
    for module in (builtins, io):
        original = module.open

        def guarded(file, mode="r", *args, _open=original, **kwargs):
            assert not any(flag in mode for flag in "wax+"), "SDK attempted a file write"
            return _open(file, mode, *args, **kwargs)

        monkeypatch.setattr(module, "open", guarded)
    original_os_open = os.open

    def guarded_os_open(path, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        return original_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_os_open)
    for name in ("mkstemp", "mkdtemp", "NamedTemporaryFile", "TemporaryFile"):
        monkeypatch.setattr(tempfile, name, forbidden)


def assert_inactive(provider, client):
    before = list(client.calls)
    assert provider.list_key_ids() == []
    with pytest.raises((NoActiveSigningKeyError, ArgumentError, ValueError)):
        provider.signing_key()
    with pytest.raises((NoActiveSigningKeyError, ArgumentError, ValueError)):
        provider.sign(PAYLOAD)
    assert client.calls == before


def test_aws_empty_load_generate_activate_state_reopen(tmp_path, monkeypatch):
    """**Mode**: real-capable. Given empty state, when generated, then activate explicitly.

    Fake-only custody guards additionally cover this offline execution.
    """
    client = AwsService()
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        provider = AwsKmsKeyProvider.load(
            client, AwsKmsConfig(algorithm="ED25519_SHA_512", state=AwsKmsKeyState(active_key_id="")),
        )
        assert client.calls == []
        assert_inactive(provider, client)
        kid = provider.generate_key()
        assert kid == assert_public(provider.jwk(kid))
        state = provider.state_snapshot()
        assert state.active_key_id == "" and state.pending_key_ids == [ARN]
        assert_inactive(provider, client)
        client.public.verify(provider.sign_key(kid, PAYLOAD), PAYLOAD)
        provider.activate(kid)
        assert provider.list_key_ids() == [kid]
        client.public.verify(provider.sign(PAYLOAD), PAYLOAD)
        state = provider.state_snapshot()
        assert state.active_key_id == ARN and state.pending_key_ids == []
        reopened = AwsKmsKeyProvider.load(
            client, AwsKmsConfig(algorithm="ED25519_SHA_512", state=state),
        )
        assert assert_public(reopened.signing_key()) == kid
        client.public.verify(reopened.sign(PAYLOAD), PAYLOAD)
        assert sum(name == "create" for name, _ in client.calls) == 1
    assert list(tmp_path.iterdir()) == []


def test_gcp_first_version_pending_activate_reopen(tmp_path, monkeypatch):
    """**Mode**: real-capable. Given versionless parent, when created, then pending/ref reopen.

    Fake-only custody guards additionally cover this offline execution.
    """
    create = GoogleKmsKeyProvider.create
    client = FirstVersionService()
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        provider, kid, reference = create(client, PARENT)
        assert reference == VERSION
        assert kid == assert_public(provider.jwk(kid))
        assert_inactive(provider, client)
        client.public.verify(provider.sign_key(kid, PAYLOAD), PAYLOAD)
        provider.activate(kid)
        assert provider.list_key_ids() == [kid]
        assert assert_public(provider.signing_key()) == kid
        client.public.verify(provider.sign(PAYLOAD), PAYLOAD)
        reopened = GoogleKmsKeyProvider(client, reference)
        assert assert_public(reopened.signing_key()) == kid
        client.public.verify(reopened.sign(PAYLOAD), PAYLOAD)
        assert sum(name == "create" for name, _ in client.calls) == 1
        assert not client.closed, "caller owns injected client lifetime"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("fault", [
    "denied", "missing_name", "foreign_parent", "create_algorithm", "create_protection",
    "public_unavailable", "public_crc", "public_algorithm", "public_name", "public_pem",
])
def test_gcp_failed_first_version_returns_no_provider_or_fallback(fault, tmp_path, monkeypatch):
    """**Mode**: fake-only. Given native fault, when creating, then fail once without local custody."""
    create = GoogleKmsKeyProvider.create
    client = FirstVersionService(fault)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        with pytest.raises((ArgumentError, ValueError, PermissionError)):
            create(client, PARENT)
        assert sum(name == "create" for name, _ in client.calls) == 1
        assert all(name != "sign" for name, _ in client.calls)
        assert not client.closed, "failure does not close caller's client"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("parent", ["", VERSION, "projects/p/locations/l/keyRings/r"])
def test_gcp_invalid_parent_fails_before_mutation(parent):
    """**Mode**: fake-only. Given invalid parent, when creating, then no cloud mutation."""
    create = GoogleKmsKeyProvider.create
    client = FirstVersionService()
    with pytest.raises((ArgumentError, ValueError)):
        create(client, parent)
    assert client.calls == []
    assert not client.closed


def test_gcp_existing_constructor_is_open_only():
    """**Mode**: real-capable. Given existing version, when opening, then no create."""
    client = FirstVersionService()
    client.created = True  # Remote precondition, not an SDK operation.
    provider = GoogleKmsKeyProvider(client, VERSION)
    assert_public(provider.signing_key())
    client.public.verify(provider.sign(PAYLOAD), PAYLOAD)
    assert all(name != "create" for name, _ in client.calls)
    assert not client.closed


@pytest.mark.parametrize("fault", ["denied", "public_unavailable", "malformed_reference"])
def test_aws_failed_first_create_has_no_partial_activation(fault, tmp_path, monkeypatch):
    """**Mode**: fake-only. Given create/read failure, when generated, then no fallback/activation."""
    client = AwsService()
    original_create = client.create_signing_key

    def create(key_spec, description=None, tags=None):
        if fault == "denied":
            client.calls.append(("create", key_spec))
            raise PermissionError("fixture create denied")
        reference = original_create(key_spec, description, tags)
        return "" if fault == "malformed_reference" else reference

    def unavailable(key_id):
        client.calls.append(("public", key_id))
        raise PermissionError("fixture public read denied")

    client.create_signing_key = create
    if fault == "public_unavailable":
        client.get_public_key = unavailable
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        provider = AwsKmsKeyProvider.load(
            client, AwsKmsConfig(algorithm="ED25519_SHA_512", state=AwsKmsKeyState(active_key_id="")),
        )
        with pytest.raises((ArgumentError, ValueError, PermissionError)):
            provider.generate_key()
        state = provider.state_snapshot()
        assert state.active_key_id == "" and state.pending_key_ids == []
        assert_inactive(provider, client)
        assert sum(name == "create" for name, _ in client.calls) == 1
        assert not client.closed
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("fault", [
    "parent_name", "parent_purpose", "parent_algorithm", "parent_protection",
])
def test_gcp_incompatible_parent_rejected_before_create(fault, tmp_path, monkeypatch):
    """**Mode**: fake-only. Given wrong parent/template, when bootstrapping, then no create."""
    create = GoogleKmsKeyProvider.create
    client = FirstVersionService(fault)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        with pytest.raises((ArgumentError, ValueError)):
            create(client, PARENT)
        assert client.calls == [("parent", PARENT)]
        assert not client.closed
    assert list(tmp_path.iterdir()) == []
