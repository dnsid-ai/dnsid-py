"""#61 unchanged contract; real-capable AWS/GCP run with synthetic clients only.

No service replication/location proof, provisioning, cloud calls or fallback.
"""
import base64
import hashlib
import json

import google_crc32c
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from google.cloud.kms_v1.types import (
    AsymmetricSignResponse,
    CryptoKeyVersion,
    ProtectionLevel,
    PublicKey,
)

from dnsid import AwsKmsConfig, AwsKmsKeyProvider, GoogleKmsKeyProvider

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
PRIVATE = Ed25519PrivateKey.from_private_bytes(SEED)
WRONG = Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def thumbprint(x):
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    return b64(hashlib.sha256(canonical.encode("ascii")).digest())


class Aws:
    def __init__(self, ref):
        self.ref, self.calls = ref, []

    def get_public_key(self, key_id):
        assert key_id == self.ref
        self.calls.append("get")
        return dict(key_id=self.ref, public_key=PRIVATE.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            key_spec="ECC_NIST_EDWARDS25519", key_usage="SIGN_VERIFY", signing_algorithms=["ED25519_SHA_512"])

    def sign(self, key_id, message, signing_algorithm, message_type):
        assert (key_id, signing_algorithm, message_type) == (self.ref, "ED25519_SHA_512", "RAW")
        self.calls.append("sign")
        return dict(key_id=self.ref, signature=PRIVATE.sign(message), signing_algorithm=signing_algorithm)

    def create_signing_key(self, *args, **kwargs):
        pytest.fail("open/sign must not provision")

    def schedule_key_deletion(self, *args, **kwargs):
        pytest.fail("unexpected mutation")


class Google:
    def __init__(self, ref):
        self.ref, self.calls = ref, []

    def get_public_key(self, request):
        assert request == {"name": self.ref}
        self.calls.append("get")
        pem = PRIVATE.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        return PublicKey(name=self.ref, pem=pem.decode("ascii"), pem_crc32c=google_crc32c.value(pem),
                         algorithm=CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519,
                         protection_level=ProtectionLevel.SOFTWARE)

    def asymmetric_sign(self, request):
        assert request["name"] == self.ref
        assert "digest" not in request
        assert request["data_crc32c"] == google_crc32c.value(request["data"])
        self.calls.append("sign")
        signature = PRIVATE.sign(request["data"])
        return AsymmetricSignResponse(name=self.ref, signature=signature,
                                      signature_crc32c=google_crc32c.value(signature), verified_data_crc32c=True)

    def create_crypto_key_version(self, *args, **kwargs):
        pytest.fail("open/sign must not generate")


def test_given_rfc_oracle_when_checked_then_verifier_and_same_key_proof_discriminate():
    """Mode: real-capable (local cryptography only); F1 proof guard."""
    signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    Ed25519PublicKey.from_public_bytes(PUBLIC).verify(signature, b"")
    assert PRIVATE.sign(b"") == signature
    assert google_crc32c.value(b"123456789") == 0xE3069283
    assert thumbprint(b64(WRONG.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))) != thumbprint(b64(PUBLIC))


@pytest.mark.parametrize("topology", ["aws", "us", "global"])
def test_given_same_key_clients_when_reopened_then_native_kids_and_cross_signatures_remain_bound(topology):
    """Mode: real-capable (AWS/GCP=fake); A1/G1 with F1 verification guards."""
    refs = [f"arn:aws:kms:{region}:123456789012:key/mrk-0123456789abcdef0123456789abcdef" for region in ("us-east-1", "us-west-2")]
    if topology != "aws":
        refs = [f"projects/fixture/locations/{topology}/keyRings/agents/cryptoKeys/signer/cryptoKeyVersions/7"] * 2
    publics, signatures = [], []
    payload = b"#61 bounded RAW cross-region payload"
    for _reopen in range(2):
        for ref in refs:
            # Given separate clients; When exact existing refs are freshly opened.
            client = Aws(ref) if topology == "aws" else Google(ref)
            provider = (AwsKmsKeyProvider.load(client, AwsKmsConfig(active_key_id=ref, algorithm="ED25519_SHA_512"))
                        if topology == "aws" else GoogleKmsKeyProvider(client, ref))
            key = provider.signing_key().to_dict()
            # Then public material/thumbprints match, native thumbprint IDs survive.
            assert {k: key[k] for k in ("kty", "crv", "alg", "x")} == dict(kty="OKP", crv="Ed25519", alg="EdDSA", x=b64(PUBLIC))
            assert "d" not in key
            assert thumbprint(key["x"]) == thumbprint(b64(PUBLIC))
            kid = thumbprint(b64(PUBLIC))
            assert key["kid"] == kid
            assert provider.list_key_ids() == [kid]
            assert provider.jwk(kid).to_dict()["x"] == b64(PUBLIC)
            publics.append(Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(key["x"] + "=")))
            signatures.extend([provider.sign(payload), provider.sign_key(kid, payload)])
            assert client.calls == ["get", "sign", "sign"]
    for signature in signatures:
        for public in publics:
            public.verify(signature, payload)
        with pytest.raises(InvalidSignature):
            publics[0].verify(signature, payload + b"tampered")
        with pytest.raises(InvalidSignature):
            WRONG.verify(signature, payload)


def test_given_regional_config_when_reopened_then_exact_region_and_arn_remain_selected(tmp_path, monkeypatch):
    """A2 real-capable (AWS=fake); wrong-response variant fake-only."""
    from botocore.client import BaseClient

    from dnsid import identity_manager_from_file
    from dnsid.exceptions import ArgumentError
    from tests._kms_publication import publication

    calls = []
    wrong_binding = False
    requests = []
    other_ref = "arn:aws:kms:us-west-2:123456789012:key/mrk-fedcba9876543210fedcba9876543210"

    def api_call(client, operation, params):
        region = client.meta.region_name
        # Account for every attempted RPC before any fixture assertion can fail.
        calls.append(operation)
        requests.append((region, operation, params.copy()))
        ref = f"arn:aws:kms:{region}:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
        assert params["KeyId"] == ref
        assert region in ("us-east-1", "us-west-2")
        if operation == "GetPublicKey":
            return dict(KeyId=other_ref if wrong_binding else ref,
                        PublicKey=PRIVATE.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                        KeySpec="ECC_NIST_EDWARDS25519", KeyUsage="SIGN_VERIFY", SigningAlgorithms=["ED25519_SHA_512"])
        assert operation == "Sign", "no provisioning/fallback RPC"
        assert params["MessageType"] == "RAW"
        assert params["SigningAlgorithm"] == "ED25519_SHA_512"
        return dict(KeyId=ref, Signature=PRIVATE.sign(params["Message"]), SigningAlgorithm="ED25519_SHA_512")

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-test")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(BaseClient, "_make_api_call", api_call)
    for region in ("us-east-1", "us-west-2"):
        ref = f"arn:aws:kms:{region}:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
        evidence = publication(tmp_path, key_source=dict(provider="aws-kms", keyRef=ref, settings=dict(region=region, algorithm="EdDSA")))
        before = evidence.path.read_bytes()
        for _reopen in range(2):
            with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
                assert manager.key_provider.signing_key().to_dict()["x"] == b64(PUBLIC)
                assert manager.key_provider.signing_key().kid == thumbprint(b64(PUBLIC))
                Ed25519PublicKey.from_public_bytes(PUBLIC).verify(manager.key_provider.sign(b"config"), b"config")
        assert evidence.path.read_bytes() == before
    assert calls == ["GetPublicKey", "Sign"] * 4
    wrong_binding = True
    assert ref != other_ref
    result = None
    with pytest.raises(ArgumentError) as caught:
        result = identity_manager_from_file(evidence.path, deps=evidence.deps)
    assert result is None
    # Require reference-mismatch meaning, not exact wording or both ARN strings.
    message = str(caught.value).lower()
    assert any(term in message for term in ("key", "reference", "arn"))
    assert any(term in message for term in ("mismatch", "does not match", "different", "unexpected"))
    assert calls == ["GetPublicKey", "Sign"] * 4 + ["GetPublicKey"]
    assert [(region, operation, params["KeyId"]) for region, operation, params in requests] == [
        (region, operation,
         f"arn:aws:kms:{region}:123456789012:key/mrk-0123456789abcdef0123456789abcdef")
        for region in ("us-east-1", "us-west-2")
        for _reopen in range(2)
        for operation in ("GetPublicKey", "Sign")
    ] + [("us-west-2", "GetPublicKey", ref)]
    assert requests[-1][2] == {"KeyId": ref}
    assert evidence.path.read_bytes() == before


@pytest.mark.parametrize("size", [4096, 4097])
def test_aws_raw_boundary_61(size):
    """F2 Mode: fake-only; Given RAW bytes, When signing, Then enforce 4096 bound."""
    class CountedAws(Aws):
        creates = 0

        def create_signing_key(self, *args, **kwargs):
            self.creates += 1
            raise RuntimeError("unexpected generation")

    ref = "arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
    client = CountedAws(ref)
    provider = AwsKmsKeyProvider.load(client, AwsKmsConfig(active_key_id=ref, algorithm="ED25519_SHA_512"))
    kid = provider.signing_key().kid
    payload = b"a" * size
    outcomes = []
    # Fake native Sign accepts both sizes; provider must reject oversized data first.
    for action in (lambda: provider.sign(payload), lambda: provider.sign_key(kid, payload)):
        before = client.calls.count("sign")
        signature, error = None, None
        try:
            signature = action()
        except Exception as caught:
            error = caught
        outcomes.append((signature, error, client.calls.count("sign") - before))
    assert client.creates == 0
    for signature, error, native_calls in outcomes:
        if size == 4096:
            assert error is None and signature is not None
            assert native_calls == 1
            Ed25519PublicKey.from_public_bytes(PUBLIC).verify(signature, payload)
        else:
            assert (error is not None, signature is None, native_calls) == (True, True, 0), (
                "4097 bytes must error without substitute before native Sign", error, signature is not None, native_calls
            )


def test_aws_compatibility_cov1_omitted_response_key_id():
    """COV-1 Mode: real-capable (AWS=fake); unchanged existing-ARN compatibility."""
    from dnsid import BotoKmsFacade

    ref = "arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
    payload = b"COV-1 unchanged compatibility"

    class NativeExistingKms:
        def __init__(self):
            self.calls = []

        def get_public_key(self, **request):
            self.calls.append("GetPublicKey")
            assert request == {"KeyId": ref}
            # Intentionally no KeyId: ordinary existing opens preserve the request.
            return dict(PublicKey=PRIVATE.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                KeySpec="ECC_NIST_EDWARDS25519", KeyUsage="SIGN_VERIFY", SigningAlgorithms=["ED25519_SHA_512"])

        def sign(self, **request):
            self.calls.append("Sign")
            assert request == dict(KeyId=ref, Message=payload, MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
            return dict(KeyId=ref, Signature=PRIVATE.sign(payload), SigningAlgorithm="ED25519_SHA_512")

        def create_key(self, **request):
            self.calls.append("CreateKey")
            pytest.fail("existing-key open/sign must not generate")

    # Given immutable ARN plus omitted native response KeyId; When facade loads.
    client = NativeExistingKms()
    provider = AwsKmsKeyProvider.load(BotoKmsFacade(client), AwsKmsConfig(active_key_id=ref, algorithm="ED25519_SHA_512"))
    key = provider.signing_key().to_dict()
    # Then public binding and native thumbprint kid survive, no substitute signer.
    assert {k: key[k] for k in ("kty", "crv", "alg", "x", "kid")} == dict(
        kty="OKP", crv="Ed25519", alg="EdDSA", x=b64(PUBLIC), kid=thumbprint(b64(PUBLIC)))
    assert "d" not in key
    assert provider.list_key_ids() == [key["kid"]]
    assert provider.jwk(key["kid"]).to_dict()["x"] == b64(PUBLIC)
    assert provider.state_snapshot().active_key_id == ref
    Ed25519PublicKey.from_public_bytes(PUBLIC).verify(provider.sign(payload), payload)
    assert client.calls == ["GetPublicKey", "Sign"]
