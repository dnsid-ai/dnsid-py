"""Concrete Boto adapter supplement; all cases Mode: fake-only.

Given native KMS dictionaries and typed client exceptions, when an explicit
bootstrap runs, then the published key-only contract holds. AWS field spelling
comes from botocore 1.43.85's KMS 2014-11-01 model (CreateKey/GetPublicKey/
CreateAlias/Sign), not product observations. No client/service discovery occurs.
Resource disposition is deferred: nondestructive partial bootstrap only.
"""

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("botocore")

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from dnsid import (
    AwsKmsBootstrapConfig,
    BotoKmsFacade,
    create_or_reuse_aws_kms_key_provider,
)

ALIAS = "alias/dnsid/test-org/boto-agent"
WIN_ID = "11111111-1111-4111-8111-111111111111"
CAND_ID = "22222222-2222-4222-8222-222222222222"
PREFIX = "arn:aws:kms:us-east-1:123456789012:key/"
WIN = PREFIX + WIN_ID
CAND = PREFIX + CAND_ID
ALGORITHMS = [
    ("ECDSA_SHA_256", "ECC_NIST_P256", "ES256"),
    ("ED25519_SHA_512", "ECC_NIST_EDWARDS25519", "EdDSA"),
]


class NativeNotFound(ClientError):
    """Injected client's typed NotFoundException."""


class NativeAlreadyExists(ClientError):
    """Injected client's typed AlreadyExistsException."""


class NativeDenied(ClientError):
    """Injected client's typed permission failure."""


def error(cls, operation, code):
    return cls({"Error": {"Code": code, "Message": "controlled offline fault"}}, operation)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class NativeClient:
    """Finite native-shaped client; no fallback for other AWS operations."""

    exceptions = SimpleNamespace(
        NotFoundException=NativeNotFound,
        AlreadyExistsException=NativeAlreadyExists,
        AccessDeniedException=NativeDenied,
    )

    def __init__(self, algorithm, spec, mode="existing", fault=None):
        self.algorithm, self.spec, self.mode = algorithm, spec, mode
        self.fault = fault
        self.calls = []
        self.alias_reads = 0
        self.keys = {
            ref: (ec.generate_private_key(ec.SECP256R1())
                  if algorithm == "ECDSA_SHA_256" else ed25519.Ed25519PrivateKey.generate())
            for ref in (WIN, CAND)
        }
        self.winner = WIN if mode != "missing" else CAND

    def call(self, operation, kwargs, stage):
        self.calls.append((operation, kwargs))
        assert len(self.calls) <= 12, "bootstrap/sign exceeded finite call budget"
        if self.fault and self.fault[0] == stage:
            raise self.fault[1]

    def get_public_key(self, **kwargs):
        ref = kwargs["KeyId"]
        assert kwargs == {"KeyId": ref}
        if ref == ALIAS:
            self.alias_reads += 1
            stage = "initial" if self.alias_reads == 1 else "winner"
        else:
            stage = "validation"
        self.call("get_public_key", kwargs, stage)
        if ref == ALIAS and self.alias_reads == 1 and self.mode != "existing":
            raise error(NativeNotFound, "GetPublicKey", "NotFoundException")
        assert self.alias_reads <= (1 if self.mode == "existing" else 2)
        resolved = self.winner if ref == ALIAS else ref
        assert resolved in self.keys
        return {
            "KeyId": resolved,  # AWS GetPublicKey KeyId is the key ARN.
            "PublicKey": self.keys[resolved].public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "KeySpec": self.spec,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": [self.algorithm],
        }

    def create_key(self, **kwargs):
        self.call("create_key", kwargs, "create")
        assert kwargs == {"KeySpec": self.spec, "KeyUsage": "SIGN_VERIFY"}
        return {"KeyMetadata": {
            "Arn": CAND, "KeyId": CAND_ID,
            "KeySpec": self.spec, "KeyUsage": "SIGN_VERIFY",
        }}

    def create_alias(self, **kwargs):
        self.call("create_alias", kwargs, "alias")
        assert kwargs == {"AliasName": ALIAS, "TargetKeyId": CAND}
        if self.mode == "conflict":
            raise error(NativeAlreadyExists, "CreateAlias", "AlreadyExistsException")
        return {}

    def sign(self, **kwargs):
        self.call("sign", kwargs, "sign")
        assert kwargs == {
            "KeyId": self.winner, "Message": b"boto bootstrap proof",
            "SigningAlgorithm": self.algorithm, "MessageType": "RAW",
        }
        key = self.keys[self.winner]
        signature = (key.sign(kwargs["Message"], ec.ECDSA(hashes.SHA256()))
                     if self.algorithm == "ECDSA_SHA_256" else key.sign(kwargs["Message"]))
        return {"KeyId": self.winner, "Signature": signature,
                "SigningAlgorithm": self.algorithm}


def bootstrap(client):
    return create_or_reuse_aws_kms_key_provider(
        BotoKmsFacade(client), AwsKmsBootstrapConfig(ALIAS, client.algorithm)
    )


def assert_finite(client, created):
    operations = [name for name, _ in client.calls]
    assert operations.count("create_key") == created
    assert operations.count("create_alias") == created
    assert set(operations) <= {"get_public_key", "create_key", "create_alias", "sign"}
    assert client.alias_reads == (2 if created else 1)


@pytest.mark.parametrize("algorithm,spec,jose", ALGORITHMS)
@pytest.mark.parametrize("mode", ["existing", "missing", "conflict"])
def test_boto_public_bootstrap_winner_and_independent_signature(algorithm, spec, jose, mode):
    # Given independent cryptography keys, including a distinct losing candidate.
    client = NativeClient(algorithm, spec, mode)
    # When using the concrete adapter, not a facade-level double.
    result = bootstrap(client)
    provider = result.key_provider
    # Then native ARN identity and public thumbprint are distinct and consistent.
    assert result.key_ref == client.winner
    state = provider.state_snapshot()
    assert state.active_key_id == client.winner
    assert state.pending_key_ids == []
    assert state.retained_key_ids == []
    public = client.keys[client.winner].public_key()
    if jose == "ES256":
        numbers = public.public_numbers()
        material = {"kty": "EC", "crv": "P-256",
                    "x": b64(numbers.x.to_bytes(32, "big")),
                    "y": b64(numbers.y.to_bytes(32, "big"))}
    else:
        material = {"kty": "OKP", "crv": "Ed25519", "x": b64(public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))}
    thumbprint = b64(hashlib.sha256(json.dumps(
        material, sort_keys=True, separators=(",", ":")
    ).encode()).digest())
    jwk = provider.signing_key().to_dict()
    assert {k: jwk[k] for k in material} == material
    assert jwk["kid"] == thumbprint != result.key_ref
    assert jwk["alg"] == jose
    assert not {"d", "p", "q", "dp", "dq", "qi", "k"}.intersection(jwk)
    assert provider.list_key_ids() == [thumbprint]
    assert provider.jwk(thumbprint).to_dict() == jwk
    signature = provider.sign(b"boto bootstrap proof")
    assert len(signature) == 64
    if jose == "ES256":
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        public.verify(utils.encode_dss_signature(r, s), b"boto bootstrap proof",
                      ec.ECDSA(hashes.SHA256()))
    else:
        public.verify(signature, b"boto bootstrap proof")
    assert_finite(client, int(mode != "existing"))


def test_boto_exact_alias_request_and_native_exception_types():
    # Given the injected native exception namespace, when adapted, then identity holds.
    client = NativeClient(*ALGORITHMS[0][:2], mode="missing")
    facade = BotoKmsFacade(client)
    assert facade.not_found_exception is client.exceptions.NotFoundException
    assert facade.already_exists_exception is client.exceptions.AlreadyExistsException
    assert facade.create_alias(ALIAS, CAND) is None
    assert client.calls == [("create_alias", {"AliasName": ALIAS, "TargetKeyId": CAND})]


@pytest.mark.parametrize("algorithm,spec,jose", ALGORITHMS)
def test_boto_native_field_mapping_and_create_metadata_arn(algorithm, spec, jose):
    # Given AWS-native fields, then map them exactly; do not confuse ARN and UUID.
    client = NativeClient(algorithm, spec)
    facade = BotoKmsFacade(client)
    assert facade.create_signing_key(spec) == CAND != CAND_ID
    expected_spki = client.keys[WIN].public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert facade.get_public_key(WIN) == {
        "key_id": WIN, "public_key": expected_spki, "key_spec": spec,
        "key_usage": "SIGN_VERIFY", "signing_algorithms": [algorithm],
    }


# Same spelling and AWS error code do not make unrelated classes native types.
UnrelatedNotFound = type("NotFoundException", (ClientError,), {})
UnrelatedAlreadyExists = type("AlreadyExistsException", (ClientError,), {})
FAULTS = [
    ("initial", NativeDenied, "AccessDeniedException", "existing"),
    ("initial", UnrelatedNotFound, "NotFoundException", "existing"),
    ("create", NativeDenied, "AccessDeniedException", "missing"),
    ("alias", NativeDenied, "AccessDeniedException", "missing"),
    ("alias", UnrelatedAlreadyExists, "AlreadyExistsException", "missing"),
    ("winner", NativeNotFound, "NotFoundException", "conflict"),
    ("validation", NativeDenied, "AccessDeniedException", "existing"),
    ("sign", NativeDenied, "AccessDeniedException", "existing"),
]


@pytest.mark.parametrize("stage,cls,code,mode", FAULTS,
                         ids=[f"{stage}-{code}-{cls.__name__}" for stage, cls, code, _ in FAULTS])
def test_boto_native_and_unrelated_errors_propagate_identically(stage, cls, code, mode):
    # Given an exact injected error, when its stage runs, then it is not normalized.
    fault = error(cls, stage, code)
    client = NativeClient(*ALGORITHMS[0][:2], mode=mode, fault=(stage, fault))
    with pytest.raises(cls) as caught:
        result = bootstrap(client)
        if stage == "sign":
            result.key_provider.sign(b"boto bootstrap proof")
    assert caught.value is fault
    operations = [name for name, _ in client.calls]
    created = int(stage in {"alias", "winner"})
    assert operations.count("create_key") == created + int(stage == "create")
    assert operations.count("create_alias") == created
    assert client.alias_reads == (2 if stage == "winner" else 1)
    assert set(operations) <= {"get_public_key", "create_key", "create_alias", "sign"}
