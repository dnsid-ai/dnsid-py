"""AWS config-open proof: real factory/provider/native facade and verification.

Shared design 12; fake-only AWS RPC and existing publication/log-fetch boundaries.
No creation, rotation, issuance orchestration, or application recovery claim.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("botocore")

from botocore.client import BaseClient
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from dnsid import ValidationError, identity_manager_from_file
from dnsid._utils import b64url_decode
from tests._kms_publication import SEED, checked_profile, publication

A = "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-4111-8111-111111111111"
B = "arn:aws:kms:us-east-1:111122223333:key/22222222-2222-4222-8222-222222222222"


@pytest.mark.parametrize("mode", ["existing A", "selected B", "read denied"])
def test_aws_config_open_functional(tmp_path, monkeypatch, mode):
    """Open exact A, reject B/publication A, or propagate denied public read."""
    # Shared cloud-neutral consumer publication helper: independent signed A,
    # real C2SP verification, DNS record/status/JWKS checks, and JOSE verification.
    evidence = publication(tmp_path, key_source={"provider": "aws-kms", "keyRef": A})
    keys = {
        A: Ed25519PrivateKey.from_private_bytes(SEED),
        B: Ed25519PrivateKey.from_private_bytes(bytes([29]) * 32),
    }
    selected = B if mode == "selected B" else A
    calls = []
    denied = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "fixture public read denied"}},
        "GetPublicKey",
    )

    def api_call(client, operation, params):
        assert client.meta.service_model.service_name == "kms"
        calls.append((operation, params.copy()))
        if operation == "GetPublicKey":
            assert params == {"KeyId": selected}
            if mode == "read denied":
                raise denied
            return {
                "KeyId": selected,
                "PublicKey": keys[selected].public_key().public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                ),
                "KeySpec": "ECC_NIST_EDWARDS25519",
                "KeyUsage": "SIGN_VERIFY",
                "SigningAlgorithms": ["ED25519_SHA_512"],
            }
        if operation == "Sign":
            assert params["KeyId"] == A
            assert params["SigningAlgorithm"] == "ED25519_SHA_512"
            assert params["MessageType"] == "RAW"
            return {
                "KeyId": A,
                "Signature": keys[A].sign(params["Message"]),
                "SigningAlgorithm": "ED25519_SHA_512",
            }
        pytest.fail(f"unexpected AWS operation: {operation}")

    # Real boto client and own BotoKmsFacade remain intact. Ambient test-only
    # credentials prevent metadata/credential discovery outside the RPC seam.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "functional-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "functional-test")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(BaseClient, "_make_api_call", api_call)
    document = json.loads(evidence.path.read_text())
    document["keySource"] = {
        "provider": "aws-kms", "keyRef": selected,
        "settings": {"region": "us-east-1", "algorithm": "EdDSA"},
    }
    evidence.path.write_text(json.dumps(document))
    before = evidence.path.read_bytes()

    if mode == "existing A":
        with identity_manager_from_file(evidence.path, deps=evidence.deps) as manager:
            assert manager.key_provider.signing_key().to_dict() == evidence.key.to_dict()
            observed = manager.verify_local_publication()
            assert observed.domain == "agent.example" and observed.jwks.keys == [evidence.key]
            token = checked_profile(manager)
            header, body, signature = token.split(".")
            # Independent cryptography verification, not the provider's verdict.
            keys[A].public_key().verify(
                b64url_decode(signature), f"{header}.{body}".encode("ascii")
            )
            assert evidence.calls and evidence.resources.calls
            assert any(operation == "Sign" for operation, _ in calls)
    elif mode == "selected B":
        with pytest.raises(ValidationError, match="configured signer does not match local publication"):
            identity_manager_from_file(evidence.path, deps=evidence.deps)
        assert evidence.calls and evidence.resources.calls
        assert calls == [("GetPublicKey", {"KeyId": B})]
    else:
        with pytest.raises(ClientError) as caught:
            identity_manager_from_file(evidence.path, deps=evidence.deps)
        assert caught.value is denied
        assert calls == [("GetPublicKey", {"KeyId": A})]
        assert evidence.calls == [] and evidence.resources.calls == []

    assert all(operation in {"GetPublicKey", "Sign"} for operation, _ in calls)
    assert sum(operation == "CreateKey" for operation, _ in calls) == 0
    assert {params["KeyId"] for _, params in calls} == {selected}
    assert evidence.path.read_bytes() == before


@pytest.mark.parametrize("fault,boundary", [
    (fault, boundary)
    for fault in ("AccessDeniedException", "DisabledException", "NotFoundException", "KMSInternalException")
    for boundary in ("open", "sign")
    if (fault, boundary) != ("AccessDeniedException", "open")  # existing config-open denial
])
def test_existing_key_faults_fail_closed(tmp_path, monkeypatch, fault, boundary):
    """**Mode**: fake-only. Given exact ARN, When RPC fails, Then no result/replacement."""
    import boto3

    from dnsid import AwsKmsConfig, AwsKmsKeyProvider
    from dnsid.aws_kms_key_provider import BotoKmsFacade

    key = Ed25519PrivateKey.from_private_bytes(SEED)
    calls = []
    failure = ClientError({"Error": {"Code": fault, "Message": f"{fault} selected {A}"}},
                          "GetPublicKey" if boundary == "open" else "Sign")

    def rpc(client, operation, params):
        # Record BEFORE raising, including every forbidden native operation.
        calls.append((operation, params.copy()))
        if operation == "GetPublicKey":
            if boundary == "open":
                raise failure
            return {"KeyId": A, "PublicKey": key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
                    "KeySpec": "ECC_NIST_EDWARDS25519", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": ["ED25519_SHA_512"]}
        if operation == "Sign":
            raise failure
        raise AssertionError(f"forbidden AWS operation {operation}")

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(BaseClient, "_make_api_call", rpc)
    native = boto3.client("kms", region_name="us-east-1", aws_access_key_id="fixture", aws_secret_access_key="fixture")
    before = list(tmp_path.iterdir())
    try:
        def load():
            return AwsKmsKeyProvider.load(BotoKmsFacade(native), AwsKmsConfig(active_key_id=A, algorithm="ED25519_SHA_512"))
        if boundary == "open":
            result = None
            with pytest.raises(ClientError) as caught:
                result = load()
            assert result is None
            # Narrow characterization of this native seam, not a universal
            # public promise about how all provider failures are represented.
            assert caught.value is failure
        else:
            signer = load()
            public = signer.signing_key().to_dict()
            ids = signer.list_key_ids()
            assert public["crv"] == "Ed25519" and ids == [public["kid"]]
            signature = None
            with pytest.raises(ClientError) as caught:
                signature = signer.sign(b"must not return a signature")
            assert signature is None
            assert caught.value is failure
            assert signer.signing_key().to_dict() == public
            assert signer.list_key_ids() == ids
        assert [operation for operation, _ in calls] == (["GetPublicKey"] if boundary == "open" else ["GetPublicKey", "Sign"])
        assert all(params["KeyId"] == A for _, params in calls)
        assert sum(operation not in {"GetPublicKey", "Sign"} for operation, _ in calls) == 0
        assert list(tmp_path.iterdir()) == before
    finally:
        native.close()
