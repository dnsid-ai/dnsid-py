"""Offline execution of the AWS setup consumer, not protocol issuance proof.

Shared KMS-first contract: explicit remote create, pending/local activation,
immutable reference reopen and public-only handoff; no local custody/files.
"""

import json
import runpy
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from dnsid import ArgumentError
from tests.test_kms_first_creation import (
    ARN,
    RemoteMaterial,
    assert_public,
    forbid_local_custody,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "aws-kms-first" / "main.py"
SETTINGS = {
    "AWS_REGION": "us-east-1",
    "DNSID_DOMAIN": "agent.example.com",
    "DNSID_GOVERNANCE_ID": "example.com",
    "DNSID_LOG_REF": "c2sp-tlog:public:https://log.example.com#instance-first",
    "DNSID_STATUS_URL": "https://agent.example.com/status",
    "DNSID_EK_URL": "https://example.com/jwks.json",
    "DNSID_KU_URL": "https://agent.example.com/jwks.json",
}


class BotoService(RemoteMaterial):
    """AWS-native-shaped boundary; private fixture stays behind service methods."""

    def __init__(self, failure=None):
        super().__init__()
        self.failure = failure
        self.signatures = []
        self.context_events = []

    def __enter__(self):
        self.context_events.append("enter")
        return self

    def __exit__(self, *exc):
        # This is application context management, not provider ownership.
        self.context_events.append("exit")

    def create_key(self, **request):
        self.calls.append(("create", request))
        assert request["KeySpec"] == "ECC_NIST_EDWARDS25519"
        assert request["KeyUsage"] == "SIGN_VERIFY"
        assert not self.created, "no automatic retry/recreate"
        self.created = True
        if self.failure == "create":
            raise PermissionError("indeterminate remote create")
        return {"KeyMetadata": {"Arn": ARN, "KeyId": ARN.rsplit("/", 1)[1]}}

    def get_public_key(self, **request):
        self.calls.append(("public", request))
        assert self.created and request == {"KeyId": ARN}
        if self.failure == "public":
            raise PermissionError("remote public read denied")
        return dict(KeyId=ARN, PublicKey=self.der, KeySpec="ECC_NIST_EDWARDS25519",
                    KeyUsage="SIGN_VERIFY", SigningAlgorithms=["ED25519_SHA_512"])

    def sign(self, **request):
        self.calls.append(("sign", request))
        assert request["KeyId"] == ARN
        assert request["MessageType"] == "RAW"
        assert request["SigningAlgorithm"] == "ED25519_SHA_512"
        payload = request["Message"]
        assert payload == b"DNSid AWS first-key example: pending possession only"
        signature = self.private.sign(payload)
        self.signatures.append((payload, signature))
        return dict(KeyId=ARN, Signature=signature, SigningAlgorithm="ED25519_SHA_512")


def prepare(monkeypatch, client):
    """Load actual example and replace only external boto/network dependencies."""
    boto3 = pytest.importorskip("boto3")

    main = runpy.run_path(str(EXAMPLE))["main"]
    for name, value in SETTINGS.items():
        monkeypatch.setenv(name, value)
    requests = []

    def factory(service, **kwargs):
        requests.append((service, kwargs))
        assert service == "kms" and kwargs == {"region_name": SETTINGS["AWS_REGION"]}
        return client

    def no_network(*args, **kwargs):
        pytest.fail("offline example must not perform discovery/publication/issuance network work")

    monkeypatch.setattr(boto3, "client", factory)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    return main, requests


def test_given_remote_key_when_example_runs_then_public_handoff_reopens_once(
    tmp_path, monkeypatch, capsys,
):
    """**Mode**: fake-only (native AWS and custody/network guards). GWT public handoff."""
    client = BotoService()
    main, requests = prepare(monkeypatch, client)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        main()  # Real BotoKmsFacade, provider, IdentityManager and get_key_set.
    output = capsys.readouterr()
    assert output.err == ""
    lines = output.out.splitlines()
    assert len(lines) == 5
    pending = json.loads(lines[0].removeprefix("pending public JWK: "))
    kid = assert_public(SimpleNamespace(to_dict=lambda: pending))
    assert json.loads(lines[1].removeprefix("pending state: ")) == {
        "active_key_id": "", "retained_key_ids": [], "pending_key_ids": [ARN],
    }
    assert lines[2] == "pending SignKey signature bytes: 64"
    assert json.loads(lines[3].removeprefix("application-owned state handoff: ")) == {
        "active_key_id": ARN, "retained_key_ids": [], "pending_key_ids": [],
    }
    jwks = json.loads(lines[4].removeprefix("public JWKS for the configured ku endpoint: "))
    assert jwks == {"keys": [pending]}
    assert jwks["keys"][0]["kid"] == kid
    assert len(requests) == 1
    assert [name for name, _ in client.calls] == ["create", "public", "sign", "public"]
    assert len(client.signatures) == 1
    for payload, signature in client.signatures:
        client.public.verify(signature, payload)
    assert client.context_events == ["enter", "exit"]
    assert list(tmp_path.iterdir()) == []
    # Output is fully accounted for above: no private material, status success,
    # entity issuance, DNS publication or protocol ACTIVE assertion is produced.


@pytest.mark.parametrize("missing", SETTINGS)
def test_given_missing_setting_when_example_runs_then_no_client_or_create(
    missing, tmp_path, monkeypatch, capsys,
):
    """**Mode**: fake-only. Given absent required env, when run, then fail before billing."""
    client = BotoService()
    main, requests = prepare(monkeypatch, client)
    monkeypatch.delenv(missing)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        with pytest.raises(KeyError) as caught:
            main()
    assert caught.value.args == (missing,)
    assert requests == [] and client.calls == [] and client.context_events == []
    assert capsys.readouterr().out == ""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("failure", ["create", "public"])
def test_given_remote_failure_when_example_runs_then_no_retry_fallback_or_files(
    failure, tmp_path, monkeypatch, capsys,
):
    """**Mode**: fake-only. Given ambiguous service failure, when run, then stop safely."""
    client = BotoService(failure)
    main, requests = prepare(monkeypatch, client)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        with pytest.raises((PermissionError, ArgumentError)):
            main()
    assert len(requests) == 1
    assert [name for name, _ in client.calls] == (
        ["create"] if failure == "create" else ["create", "public"]
    )
    assert client.context_events == ["enter", "exit"]
    assert capsys.readouterr().out == ""
    assert list(tmp_path.iterdir()) == []
