"""Independent offline proof for GCP setup consumer and first-version readiness."""

import json
import runpy
import socket
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from google.cloud import kms_v1

from dnsid import ArgumentError, GoogleKmsKeyProvider
from tests.test_aws_kms_first_example import SETTINGS
from tests.test_google_kms_runtime_contract import crc32c
from tests.test_kms_first_creation import (
    PARENT,
    VERSION,
    FirstVersionService,
    assert_inactive,
    assert_public,
    forbid_local_custody,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "gcp-kms-first" / "main.py"
STATE = kms_v1.CryptoKeyVersion.CryptoKeyVersionState
ENV = {name: value for name, value in SETTINGS.items() if name != "AWS_REGION"}
ENV["GOOGLE_KMS_CRYPTO_KEY"] = PARENT


class ExampleService(FirstVersionService):
    def __init__(self, fault=None):
        super().__init__(fault)
        self.context_events = []
        self.signatures = []

    def __enter__(self):
        self.context_events.append("enter")
        return self

    def __exit__(self, *exc):
        self.context_events.append("exit")

    def asymmetric_sign(self, request):
        self.calls.append(("sign", request["name"]))
        assert self.created and request["name"] == VERSION
        payload = request["data"]
        assert payload == b"DNSid Google first-key example: pending possession only"
        assert "digest" not in request and request["data_crc32c"] == crc32c(payload)
        signature = self.private.sign(payload)
        self.signatures.append((payload, signature))
        return SimpleNamespace(name=VERSION, signature=signature,
                               signature_crc32c=crc32c(signature), verified_data_crc32c=True)


def prepare_example(monkeypatch, client):
    main = runpy.run_path(str(EXAMPLE))["main"]
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    constructions = []

    def factory():
        constructions.append(True)
        return client

    def no_network(*args, **kwargs):
        pytest.fail("offline setup must not perform publication/issuance network work")

    monkeypatch.setattr(kms_v1, "KeyManagementServiceClient", factory)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    return main, constructions


def test_given_versionless_parent_when_example_runs_then_public_handoff_only(
    tmp_path, monkeypatch, capsys,
):
    """**Mode**: fake-only. Given native fake, when actual main runs, then exact public JWKS."""
    client = ExampleService()
    main, constructions = prepare_example(monkeypatch, client)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        main()  # Actual provider.create/SignKey/activate/reopen/manager.get_key_set.
    output = capsys.readouterr()
    assert output.err == ""
    lines = output.out.splitlines()
    assert len(lines) == 4
    pending = json.loads(lines[0].removeprefix("pending public JWK: "))
    assert_public(SimpleNamespace(to_dict=lambda: pending))
    assert lines[1] == "pending SignKey signature bytes: 64"
    assert lines[2] == "application-owned immutable version handoff: " + VERSION
    assert json.loads(lines[3].removeprefix("public JWKS for the configured ku endpoint: ")) == {
        "keys": [pending],
    }
    assert constructions == [True]
    assert client.calls == [
        ("parent", PARENT), ("create", PARENT), ("public", VERSION),
        ("sign", VERSION), ("public", VERSION),
    ]
    assert len(client.signatures) == 1
    for payload, signature in client.signatures:
        client.public.verify(signature, payload)
    assert client.context_events == ["enter", "exit"]
    assert not client.closed  # Provider never owns injected client.
    assert list(tmp_path.iterdir()) == []
    # Entire output accounted for: public handoff is not protocol ACTIVE/issuance.


@pytest.mark.parametrize("missing", ENV)
def test_given_missing_env_when_google_example_runs_then_no_client_or_create(
    missing, tmp_path, monkeypatch, capsys,
):
    """**Mode**: fake-only. Given missing required setting, when run, then fail before create."""
    client = ExampleService()
    main, constructions = prepare_example(monkeypatch, client)
    monkeypatch.delenv(missing)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        with pytest.raises(KeyError) as caught:
            main()
    assert caught.value.args == (missing,)
    assert constructions == [] and client.calls == [] and client.context_events == []
    assert capsys.readouterr().out == ""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("fault", ["denied", "public_unavailable"])
def test_given_remote_failure_when_google_example_runs_then_no_retry_or_files(
    fault, tmp_path, monkeypatch, capsys,
):
    """**Mode**: fake-only. Given service failure, when run, then no fallback/partial output."""
    client = ExampleService(fault)
    main, constructions = prepare_example(monkeypatch, client)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        with pytest.raises((PermissionError, ArgumentError, ValueError)):
            main()
    assert constructions == [True]
    assert sum(name == "create" for name, _ in client.calls) == 1
    assert all(name != "sign" for name, _ in client.calls)
    assert client.context_events == ["enter", "exit"] and not client.closed
    assert capsys.readouterr().out == ""
    assert list(tmp_path.iterdir()) == []


class ReadinessService(FirstVersionService):
    """Native service state machine, not SDK verdicts; immutable version throughout."""

    def __init__(self, outcome):
        super().__init__()
        self.outcome = outcome
        self.polls = 0

    def create_crypto_key_version(self, request):
        response = super().create_crypto_key_version(request)
        response.state = STATE.PENDING_GENERATION
        return response

    def get_crypto_key_version(self, request, **options):
        self.calls.append(("poll", request["name"]))
        self.polls += 1
        assert request["name"] == VERSION
        assert self.polls <= 100, "readiness must be finite, without duplicate create"
        if self.outcome == "permission":
            raise PermissionError("version metadata access denied")
        fields = dict(name=VERSION, algorithm=40, protection_level=1,
                      state=STATE.ENABLED if self.polls > 1 else STATE.PENDING_GENERATION)
        if self.outcome == "timeout":
            fields["state"] = STATE.PENDING_GENERATION
        elif self.outcome == "terminal":
            fields["state"] = STATE.DESTROYED
        elif self.outcome == "rebound":
            fields["name"] = VERSION + "0"
        elif self.outcome == "algorithm":
            fields["algorithm"] = 12
        elif self.outcome == "protection":
            fields["protection_level"] = 2
        elif self.outcome == "malformed":
            # Native protobuf omitted scalar fields read as their default value.
            fields["name"] = ""
        return SimpleNamespace(**fields)


def virtual_time(monkeypatch):
    """Replace time dependency, not provider helpers; never wait ten real seconds."""
    now = [0.0]
    sleeps = []

    def monotonic():
        now[0] += 0.05
        return now[0]

    def sleep(delay):
        assert delay >= 0
        sleeps.append(delay)
        now[0] += delay

    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(time, "sleep", sleep)
    return now, sleeps


def test_given_generating_version_when_ready_then_same_pending_identity(
    tmp_path, monkeypatch,
):
    """**Mode**: fake-only. Given PENDING_GENERATION, when ENABLED, then still local pending."""
    client = ReadinessService("ready")
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        virtual_time(guard)
        forbid_local_custody(guard)
        provider, kid, reference = GoogleKmsKeyProvider.create(client, PARENT)
        assert reference == VERSION and kid == assert_public(provider.jwk(kid))
        assert client.polls >= 2
        assert_inactive(provider, client)
        payload = b"first operational signing, not a prehashed digest"
        client.public.verify(provider.sign_key(kid, payload), payload)
        provider.activate(kid)
        client.public.verify(provider.sign(payload), payload)
        reopened = GoogleKmsKeyProvider(client, reference)
        assert assert_public(reopened.signing_key()) == kid
        assert sum(name == "create" for name, _ in client.calls) == 1
        assert all(ref == VERSION for name, ref in client.calls if name in ("poll", "public"))
        assert not client.closed
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("outcome", [
    "timeout", "terminal", "rebound", "algorithm", "protection", "malformed", "permission",
])
def test_given_readiness_failure_when_creating_then_no_usable_provider_or_recreate(
    outcome, tmp_path, monkeypatch,
):
    """**Mode**: fake-only. Given failed readiness, when creating, then bounded fail closed."""
    client = ReadinessService(outcome)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as guard:
        now, sleeps = virtual_time(guard)
        forbid_local_custody(guard)
        with pytest.raises((ArgumentError, ValueError, PermissionError, TimeoutError)):
            GoogleKmsKeyProvider.create(client, PARENT)
        assert 1 <= client.polls <= 100
        assert sum(name == "create" for name, _ in client.calls) == 1
        assert all(name not in ("public", "sign") for name, _ in client.calls)
        assert not client.closed
        if outcome == "timeout":
            assert now[0] > 0 and sleeps, "exercise waiting budget, not immediate rejection"
    assert list(tmp_path.iterdir()) == []
