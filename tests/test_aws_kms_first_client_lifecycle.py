"""Offline real-boto lifecycle regression for the AWS first-key consumer.

Shared 01 KMS-first setup and the example's application-owned client lifetime;
AWS RPCs alone are fake, not BaseClient's context-management protocol.
"""

import json
import runpy
import socket

import pytest

from dnsid import ArgumentError
from tests.test_aws_kms_first_example import EXAMPLE, SETTINGS, BotoService
from tests.test_kms_first_creation import ARN, forbid_local_custody


@pytest.mark.parametrize("failure", [None, "create", "public"], ids=["success", "create-denied", "public-denied"])
def test_given_real_boto_client_when_setup_runs_then_native_client_is_closed(
    failure, tmp_path, monkeypatch, capsys,
):
    """**Mode**: fake-only AWS RPC; real boto factory, BaseClient and close lifecycle."""
    # Deny transport and credential discovery BEFORE importing boto or the example.
    def no_network(*args, **kwargs):
        pytest.fail("offline first-key consumer attempted network access")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket.socket, "connect_ex", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "functional-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "functional-test")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "functional-test")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "absent-credentials"))
    for name, value in SETTINGS.items():
        monkeypatch.setenv(name, value)

    pytest.importorskip("boto3")
    from botocore.client import BaseClient

    service = BotoService(failure)
    operations = []
    clients = []
    closed = []
    native_close = BaseClient.close

    def api_call(client, operation, params):
        assert isinstance(client, BaseClient)
        assert client.meta.service_model.service_name == "kms"
        if not clients:
            clients.append(client)
        assert client is clients[0]
        operations.append(operation)
        if operation == "CreateKey":
            return service.create_key(**params)
        if operation == "GetPublicKey":
            return service.get_public_key(**params)
        if operation == "Sign":
            return service.sign(**params)
        pytest.fail(f"unexpected AWS operation: {operation}")

    def close(client):
        # Observe, but still execute the real native resource cleanup.
        native_close(client)
        closed.append(client)

    monkeypatch.setattr(BaseClient, "_make_api_call", api_call)
    monkeypatch.setattr(BaseClient, "close", close)
    main = runpy.run_path(str(EXAMPLE))["main"]
    monkeypatch.chdir(tmp_path)
    caught = None
    with monkeypatch.context() as guard:
        forbid_local_custody(guard)
        try:
            main()
        except Exception as exc:  # Preserve the actual failure for an assertion-level red.
            caught = exc

    # No patched boto factory and no invented __enter__/__exit__ verdict.
    # On the broken example this fails with TypeError and zero CreateKey calls.
    assert not isinstance(caught, TypeError), (
        f"real boto client could not start setup: {caught!r}; AWS operations={operations!r}"
    )
    if failure is None:
        assert caught is None
        assert operations == ["CreateKey", "GetPublicKey", "Sign", "GetPublicKey"]
        lines = capsys.readouterr().out.splitlines()
        assert len(lines) == 5
        assert json.loads(lines[3].removeprefix("application-owned state handoff: ")) == {
            "active_key_id": ARN, "retained_key_ids": [], "pending_key_ids": [],
        }
    else:
        if failure == "public":
            assert isinstance(caught, ArgumentError)
            assert caught.__cause__ is service.public_failure
            assert isinstance(caught.__cause__, PermissionError)
            assert ARN in str(caught)
        else:
            assert isinstance(caught, PermissionError)
        assert operations == (["CreateKey"] if failure == "create" else ["CreateKey", "GetPublicKey"])
        assert capsys.readouterr().out == ""
    assert closed == clients and len(closed) == 1
    assert operations.count("CreateKey") == 1
    assert "ScheduleKeyDeletion" not in operations
    assert list(tmp_path.iterdir()) == []
