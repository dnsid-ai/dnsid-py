"""A2A example boundaries and cleanup; requires the optional example packages."""

import asyncio
import base64
import importlib
import importlib.util
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dnsid import ParseError, RegistryClient, VerificationCode, VerificationError


@pytest.fixture
def example(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("uvicorn")
    pytest.importorskip("a2a.types.a2a_pb2")
    directory = Path(__file__).parents[1] / "examples" / "a2a"
    monkeypatch.syspath_prepend(str(directory))
    return SimpleNamespace(
        server=importlib.import_module("server"),
        startup=importlib.import_module("startup"),
        directory=directory,
    )


def _scope(server):
    return {
        "type": "http", "method": "POST", "scheme": "https", "path": "/",
        "headers": [
            (b"host", b"bob.test"),
            (b"a2a-version", server.A2A_VERSION.encode()),
            (b"a2a-extensions", server.DNSID_A2A_EXTENSION_URI.encode()),
        ],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("sizes", [[8 * 1024 * 1024 + 1], [4 * 1024 * 1024, 4 * 1024 * 1024, 1]])
async def test_oversized_bodies_are_rejected_before_verification(example, sizes):
    server = example.server
    app, verifier, send = AsyncMock(), SimpleNamespace(async_verify_signed_http_request=AsyncMock()), AsyncMock()
    messages = [{"type": "http.request", "body": b"x" * size, "more_body": True} for size in sizes]
    receive = AsyncMock(side_effect=messages + [AssertionError("read past limit")])
    middleware = server._DnsidSignatureMiddleware(app, SimpleNamespace(local_domain="bob.test"), verifier)
    await middleware(_scope(server), receive, send)
    assert send.await_args_list[0].args[0]["status"] == 413
    assert receive.await_count == len(sizes)
    verifier.async_verify_signed_http_request.assert_not_awaited()
    app.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [0, 8 * 1024 * 1024])
async def test_bounded_bodies_are_verified_and_replayed(example, size):
    server, body = example.server, b"x" * size
    verifier = SimpleNamespace(async_verify_signed_http_request=AsyncMock(
        return_value=SimpleNamespace(domain="alice.test")
    ))
    receive = AsyncMock(return_value={"type": "http.request", "body": body, "more_body": False})

    async def app(scope, receive, send):
        assert scope["_dnsid_sender"].user_name == "alice.test"
        assert (await receive())["body"] == body
        assert (await receive())["type"] == "http.disconnect"

    await server._DnsidSignatureMiddleware(app, SimpleNamespace(local_domain="bob.test"), verifier)(
        _scope(server), receive, AsyncMock()
    )
    request, options = verifier.async_verify_signed_http_request.await_args.args
    assert request.body == body
    assert options is server._VERIFY_OPTS


@pytest.mark.asyncio
async def test_disconnected_body_never_verifies(example):
    server, app = example.server, AsyncMock()
    verifier = SimpleNamespace(async_verify_signed_http_request=AsyncMock())
    receive = AsyncMock(return_value={"type": "http.disconnect"})
    await server._DnsidSignatureMiddleware(app, SimpleNamespace(local_domain="bob.test"), verifier)(
        _scope(server), receive, AsyncMock()
    )
    verifier.async_verify_signed_http_request.assert_not_awaited()
    app.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("error,expected", [
    (VerificationError(VerificationCode.STATUS_UNAVAILABLE, "outage", transient=True), 503),
    (VerificationError(VerificationCode.DEADLINE_EXCEEDED, "timeout", transient=True), 503),
    (VerificationError(VerificationCode.SIGNATURE_INVALID, "invalid"), 401),
    (VerificationError(VerificationCode.COUNTERPARTY_NOT_ACCEPTED, "denied"), 403),
    (ParseError("malformed signature"), 401),
])
async def test_verification_error_responses_preserve_retry_semantics(example, error, expected):
    server, app, send = example.server, AsyncMock(), AsyncMock()
    verifier = SimpleNamespace(async_verify_signed_http_request=AsyncMock(side_effect=error))
    receive = AsyncMock(return_value={"type": "http.request", "body": b"{}", "more_body": False})
    await server._DnsidSignatureMiddleware(app, SimpleNamespace(local_domain="bob.test"), verifier)(
        _scope(server), receive, send
    )
    assert send.await_args_list[0].args[0]["status"] == expected
    app.assert_not_awaited()


@pytest.mark.asyncio
async def test_unexpected_errors_are_not_reported_as_authentication_failures(example):
    server = example.server
    verifier = SimpleNamespace(async_verify_signed_http_request=AsyncMock(side_effect=RuntimeError("bug")))
    receive = AsyncMock(return_value={"type": "http.request", "body": b"{}", "more_body": False})
    with pytest.raises(RuntimeError, match="bug"):
        await server._DnsidSignatureMiddleware(AsyncMock(), SimpleNamespace(local_domain="bob.test"), verifier)(
            _scope(server), receive, AsyncMock()
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_challenge_signing_is_offloaded(example, fails):
    startup = example.startup
    started, release = threading.Event(), threading.Event()
    loop_thread = threading.get_ident()
    key_provider, registry = MagicMock(), MagicMock()
    registry.async_get_agent_status = AsyncMock(side_effect=[
        SimpleNamespace(failed=False, terminal=False, raw={"challenge": base64.urlsafe_b64encode(b"nonce").decode()}),
        SimpleNamespace(failed=False, terminal=False, ready_for_publication=True),
    ])
    registry.async_submit_challenge_signature = AsyncMock()

    def sign(payload):
        assert threading.get_ident() != loop_thread
        assert payload == b"nonce"
        started.set()
        assert release.wait(2)
        if fails:
            raise RuntimeError("KMS failed")
        return b"signature"

    key_provider.sign.side_effect = sign
    task = asyncio.create_task(startup._verify_with_challenge(
        key_provider, registry, "bob.test", SimpleNamespace(registry_status="VERIFICATION")
    ))
    try:
        async with asyncio.timeout(2):
            while not started.is_set():
                await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
    if fails:
        with pytest.raises(RuntimeError, match="KMS failed"):
            await task
        registry.async_submit_challenge_signature.assert_not_awaited()
    else:
        await task
        assert registry.async_submit_challenge_signature.await_args.args[2] == b"signature"


@pytest.mark.asyncio
async def test_registration_uses_native_registry_calls(example):
    registry = MagicMock(spec=RegistryClient)
    registry.async_get_agent_status.side_effect = [
        None, SimpleNamespace(published=True, ready_for_publication=False, registry_status="ACTIVE"),
    ]
    manager = MagicMock()
    manager.local_domain = "bob.test"
    manager.config.identity.capabilities_url = "https://bob.test/card"
    with patch.object(asyncio.get_running_loop(), "run_in_executor",
                      side_effect=AssertionError("unexpected worker")):
        await example.startup._register_and_publish(manager, MagicMock(), registry)
    registry.async_register_agent.assert_awaited_once()
    assert registry.async_register_agent.await_args.args[0].domain == "bob.test"
    registry.register_agent.assert_not_called()
    registry.get_agent_status.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_cancelled_startup_operation_is_drained_before_cleanup(example, fails):
    started, release = threading.Event(), threading.Event()

    def blocking():
        started.set()
        assert release.wait(2)
        if fails:
            raise RuntimeError("late failure")

    task = asyncio.create_task(example.startup._run_blocking(blocking))
    try:
        async with asyncio.timeout(2):
            while not started.is_set():
                await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["create", "start", "registration", "self_verify", "success"])
async def test_startup_resources_are_closed_on_failure_and_shutdown(example, monkeypatch, stage):
    startup, calls = example.startup, []
    manager = MagicMock()
    manager.local_domain, manager.key_provider = "bob.test", MagicMock()
    manager.__aenter__ = AsyncMock(return_value=manager)
    manager.__aexit__ = AsyncMock(side_effect=lambda *args: calls.append("manager"))
    agent = SimpleNamespace(
        url="https://bob.test", start=AsyncMock(),
        stop=AsyncMock(side_effect=lambda: calls.append("agent")),
    )
    registry = MagicMock()
    registry.__aenter__ = AsyncMock(return_value=registry)
    registry.__aexit__ = AsyncMock(side_effect=lambda *args: calls.append("registry"))
    create, register, poll = AsyncMock(return_value=agent), AsyncMock(), AsyncMock()
    failure = RuntimeError(stage)
    if stage == "create":
        create.side_effect = failure
    elif stage == "start":
        agent.start.side_effect = failure
    elif stage == "registration":
        register.side_effect = failure
    elif stage == "self_verify":
        poll.side_effect = failure
    monkeypatch.setenv("DNSID_AGENT_PORT", "3002")
    monkeypatch.setenv("DNSID_API_KEY", "example-secret")
    loaded = SimpleNamespace(dnsid=SimpleNamespace(identity=SimpleNamespace(capabilities_url="https://bob.test/card")))
    monkeypatch.setattr(startup, "load_environment", lambda: loaded)
    monkeypatch.setattr(startup, "merge_loaded_config", lambda *args: loaded)
    monkeypatch.setattr(startup, "construct_identity_manager", lambda *args: manager)
    monkeypatch.setattr(startup.EchoAgent, "create", create)
    monkeypatch.setattr(startup, "echo_executor", lambda *args: None)
    monkeypatch.setattr(startup, "registry_client_from_environment", lambda: registry)
    monkeypatch.setattr(startup, "_register_and_publish", register)
    monkeypatch.setattr(startup, "poll", poll)
    monkeypatch.setattr(startup, "asyncio", SimpleNamespace(sleep=AsyncMock()))
    if stage == "success":
        idm, returned_agent, stop = await startup.start_echo_agent()
        assert idm is manager and returned_agent is agent
        assert calls == ["registry"]
        await stop()
        await stop()
    else:
        with pytest.raises(RuntimeError, match=stage):
            await startup.start_echo_agent()
    assert calls[-1] == "manager"
    assert calls.count("manager") == 1
    assert calls.count("agent") == (stage != "create")
    assert calls.count("registry") == (stage not in ("create", "start"))


@pytest.mark.asyncio
async def test_main_closes_resources_after_send_failure(example, monkeypatch):
    spec = importlib.util.spec_from_file_location("_a2a_example_main", example.directory / "main.py")
    main = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main)
    stop = AsyncMock()
    monkeypatch.setattr(main, "start_echo_agent", AsyncMock(return_value=(object(), object(), stop)))
    monkeypatch.setattr(main, "send_hello", AsyncMock(side_effect=RuntimeError("send failed")))
    monkeypatch.setattr(main.sys, "argv", ["main.py", "bob.test"])
    with pytest.raises(RuntimeError, match="send failed"):
        await main.main()
    stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_agent_drains_server_before_clients_and_closes_all_clients_on_error(example):
    server, order = example.server, []
    agent = server.EchoAgent(None, None, None, 3002, None, None)

    async def serve():
        order.append("server")

    agent._serve_task = asyncio.create_task(serve())
    first, second = SimpleNamespace(aclose=AsyncMock()), SimpleNamespace(aclose=AsyncMock())
    first.aclose.side_effect = lambda: order.append("first")
    second.aclose.side_effect = RuntimeError("close failed")
    agent._clients = {"first": first, "second": second}
    with pytest.raises(RuntimeError, match="close failed"):
        await agent.stop()
    assert order == ["server", "first"]
    first.aclose.assert_awaited_once()
    second.aclose.assert_awaited_once()
    assert not agent._clients
