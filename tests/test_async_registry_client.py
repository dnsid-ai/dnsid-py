"""Native registry I/O retains the synchronous workflow and security contracts."""

import asyncio
import gzip
import hashlib
import inspect
import json
import threading
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dnsid import (
    AgentRegistrationInput,
    ArgumentError,
    DNSidError,
    KeyRotationPreparationRequest,
    LiveAgentRegistrationInput,
    LiveProofReissueRequest,
    LiveProofRequest,
    RegistryClient,
    RegistryRevocationReason,
    VerificationCode,
    VerificationError,
    verification_budget,
)
from tests.test_async_https_client import _Chunks
from tests.test_registry_client import (
    _DOMAIN,
    _FAKE_API_KEY,
    _REGISTER_RESPONSE,
    _VALID_CANONICAL,
    _live_challenge_response,
    _live_key,
)

_KEY = _live_key()
_ENTRY = b'{"event":"signed"}'
_OPERATIONS = [
    ("register_agent", (AgentRegistrationInput(domain=_DOMAIN), "create-1")),
    ("register_live_agent", (LiveAgentRegistrationInput(public_key_jwk=_KEY), "live-1")),
    ("verify_agent", (_DOMAIN,)),
    ("revoke_agent", (_DOMAIN, "agent-123", RegistryRevocationReason.KEY_COMPROMISE)),
    ("retire_agent", (_DOMAIN, "agent-123")),
    ("cancel_agent", (_DOMAIN,)),
    ("submit_challenge_signature", (_DOMAIN, "nonce", b"signature")),
    ("submit_live_proof", (_DOMAIN, LiveProofRequest("live-1", "challenge", _KEY, "sig"))),
    ("reissue_live_proof", (_DOMAIN, LiveProofReissueRequest("live-1", _KEY))),
    ("get_status", (_DOMAIN,)),
    ("get_agent_status", (_DOMAIN,)),
    ("get_organization_onboarding", ()),
    ("get_registration", (_DOMAIN,)),
    ("get_agent_detail", (_DOMAIN,)),
    ("unregister_agent", (_DOMAIN,)),
    ("canonical_record_content", (_DOMAIN, "kid-1")),
    ("publish_signature", (_DOMAIN, "signature")),
    ("prepare_issuance", (_DOMAIN, "issue-1")),
    ("prepare_key_rotation", (_DOMAIN, KeyRotationPreparationRequest("old", _KEY), "rotate-1")),
    ("submit_prepared_event", (_DOMAIN, _ENTRY, "append-1")),
]


def _response(request):
    path = request.url.path
    if path == "/api/v1/org/onboarding":
        return httpx.Response(200, json={"org_id": "org-1"})
    if request.method == "GET":
        return httpx.Response(200, json={**_REGISTER_RESPONSE, "managed": "self", "dns_published": True})
    if path == "/api/v1/agent":
        if json.loads(request.content).get("tier") == "live":
            return httpx.Response(202, json=_live_challenge_response(_KEY))
        return httpx.Response(201, json=_REGISTER_RESPONSE)
    if path.endswith("/proof/reissue"):
        return httpx.Response(202, json=_live_challenge_response(_KEY, domain=_DOMAIN))
    if path.endswith("/proof"):
        return httpx.Response(202, json={"request_id": "live-1", "agent_id": "agent-123", "status": "pending"})
    if path.endswith("/record"):
        return httpx.Response(200, json={"canonicalContent": _VALID_CANONICAL, "signingKid": "kid-1"})
    if path.endswith("/prepare"):
        return httpx.Response(200, content=_ENTRY, headers={"DNSID-Log-Reference": "c2sp-tlog:testnet:https://log.example#agent.example.com"})
    if path.endswith("/events"):
        return httpx.Response(200, json={"state": "accepted", "entryHash": hashlib.sha256(_ENTRY).hexdigest()})
    return httpx.Response(200, json={"id": "agent-123", "status": "VERIFIED"})


@pytest.mark.asyncio
@pytest.mark.parametrize("method,args", _OPERATIONS)
async def test_native_operations_match_sync_without_workers(method, args):
    calls = []
    loop_thread = threading.get_ident()

    def handle(request):
        calls.append((request.method, str(request.url), request.content, dict(request.headers)))
        assert request.headers["Authorization"] == f"Bearer {_FAKE_API_KEY}"
        return _response(request)

    async def async_handle(request):
        assert threading.get_ident() == loop_thread
        await asyncio.sleep(0)
        return handle(request)

    with RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY) as sync:
        sync._http_client = httpx.Client(transport=httpx.MockTransport(handle), trust_env=False)
        expected = getattr(sync, method)(*args)
    sync_calls = list(calls)
    calls.clear()
    async with RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY) as native:
        with (
            patch("dnsid.safe_transport.make_ssrf_safe_async_transport", return_value=httpx.MockTransport(async_handle)),
            patch.object(native, "_http_request", side_effect=AssertionError("sync HTTP")),
            patch.object(asyncio.get_running_loop(), "run_in_executor", side_effect=AssertionError("worker")),
        ):
            actual = await getattr(native, "async_" + method)(*args)
    assert actual == expected
    assert calls == sync_calls
    assert inspect.signature(getattr(RegistryClient, method)) == inspect.signature(
        getattr(RegistryClient, "async_" + method)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("method,args", _OPERATIONS)
async def test_errors_and_indeterminate_submissions_match_sync(method, args):
    def fail(request):
        raise httpx.ConnectError(f"failed with Bearer {_FAKE_API_KEY}")

    def outcome(call):
        try:
            return call()
        except VerificationError as error:
            return type(error), str(error), error.transient, error.registration_request

    with RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY) as sync:
        sync._http_client = httpx.Client(transport=httpx.MockTransport(fail))
        expected = outcome(lambda: getattr(sync, method)(*args))
    async with RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY) as native:
        native._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(fail))
        try:
            actual = await getattr(native, "async_" + method)(*args)
        except VerificationError as error:
            actual = type(error), str(error), error.transient, error.registration_request
            assert _FAKE_API_KEY not in str(error)
            assert error.__cause__ is None
            assert error.__context__ is None or error.__suppress_context__
    assert actual == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("method,args", [op for op in _OPERATIONS if op[0] not in {"get_status", "get_agent_status"}])
async def test_hosted_credentials_checked_before_io(method, args):
    async with RegistryClient("https://registry.example.com") as client:
        with patch.object(client, "_async_http_request", side_effect=AssertionError("unexpected I/O")):
            with pytest.raises(ArgumentError, match="requires registry credentials"):
                await getattr(client, "async_" + method)(*args)


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[], {"domain": "other.example", "status": "READY", "managed": "self"}, {"status": "READY"}])
async def test_invalid_registration_responses_fail_closed(payload):
    async with RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY) as client:
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=payload)
        ))
        with pytest.raises(DNSidError):
            await client.async_get_registration(_DOMAIN)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [302, 401, 409, 503])
async def test_http_errors_do_not_follow_redirects_retry_or_expose_credentials(status):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(status, json={"error": "DENIED", "detail": _FAKE_API_KEY}, headers={"location": "https://other.example"})

    async with RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY) as client:
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        with pytest.raises(VerificationError) as error:
            await client.async_register_agent(AgentRegistrationInput(domain=_DOMAIN), "create-1")
        assert _FAKE_API_KEY not in str(error.value)
        assert error.value.registration_idempotency_key == "create-1"
        assert error.value.registration_request == {"domain": _DOMAIN}
        assert error.value.transient == (status >= 500)
    assert len(requests) == 1
    assert requests[0].headers["Idempotency-Key"] == "create-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("compressed", [False, True])
async def test_decoded_response_limit_closes_stream(compressed):
    body = b"x" * (4 * 1024 * 1024 + 1)
    stream = _Chunks([gzip.compress(body) if compressed else body, b"unread"])
    async with RegistryClient() as client:
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream, headers={"content-encoding": "gzip"} if compressed else {})
        ))
        with pytest.raises(VerificationError, match="resource limit"):
            await client.async_get_status(_DOMAIN)
    assert stream.closed
    assert stream.yielded == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("target,settled", [(None, "ACTIVE"), ("VERIFIED", "VERIFIED")])
async def test_polling_uses_native_reads_until_published_or_target(target, settled):
    states = iter(["PENDING", settled])
    requests = []

    async def handle(request):
        requests.append(request)
        await asyncio.sleep(0)
        state = next(states)
        return httpx.Response(200, json={"status": state, "dns_published": state == "ACTIVE"})

    async with RegistryClient() as client:
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        with patch.object(asyncio.get_running_loop(), "run_in_executor",
                          side_effect=AssertionError("worker")):
            result = await client.async_wait_for_status(_DOMAIN, interval=0, target_state=target)
    assert result.registry_status == settled
    assert len(requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline", [False, True])
async def test_polling_yields_and_interrupts_inflight_reads(deadline):
    started = asyncio.Event()

    class Stream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            started.set()
            await asyncio.Event().wait()
            yield b"unreachable"

        async def aclose(self):
            self.closed = True

    stream = Stream()
    async with RegistryClient() as client:
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream)
        ))
        async def poll():
            with verification_budget(0.05 if deadline else 2):
                return await client.async_wait_for_status(_DOMAIN)

        task = asyncio.create_task(poll())
        await asyncio.wait_for(started.wait(), 1)
        assert not task.done()
        if deadline:
            with pytest.raises(VerificationError) as error:
                await task
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
        else:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(404, None), (200, "ACTIVE")])
async def test_status_reads_reuse_one_protected_pool_and_close(status, expected):
    transport = httpx.MockTransport(lambda request: httpx.Response(status, json={"status": "ACTIVE"}))
    with (
        patch("dnsid.safe_transport.make_ssrf_safe_async_transport", return_value=transport) as make,
        patch.object(transport, "aclose", wraps=transport.aclose) as close,
    ):
        async with RegistryClient() as client:
            assert await client.async_get_status(_DOMAIN) == expected
            assert await client.async_get_status(_DOMAIN) == expected
            with pytest.raises(RuntimeError, match="aclose"):
                client.close()
        await client.aclose()
    make.assert_called_once_with(client._transport_config, allow_loopback_host="127.0.0.1")
    close.assert_awaited_once()


@pytest.mark.asyncio
async def test_close_releases_both_pools_after_mixed_use():
    client = RegistryClient()
    sync_thread = []
    loop_thread = threading.get_ident()
    client._http_client = httpx.Client(transport=httpx.MockTransport(_response))
    original_close = client._http_client.close

    def close_sync():
        sync_thread.append(threading.get_ident())
        original_close()

    with patch.object(client._http_client, "close", side_effect=close_sync):
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(_response))
        await client.async_get_status(_DOMAIN)
        await client.aclose()
    assert sync_thread and sync_thread[0] != loop_thread
    assert client._http_client.is_closed and client._async_http_client.is_closed


@pytest.mark.asyncio
async def test_cross_loop_use_fails_before_io():
    async with RegistryClient() as client:
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(_response))
        await client.async_get_status(_DOMAIN)
        with pytest.raises(RuntimeError, match="one event loop"):
            await asyncio.to_thread(asyncio.run, client.async_get_status(_DOMAIN))


@pytest.mark.asyncio
async def test_private_registry_destination_is_blocked_without_dns():
    async with RegistryClient("https://10.0.0.1", api_key=_FAKE_API_KEY) as client:
        with pytest.raises(VerificationError, match="dnsid-ssrf-blocked"):
            await client.async_get_status(_DOMAIN)


@pytest.mark.asyncio
async def test_failed_detail_read_retains_known_creation_facts():
    async with RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY) as client:
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(_response))
        with patch.object(client, "async_get_agent_detail", new_callable=AsyncMock,
                          side_effect=VerificationError(VerificationCode.LOG_ERROR, "offline")):
            with pytest.raises(VerificationError) as error:
                await client.async_register_agent(AgentRegistrationInput(domain=_DOMAIN), "same-key")
    assert error.value.registration_request == {"domain": _DOMAIN}
    assert error.value.registration_idempotency_key == "same-key"
    assert error.value.registration_response == _REGISTER_RESPONSE


@pytest.mark.asyncio
async def test_native_loopback_http_without_workers():
    requests = []

    async def serve(reader, writer):
        try:
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            body = b'{"status":"ACTIVE"}'
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async with await asyncio.start_server(serve, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        with patch.object(asyncio.get_running_loop(), "run_in_executor",
                          side_effect=AssertionError("worker")):
            async with RegistryClient(f"http://127.0.0.1:{port}") as client:
                results = await asyncio.gather(*(client.async_get_status(_DOMAIN) for _ in range(3)))
    assert results == ["ACTIVE"] * 3
    assert len(requests) == 3
    assert all(b"Authorization" not in request for request in requests)


@pytest.mark.asyncio
async def test_cancelled_mutation_does_not_retry():
    started = asyncio.Event()
    requests = []

    async def handle(request):
        requests.append(request)
        started.set()
        await asyncio.Event().wait()

    async with RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY) as client:
        client._async_http_client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        task = asyncio.create_task(client.async_register_agent(AgentRegistrationInput(domain=_DOMAIN), "same-key"))
        await asyncio.wait_for(started.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert len(requests) == 1
    assert requests[0].headers["Idempotency-Key"] == "same-key"
