"""Native TXT lookup preserves DNSSEC, absolute names, bounds and deadlines."""

import asyncio
import gzip
from unittest.mock import AsyncMock, MagicMock, patch

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.resolver
import dns.rrset
import httpx
import pytest

from dnsid import AsyncDNSResolver, verification_budget
from dnsid._default_resolver import _MAX_DOH_BODY_BYTES, DefaultDNSResolver
from dnsid.enums import DNSSECState, VerificationCode
from dnsid.exceptions import VerificationError
from tests.test_async_https_client import _Chunks

_NAME = "_dnsid.agent.test"


def _answer():
    query = dns.message.make_query(_NAME, "TXT")
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text(_NAME + ".", 60, "IN", "TXT", '"first" "second"'))
    return dns.resolver.Answer(
        query.question[0].name, query.question[0].rdtype, 1,
        dns.message.from_wire(response.to_wire()),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("server", ["", "192.0.2.53:5353"])
async def test_native_configuration_absolute_names_and_budget(server):
    resolver = DefaultDNSResolver(server)
    assert isinstance(resolver, AsyncDNSResolver)
    native = MagicMock()
    native.resolve = AsyncMock(return_value=_answer())
    with (
        patch("dns.asyncresolver.Resolver", return_value=native) as constructor,
        patch.object(asyncio.get_running_loop(), "run_in_executor",
                     side_effect=AssertionError("unexpected worker")),
        verification_budget(0.5),
    ):
        records, state = await resolver.async_fetch_txt(_NAME)
    constructor.assert_called_once_with(configure=not bool(server))
    if server:
        assert native.nameservers == ["192.0.2.53"]
        assert native.port == 5353
    args, kwargs = native.resolve.await_args
    assert args == (_NAME, "TXT")
    assert kwargs["search"] is False
    assert 0 < kwargs["lifetime"] <= 0.5
    assert state == DNSSECState.UNKNOWN
    assert records[0].strings == [b"first", b"second"]
    assert records[0].ttl == 60


@pytest.mark.parametrize("server", ["", "192.0.2.53:5353"])
def test_sync_lookup_also_disables_search_domains(server):
    native = MagicMock()
    native.resolve.return_value = _answer()
    with (
        patch("dns.resolver.Resolver", return_value=native),
        patch("dns.resolver.resolve", return_value=_answer()) as system,
    ):
        records, state = DefaultDNSResolver(server).fetch_txt(_NAME)
    call = native.resolve if server else system
    assert call.call_args.kwargs["search"] is False
    assert records[0].strings == [b"first", b"second"]
    assert state == DNSSECState.UNKNOWN


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,empty", [
    (dns.resolver.NXDOMAIN(), True),
    (dns.resolver.NoAnswer(), True),
    (dns.resolver.NoNameservers(), False),
    (dns.exception.Timeout(), False),
    (OSError("network error"), False),
])
async def test_native_dns_errors(failure, empty):
    with patch("dns.asyncresolver.Resolver.resolve", side_effect=failure):
        if empty:
            assert await DefaultDNSResolver().async_fetch_txt(_NAME) == ([], DNSSECState.UNKNOWN)
        else:
            with pytest.raises(VerificationError) as error:
                await DefaultDNSResolver().async_fetch_txt(_NAME)
            assert error.value.code == VerificationCode.DNS_RESOLUTION
            assert error.value.transient is True


@pytest.mark.asyncio
async def test_native_deadline_is_not_remapped_to_dns_error():
    async def resolve(*args, **kwargs):
        await asyncio.sleep(10)

    with patch("dns.asyncresolver.Resolver.resolve", side_effect=resolve):
        with pytest.raises(VerificationError) as error:
            with verification_budget(0.02):
                await DefaultDNSResolver().async_fetch_txt(_NAME)
    assert error.value.code == VerificationCode.DEADLINE_EXCEEDED


@pytest.mark.asyncio
@pytest.mark.parametrize("ttl", [0, 60])
async def test_real_udp_txt_without_workers(ttl):
    class Server(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport
            self.questions = []

        def datagram_received(self, data, peer):
            query = dns.message.from_wire(data)
            self.questions.append(query.question[0])
            response = dns.message.make_response(query)
            response.flags |= dns.flags.AD
            response.answer.append(dns.rrset.from_text(
                query.question[0].name, ttl, "IN", "TXT", '"first" "second"',
            ))
            self.transport.sendto(response.to_wire(), peer)

    loop = asyncio.get_running_loop()
    transport, server = await loop.create_datagram_endpoint(Server, local_addr=("127.0.0.1", 0))
    try:
        port = transport.get_extra_info("sockname")[1]
        with patch.object(loop, "run_in_executor", side_effect=AssertionError("unexpected worker")):
            with verification_budget(2):
                records, state = await DefaultDNSResolver(f"127.0.0.1:{port}").async_fetch_txt(_NAME)
        assert state == DNSSECState.UNKNOWN
        assert records[0].strings == [b"first", b"second"]
        assert records[0].ttl == ttl
        assert len(server.questions) == 1
        assert server.questions[0].name == dns.name.from_text(_NAME + ".")
    finally:
        transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme,ad,state", [
    ("https", True, DNSSECState.VALID),
    ("https", False, DNSSECState.UNKNOWN),
    ("http", True, DNSSECState.UNKNOWN),
])
async def test_doh_matches_sync_and_preserves_txt_components(scheme, ad, state):
    payload = {"Status": 0, "AD": ad, "Answer": [
        {"type": 16, "TTL": 37, "data": '"first" "second"'},
        {"type": 1, "TTL": 37, "data": "192.0.2.1"},
    ]}
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json=payload)

    resolver = DefaultDNSResolver(f"{scheme}://resolver.test")
    with (
        patch("dnsid.safe_transport.make_ssrf_safe_transport",
              return_value=httpx.MockTransport(handle)),
        patch("dnsid.safe_transport.make_ssrf_safe_async_transport",
              return_value=httpx.MockTransport(handle)) as make,
    ):
        expected = resolver.fetch_txt(_NAME)
        records, actual_state = await resolver.async_fetch_txt(_NAME)
    assert (records, actual_state) == expected
    assert actual_state == state
    assert records[0].strings == [b"first", b"second"]
    assert records[0].ttl == 37
    assert make.call_args.args[0].private_address_hosts == frozenset({"resolver.test"})
    assert all(request.url.params["name"] == _NAME for request in requests)
    assert all(request.url.params["type"] == "TXT" for request in requests)
    assert all(request.headers["accept"] == "application/dns-json" for request in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("status,document,transient", [
    (302, {}, False), (400, {}, False), (503, {}, True),
    (200, {"Status": 2}, True), (200, {"Status": 3}, False),
    (200, b"invalid json", False), (200, [], False), (200, {"Status": "0"}, False),
    (200, {"AD": "true"}, False), (200, {"Answer": {}}, False),
    (200, {"Answer": [None]}, False),
    (200, {"Answer": [{"type": 16, "data": None}]}, False),
    (200, {"Answer": [{"type": 16, "TTL": -1}]}, False),
    (200, {"Answer": [{"type": 16, "TTL": True}]}, False),
])
async def test_doh_rejection_matches_sync(status, document, transient):
    def handle(request):
        kwargs = {"content": document} if isinstance(document, bytes) else {"json": document}
        return httpx.Response(status, **kwargs, headers={"location": "https://other.test"})

    resolver = DefaultDNSResolver("https://resolver.test")
    with (
        patch("dnsid.safe_transport.make_ssrf_safe_transport",
              return_value=httpx.MockTransport(handle)),
        patch("dnsid.safe_transport.make_ssrf_safe_async_transport",
              return_value=httpx.MockTransport(handle)),
    ):
        with pytest.raises(VerificationError) as sync:
            resolver.fetch_txt(_NAME)
        with pytest.raises(VerificationError) as native:
            await resolver.async_fetch_txt(_NAME)
    assert native.value.code == sync.value.code == VerificationCode.DNS_RESOLUTION
    assert native.value.transient == sync.value.transient == transient


@pytest.mark.asyncio
@pytest.mark.parametrize("overflow", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
async def test_doh_decoded_limits_and_cleanup(overflow, compressed):
    body = b'{"Status":0,"Answer":[]}'
    body += b" " * (_MAX_DOH_BODY_BYTES - len(body))
    stream = _Chunks(
        [gzip.compress(body + (b"x" if overflow else b""))] if compressed
        else ([body, b"x", b"unread"] if overflow else [body])
    )
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, stream=stream, headers={"content-encoding": "gzip"} if compressed else {},
    ))
    with (
        patch("dnsid.safe_transport.make_ssrf_safe_async_transport", return_value=transport),
        patch.object(transport, "aclose", wraps=transport.aclose) as close,
    ):
        if overflow:
            with pytest.raises(VerificationError, match="too large"):
                await DefaultDNSResolver("https://resolver.test").async_fetch_txt(_NAME)
            if not compressed:
                assert stream.yielded == 2
        else:
            assert await DefaultDNSResolver("https://resolver.test").async_fetch_txt(_NAME) == (
                [], DNSSECState.UNKNOWN,
            )
        close.assert_awaited_once()
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_doh_interrupted_read_closes_owned_resources(cancel):
    started = asyncio.Event()

    class Slow(_Chunks):
        async def __aiter__(self):
            started.set()
            await asyncio.sleep(10)
            yield b"{}"

    stream = Slow([])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    resolver = DefaultDNSResolver("https://resolver.test")
    with (
        patch("dnsid.safe_transport.make_ssrf_safe_async_transport", return_value=transport),
        patch.object(transport, "aclose", wraps=transport.aclose) as close,
    ):
        if cancel:
            call = asyncio.create_task(resolver.async_fetch_txt(_NAME))
            await asyncio.wait_for(started.wait(), 2)
            call.cancel()
            with pytest.raises(asyncio.CancelledError):
                await call
        else:
            with pytest.raises(VerificationError) as error:
                with verification_budget(0.02):
                    await resolver.async_fetch_txt(_NAME)
            assert error.value.code == VerificationCode.DEADLINE_EXCEEDED
        close.assert_awaited_once()
    assert stream.closed


@pytest.mark.asyncio
async def test_doh_transport_error_and_ip_literal_policy():
    resolver = DefaultDNSResolver("https://127.0.0.1")
    assert not resolver._doh_config().private_address_hosts
    with pytest.raises(VerificationError) as error:
        await resolver.async_fetch_txt(_NAME)
    assert error.value.code == VerificationCode.DNS_RESOLUTION
    assert error.value.transient is True
