"""Compressed reads must bound allocations, not only the final stored body."""

import gzip
import tracemalloc
import zlib

import httpx
import pytest

from dnsid._https_client import _async_read_limited, _read_limited
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError


class Chunks(httpx.SyncByteStream, httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.yielded = 0

    def __iter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def __aiter__(self):
        for chunk in self:
            yield chunk


def response(chunks, encoding):
    return httpx.Response(200, stream=Chunks(chunks), headers={"content-encoding": encoding})


@pytest.mark.asyncio
@pytest.mark.parametrize("native", [False, True], ids=["sync", "async"])
async def test_compression_bomb_rejected_before_allocating_decoded_chunk(native):
    wire = gzip.compress(b"x" * (16 * 1024 * 1024))
    reply = response([wire, b"unread"], "gzip")
    tracemalloc.start()
    try:
        with pytest.raises(VerificationError, match="limit"):
            if native:
                await _async_read_limited(reply, 64 * 1024, VerificationCode.RECORD_INVALID, "limit")
            else:
                _read_limited(reply, 64 * 1024, VerificationCode.RECORD_INVALID, "limit")
        assert tracemalloc.get_traced_memory()[1] < 4 * 1024 * 1024
    finally:
        tracemalloc.stop()
    assert reply.stream.yielded == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("native", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("encoding", ["gzip", "deflate", "raw-deflate"])
@pytest.mark.parametrize("width", [1, 7, 4096])
async def test_compressed_streams_decode_at_exact_limit(native, encoding, width):
    body = b"bounded body" * 100
    if encoding == "gzip":
        wire = gzip.compress(body)
    elif encoding == "deflate":
        wire = zlib.compress(body)
    else:
        wire = zlib.compress(body)[2:-4]
    reply = response([wire[i:i + width] for i in range(0, len(wire), width)],
                     "deflate" if encoding == "raw-deflate" else encoding)
    args = reply, len(body), VerificationCode.RECORD_INVALID, "limit"
    actual = await _async_read_limited(*args) if native else _read_limited(*args)
    assert actual == body


@pytest.mark.asyncio
@pytest.mark.parametrize("native", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("wire,encoding", [(b"bad", "gzip"), (gzip.compress(b"ok")[:-1], "gzip"),
                                          (b"encoded", "br"), (b"encoded", "gzip, deflate")])
async def test_invalid_or_unsupported_content_coding_fails_closed(native, wire, encoding):
    reply = response([wire], encoding)
    with pytest.raises(VerificationError):
        if native:
            await _async_read_limited(reply, 4096, VerificationCode.RECORD_INVALID, "limit")
        else:
            _read_limited(reply, 4096, VerificationCode.RECORD_INVALID, "limit")


@pytest.mark.asyncio
@pytest.mark.parametrize("native", [False, True], ids=["sync", "async"])
async def test_trailing_compressed_data_is_rejected_before_consuming_more_chunks(native):
    reply = response([gzip.compress(b"ok"), b"trailing", b"unread"], "gzip")
    with pytest.raises(VerificationError):
        args = reply, 4096, VerificationCode.RECORD_INVALID, "limit"
        if native:
            await _async_read_limited(*args)
        else:
            _read_limited(*args)
    assert reply.stream.yielded == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("native", [False, True], ids=["sync", "async"])
async def test_c2sp_compression_bomb_closes_response_with_bounded_memory(native):
    from unittest.mock import patch

    from dnsid.c2sp_tlog import C2spTlogTransportError, SafeC2spResourceFetcher

    wire = gzip.compress(b"x" * (16 * 1024 * 1024))
    stream = Chunks([wire, b"unread"])
    reply = httpx.Response(200, stream=stream, headers={"content-encoding": "gzip"})
    transport = httpx.MockTransport(lambda request: reply)
    with SafeC2spResourceFetcher() as fetcher:
        fetcher._client.close()
        fetcher._client = httpx.Client(transport=transport)
        with patch("dnsid.c2sp_tlog.resource_fetcher.make_ssrf_safe_async_transport",
                   return_value=transport):
            tracemalloc.start()
            try:
                with pytest.raises(C2spTlogTransportError, match="byte maximum"):
                    if native:
                        await fetcher.async_fetch_bounded("https://log.example/checkpoint", 65536)
                    else:
                        fetcher.fetch_bounded("https://log.example/checkpoint", 65536)
                assert tracemalloc.get_traced_memory()[1] < 4 * 1024 * 1024
            finally:
                tracemalloc.stop()
    assert stream.yielded == 1
    assert reply.is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize("native", [False, True], ids=["sync", "async"])
async def test_unsupported_coding_is_rejected_on_already_buffered_responses(native):
    reply = httpx.Response(200, content=b"{}")
    reply.headers["content-encoding"] = "br"
    with pytest.raises(VerificationError, match="unsupported"):
        args = reply, 4096, VerificationCode.RECORD_INVALID, "limit"
        if native:
            await _async_read_limited(*args)
        else:
            _read_limited(*args)


def test_raw_reads_preserve_content_coding():
    wire = gzip.compress(b"ok")
    assert _read_limited(response([wire], "gzip"), len(wire), VerificationCode.RECORD_INVALID,
                         "limit", decode_content=False) == wire
