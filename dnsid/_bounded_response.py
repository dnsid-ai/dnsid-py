"""Bound decompression before HTTPX can allocate an entire decoded chunk."""

import zlib
from collections.abc import Callable

import httpx

from ._verification_budget import remaining_seconds

# Do not negotiate optional codecs whose decoders have no bounded-output API.
ACCEPT_ENCODING = "gzip, deflate"


class BoundedBody:
    def __init__(
        self, response: httpx.Response, limit: int, overflow: Callable[[], Exception],
        *, invalid: Callable[[str], Exception], decode_content: bool = True,
    ) -> None:
        self._body = bytearray()
        self._limit = limit
        self._overflow = overflow
        self._invalid = invalid
        self._encoding = (
            response.headers.get("content-encoding", "identity").strip().lower()
            if decode_content else "identity"
        )
        if self._encoding not in ("identity", "", "gzip", "deflate"):
            raise self._invalid("unsupported HTTP content encoding")
        if response.is_stream_consumed:
            self._encoding = "identity"
        self._decoder = None
        self._prefix = b""
        if self._encoding == "gzip":
            self._decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def append(self, chunk: bytes) -> None:
        remaining_seconds()
        if self._encoding == "deflate" and self._decoder is None:
            # Some servers send raw DEFLATE; inspect its two-byte zlib header first.
            chunk = self._prefix + chunk
            if len(chunk) < 2:
                self._prefix = chunk
                return
            self._prefix = b""
            header = int.from_bytes(chunk[:2], "big")
            wrapped = chunk[0] & 15 == 8 and chunk[0] >> 4 <= 7 and header % 31 == 0
            self._decoder = zlib.decompressobj(zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
        if self._decoder is not None:
            if self._decoder.eof and chunk:
                raise self._invalid("trailing compressed HTTP response")
            try:
                chunk = self._decoder.decompress(chunk, self._limit - len(self._body) + 1)
            except zlib.error as exc:
                raise self._invalid("invalid compressed HTTP response") from exc
            if self._decoder.unused_data:
                raise self._invalid("trailing compressed HTTP response")
        if len(self._body) + len(chunk) > self._limit:
            raise self._overflow()
        self._body.extend(chunk)

    def finish(self) -> bytes:
        if self._encoding in ("gzip", "deflate") and (
            self._decoder is None or not self._decoder.eof or self._decoder.unused_data
        ):
            raise self._invalid("incomplete or trailing compressed HTTP response")
        return bytes(self._body)
