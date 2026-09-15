"""Parsing and canonicalization of c2sp-tlog lr references.

lr form: ``c2sp-tlog:<scope>:<log-prefix>#<stream-id>[@<entry-index>]``
where scope is ``public``, ``testnet``, or ``private-<label>``.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .._utils import b64url_encode
from .errors import C2spTlogParseError

_METHOD = "c2sp-tlog:"
_SCOPE_PRIVATE_RE = re.compile(r"^private-[A-Za-z0-9-]+$")
_STREAM_ID_RE = re.compile(r"^(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+$")
_INDEX_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_SCHEME_HOST_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^/?#]*", re.IGNORECASE)
_DOT_SEGMENT_RE = re.compile(r"(^|/)\.\.?($|/)")
_ENCODED_SLASH_RE = re.compile(r"%2f|%5c", re.IGNORECASE)
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_NOTE_NAME_RE = re.compile(r"^[\x21-\x7e]+$")


@dataclass
class ParsedC2spTlogLr:
    """Structured form of a c2sp-tlog lr reference."""

    method: str
    scope: str
    log_prefix: str
    stream_id: str
    origin: str
    #: Canonical bound reference without an entry index.
    lr: str = ""
    entry_index: int | None = None


def generate_c2sp_tlog_stream_id() -> str:
    """Generate a fresh version-1 identity-instance stream ID.

    Returns:
        The unpadded base64url encoding of 128 cryptographically random bits.
    """
    return b64url_encode(secrets.token_bytes(16))


def parse_c2sp_tlog_lr(lr: str) -> ParsedC2spTlogLr:
    """Parse and validate a full c2sp-tlog lr string.

    The reference form is
    ``c2sp-tlog:<scope>:<log-prefix>#<stream-id>[@<entry-index>]`` where
    *scope* is ``public``, ``testnet``, or ``private-<label>``, and
    *log-prefix* is the log's canonical HTTPS base URL.

    Returns:
        The structured reference, with the log prefix required to already be
        canonical and ``lr`` set to the canonical bound reference (no index).

    Raises:
        C2spTlogParseError: If any component of *lr* is missing or invalid.
    """
    if not lr.startswith(_METHOD):
        raise C2spTlogParseError("lr must start with c2sp-tlog:")
    rest = lr[len(_METHOD) :]
    colon = rest.find(":")
    if colon <= 0:
        raise C2spTlogParseError("missing c2sp-tlog scope")
    scope = rest[:colon]
    validate_scope(scope)
    tail = rest[colon + 1 :]
    hash_ = tail.rfind("#")
    if hash_ <= 0 or hash_ == len(tail) - 1:
        raise C2spTlogParseError("missing log prefix or stream id")
    raw_log_prefix = tail[:hash_]
    log_prefix = canonical_log_prefix(raw_log_prefix)
    if raw_log_prefix != log_prefix:
        raise C2spTlogParseError("log prefix must already be canonical")
    ref = tail[hash_ + 1 :]
    at = ref.rfind("@")
    stream_id = ref if at == -1 else ref[:at]
    if not _STREAM_ID_RE.match(stream_id):
        raise C2spTlogParseError("invalid stream id")
    entry_index = None if at == -1 else _parse_index(ref[at + 1 :])
    origin = checkpoint_origin(log_prefix)
    _validate_signed_note_name(origin)
    if scope == "public" and not log_prefix.startswith("https://"):
        raise C2spTlogParseError("public c2sp-tlog requires an https log prefix")
    return ParsedC2spTlogLr(
        method="c2sp-tlog",
        scope=scope,
        log_prefix=log_prefix,
        stream_id=stream_id,
        origin=origin,
        lr=f"{_METHOD}{scope}:{log_prefix}#{stream_id}",
        entry_index=entry_index,
    )


def validate_scope(scope: str) -> None:
    """Check that *scope* is ``public``, ``testnet``, or ``private-<label>``.

    Raises:
        C2spTlogParseError: If *scope* is not one of the allowed forms.
    """
    if scope not in ("public", "testnet") and not _SCOPE_PRIVATE_RE.match(scope):
        raise C2spTlogParseError(f"invalid c2sp-tlog scope: {scope}")


def canonical_log_prefix(raw: str) -> str:
    """Validate and canonicalize a log-prefix URL.

    Canonical form has a lowercase scheme and host, no default port,
    normalized percent-encoding, and no trailing slash.

    Raises:
        C2spTlogParseError: If *raw* is not a valid http(s) URL or contains
            userinfo, a query, a fragment, dot segments, encoded slashes, or
            characters that must be percent-encoded.
    """
    if re.search(r"[;\s]", raw):
        raise C2spTlogParseError("log prefix must percent-encode DNS TXT tag delimiters")
    raw_path = _SCHEME_HOST_RE.sub("", raw, count=1) or "/"
    if _DOT_SEGMENT_RE.search(raw_path):
        raise C2spTlogParseError("log prefix must not contain dot segments")
    try:
        url = urlsplit(raw)
    except ValueError as exc:
        raise C2spTlogParseError(f"invalid log prefix URL: {exc}") from exc
    if not url.scheme or url.hostname is None:
        raise C2spTlogParseError("invalid log prefix URL")
    if url.username or url.password:
        raise C2spTlogParseError("log prefix must not contain userinfo")
    if url.query or url.fragment:
        raise C2spTlogParseError("log prefix must not contain query or fragment")
    path = url.path
    if path not in ("", "/") and path.endswith("/"):
        raise C2spTlogParseError("log prefix must not have trailing slash")
    if _ENCODED_SLASH_RE.search(path):
        raise C2spTlogParseError("log prefix must not percent-encode slash or backslash")
    scheme = url.scheme.lower()
    if scheme not in ("https", "http"):
        raise C2spTlogParseError("unsupported log prefix scheme")
    hostname = url.hostname.lower()
    port = url.port
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    netloc = hostname if port is None else f"{hostname}:{port}"
    normalized_path = _normalize_percent_path(path)
    if normalized_path == "/":
        normalized_path = ""
    out = urlunsplit((scheme, netloc, normalized_path, "", ""))
    return out[:-1] if out.endswith("/") else out


def checkpoint_origin(log_prefix: str) -> str:
    """Derive the signed-note origin (host + path) from a canonical log prefix."""
    url = urlsplit(log_prefix)
    host = url.netloc
    return f"{host}{url.path}".rstrip("/")


def _parse_index(s: str) -> int:
    if not _INDEX_RE.match(s):
        raise C2spTlogParseError("invalid entry index")
    return int(s)


def _normalize_percent_path(path: str) -> str:
    def _repl(m: re.Match[str]) -> str:
        byte = int(m.group(0)[1:], 16)
        ch = chr(byte)
        if re.match(r"[A-Za-z0-9._~-]", ch):
            return ch
        return m.group(0).upper()

    return _PCT_RE.sub(_repl, path)


def _validate_signed_note_name(name: str) -> None:
    if not _NOTE_NAME_RE.match(name) or re.search(r"[\s+]", name):
        raise C2spTlogParseError(f"invalid signed-note key name: {name}")
