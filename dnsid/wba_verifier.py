"""DNSid WBA request verification for the revision-00 WBA drafts.

Directory self-signatures are never a substitute for DNSid verification and
configured entity acceptance. No directory evidence is cached. Without a replay
policy, valid requests can be reused until their signatures expire.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn, cast
from urllib.parse import urljoin, urlsplit, urlunsplit

import http_sf
import httpx

from ._https_client import _assert_same_host_https_redirect, _read_limited
from ._utils import b64url_decode, b64url_encode, normalize_fqdn
from ._verification_budget import remaining_seconds, verification_budget
from .enums import VerificationCode
from .exceptions import VerificationError
from .http_signatures import (
    _build_signature_base,
    _now,
    _parse_content_digest,
    _parse_signature_dictionary,
)
from .interfaces import IdentityResolver
from .models import (
    JWK,
    HttpRequest,
    SignatureParams,
    TLSCertificate,
    VerifiedDomain,
    _parse_component_identifier,
    _parse_sf_dictionary,
)
from .safe_transport import make_ssrf_safe_transport
from .wba_signer import (
    WBA_DIRECTORY_MEDIA_TYPE,
    WBA_DIRECTORY_TAG,
    WBA_DIRECTORY_WELL_KNOWN_PATH,
    WBA_TAG,
    WebBotAuthConfig,
)


@dataclass
class WebBotAuthVerificationOptions:
    """Trusted per-invocation WBA policy.

    Without ``signer_domain``, discovery can identify the signer only when
    ``allow_signature_agent_domain`` is explicitly enabled. Discovery and
    redirects must remain on that signer's host; delegation is not supported.

    ``replay_policy(domain, keyid, nonce, retain_until)`` must atomically record
    an unused tuple through the supplied Unix timestamp and return True, or
    return False for reuse. Exceptions fail closed. Blocking callbacks and
    injected resolvers must honor the shared verification budget.
    """

    signer_domain: str = ""
    discovery_uri: str = ""
    discovery_type: str = "directory"
    allow_signature_agent_domain: bool = False
    peer_cert: TLSCertificate | None = None
    timeout: float = 30.0
    replay_policy: Callable[[str, str, str, int], bool] | None = None


def _reject(message: str) -> NoReturn:
    raise VerificationError(VerificationCode.SIGNATURE_INVALID, message)


def _signatures(message: HttpRequest, tag: str) -> list[tuple[SignatureParams, bytes]]:
    inputs = message.get_header("signature-input")
    signatures = message.get_header("signature")
    if (
        not inputs or not signatures
        or sum(len(value) for value in message.headers.values()) > 65536
        or (message.body is not None and len(message.body) > 8 * 1024 * 1024)
    ):
        _reject("missing signature fields or WBA input limit exceeded")
    params = SignatureParams.parse_dictionary(inputs)
    raw = _parse_signature_dictionary(signatures)
    if len(params) > 16 or len(raw) > 16 or any(
        len(item.components) > 64 for item in params.values()
    ):
        _reject("WBA signature count or component limit exceeded")
    return [(item, raw[label]) for label, item in params.items()
            if label in raw and item.tag == tag]


def _check_time(params: SignatureParams, skew: int) -> None:
    now = _now().timestamp()
    if (
        type(params.created) is not int or type(params.expires) is not int
        or not 0 <= params.expires - params.created <= 300
        or params.created > now + skew or now > params.expires + skew
        or params.alg != "ed25519"
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.key_id)
        or b64url_encode(b64url_decode(params.key_id)) != params.key_id
    ):
        _reject("invalid WBA timestamps, algorithm, or thumbprint")


def _check_digest(message: HttpRequest, params: SignatureParams) -> None:
    if message.body is not None or "content-digest" in params.components:
        if message.body is None or "content-digest" not in params.components:
            _reject("supplied content requires covered Content-Digest")
        _, expected = _parse_content_digest(message.get_header("content-digest"))
        if not hmac.compare_digest(expected, hashlib.sha256(message.body).digest()):
            _reject("WBA Content-Digest mismatch")


def _directory_url(uri: str, discovery_type: str) -> str:
    try:
        parsed = urlsplit(uri)
        parsed.port
    except ValueError as exc:
        raise VerificationError(VerificationCode.TLS_ERROR, "invalid discovery URI") from exc
    if discovery_type == "directory":
        uri = urlunsplit((parsed.scheme, parsed.netloc, WBA_DIRECTORY_WELL_KNOWN_PATH, "", ""))
    elif discovery_type != "jwks_uri":
        _reject("unsupported Signature-Agent discovery type")
    # Validate the original credentials too, including an empty username.
    if parsed.username is not None or parsed.password is not None:
        _reject("Signature-Agent credentials are forbidden")
    _assert_same_host_https_redirect(uri, parsed.hostname or "")
    return uri


def _bounded_json(body: bytes) -> dict[str, Any]:
    # Bound nesting before decoding to prevent recursive JSON allocation.
    depth = 0
    quoted = escaped = False
    for byte in body:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                _reject("directory JSON depth exceeded")
        elif byte in (93, 125):
            depth -= 1
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise VerificationError(VerificationCode.RECORD_INVALID, "invalid directory JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        _reject("directory must contain a JWKS key array")
    if not 1 <= len(data["keys"]) <= 32:
        _reject("directory key count limit exceeded")
    return cast(dict[str, Any], data)


class WBAHttpVerifier:
    """Verify DNSid WBA requests and their signed directories.

    Construction needs no local identity or signing key. The default transport
    validates Web PKI and pins connections to public DNS addresses. An injected
    transport is trusted infrastructure and MUST enforce the same constraints,
    including on redirects and every connection; it must honor remaining_seconds().

    Requests are buffered: hosts must enforce the 8 MiB body and 64 KiB header
    limits while reading. Directory reads are limited to 1 MiB, 32 keys, JSON
    depth 16, 16 signatures, and five same-host HTTPS redirects. The complete
    operation has a default 30-second cooperative deadline.
    """

    def __init__(
        self, resolver: IdentityResolver, *, config: WebBotAuthConfig | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Set the identity resolver, profile configuration, and discovery transport."""
        self._resolver = resolver
        self._config = config or WebBotAuthConfig()
        self._transport = transport

    def verify_web_bot_auth_signed_request(
        self, req: HttpRequest, opts: WebBotAuthVerificationOptions | None = None,
    ) -> VerifiedDomain:
        """Return the signer only after request, directory, and DNSid checks succeed.

        Args:
            req: Buffered application request, including exact supplied content.
            opts: Trusted discovery, application peer, deadline, and replay policy.

        Returns:
            Verified DNSid signer identity, not application authorization.

        Raises:
            VerificationError: On invalid evidence, discovery, acceptance, or replay.
        """
        opts = opts or WebBotAuthVerificationOptions()
        with verification_budget(opts.timeout):
            return self._verify(req, opts)

    def _verify(self, req: HttpRequest, opts: WebBotAuthVerificationOptions) -> VerifiedDomain:
        candidates = _signatures(req, WBA_TAG)
        if len(candidates) != 1:
            _reject("expected exactly one complete WBA request signature")
        params, signature = candidates[0]
        _check_time(params, self._config.clock_skew)
        if "@authority" not in params.components:
            _reject("WBA request requires exact @authority coverage")
        _check_digest(req, params)
        request_base = _build_signature_base(req, params)
        uri, discovery_type = opts.discovery_uri, opts.discovery_type
        if req.has_header("signature-agent"):
            selected = []
            for component in params.components:
                name, parameters = _parse_component_identifier(component)
                if name == "signature-agent" and set(dict(parameters)) == {"key"}:
                    selected.append(dict(parameters)["key"])
            if len(selected) != 1:
                _reject("Signature-Agent requires exactly one covered member")
            try:
                member = _parse_sf_dictionary(req.get_header("signature-agent"))[selected[0]]
                value, attributes = member
                if type(value) is not str:
                    raise ValueError("URI must be a String")
                kind = attributes.get("type", http_sf.Token("directory"))
                if not isinstance(kind, http_sf.Token):
                    raise ValueError("type must be a Token")
                uri, discovery_type = value, str(kind)
            except (ValueError, KeyError, TypeError) as exc:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID, "invalid Signature-Agent member"
                ) from exc
        if not uri:
            if not opts.signer_domain:
                _reject("trusted signer and discovery policy required")
            uri = f"https://{opts.signer_domain}"
        url = _directory_url(uri, discovery_type)
        host = normalize_fqdn(urlsplit(url).hostname or "")
        if not opts.signer_domain and not opts.allow_signature_agent_domain:
            _reject("Signature-Agent signer discovery is not permitted")
        domain = normalize_fqdn(opts.signer_domain) if opts.signer_domain else host
        if domain != host:
            _reject("cross-host WBA delegation is unsupported")
        directory_request, response = self._fetch(url, domain)
        if response.get_header("content-type").split(";", 1)[0].strip().lower() != (
            WBA_DIRECTORY_MEDIA_TYPE
        ):
            _reject("invalid directory media type")
        data = _bounded_json(response.body or b"")
        keys = []
        for raw in data["keys"]:
            if (
                not isinstance(raw, dict) or raw.get("kty") != "OKP"
                or raw.get("crv") != "Ed25519" or "d" in raw
                or raw.get("alg", "ed25519") != "ed25519"
                or raw.get("use", "sig") != "sig"
                or not isinstance(raw.get("x"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", raw["x"])
                or b64url_encode(b64url_decode(raw["x"])) != raw["x"]
            ):
                _reject("invalid public directory JWK")
            key = JWK.from_dict({**raw, "alg": "EdDSA"})
            if key.thumbprint() != raw.get("kid"):
                _reject("directory kid does not match its thumbprint")
            if raw["kid"] == params.key_id:
                keys.append(key)
        if len(keys) != 1:
            _reject("expected exactly one matching directory key")
        key = keys[0]
        directory_candidates = [
            (item, raw) for item, raw in _signatures(response, WBA_DIRECTORY_TAG)
            if item.key_id == params.key_id
        ]
        if len(directory_candidates) != 1:
            _reject("expected exactly one matching directory signature")
        directory_params, directory_signature = directory_candidates[0]
        _check_time(directory_params, self._config.clock_skew)
        required = {"@authority;req", "content-type", "cache-control", "content-digest"}
        if not required.issubset(directory_params.components):
            _reject("directory signature missing required coverage")
        _check_digest(response, directory_params)
        if not key.verify(
            _build_signature_base(response, directory_params, directory_request),
            directory_signature,
        ):
            _reject("invalid directory signature")
        if not key.verify(request_base, signature):
            _reject("invalid WBA request signature")
        verified = self._resolver.verify_domain(domain, peer_cert=opts.peer_cert)
        if verified.domain != domain or not any(
            candidate.signature_alg() == "EdDSA" and candidate.thumbprint() == params.key_id
            for candidate in verified.jwks.signing_keys()
        ):
            _reject("WBA key is not in verified current DNSid ku material")
        self._final_check(params, directory_params, verified)
        if opts.replay_policy is not None:
            if not params.nonce:
                _reject("replay policy requires a non-empty nonce")
            assert params.expires is not None
            try:
                accepted = opts.replay_policy(
                    domain, params.key_id, params.nonce,
                    params.expires + self._config.clock_skew,
                )
            except Exception as exc:
                raise VerificationError(
                    VerificationCode.SIGNATURE_INVALID, "WBA replay store failed"
                ) from exc
            if accepted is not True:
                _reject("WBA nonce replay rejected")
            self._final_check(params, directory_params, verified)
        return verified

    def _final_check(
        self, params: SignatureParams, directory: SignatureParams, verified: VerifiedDomain,
    ) -> None:
        remaining_seconds()
        _check_time(params, self._config.clock_skew)
        _check_time(directory, self._config.clock_skew)
        if _now() >= verified.expiry():
            _reject("DNSid evidence expired during WBA verification")

    def _fetch(self, url: str, domain: str) -> tuple[HttpRequest, HttpRequest]:
        transport = self._transport or make_ssrf_safe_transport()
        try:
            with httpx.Client(transport=transport, trust_env=False) as client:
                for _ in range(6):
                    _assert_same_host_https_redirect(url, domain)
                    with client.stream(
                        "GET", url, follow_redirects=False, timeout=remaining_seconds(10)
                    ) as response:
                        if response.is_redirect:
                            url = urljoin(url, response.headers.get("location", ""))
                            continue
                        if response.status_code != 200:
                            _reject("directory response must have status 200")
                        body = _read_limited(
                            response, 1024 * 1024, VerificationCode.RECORD_INVALID,
                            "directory response size exceeded",
                        )
                        return (
                            HttpRequest(method="GET", url=str(response.request.url)),
                            HttpRequest(method="GET", url=url, headers=dict(response.headers),
                                        body=body),
                        )
        except httpx.TransportError as exc:
            raise VerificationError(VerificationCode.TLS_ERROR, "directory fetch failed") from exc
        _reject("directory redirect limit exceeded")
