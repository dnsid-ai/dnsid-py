"""HTTP Message Signature profile (RFC 9421).

Application-layer conveniences built on top of DNSid identity verification.
Not part of the DNSid protocol; not required for DNSid conformance.

Usage::

    from dnsid import IdentityManager
    from dnsid.http_signatures import HttpSignatureProfile, HttpMessageSignatureConfig

    manager = IdentityManager(config, key_provider)
    http_signer = HttpSignatureProfile(
        resolver=manager,
        key_provider=key_provider,
        domain=config.identity.domain,
    )

    # Sign an outbound request
    signed_req = http_signer.create_signed_http_request(req)

    # Verify an inbound request
    verified = http_signer.verify_signed_http_request(req)
"""

from __future__ import annotations

import datetime
import hashlib
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ._verification_budget import verification_operation

if TYPE_CHECKING:
    import httpx

from ._utils import (
    b64_std_encode,
    jose_alg_to_http_sig_alg,
    normalize_fqdn,
    parse_key_id,
)
from .enums import VerificationCode
from .exceptions import ArgumentError, DNSidError, VerificationError
from .interfaces import IdentityResolver, KeyProvider
from .models import (
    HttpRequest,
    HttpSigningOptions,
    HttpVerificationOptions,
    SignatureParams,
    TLSCertificate,
    TransportConfig,
    VerifiedDomain,
    _canonical_component_identifier,
    _parse_component_identifier,
    _parse_sf_dictionary,
    _validate_component_identifiers,
)

_CONTENT_SUPPLIED_EXTENSION = "dnsid.content_supplied"


@dataclass
class HttpMessageSignatureConfig:
    """Freshness settings for the HTTP Message Signature profile (RFC 9421)."""

    max_age: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(seconds=300))
    clock_skew: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(seconds=5))

    def __post_init__(self) -> None:
        """Reject freshness settings outside the profile bounds."""
        if self.max_age.total_seconds() <= 0:
            raise ArgumentError("HTTP message signature max_age must be positive")
        if self.clock_skew.total_seconds() < 0:
            raise ArgumentError("HTTP message signature clock_skew must be non-negative")


class HttpSignatureProfile:
    """RFC 9421 HTTP Message Signature helpers for a DNSid identity.

    An application profile layered on top of DNSid identity verification.
    Application profiles are not part of the core DNSid protocol and are not
    required for DNSid conformance.
    """

    @classmethod
    def from_identity_manager(
        cls,
        manager: object,
        config: HttpMessageSignatureConfig | None = None,
    ) -> HttpSignatureProfile:
        """Construct an HttpSignatureProfile from a fully-initialised IdentityManager.

        Reads domain, key provider, and transport configuration from the manager
        so callers don't need to repeat them. Mirrors
        ``HttpSignaturesProfile.fromIdentityManager(idm)`` in the TypeScript SDK.

        The inherited transport is the manager's validated snapshot: a manager
        built with an injected ``https_fetcher`` rejects ``ca_bundle_path``, so
        the clients this profile creates will not carry that bundle. Construct
        the profile directly with ``transport_config=`` to supply one.
        """
        return cls(
            resolver=manager,  # type: ignore[arg-type]
            key_provider=manager._key_provider,  # type: ignore[attr-defined]
            domain=manager.local_domain,  # type: ignore[attr-defined]
            config=config,
            transport_config=manager.config.transport,  # type: ignore[attr-defined]
        )

    def __init__(
        self,
        resolver: IdentityResolver,
        key_provider: KeyProvider | None,
        domain: str,
        config: HttpMessageSignatureConfig | None = None,
        transport_config: TransportConfig | None = None,
    ) -> None:
        """Initialize the profile for a local DNSid identity.

        Args:
            resolver: Any object satisfying the IdentityResolver protocol.
            key_provider: Key management implementation for the local identity.
            domain: FQDN of the local identity.  Used as the domain portion of
                the ``{domain}#{kid}`` keyId in Signature-Input headers.
            config: Optional freshness overrides. Defaults to 300 s max age /
                5 s skew.
            transport_config: Optional DNS and TLS settings for clients created
                by this profile.
        """
        self._resolver = resolver
        self._key_provider = key_provider
        self._domain = normalize_fqdn(domain) if domain else ""
        self._config = config or HttpMessageSignatureConfig()
        self._transport_config = transport_config

    def _require_signing_provider(self) -> KeyProvider:
        if self._key_provider is None or not self._domain:
            raise ArgumentError(
                "HTTP message signing requires a key_provider; profile is verification-only"
            )
        return self._key_provider

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def create_signed_http_request(
        self,
        req: HttpRequest,
        opts: HttpSigningOptions | None = None,
    ) -> HttpRequest:
        """Sign an outgoing HTTP request (RFC 9421 HTTP Message Signatures).

        Sets Signature-Input and Signature headers on *req* and returns it.
        When *req* has a body, a Content-Digest header is computed and covered
        by the signature.

        Args:
            req: The request to sign; headers are set in place.
            opts: Optional signing overrides (label, extra covered components,
                expiry, tag).

        Returns:
            The same request with Signature-Input and Signature headers set.

        Raises:
            ArgumentError: If the signing key kid contains ``'#'`` or an
                additional component is not a known derived component or a
                lowercase HTTP field name.
            VerificationError: If a covered component cannot be derived from
                the message (for example a covered header is absent).
        """
        if opts is None:
            opts = HttpSigningOptions()
        max_age = int(self._config.max_age.total_seconds())
        if not 0 < opts.expires_in_seconds <= max_age:
            raise ArgumentError(
                "HTTP message signature expiry must be positive and no greater than max_age"
            )

        key_provider = self._require_signing_provider()
        signing_key = key_provider.signing_key()
        if "#" in signing_key.kid:
            raise ArgumentError("signing key kid must not contain '#'")

        components = ["@method", "@authority", "@target-uri"]

        if req.body is not None:
            digest = hashlib.sha256(req.body).digest()
            req.set_header("content-digest", f"sha-256=:{b64_std_encode(digest)}:")
            if "content-digest" not in components:
                components.append("content-digest")

        for component in opts.additional_components:
            if component not in components:
                components.append(component)

        try:
            _validate_component_identifiers(components, request_context=False)
        except VerificationError as exc:
            raise ArgumentError(exc.message) from exc

        http_alg = jose_alg_to_http_sig_alg(signing_key.signature_alg())
        key_id = f"{self._domain}#{signing_key.kid}"
        now_ts = int(_now().timestamp())

        params = SignatureParams(
            label=opts.label,
            key_id=key_id,
            alg=http_alg,
            created=now_ts,
            expires=now_ts + opts.expires_in_seconds,
            nonce=_generate_nonce(),
            components=components,
            tag=opts.tag or None,
        )

        sig_base = _build_signature_base(req, params)
        sig_bytes = key_provider.sign(sig_base)

        req.set_header(
            "signature-input",
            _replace_signature_input_member(req.get_header("signature-input"), params),
        )
        req.set_header(
            "signature",
            _replace_signature_member(req.get_header("signature"), opts.label, sig_bytes),
        )
        return req

    def create_signed_http_client(
        self,
        base_client: httpx.Client,
        opts: HttpSigningOptions | None = None,
    ) -> httpx.Client:
        """Wrap an httpx.Client so every outbound request is automatically signed.

        Args:
            base_client: Client whose transport performs the actual I/O.
            opts: Optional signing overrides applied to every request.

        Returns:
            A new httpx.Client that signs each request before sending it.
        """
        import httpx

        profile = self
        signing_opts = opts

        class _SigningTransport(httpx.BaseTransport):
            def __init__(self, inner: httpx.Client) -> None:
                self._inner = inner

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                content_supplied = bool(
                    request.extensions.get(_CONTENT_SUPPLIED_EXTENSION, bool(request.content))
                )
                sdk_req = HttpRequest(
                    method=request.method,
                    url=str(request.url),
                    headers={k.decode(): v.decode() for k, v in request.headers.raw},
                    body=request.read() if content_supplied else None,
                )
                signed = profile.create_signed_http_request(sdk_req, signing_opts)
                new_request = request.__class__(
                    method=signed.method,
                    url=signed.url,
                    headers=signed.headers,
                    content=signed.body or b"",
                    extensions=request.extensions,
                )
                return self._inner._transport.handle_request(new_request)

        class _SignedClient(httpx.Client):
            def build_request(self, method: str, url: Any, **kwargs: Any) -> httpx.Request:
                content_supplied = any(
                    kwargs.get(name) is not None for name in ("content", "data", "files", "json")
                )
                request = super().build_request(method, url, **kwargs)
                request.extensions[_CONTENT_SUPPLIED_EXTENSION] = content_supplied
                return request

        return _SignedClient(transport=_SigningTransport(base_client))

    def create_signed_async_http_client(
        self,
        base_headers: dict[str, str] | None = None,
        opts: HttpSigningOptions | None = None,
        transport_config: TransportConfig | None = None,
    ) -> httpx.AsyncClient:
        """Return an httpx.AsyncClient that auto-signs every outbound request.

        Args:
            base_headers: Default headers applied to every request.
            opts: Optional signing overrides applied to every request.
            transport_config: Optional DNS and TLS settings. Defaults to the
                configuration inherited by :meth:`from_identity_manager`.
                Custom hostname resolution supports ``host:port`` DNS servers;
                DoH URLs apply only to DNSid TXT lookups.

        Returns:
            An httpx.AsyncClient that signs each request before sending it.
        """
        import httpx

        from .manager import _make_async_sdk_transport

        profile = self
        signing_opts = opts

        class _AsyncSigningTransport(httpx.AsyncBaseTransport):
            def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
                self._inner = inner

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raw = await request.aread()
                content_supplied = bool(
                    request.extensions.get(_CONTENT_SUPPLIED_EXTENSION, bool(raw))
                )
                headers_dict = {k.decode(): v.decode() for k, v in request.headers.raw}
                raw_path = request.url.raw_path.decode()
                url = (
                    f"{request.url.scheme}://{headers_dict.get('host', request.url.host)}{raw_path}"
                )
                sdk_req = HttpRequest(
                    method=request.method,
                    url=url,
                    headers=headers_dict,
                    body=raw if content_supplied else None,
                )
                signed = profile.create_signed_http_request(sdk_req, signing_opts)
                new_request = httpx.Request(
                    method=signed.method,
                    url=signed.url,
                    headers=signed.headers,
                    content=signed.body or b"",
                    extensions=request.extensions,
                )
                return await self._inner.handle_async_request(new_request)

            async def aclose(self) -> None:
                await self._inner.aclose()

        class _SignedAsyncClient(httpx.AsyncClient):
            def build_request(self, method: str, url: Any, **kwargs: Any) -> httpx.Request:
                content_supplied = any(
                    kwargs.get(name) is not None for name in ("content", "data", "files", "json")
                )
                request = super().build_request(method, url, **kwargs)
                request.extensions[_CONTENT_SUPPLIED_EXTENSION] = content_supplied
                return request

        inner = _make_async_sdk_transport(transport_config or self._transport_config)
        transport = _AsyncSigningTransport(inner)
        return _SignedAsyncClient(headers=base_headers or {}, transport=transport)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    @verification_operation
    def verify_signed_http_request(
        self,
        req: HttpRequest,
        opts: HttpVerificationOptions | None = None,
        *,
        peer_cert: TLSCertificate | None = None,
    ) -> VerifiedDomain:
        """Verify an inbound HTTP request bearing an HTTP Message Signature (RFC 9421).

        Verifies the DNSid identity of the signer, then checks signature
        freshness, Content-Digest integrity, and the signature itself.

        Args:
            req: The inbound request to verify.
            opts: Optional verification requirements (required tag, required
                covered components).
            peer_cert: Certificate from the current peer connection. Required
                when the signer's DNSid record carries ``fl=mtls``.

        Returns:
            The VerifiedDomain for the signer's DNSid identity.

        Raises:
            VerificationError: If the Signature/Signature-Input headers are
                missing or malformed, the signature is stale or expired, the
                Content-Digest does not match the body, the key or algorithm
                cannot be validated, or the signature is invalid; also
                propagated from signer identity verification.  Carries a
                VerificationCode.
        """
        if opts is None:
            opts = HttpVerificationOptions()

        sig_input_header = req.get_header("signature-input")
        sig_header = req.get_header("signature")

        if not sig_input_header or not sig_header:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "missing Signature or Signature-Input headers",
            )

        # HttpRequest is already buffered: hosts must enforce these bounds while reading.
        if (
            len(sig_input_header) + len(sig_header) > 65536
            or len(req.get_header("content-digest")) > 16384
            or (req.body is not None and len(req.body) > 8 * 1024 * 1024)
        ):
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "HTTP signature input too large"
            )
        sig_inputs = SignatureParams.parse_dictionary(sig_input_header)
        signatures = _parse_signature_dictionary(sig_header)
        if (
            len(sig_inputs) > 16 or len(signatures) > 16
            or any(len(params.components) > 64 for params in sig_inputs.values())
        ):
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "HTTP signature limits exceeded"
            )
        complete = [params for label, params in sig_inputs.items() if label in signatures]
        candidates = [
            params
            for params in complete
            if opts.required_tag is None or params.tag == opts.required_tag
        ]
        if opts.required_tag is not None and not candidates and len(complete) == 1:
            if complete[0].tag is None:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "Signature-Input missing required `tag` parameter",
                )
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"Signature-Input tag mismatch: expected {opts.required_tag!r},"
                f" got {complete[0].tag!r}",
            )
        if not candidates:
            qualifier = f" with tag {opts.required_tag!r}" if opts.required_tag is not None else ""
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "expected at least one complete HTTP message signature"
                f"{qualifier}, found {len(candidates)}",
            )

        verified_domain: VerifiedDomain | None = None
        last_error: DNSidError | None = None
        for sig_params in candidates:
            try:
                candidate = self._verify_signature_candidate(
                    req, sig_params, signatures[sig_params.label], opts, peer_cert
                )
            except DNSidError as exc:
                last_error = exc
                continue
            if verified_domain is not None:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "multiple valid HTTP message signatures",
                )
            verified_domain = candidate

        if verified_domain is not None:
            return verified_domain
        if last_error is not None:
            raise last_error
        raise VerificationError(
            VerificationCode.SIGNATURE_INVALID,
            "no valid HTTP message signature",
        )

    def _verify_signature_candidate(
        self,
        req: HttpRequest,
        sig_params: SignatureParams,
        raw_sig: bytes,
        opts: HttpVerificationOptions,
        peer_cert: TLSCertificate | None,
    ) -> VerifiedDomain:
        for required in opts.required_components:
            if required not in sig_params.components:
                raise VerificationError(
                    VerificationCode.SIGNATURE_INVALID,
                    f"Signature-Input missing required covered component: {required}",
                )
        domain, kid = parse_key_id(sig_params.key_id)

        now_ts = int(_now().timestamp())
        if sig_params.created is None:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "Signature-Input missing required `created` parameter",
            )
        max_age = int(self._config.max_age.total_seconds())
        skew = int(self._config.clock_skew.total_seconds())

        if (now_ts - sig_params.created) > max_age:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "HTTP message signature has expired (created too far in the past)",
            )
        if sig_params.created > (now_ts + skew):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "HTTP message signature created time is in the future",
            )
        if sig_params.expires is not None and sig_params.expires < sig_params.created:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "HTTP message signature expires before created",
            )
        if sig_params.expires is not None and now_ts > (sig_params.expires + skew):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "HTTP message signature has expired (expires parameter)",
            )
        if sig_params.expires is not None and (sig_params.expires - sig_params.created) > max_age:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "HTTP message signature lifetime exceeds maximum allowed age",
            )

        if req.body is not None and "content-digest" not in sig_params.components:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "request body is present but content-digest is not covered by the signature",
            )
        if "content-digest" in sig_params.components:
            if req.body is None:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "content-digest is a covered component but request has no body",
                )
            digest_header = req.get_header("content-digest")
            if not digest_header:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "content-digest is a covered component but Content-Digest header is absent",
                )
            hashlib_alg, expected = _parse_content_digest(digest_header)
            actual = hashlib.new(hashlib_alg, req.body).digest()
            if not _constant_time_equal(expected, actual):
                raise VerificationError(
                    VerificationCode.SIGNATURE_INVALID,
                    "Content-Digest does not match request body",
                )

        verified_domain = (
            self._resolver.verify_domain(domain, peer_cert=peer_cert)
            if peer_cert is not None
            else self._resolver.verify_domain(domain)
        )

        signing_key = verified_domain.jwks.key_by_id(kid)
        if signing_key is None:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "request kid not found in signer JWKS",
            )

        expected_http_alg = jose_alg_to_http_sig_alg(signing_key.signature_alg())
        if sig_params.alg and sig_params.alg != expected_http_alg:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"HTTP sig alg mismatch: Signature-Input declares {sig_params.alg!r} "
                f"but key maps to {expected_http_alg!r}",
            )

        sig_base = _build_signature_base(req, sig_params)
        if not signing_key.verify(sig_base, raw_sig):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "HTTP message signature invalid",
            )

        return verified_domain


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _generate_nonce() -> str:
    from ._utils import b64url_encode

    return b64url_encode(os.urandom(32))


def _build_signature_base(req: HttpRequest, params: SignatureParams) -> bytes:
    from urllib.parse import parse_qsl, quote, urlsplit

    _validate_component_identifiers(params.components, request_context=False)

    lines: list[str] = []
    for component in params.components:
        name, component_parameters = _parse_component_identifier(component)
        parameter_values = dict(component_parameters)
        identifier = _canonical_component_identifier(component)
        if name == "@method":
            value = req.method
        elif name == "@authority":
            authority = _resolve_authority(req)
            value = authority
        elif name == "@target-uri":
            value = req.url
        elif name == "@path":
            path = urlsplit(req.url).path or "/"
            value = path
        elif name == "@query":
            q = urlsplit(req.url).query
            value = "?" + q if q else "?"
        elif name == "@request-target":
            parsed = urlsplit(req.url)
            value = parsed.path or "/"
            if parsed.query:
                value += "?" + parsed.query
        elif name == "@scheme":
            value = urlsplit(req.url).scheme.lower()
        elif name == "@query-param":
            selected_name = str(parameter_values["name"])
            decoded_name = __import__("urllib.parse", fromlist=["unquote_plus"]).unquote_plus(
                selected_name
            )
            matches = [
                value
                for key, value in parse_qsl(urlsplit(req.url).query, keep_blank_values=True)
                if key == decoded_name
            ]
            if len(matches) != 1:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "@query-param selected parameter must be present exactly once",
                )
            value = quote(matches[0], safe="-._~")
        elif name.startswith("@"):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"unsupported or unavailable derived component: {name!r}",
            )
        else:
            if not req.has_header(name):
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    f"covered component header is absent from the message: {name!r}",
                )
            if "key" not in parameter_values:
                value = req.get_header(name)
            else:
                # RFC 9421 §2.1.2 'key' parameter: the component value is the
                # serialized member value selected from the field parsed as an
                # RFC 8941 Dictionary.
                member = str(parameter_values["key"])
                member_value = _sf_dictionary_member(req.get_header(name), member)
                if member_value is None:
                    raise VerificationError(
                        VerificationCode.RECORD_INVALID,
                        f"field {name!r} has no dictionary member {member!r}",
                    )
                value = member_value
        lines.append(f"{identifier}: {value}")

    lines.append(f'"@signature-params": {params.value_string()}')
    return "\n".join(lines).encode("utf-8")


def _replace_signature_input_member(header: str, params: SignatureParams) -> str:
    members = SignatureParams.parse_dictionary(header) if header else {}
    members[params.label] = params
    return ", ".join(member.serialize() for member in members.values())


def _replace_signature_member(header: str, label: str, signature: bytes) -> str:
    members = _parse_signature_dictionary(header) if header else {}
    members[label] = signature
    return ", ".join(f"{name}=:{b64_std_encode(value)}:" for name, value in members.items())


def _sf_dictionary_member(field_value: str, member: str) -> str | None:
    """Return the serialized value of *member* in an RFC 8941 Dictionary field.

    Splits members quote-aware; returns the member's serialized value (for a
    member without a value, the bare-key form serializes as Boolean true,
    "?1").  Returns None when the member is absent.
    """
    import http_sf

    try:
        dictionary = _parse_sf_dictionary(field_value)
    except ValueError as exc:
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            f"malformed Structured Fields Dictionary: {exc}",
        ) from exc
    selected = dictionary.get(member)
    if selected is None:
        return None
    if not (isinstance(selected, tuple) and len(selected) == 2):
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            f"dictionary member {member!r} is not an Item",
        )
    return http_sf.ser(selected)


def _resolve_authority(req: HttpRequest) -> str:
    """Derive @authority per RFC 9421 §2.2.3: lowercase host, omit default ports."""
    from urllib.parse import urlsplit

    host_header = req.get_header("host")
    if host_header:
        return _normalize_authority(host_header, urlsplit(req.url).scheme)
    parsed = urlsplit(req.url)
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port and not (
        (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    ):
        return f"{host}:{port}"
    return host


def _normalize_authority(authority: str, scheme: str) -> str:
    """Lowercase host and strip default port from an authority string."""
    # Split host:port — careful with IPv6 brackets
    host, sep, port_str = authority.rpartition(":")
    if sep and ":" not in host and port_str.isdigit():
        host = host.lower()
        if (scheme == "https" and port_str == "443") or (scheme == "http" and port_str == "80"):
            return host
        return f"{host}:{port_str}"
    return authority.lower()


def _extract_signature_bytes(sig_header: str, label: str) -> bytes:
    """Extract the signature bytes for *label* from a Signature header value.

    Uses quote-aware splitting so that commas inside quoted strings or
    base64 byte sequences are not treated as member separators.
    Rejects duplicate labels per RFC 9421 (dictionary keys must be unique).
    """
    signatures = _parse_signature_dictionary(sig_header)
    if label in signatures:
        return signatures[label]
    raise VerificationError(
        VerificationCode.SIGNATURE_INVALID,
        f"Signature header missing entry for label {label!r}",
    )


def _parse_signature_dictionary(sig_header: str) -> dict[str, bytes]:
    """Parse every byte-sequence member of an RFC 9421 Signature dictionary."""
    try:
        dictionary = _parse_sf_dictionary(sig_header)
    except ValueError as exc:
        raise VerificationError(
            VerificationCode.SIGNATURE_INVALID,
            f"malformed Signature dictionary: {exc}",
        ) from exc
    result: dict[str, bytes] = {}
    for label, member in dictionary.items():
        if not (
            isinstance(member, tuple)
            and len(member) == 2
            and isinstance(member[0], bytes)
            and member[1] == {}
        ):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"Signature member {label!r} must be an unparameterized byte sequence",
            )
        result[label] = member[0]
    return result


def _parse_content_digest(header_value: str) -> tuple[str, bytes]:
    try:
        dictionary = _parse_sf_dictionary(header_value)
    except ValueError as exc:
        raise VerificationError(
            VerificationCode.SIGNATURE_INVALID,
            f"malformed Content-Digest header: {header_value!r}: {exc}",
        ) from exc
    selected = dictionary.get("sha-256")
    if not (isinstance(selected, tuple) and len(selected) == 2 and isinstance(selected[0], bytes)):
        raise VerificationError(
            VerificationCode.SIGNATURE_INVALID,
            "Content-Digest does not contain the required sha-256 member",
        )
    return "sha256", selected[0]


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    import hmac

    return hmac.compare_digest(a, b)
