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

import asyncio
import datetime
import hashlib
import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Any

import httpx

from ._utils import (
    b64_std_encode,
    jose_alg_to_http_sig_alg,
    normalize_fqdn,
    parse_key_id,
)
from ._verification_budget import async_verification_operation, verification_operation
from .enums import VerificationCode
from .exceptions import ArgumentError, DNSidError, ValidationError, VerificationError
from .interfaces import AsyncIdentityResolver, IdentityResolver, KeyProvider
from .models import (
    JWK,
    HttpRequest,
    HttpSigningOptions,
    HttpVerificationOptions,
    ResponseSignatureOptions,
    SignatureParams,
    TLSCertificate,
    TransportConfig,
    VerifiedDomain,
    _canonical_component_identifier,
    _component_structure,
    _parse_component_identifier,
    _parse_sf_dictionary,
    _validate_component_identifiers,
)

_CONTENT_SUPPLIED_EXTENSION = "dnsid.content_supplied"


class _SyncReplayStream(httpx.ByteStream):
    def __init__(self, content: bytes, original_close: Callable[[], None]) -> None:
        super().__init__(content)
        self.original_close = original_close

    def close(self) -> None:
        self.original_close()


class _AsyncReplayStream(httpx.ByteStream):
    def __init__(self, content: bytes, original_close: Callable[[], Awaitable[None]]) -> None:
        super().__init__(content)
        self.original_close = original_close

    async def aclose(self) -> None:
        await self.original_close()


@dataclass
class HttpMessageSignatureConfig:
    """Freshness settings for the HTTP Message Signature profile (RFC 9421)."""

    max_age: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(seconds=300))
    clock_skew: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(seconds=5))

    def __post_init__(self) -> None:
        """Reject freshness settings outside the profile bounds."""
        if not isinstance(self.max_age, datetime.timedelta) or self.max_age.total_seconds() <= 0:
            raise ArgumentError("HTTP message signature max_age must be positive")
        if (
            not isinstance(self.clock_skew, datetime.timedelta)
            or self.clock_skew.total_seconds() < 0
        ):
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
        resolver: IdentityResolver | AsyncIdentityResolver,
        key_provider: KeyProvider | None,
        domain: str,
        config: HttpMessageSignatureConfig | None = None,
        transport_config: TransportConfig | None = None,
    ) -> None:
        """Initialize the profile for a local DNSid identity.

        Args:
            resolver: An IdentityResolver or AsyncIdentityResolver. Sync verification
                requires IdentityResolver; async verification accepts either.
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
        by the signature. With response_signature set, requires HTTPS and prepares
        Accept-Signature; this helper does not send or verify a response. Retain
        an unmodified prepared request and original policy snapshot for the
        standalone response verifier.

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

        if opts.response_signature is None:
            return self._sign_http_request(req, opts)
        # Negotiated preparation is atomic: a failure leaves the caller's request unchanged.
        original = req.headers.copy()
        try:
            return self._sign_http_request(req, opts)
        except BaseException:
            req.headers = original
            raise

    def _sign_http_request(self, req: HttpRequest, opts: HttpSigningOptions) -> HttpRequest:
        if opts.response_signature is not None:
            _prepare_response_negotiation(req, opts.response_signature, opts.label)

        key_provider = self._require_signing_provider()
        signing_key = key_provider.signing_key()
        if "#" in signing_key.kid:
            raise ArgumentError("signing key kid must not contain '#'")

        components = ["@method", "@authority", "@target-uri"]
        if opts.response_signature is not None:
            components.append("accept-signature")

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
            A new httpx.Client that signs each request before sending it. Content
            is buffered up to 8 MiB; replay streams retain original cleanup. The
            base client and its transport remain caller-owned. With response_signature,
            snapshots policy and verifies every response (including HTTP errors)
            before returning it. Disables redirects/auth resends and rejects transports
            other than HTTPX/SDK transports with retries=0 or MockTransport. Does not
            inherit base-client hooks, mounts, authentication flows, or caches.
            Uses a shared 30-second budget and 8 MiB raw/decoded response limits.
        """
        import httpx

        if opts is not None and opts.response_signature is not None:
            from ._negotiated_http_client import signed_client

            return signed_client(self, base_client, opts)

        profile = self
        signing_opts = opts

        class _SigningTransport(httpx.BaseTransport):
            def __init__(self, inner: httpx.Client) -> None:
                self._inner = inner

            def handle_request(self, request: httpx.Request) -> httpx.Response:
                original_stream = request.stream
                assert isinstance(original_stream, httpx.SyncByteStream)
                original_close = (
                    original_stream.original_close
                    if isinstance(original_stream, _SyncReplayStream) else original_stream.close
                )
                body = bytearray()
                try:
                    for chunk in original_stream:
                        if len(body) + len(chunk) > 8 * 1024 * 1024:
                            raise ArgumentError("HTTP signing content exceeds 8 MiB")
                        body.extend(chunk)
                except BaseException:
                    original_close()
                    raise

                replay = _SyncReplayStream(bytes(body), original_close)
                request.stream = replay
                request.read()
                request.stream = replay
                content_supplied = bool(body) or bool(request.extensions.get(
                    _CONTENT_SUPPLIED_EXTENSION, type(original_stream) is not httpx.ByteStream,
                ))
                request.extensions[_CONTENT_SUPPLIED_EXTENSION] = content_supplied
                sdk_req = HttpRequest(
                    method=request.method, url=str(request.url), headers=dict(request.headers),
                    body=request.content if content_supplied else None,
                )
                signed = profile.create_signed_http_request(sdk_req, signing_opts)
                new_request = request.__class__(
                    method=signed.method,
                    url=signed.url,
                    headers=signed.headers,
                    content=signed.body or b"",
                    extensions=request.extensions,
                )
                new_request.stream = replay
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
        *, transport: httpx.AsyncBaseTransport | None = None,
    ) -> httpx.AsyncClient:
        """Return an httpx.AsyncClient that auto-signs every outbound request.

        Args:
            base_headers: Default headers applied to every request.
            opts: Optional signing overrides applied to every request.
            transport_config: Optional DNS and TLS settings. Defaults to the
                configuration inherited by :meth:`from_identity_manager`.
                Custom hostname resolution supports ``host:port`` DNS servers;
                DoH URLs apply only to DNSid TXT lookups.
            transport: Optional outbound transport, for example MockTransport or
                a proxy-configured AsyncHTTPTransport. The returned client owns
                and closes it, as with httpx.AsyncClient. An injected transport
                handles its own DNS/TLS settings; transport_config is rejected
                when supplied together with it.

        Returns:
            An httpx.AsyncClient that signs each request before sending it.
            Content is buffered up to 8 MiB; replay streams retain original cleanup.
            With response_signature, snapshots policy and verifies every response
            before return, including errors. Disables redirects/auth resends; accepts
            only HTTPX/SDK transports with retries=0 or MockTransport. The shared
            budget defaults to 30 seconds; raw and decoded content are each capped
            at 8 MiB. Rejected/cancelled responses are closed, never cached.
        """
        import httpx

        from .manager import _make_async_sdk_transport

        if opts is not None and opts.response_signature is not None:
            from ._negotiated_http_client import signed_async_client

            if transport is not None and transport_config is not None:
                raise ArgumentError("transport and transport_config are mutually exclusive")
            inner = transport if transport is not None else _make_async_sdk_transport(
                transport_config or self._transport_config
            )
            return signed_async_client(self, inner, opts, base_headers)

        profile = self
        signing_opts = opts

        class _AsyncSigningTransport(httpx.AsyncBaseTransport):
            def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
                self._inner = inner

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                original_stream = request.stream
                assert isinstance(original_stream, httpx.AsyncByteStream)
                original_close = (
                    original_stream.original_close
                    if isinstance(original_stream, _AsyncReplayStream) else original_stream.aclose
                )
                body = bytearray()
                try:
                    async for chunk in original_stream:
                        if len(body) + len(chunk) > 8 * 1024 * 1024:
                            raise ArgumentError("HTTP signing content exceeds 8 MiB")
                        body.extend(chunk)
                except BaseException:
                    await original_close()
                    raise

                replay = _AsyncReplayStream(bytes(body), original_close)
                request.stream = replay
                raw = await request.aread()
                request.stream = replay
                content_supplied = bool(body) or bool(request.extensions.get(
                    _CONTENT_SUPPLIED_EXTENSION, type(original_stream) is not httpx.ByteStream,
                ))
                request.extensions[_CONTENT_SUPPLIED_EXTENSION] = content_supplied
                headers_dict = dict(request.headers)
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
                signed = await asyncio.to_thread(
                    profile.create_signed_http_request, sdk_req, signing_opts
                )
                new_request = httpx.Request(
                    method=signed.method,
                    url=signed.url,
                    headers=signed.headers,
                    content=signed.body or b"",
                    extensions=request.extensions,
                )
                new_request.stream = replay
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

        if transport is not None and transport_config is not None:
            raise ArgumentError("transport and transport_config are mutually exclusive")
        inner = transport if transport is not None else _make_async_sdk_transport(
            transport_config or self._transport_config
        )
        signing_transport = _AsyncSigningTransport(inner)
        return _SignedAsyncClient(headers=base_headers or {}, transport=signing_transport)

    @verification_operation
    def sign_requested_http_response(
        self, request: HttpRequest, response: HttpRequest,
    ) -> HttpRequest:
        """Fulfill one strict RFC 9421 response signature request atomically.

        Args:
            request: Trusted originating request, with its final signature fields.
            response: Final buffered response, represented by HttpRequest with status.
                Finalize content coding and covered fields before calling this method.

        Returns:
            The same response, unchanged when Accept-Signature is absent. Otherwise
            sets Content-Digest, adds no-store, and signs with the operational key.

        Raises:
            VerificationError: Malformed/unsupported peer negotiation, unavailable
                content or fields, colliding label, unsupported status, or resource limit.
            ArgumentError: Missing signing configuration or a key change during signing.
        """
        if not request.has_header("accept-signature"):
            return response
        challenge = _parse_response_negotiation(request)
        _check_message_limits(response)
        inputs = response.get_header("signature-input")
        signatures = response.get_header("signature")
        if (
            challenge.label in (SignatureParams.parse_dictionary(inputs) if inputs else {})
            or challenge.label in (_parse_signature_dictionary(signatures) if signatures else {})
        ):
            raise _response_error("requested response signature label already exists")
        content = _response_content(request, response, signing=True)
        staged = replace(response, headers=response.headers.copy(), body=content)
        digest = b64_std_encode(hashlib.sha256(content).digest())
        staged.set_header("content-digest", f"sha-256=:{digest}:")
        cache = staged.get_header("cache-control")
        if not _has_no_store(cache):
            staged.set_header("cache-control", f"{cache}, no-store" if cache else "no-store")
        provider = self._require_signing_provider()
        key = JWK.from_dict(provider.signing_key().to_dict())
        if not key.kid or "#" in key.kid:
            raise ArgumentError("signing key kid must be nonempty and must not contain '#'")
        lifetime = _RESPONSE_SIGNATURE_LIFETIME
        now = int(_now().timestamp())
        params = SignatureParams(
            label=challenge.label, components=challenge.components,
            nonce=challenge.nonce, created=now, expires=now + lifetime,
            key_id=f"{self._domain}#{key.kid}",
            alg=jose_alg_to_http_sig_alg(key.signature_alg()),
        )
        base = _build_signature_base(staged, params, request_context=request)
        signature = provider.sign(base)
        if not key.verify(base, signature):
            raise ArgumentError("response signing key changed during signing")
        if _now().timestamp() >= now + lifetime:
            raise ArgumentError("response signature expired during signing")
        staged.set_header("signature-input", _replace_signature_input_member(inputs, params))
        staged.set_header(
            "signature", _replace_signature_member(signatures, params.label, signature),
        )
        self._signature_candidates(staged, HttpVerificationOptions())
        # Commit only after all validation, signing, and output bounds checks succeed.
        response.headers = staged.headers
        return response

    @verification_operation
    def verify_signed_http_response(
        self, request: HttpRequest, response: HttpRequest, opts: ResponseSignatureOptions,
        *, peer_cert: TLSCertificate | None = None,
    ) -> VerifiedDomain:
        """Verify the requested response label against local identity policy.

        Args:
            request: Unmodified prepared originating request. Standalone callers must
                retain this request and the original policy snapshot for this invocation.
            response: Actual buffered response (HttpRequest with status). None content
                is accepted only for HEAD, 204, or 304, never for an unavailable body.
            opts: Original expected domain and additional coverage policy.
            peer_cert: Trusted server certificate from the current application connection.

        Returns:
            Verified DNSid identity after signature, digest, and no-store checks.
            Uncovered metadata, including Content-Type and Location, is not authenticated.

        Raises:
            ArgumentError: Invalid local policy or non-HTTPS target.
            VerificationError: Missing/invalid negotiation or response authentication.
                Resolver failures retain their native classification.
        """
        params, signature, domain, kid = self._response_verification_input(request, response, opts)
        if not isinstance(self._resolver, IdentityResolver):
            raise ArgumentError("synchronous verification requires an IdentityResolver")
        resolved = self._resolver.verify_domain(domain, **(
            {"peer_cert": peer_cert} if peer_cert is not None else {}
        ))
        return self._finish_response_verification(
            request, response, params, signature, kid, resolved,
        )

    @async_verification_operation
    async def async_verify_signed_http_response(
        self, request: HttpRequest, response: HttpRequest, opts: ResponseSignatureOptions,
        *, peer_cert: TLSCertificate | None = None,
    ) -> VerifiedDomain:
        """Verify a response with async resolution and the standalone snapshot contract.

        Uses the same policy, bounds, current-peer evidence, and checks as
        verify_signed_http_response. Sync-only resolvers run in a worker.
        """
        params, signature, domain, kid = self._response_verification_input(request, response, opts)
        if isinstance(self._resolver, AsyncIdentityResolver):
            resolved = await self._resolver.async_verify_domain(domain, peer_cert=peer_cert)
        else:
            resolved = await asyncio.to_thread(self._resolver.verify_domain, domain, **(
                {"peer_cert": peer_cert} if peer_cert is not None else {}
            ))
        return self._finish_response_verification(
            request, response, params, signature, kid, resolved,
        )

    def _response_verification_input(
        self, request: HttpRequest, response: HttpRequest, opts: ResponseSignatureOptions,
    ) -> tuple[SignatureParams, bytes, str, str]:
        policy = _response_policy(opts)
        _require_https(request)
        challenge = _parse_response_negotiation(request)
        requested = {_component_identity(c) for c in challenge.components}
        if not all(_component_identity(c) in requested for c in policy.additional_components):
            raise _response_error("saved negotiation omits locally required response coverage")
        _check_message_limits(response)
        candidates, signatures = self._signature_candidates(response, HttpVerificationOptions())
        selected = next((p for p in candidates if p.label == challenge.label), None)
        if selected is None:
            raise _response_error("response is missing the requested complete signature")
        if (
            [_component_identity(c) for c in selected.components]
            != [_component_identity(c) for c in challenge.components]
            or selected.nonce != challenge.nonce
        ):
            raise _response_error("response components or nonce differ from the saved challenge")
        self._check_response_freshness(selected)
        if selected.alg not in {"ed25519", "ecdsa-p256-sha256"}:
            raise _response_error("response signature requires a supported alg")
        try:
            domain, kid = parse_key_id(selected.key_id)
        except (ArgumentError, ValidationError) as exc:
            raise _response_error("response requires a valid compound keyid") from exc
        if domain != policy.expected_domain:
            raise _response_error("response keyid domain differs from expected_domain")
        return selected, signatures[selected.label], domain, kid

    def _finish_response_verification(
        self, request: HttpRequest, response: HttpRequest, params: SignatureParams,
        signature: bytes, kid: str, resolved: VerifiedDomain,
    ) -> VerifiedDomain:
        self._verify_candidate_signature(response, params, signature, kid, resolved, request)
        content = _response_content(request, response)
        _check_content_digest(replace(response, body=content), params)
        if not _has_no_store(response.get_header("cache-control")):
            raise _response_error("signed response Cache-Control must contain no-store")
        self._check_response_freshness(params)
        return resolved

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
        opts = opts or HttpVerificationOptions()
        candidates, signatures = self._signature_candidates(req, opts)
        digest_matches: dict[str, bool] = {}
        verified_domain: VerifiedDomain | None = None
        last_error: DNSidError | None = None
        for sig_params in candidates:
            try:
                candidate = self._verify_signature_candidate(
                    req, sig_params, signatures[sig_params.label], opts, peer_cert, digest_matches
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

    @async_verification_operation
    async def async_verify_signed_http_request(
        self, req: HttpRequest, opts: HttpVerificationOptions | None = None,
        *, peer_cert: TLSCertificate | None = None,
    ) -> VerifiedDomain:
        """Verify inbound signatures using async identity resolution.

        Local validation is shared with the synchronous verifier. Legacy
        synchronous resolvers run in a worker; async resolvers are awaited.
        """
        opts = opts or HttpVerificationOptions()
        candidates, signatures = self._signature_candidates(req, opts)
        digest_matches: dict[str, bool] = {}
        verified_domain: VerifiedDomain | None = None
        last_error: DNSidError | None = None
        for sig_params in candidates:
            try:
                domain, kid = self._verify_candidate_input(req, sig_params, opts, digest_matches)
                if isinstance(self._resolver, AsyncIdentityResolver):
                    resolved = await self._resolver.async_verify_domain(domain, peer_cert=peer_cert)
                else:
                    resolved = await asyncio.to_thread(
                        self._resolver.verify_domain, domain, **(
                            {"peer_cert": peer_cert} if peer_cert is not None else {}
                        )
                    )
                candidate = self._verify_candidate_signature(
                    req, sig_params, signatures[sig_params.label], kid, resolved
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

    def _signature_candidates(
        self, req: HttpRequest, opts: HttpVerificationOptions
    ) -> tuple[list[SignatureParams], dict[str, bytes]]:
        sig_input_header = req.get_header("signature-input")
        sig_header = req.get_header("signature")

        if not sig_input_header or not sig_header:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "missing Signature or Signature-Input headers",
            )

        _check_message_limits(req)
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

        return candidates, signatures

    def _verify_signature_candidate(
        self,
        req: HttpRequest,
        sig_params: SignatureParams,
        raw_sig: bytes,
        opts: HttpVerificationOptions,
        peer_cert: TLSCertificate | None,
        digest_matches: dict[str, bool],
    ) -> VerifiedDomain:
        domain, kid = self._verify_candidate_input(req, sig_params, opts, digest_matches)
        if not isinstance(self._resolver, IdentityResolver):
            raise ArgumentError("synchronous verification requires an IdentityResolver")
        verified_domain = (
            self._resolver.verify_domain(domain, peer_cert=peer_cert)
            if peer_cert is not None
            else self._resolver.verify_domain(domain)
        )
        return self._verify_candidate_signature(req, sig_params, raw_sig, kid, verified_domain)

    def _verify_candidate_input(
        self, req: HttpRequest, sig_params: SignatureParams, opts: HttpVerificationOptions,
        digest_matches: dict[str, bool],
    ) -> tuple[str, str]:
        for required in opts.required_components:
            if required not in sig_params.components:
                raise VerificationError(
                    VerificationCode.SIGNATURE_INVALID,
                    f"Signature-Input missing required covered component: {required}",
                )
        domain, kid = parse_key_id(sig_params.key_id)

        self._check_freshness(sig_params)
        _check_content_digest(req, sig_params, digest_matches)
        return domain, kid

    def _check_response_freshness(self, sig_params: SignatureParams) -> None:
        """Apply the fixed response lifetime, then local created-age and skew policy."""
        created, expires = sig_params.created, sig_params.expires
        if (
            type(created) is not int or type(expires) is not int
            or not 0 < expires - created <= _RESPONSE_SIGNATURE_LIFETIME
        ):
            raise _response_error("response signature lifetime must be 1 to 60 seconds")
        self._check_freshness(replace(sig_params, expires=None))
        if int(_now().timestamp()) > expires + int(self._config.clock_skew.total_seconds()):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID, "response signature has expired",
            )

    def _check_freshness(self, sig_params: SignatureParams) -> None:
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

    def _verify_candidate_signature(
        self, req: HttpRequest, sig_params: SignatureParams, raw_sig: bytes,
        kid: str, verified_domain: VerifiedDomain,
        request_context: HttpRequest | None = None,
    ) -> VerifiedDomain:
        signing_key = verified_domain.jwks.key_by_id(kid)
        if signing_key is None:
            raise VerificationError(
                VerificationCode.KEY_NOT_FOUND,
                "request kid not found in signer JWKS",
            )

        expected_http_alg = jose_alg_to_http_sig_alg(signing_key.signature_alg())
        if sig_params.alg and sig_params.alg != expected_http_alg:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                f"HTTP sig alg mismatch: Signature-Input declares {sig_params.alg!r} "
                f"but key maps to {expected_http_alg!r}",
            )

        sig_base = _build_signature_base(req, sig_params, request_context=request_context)
        if not signing_key.verify(sig_base, raw_sig):
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID,
                "HTTP message signature invalid",
            )

        return verified_domain


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _response_components(request_label: str) -> list[str]:
    """Required response coverage; the key selects the client's request signature member."""
    key = json.dumps(request_label)
    return [
        "@status", "@method;req", "@authority;req", "@target-uri;req", "accept-signature;req",
        f"signature-input;req;key={key}", f"signature;req;key={key}",
        "content-digest", "cache-control",
    ]


# Fixed so peers with different max_age settings interoperate.
_RESPONSE_SIGNATURE_LIFETIME = 60
_NO_CONTENT_STATUSES = frozenset({204, 205, 304})
_MAX_BODY = 8 * 1024 * 1024
_MAX_ACCEPT_SIGNATURE = 16384
_MAX_NONCE = 1024


def _response_error(message: str) -> VerificationError:
    return VerificationError(VerificationCode.SIGNATURE_INVALID, message)


def _component_identity(component: str) -> tuple[str, frozenset[tuple[str, Any]]]:
    name, parameters = _parse_component_identifier(component)
    return name, frozenset(parameters)


def _validate_response_components(components: list[str]) -> None:
    if len(components) > 64:
        raise _response_error("response component limit exceeded")
    _validate_component_identifiers(components, request_context=True)
    for component in components:
        name, parameters = _parse_component_identifier(component)
        req = dict(parameters).get("req") is True
        if name.startswith("@") and name != "@status" and not req:
            raise _response_error("request derived response components require req")
        # The response signature fields are written by signing, so they cannot cover themselves.
        if name in {"signature", "signature-input"} and not req:
            raise _response_error("response components cannot cover response signature fields")


def _response_policy(
    opts: ResponseSignatureOptions, request_label: str = "sig1",
) -> ResponseSignatureOptions:
    if (
        not isinstance(opts, ResponseSignatureOptions)
        or not isinstance(opts.expected_domain, str)
        or not isinstance(opts.additional_components, list)
        or any(not isinstance(c, str) for c in opts.additional_components)
    ):
        raise ArgumentError("invalid ResponseSignatureOptions")
    try:
        domain = normalize_fqdn(opts.expected_domain, agent_fqdn=True)
        # Validate additions separately so equivalent required components are not duplicated.
        additions: list[str] = []
        required = _response_components(request_label)
        identities = {_component_identity(c) for c in required}
        for component in opts.additional_components:
            _validate_response_components([component])
            identity = _component_identity(component)
            if identity not in identities:
                additions.append(component)
                identities.add(identity)
        _validate_response_components(required + additions)
    except (ValidationError, VerificationError, ValueError) as exc:
        raise ArgumentError(str(exc)) from exc
    return ResponseSignatureOptions(domain, additions)


def _require_https(request: HttpRequest) -> None:
    from urllib.parse import urlsplit

    try:
        url = urlsplit(request.url)
        if url.scheme == "https" and url.hostname and url.port != 0:
            return
    except ValueError:
        pass
    raise ArgumentError("negotiated response authentication requires an HTTPS target")


def _prepare_response_negotiation(
    request: HttpRequest, opts: ResponseSignatureOptions, request_label: str,
) -> None:
    import http_sf

    policy = _response_policy(opts, request_label)
    _require_https(request)
    if request.has_header("accept-signature"):
        raise ArgumentError("Accept-Signature is already present")
    _check_message_limits(request)
    components = _response_components(request_label) + policy.additional_components
    value: Any = {"sig1": (
        [_component_structure(c) for c in components],
        {"created": True, "expires": True, "nonce": _generate_nonce()},
    )}
    header = http_sf.ser(value)
    if len(header) > _MAX_ACCEPT_SIGNATURE:
        raise ArgumentError("Accept-Signature exceeds 16 KiB")
    request.set_header("accept-signature", header)


def _parse_response_negotiation(request: HttpRequest) -> SignatureParams:
    from ._utils import b64url_decode, b64url_encode

    header = request.get_header("accept-signature")
    if len(header) > _MAX_ACCEPT_SIGNATURE:
        raise _response_error("Accept-Signature exceeds 16 KiB")
    _check_message_limits(request)
    try:
        dictionary = _parse_sf_dictionary(header, reject_duplicate_parameters=True)
    except ValueError as exc:
        raise _response_error(f"malformed Accept-Signature: {exc}") from exc
    if len(dictionary) != 1:
        raise _response_error("Accept-Signature requires exactly one member")
    label, member = next(iter(dictionary.items()))
    if not (isinstance(member, tuple) and isinstance(member[0], list)):
        raise _response_error("Accept-Signature member must be an Inner List")
    items, parameters = member
    if (
        set(parameters) != {"created", "expires", "nonce"}
        or parameters["created"] is not True or parameters["expires"] is not True
    ):
        raise _response_error("Accept-Signature requires only true time flags and nonce")
    nonce = parameters["nonce"]
    if not isinstance(nonce, str) or not 43 <= len(nonce) <= _MAX_NONCE:
        raise _response_error(
            "response nonce must be canonical base64url of 32+ bytes, at most 1024 characters",
        )
    try:
        decoded = b64url_decode(nonce)
        if len(decoded) < 32 or b64url_encode(decoded) != nonce:
            raise ValueError("noncanonical or short nonce")
    except (ValueError, DNSidError) as exc:
        raise _response_error("invalid response challenge nonce") from exc
    # Reuse the signature member parser, substituting integers for request-only time flags.
    parsed = SignatureParams._from_structured_member(label, (
        items, {**parameters, "created": 0, "expires": 0},
    ))
    _validate_response_components(parsed.components)
    identities = {_component_identity(c) for c in parsed.components}
    request_label = _requested_signature_member(parsed.components)
    if not all(_component_identity(c) in identities for c in _response_components(request_label)):
        raise _response_error("Accept-Signature omits required response components")
    return parsed


def _requested_signature_member(components: list[str]) -> str:
    """Return the one request signature member bound by matching signature-input/signature keys."""
    keys: dict[str, list[str]] = {"signature-input": [], "signature": []}
    for component in components:
        name, parameters = _parse_component_identifier(component)
        values = dict(parameters)
        if name in keys and values.get("req") is True and isinstance(values.get("key"), str):
            keys[name].append(values["key"])
    if (
        len(keys["signature-input"]) != 1 or len(keys["signature"]) != 1
        or keys["signature-input"] != keys["signature"]
    ):
        raise _response_error("response negotiation must bind one request signature member")
    return keys["signature"][0]


def _check_message_limits(message: HttpRequest) -> None:
    # Already-buffered messages: hosts must also bound allocation while reading.
    if (
        len(message.get_header("signature-input")) + len(message.get_header("signature")) > 65536
        or len(message.get_header("content-digest")) > 16384
        or (message.body is not None and len(message.body) > _MAX_BODY)
    ):
        raise VerificationError(VerificationCode.RECORD_INVALID, "HTTP signature input too large")


def _response_content(
    request: HttpRequest, response: HttpRequest, *, signing: bool = False,
) -> bytes:
    _check_message_limits(response)
    if (
        type(response.status) is not int or not 200 <= response.status <= 599
        or (request.method.upper() == "CONNECT" and 200 <= response.status < 300)
    ):
        raise _response_error("negotiated authentication requires an ordinary final response")
    if request.method.upper() == "HEAD" or response.status in _NO_CONTENT_STATUSES:
        # A signer ignores supplied content; a verifier rejects delivered content.
        if response.body and not signing:
            raise _response_error("no-content response contains content")
        return b""
    if response.body is None:
        raise _response_error("ordinary response content is unavailable")
    return response.body


def _has_no_store(cache_control: str) -> bool:
    # Cache-Control is an HTTP list, not a Structured Field; quoted commas cannot create directives.
    import re

    tokens = re.findall(r'"(?:[^"\\]|\\.)*"|[^,"\\]+|,', cache_control)
    if "".join(tokens) != cache_control:
        return False
    directives: list[str] = []
    current = ""
    for part in tokens:
        if part == ",":
            directives.append(current.strip().lower())
            current = ""
        else:
            current += part
    directives.append(current.strip().lower())
    return "no-store" in directives


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _generate_nonce() -> str:
    from ._utils import b64url_encode

    return b64url_encode(os.urandom(32))


def _build_signature_base(
    req: HttpRequest, params: SignatureParams, request_context: HttpRequest | None = None
) -> bytes:
    from urllib.parse import parse_qsl, quote, unquote_plus, urlsplit

    _validate_component_identifiers(
        params.components, request_context=req.status is not None or request_context is not None
    )

    response = req
    lines: list[str] = []
    for component in params.components:
        name, component_parameters = _parse_component_identifier(component)
        parameter_values = dict(component_parameters)
        identifier = _canonical_component_identifier(component)
        req = response
        if "req" in parameter_values:
            if request_context is None:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID, "originating request is unavailable",
                )
            req = request_context
        elif response.status is not None and name.startswith("@") and name != "@status":
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "request derived component requires req",
            )
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
            decoded_name = unquote_plus(selected_name)
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
            value = quote(matches[0], safe="*-._").replace("~", "%7E")
        elif name == "@status":
            if type(response.status) is not int or not 100 <= response.status <= 599:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID, "actual response status is unavailable",
                )
            value = str(response.status)
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
    if isinstance(selected[0], list):
        # http_sf.ser treats every 2-tuple as an Item; serialize Inner Lists in a Dictionary.
        return http_sf.ser({member: selected})[len(member) + 1:]
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


def _check_content_digest(
    message: HttpRequest, params: SignatureParams,
    digest_matches: dict[str, bool] | None = None,
) -> None:
    if message.body is not None and "content-digest" not in params.components:
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            "supplied content requires covered Content-Digest",
        )
    if any(_parse_component_identifier(component)[0] == "content-digest"
           for component in params.components):
        if message.body is None:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "covered Content-Digest requires supplied content",
            )
        if not message.has_header("content-digest"):
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "covered Content-Digest header is absent",
            )
        header = message.get_header("content-digest")
        if digest_matches is None:
            digest_matches = {}
        if header not in digest_matches:
            algorithm, expected = _parse_content_digest(header)
            digest_matches[header] = _constant_time_equal(
                expected, hashlib.new(algorithm, message.body).digest()
            )
        if not digest_matches[header]:
            raise VerificationError(
                VerificationCode.SIGNATURE_INVALID, "Content-Digest does not match content",
            )


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    import hmac

    return hmac.compare_digest(a, b)
