---
title: "Python: HTTP Message Signatures profile"
description: "RFC 9421 HTTP Message Signatures signing and verification (dnsid.http_signatures)."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

> Application profiles are **not part of the core DNSid protocol** — they are optional application-layer integrations built on top of it.

## `HttpSignatureProfile`

```python
from dnsid import HttpSignatureProfile
```

RFC 9421 HTTP Message Signature helpers for a DNSid identity.

An application profile layered on top of DNSid identity verification.
Application profiles are not part of the core DNSid protocol and are not
required for DNSid conformance.

### `HttpSignatureProfile` constructor

```python
HttpSignatureProfile(resolver: IdentityResolver | AsyncIdentityResolver, key_provider: KeyProvider | None, domain: str, config: HttpMessageSignatureConfig | None = None, transport_config: TransportConfig | None = None) -> None
```

Initialize the profile for a local DNSid identity.

**Arguments:**

- `resolver` (`IdentityResolver | AsyncIdentityResolver`): An IdentityResolver or AsyncIdentityResolver. Sync verification requires IdentityResolver; async verification accepts either.
- `key_provider` (`KeyProvider | None`): Key management implementation for the local identity.
- `domain` (`str`): FQDN of the local identity. Used as the domain portion of the ``{domain}#{kid}`` keyId in Signature-Input headers.
- `config` (`HttpMessageSignatureConfig | None`): Optional freshness overrides. Defaults to 300 s max age / 5 s skew. — default `None`
- `transport_config` (`TransportConfig | None`): Optional DNS and TLS settings for clients created by this profile. — default `None`

### `from_identity_manager`

```python
HttpSignatureProfile.from_identity_manager(manager: object, config: HttpMessageSignatureConfig | None = None) -> HttpSignatureProfile
```

Construct an HttpSignatureProfile from a fully-initialised IdentityManager.

Reads domain, key provider, and transport configuration from the manager
so callers don't need to repeat them. Mirrors
``HttpSignaturesProfile.fromIdentityManager(idm)`` in the TypeScript SDK.

The inherited transport is the manager's validated snapshot: a manager
built with an injected ``https_fetcher`` rejects ``ca_bundle_path``, so
the clients this profile creates will not carry that bundle. Construct
the profile directly with ``transport_config=`` to supply one.

### `create_signed_http_request`

```python
HttpSignatureProfile.create_signed_http_request(req: HttpRequest, opts: HttpSigningOptions | None = None) -> HttpRequest
```

Sign an outgoing HTTP request (RFC 9421 HTTP Message Signatures).

Sets Signature-Input and Signature headers on *req* and returns it.
When *req* has a body, a Content-Digest header is computed and covered
by the signature. With response_signature set, requires HTTPS and prepares
Accept-Signature; this helper does not send or verify a response. Retain
an unmodified prepared request and original policy snapshot for the
standalone response verifier.

**Arguments:**

- `req` (`HttpRequest`): The request to sign; headers are set in place.
- `opts` (`HttpSigningOptions | None`): Optional signing overrides (label, extra covered components, expiry, tag). — default `None`

**Returns:**

- `HttpRequest` — The same request with Signature-Input and Signature headers set.

**Raises:**

- `ArgumentError`: If the signing key kid contains ``'#'`` or an additional component is not a known derived component or a lowercase HTTP field name.
- `VerificationError`: If a covered component cannot be derived from the message (for example a covered header is absent).

### `create_signed_http_client`

```python
HttpSignatureProfile.create_signed_http_client(base_client: httpx.Client, opts: HttpSigningOptions | None = None) -> httpx.Client
```

Wrap an httpx.Client so every outbound request is automatically signed.

**Arguments:**

- `base_client` (`httpx.Client`): Client whose transport performs the actual I/O.
- `opts` (`HttpSigningOptions | None`): Optional signing overrides applied to every request. — default `None`

**Returns:**

- `httpx.Client` — A new httpx.Client that signs each request before sending it. Content is buffered up to 8 MiB; replay streams retain original cleanup. The base client and its transport remain caller-owned. With response_signature, snapshots policy and verifies every response (including HTTP errors) before returning it. Disables redirects/auth resends and rejects transports other than HTTPX/SDK transports with retries=0 or MockTransport. Does not inherit base-client hooks, mounts, authentication flows, or caches. Uses a shared 30-second budget and 8 MiB raw/decoded response limits.

### `create_signed_async_http_client`

```python
HttpSignatureProfile.create_signed_async_http_client(base_headers: dict[str, str] | None = None, opts: HttpSigningOptions | None = None, transport_config: TransportConfig | None = None, *, transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient
```

Return an httpx.AsyncClient that auto-signs every outbound request.

**Arguments:**

- `base_headers` (`dict[str, str] | None`): Default headers applied to every request. — default `None`
- `opts` (`HttpSigningOptions | None`): Optional signing overrides applied to every request. — default `None`
- `transport_config` (`TransportConfig | None`): Optional DNS and TLS settings. Defaults to the configuration inherited by `from_identity_manager`. Custom hostname resolution supports ``host:port`` DNS servers; DoH URLs apply only to DNSid TXT lookups. — default `None`
- `transport` (`httpx.AsyncBaseTransport | None`): Optional outbound transport, for example MockTransport or a proxy-configured AsyncHTTPTransport. The returned client owns and closes it, as with httpx.AsyncClient. An injected transport handles its own DNS/TLS settings; transport_config is rejected when supplied together with it. — default `None`

**Returns:**

- `httpx.AsyncClient` — An httpx.AsyncClient that signs each request before sending it. Content is buffered up to 8 MiB; replay streams retain original cleanup. With response_signature, snapshots policy and verifies every response before return, including errors. Disables redirects/auth resends; accepts only HTTPX/SDK transports with retries=0 or MockTransport. The shared budget defaults to 30 seconds; raw and decoded content are each capped at 8 MiB. Rejected/cancelled responses are closed, never cached.

### `sign_requested_http_response`

```python
HttpSignatureProfile.sign_requested_http_response(request: HttpRequest, response: HttpRequest) -> HttpRequest
```

Fulfill one strict RFC 9421 response signature request atomically.

**Arguments:**

- `request` (`HttpRequest`): Trusted originating request, with its final signature fields.
- `response` (`HttpRequest`): Final buffered response, represented by HttpRequest with status. Finalize content coding and covered fields before calling this method.

**Returns:**

- `HttpRequest` — The same response, unchanged when Accept-Signature is absent. Otherwise sets Content-Digest, adds no-store, and signs with the operational key.

**Raises:**

- `VerificationError`: Malformed/unsupported peer negotiation, unavailable content or fields, colliding label, unsupported status, or resource limit.
- `ArgumentError`: Missing signing configuration or a key change during signing.

### `verify_signed_http_response`

```python
HttpSignatureProfile.verify_signed_http_response(request: HttpRequest, response: HttpRequest, opts: ResponseSignatureOptions, *, peer_cert: TLSCertificate | None = None) -> VerifiedDomain
```

Verify the requested response label against local identity policy.

**Arguments:**

- `request` (`HttpRequest`): Unmodified prepared originating request. Standalone callers must retain this request and the original policy snapshot for this invocation.
- `response` (`HttpRequest`): Actual buffered response (HttpRequest with status). None content is accepted only for HEAD, 204, or 304, never for an unavailable body.
- `opts` (`ResponseSignatureOptions`): Original expected domain and additional coverage policy.
- `peer_cert` (`TLSCertificate | None`): Trusted server certificate from the current application connection. — default `None`

**Returns:**

- `VerifiedDomain` — Verified DNSid identity after signature, digest, and no-store checks. Uncovered metadata, including Content-Type and Location, is not authenticated.

**Raises:**

- `ArgumentError`: Invalid local policy or non-HTTPS target.
- `VerificationError`: Missing/invalid negotiation or response authentication. Resolver failures retain their native classification.

### `async_verify_signed_http_response`

```python
HttpSignatureProfile.async async_verify_signed_http_response(request: HttpRequest, response: HttpRequest, opts: ResponseSignatureOptions, *, peer_cert: TLSCertificate | None = None) -> VerifiedDomain
```

Verify a response with async resolution and the standalone snapshot contract.

Uses the same policy, bounds, current-peer evidence, and checks as
verify_signed_http_response. Sync-only resolvers run in a worker.

### `verify_signed_http_request`

```python
HttpSignatureProfile.verify_signed_http_request(req: HttpRequest, opts: HttpVerificationOptions | None = None, *, peer_cert: TLSCertificate | None = None) -> VerifiedDomain
```

Verify an inbound HTTP request bearing an HTTP Message Signature (RFC 9421).

Verifies the DNSid identity of the signer, then checks signature
freshness, Content-Digest integrity, and the signature itself.

**Arguments:**

- `req` (`HttpRequest`): The inbound request to verify.
- `opts` (`HttpVerificationOptions | None`): Optional verification requirements (required tag, required covered components). — default `None`
- `peer_cert` (`TLSCertificate | None`): Certificate from the current peer connection. Required when the signer's DNSid record carries ``fl=mtls``. — default `None`

**Returns:**

- `VerifiedDomain` — The VerifiedDomain for the signer's DNSid identity.

**Raises:**

- `VerificationError`: If the Signature/Signature-Input headers are missing or malformed, the signature is stale or expired, the Content-Digest does not match the body, the key or algorithm cannot be validated, or the signature is invalid; also propagated from signer identity verification. Carries a VerificationCode.

### `async_verify_signed_http_request`

```python
HttpSignatureProfile.async async_verify_signed_http_request(req: HttpRequest, opts: HttpVerificationOptions | None = None, *, peer_cert: TLSCertificate | None = None) -> VerifiedDomain
```

Verify inbound signatures using async identity resolution.

Local validation is shared with the synchronous verifier. Legacy
synchronous resolvers run in a worker; async resolvers are awaited.

## `HttpMessageSignatureConfig`

```python
from dnsid import HttpMessageSignatureConfig
```

Freshness settings for the HTTP Message Signature profile (RFC 9421).

## `HttpRequest`

```python
from dnsid import HttpRequest
```

Buffered HTTP message for request and response signature construction.

### `get_header`

```python
HttpRequest.get_header(name: str) -> str
```

Combine matching field lines in order; return empty string if absent.

### `has_header`

```python
HttpRequest.has_header(name: str) -> bool
```

Return True if the header is present (case-insensitive).

### `set_header`

```python
HttpRequest.set_header(name: str, value: str) -> None
```

Set (or replace) a header; stored under the lowercased name.

## `HttpSigningOptions`

```python
from dnsid import HttpSigningOptions
```

Options for HttpSignatureProfile.create_signed_http_request.

**Attributes:**

- `additional_components` (`list[str]`): Extra covered components beyond the default ``@method``/``@authority``/``@target-uri`` (derived components or lowercase HTTP field names).
- `label` (`str`): Signature label used in Signature/Signature-Input headers.
- `tag` (`str`): RFC 9421 tag parameter identifying the signature's application.
- `expires_in_seconds` (`int`): Signature validity window from creation.
- `response_signature` (`ResponseSignatureOptions | None`): When present, request mandatory response authentication.

## `ResponseSignatureOptions`

```python
from dnsid import ResponseSignatureOptions
```

Local policy for opt-in negotiated HTTP response authentication.

**Attributes:**

- `expected_domain` (`str`): Expected DNSid agent FQDN, independent of the endpoint host.
- `additional_components` (`list[str]`): Extra response components in caller order, using the same component strings as SignatureParams (for example ``content-type``).

## `ResponseSigningMiddleware`

```python
from dnsid import ResponseSigningMiddleware
```

Sign responses for requests that carry Accept-Signature.

Requests without negotiation pass through unbuffered. Negotiated responses
are buffered up to 8 MiB and signed before any header is sent. On a signing
failure or an exceeded bound, the middleware sends a 500 without the
application's headers or content; it never sends the unsigned response.
Place it after request verification and authorization, and outside any
middleware that changes the status, covered headers, or content coding.
The request URL uses the ASGI scope scheme and Host header: behind a
TLS-terminating proxy, apply trusted proxy-header handling first.

## `HttpVerificationOptions`

```python
from dnsid import HttpVerificationOptions
```

Options for HttpSignatureProfile.verify_signed_http_request.

**Attributes:**

- `required_components` (`list[str]`): Components the inbound signature must cover; verification fails if any is missing from the covered set.
- `required_tag` (`str | None`): When set, the signature's tag parameter must match.

## `SignatureParams`

```python
from dnsid import SignatureParams
```

Parsed Signature-Input parameters (RFC 9421).

``parameters`` retains the RFC 8941 parameter order and unknown bare-item
values.  The existing typed attributes remain available for compatibility.

### `value_string`

```python
SignatureParams.value_string() -> str
```

Return the structured-field value without the label prefix.

Used in the RFC 9421 signature base as the @signature-params component value.
Format: (components);keyid="...";alg="...";created=N;nonce="...";expires=N;tag="..."

### `serialize`

```python
SignatureParams.serialize() -> str
```

Serialize to Signature-Input header value: label=value_string.

### `parse`

```python
SignatureParams.parse(sig_input: str) -> SignatureParams
```

Parse a Signature-Input header value (e.g. 'sig1=(...);keyid="...";created=N').

The header is split into RFC 8941 dictionary members (quote-aware) only
far enough to reject duplicate labels and select the first member. Only
that selected member is fully validated and returned; the syntax of
non-selected members is NOT checked, since they are never used.

Raises VerificationError(RecordInvalid) on malformed input.

### `parse_dictionary`

```python
SignatureParams.parse_dictionary(sig_input: str) -> dict[str, SignatureParams]
```

Parse and validate every member of a Signature-Input dictionary.
