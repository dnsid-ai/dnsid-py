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
HttpSignatureProfile(resolver: IdentityResolver, key_provider: KeyProvider | None, domain: str, config: HttpMessageSignatureConfig | None = None, transport_config: TransportConfig | None = None) -> None
```

Initialize the profile for a local DNSid identity.

**Arguments:**

- `resolver` (`IdentityResolver`): Any object satisfying the IdentityResolver protocol.
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
by the signature.

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

- `httpx.Client` — A new httpx.Client that signs each request before sending it.

### `create_signed_async_http_client`

```python
HttpSignatureProfile.create_signed_async_http_client(base_headers: dict[str, str] | None = None, opts: HttpSigningOptions | None = None, transport_config: TransportConfig | None = None) -> httpx.AsyncClient
```

Return an httpx.AsyncClient that auto-signs every outbound request.

**Arguments:**

- `base_headers` (`dict[str, str] | None`): Default headers applied to every request. — default `None`
- `opts` (`HttpSigningOptions | None`): Optional signing overrides applied to every request. — default `None`
- `transport_config` (`TransportConfig | None`): Optional DNS and TLS settings. Defaults to the configuration inherited by `from_identity_manager`. Custom hostname resolution supports ``host:port`` DNS servers; DoH URLs apply only to DNSid TXT lookups. — default `None`

**Returns:**

- `httpx.AsyncClient` — An httpx.AsyncClient that signs each request before sending it.

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

## `HttpMessageSignatureConfig`

```python
from dnsid import HttpMessageSignatureConfig
```

Freshness settings for the HTTP Message Signature profile (RFC 9421).

## `HttpRequest`

```python
from dnsid import HttpRequest
```

An HTTP request for use with create_signed_http_request / verify_signed_http_request.

### `get_header`

```python
HttpRequest.get_header(name: str) -> str
```

Case-insensitive header lookup; returns empty string if absent.

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
