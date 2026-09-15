---
title: "Python: Web Bot Auth profile"
description: "Web Bot Auth request signing, verification, and key-directory serving (dnsid.web_bot_auth, dnsid.wba_signer)."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

> Application profiles are **not part of the core DNSid protocol** — they are optional application-layer integrations built on top of it.

## `WebBotAuthProfile`

```python
from dnsid import WebBotAuthProfile
```

Web bot authentication helpers using DNSid-issued JWTs.

Implements the Agent Identity Assertion (AIA) pattern for HTTP bot auth:
- Signs outbound requests with ``Authorization: Bearer <dnsid-jwt>``
- Verifies inbound requests by validating the Bearer token

An application profile layered on top of DNSid identity verification.
Application profiles are not part of the core DNSid protocol and are not
required for DNSid conformance.

### `WebBotAuthProfile` constructor

```python
WebBotAuthProfile(resolver: IdentityResolver, key_provider: KeyProvider | None, domain: str, bot: BotIdentity | None = None, config: BotAuthConfig | None = None) -> None
```

Initialize the profile for a local bot identity.

**Arguments:**

- `resolver` (`IdentityResolver`): Any object satisfying the IdentityResolver protocol.
- `key_provider` (`KeyProvider | None`): Key management implementation for the local bot identity, or None for a verification-only profile.
- `domain` (`str`): FQDN of the local bot identity, or "" when verification-only.
- `bot` (`BotIdentity | None`): Bot metadata to include in signed JWTs. — default `None`
- `config` (`BotAuthConfig | None`): Optional freshness/verification overrides. — default `None`

### `from_identity_manager`

```python
WebBotAuthProfile.from_identity_manager(manager: object, bot: BotIdentity | None = None, config: BotAuthConfig | None = None) -> WebBotAuthProfile
```

Construct from a fully-initialised IdentityManager.

Reads domain and key_provider from the manager.

### `create_bot_token`

```python
WebBotAuthProfile.create_bot_token(target_url: str, expiry: datetime.timedelta | None = None, additional_claims: dict[str, Any] | None = None) -> str
```

Create a signed JWT for bot authentication.

The JWT includes:
- ``iss``/``sub``: the bot's DNSid domain
- ``aud``: the target URL origin (scheme + host)
- ``bot``: bot identity metadata
- ``iat``, ``exp``, ``jti``: standard temporal claims

**Arguments:**

- `target_url` (`str`): The URL being requested. The audience is derived from its origin.
- `expiry` (`datetime.timedelta | None`): Token lifetime. Default 5 minutes. — default `None`
- `additional_claims` (`dict[str, Any] | None`): Extra claims to include in the JWT payload. — default `None`

**Returns:**

- `str` — The signed JWT in compact serialization.

**Raises:**

- `ArgumentError`: If the profile is verification-only, ``target_url`` is not a valid URL, the requested expiry exceeds the configured maximum lifetime, or ``additional_claims`` would override a reserved claim.

### `sign_bot_request`

```python
WebBotAuthProfile.sign_bot_request(request: httpx.Request, expiry: datetime.timedelta | None = None, additional_claims: dict[str, Any] | None = None) -> httpx.Request
```

Sign an outbound httpx.Request with a bot auth JWT.

Adds an ``Authorization: Bearer <jwt>`` header to the request and
sets a ``User-Agent`` header incorporating the bot identity.

**Arguments:**

- `request` (`httpx.Request`): The httpx.Request to sign.
- `expiry` (`datetime.timedelta | None`): Token lifetime override. — default `None`
- `additional_claims` (`dict[str, Any] | None`): Extra claims for the JWT. — default `None`

**Returns:**

- `httpx.Request` — A new httpx.Request with the Authorization header set.

**Raises:**

- `ArgumentError`: Propagated from token creation (invalid URL, expiry over the maximum, or reserved-claim override).

### `create_signed_bot_client`

```python
WebBotAuthProfile.create_signed_bot_client(expiry: datetime.timedelta | None = None, additional_claims: dict[str, Any] | None = None, base_headers: dict[str, str] | None = None) -> httpx.Client
```

Return an httpx.Client that automatically signs every request with bot auth.

Every outbound request gets an ``Authorization: Bearer <dnsid-jwt>`` header.

**Arguments:**

- `expiry` (`datetime.timedelta | None`): Token lifetime override applied to every request. — default `None`
- `additional_claims` (`dict[str, Any] | None`): Extra claims added to every JWT. — default `None`
- `base_headers` (`dict[str, str] | None`): Default headers applied to every request. — default `None`

**Returns:**

- `httpx.Client` — An httpx.Client that signs each request before sending it.

### `verify_bot_request`

```python
WebBotAuthProfile.verify_bot_request(headers: dict[str, str], expected_audience: str | None = None, peer_cert: TLSCertificate | None = None) -> VerifiedBotRequest
```

Verify an inbound bot request by validating its Authorization Bearer JWT.

Resolves the JWT issuer's DNSid identity and verifies the signature.

**Arguments:**

- `headers` (`dict[str, str]`): The HTTP request headers (case-insensitive lookup for Authorization).
- `expected_audience` (`str | None`): If provided, the JWT ``aud`` claim must match this value. Typically the origin of the server receiving the request. — default `None`
- `peer_cert` (`TLSCertificate | None`): Certificate from the current peer connection. Required when the issuer's DNSid record carries ``fl=mtls``. — default `None`

**Returns:**

- `VerifiedBotRequest` — A VerifiedBotRequest with the verified domain and bot metadata.

**Raises:**

- `VerificationError`: If the token is missing, malformed, expired, or signature-invalid, or a claim fails validation; also propagated from issuer identity verification. Carries a VerificationCode.

## `BotAuthConfig`

```python
from dnsid import BotAuthConfig
```

Configuration for the Web Bot Auth profile.

**Attributes:**

- `max_lifetime` (`datetime.timedelta`): Maximum acceptable JWT lifetime. Default 15 minutes.
- `clock_skew` (`datetime.timedelta`): Allowed clock skew tolerance. Default 60 seconds.
- `require_bot_claim` (`bool`): If True, verification rejects JWTs without a ``bot`` claim.

## `BotIdentity`

```python
from dnsid import BotIdentity
```

Metadata describing the bot/agent for inclusion in the JWT ``bot`` claim.

**Attributes:**

- `name` (`str`): Human-readable bot name (e.g. "AcmeSearchBot").
- `version` (`str`): Bot version string (e.g. "1.2.3").
- `purpose` (`str`): Short machine-readable purpose tag. Common values: "search-indexing", "data-collection", "monitoring", "ai-training", "summarization".
- `operator_url` (`str`): URL with more info about the bot and its operator (like robots.txt contact info). Should be an HTTPS URL.

## `VerifiedBotRequest`

```python
from dnsid import VerifiedBotRequest
```

Result of successful bot request verification.

**Attributes:**

- `domain` (`str`): The verified DNSid domain of the bot.
- `bot` (`BotIdentity | None`): Bot identity metadata extracted from the JWT ``bot`` claim, or None.
- `verified_domain` (`VerifiedDomain`): The full VerifiedDomain result from DNSid resolution.
- `claims` (`dict[str, Any]`): The decoded JWT claims.

## `WBAHttpSigner`

```python
from dnsid import WBAHttpSigner
```

Sign outbound requests as Web Bot Auth HTTP Message Signatures.

Web Bot Auth is an application profile layered on top of DNSid identity;
application profiles are not part of the core DNSid protocol and are not
required for DNSid conformance.

### `WBAHttpSigner` constructor

```python
WBAHttpSigner(key_provider: KeyProvider, domain: str, config: WebBotAuthConfig | None = None, signature_agent: str | None = None, label: str = DEFAULT_LABEL, expires_in_seconds: int | None = None) -> None
```

Initialize the signer for a local DNSid identity.

**Arguments:**

- `key_provider` (`KeyProvider`): Provides the Ed25519 signing key. WBA signing requires Ed25519; other key types raise ArgumentError at signing time.
- `domain` (`str`): The DNSid FQDN, used to derive the default directory URL.
- `config` (`WebBotAuthConfig | None`): Optional `WebBotAuthConfig`. — default `None`
- `signature_agent` (`str | None`): Back-compat override for the directory URL placed in Signature-Agent. — default `None`
- `label` (`str`): Signature label and Signature-Agent dictionary member name (profile default: ``sig1``). — default `DEFAULT_LABEL`
- `expires_in_seconds` (`int | None`): Back-compat override for the request signature TTL. — default `None`

**Raises:**

- `ArgumentError`: If the resolved Signature-Agent directory URL is not https.

### `sign`

```python
WBAHttpSigner.sign(req: HttpRequest, variant: WBAVariant = WBAVariant.ACTIVE, options: WebBotAuthSigningOptions | None = None) -> HttpRequest
```

Sign *req* in place and return it.

``REVOKED`` signs normally — revocation is a directory-state concern
checked by the verifier, not a property of the signature bytes.

**Arguments:**

- `req` (`HttpRequest`): The request to sign; headers (and, for ``TAMPERED``, the body) are modified in place.
- `variant` (`WBAVariant`): Signing variant to produce. ``NO_SIG`` returns *req* unmodified; other variants produce deliberately broken signatures for verifier testing. — default `WBAVariant.ACTIVE`
- `options` (`WebBotAuthSigningOptions | None`): Optional per-request overrides. — default `None`

**Returns:**

- `HttpRequest` — The same request, with Signature-Input, Signature, and (when
- `HttpRequest` — enabled) Signature-Agent headers set.

**Raises:**

- `ArgumentError`: If the signing key is not Ed25519, or an additional component is not a known derived component or a lowercase HTTP field name.

## `WBAVariant`

```python
from dnsid import WBAVariant
```

Signing variants the test driver toggles (§7).

**Members:**

- `ACTIVE` = `'active'`
- `REVOKED` = `'revoked'`
- `KEY_MISMATCH` = `'key-mismatch'`
- `NO_SIG` = `'no-sig'`
- `TAMPERED` = `'tampered'`
- `EXPIRED` = `'expired'`

## `WBADirectoryResponse`

```python
from dnsid import WBADirectoryResponse
```

A signed HTTP Message Signatures Directory response.

## `WebBotAuthConfig`

```python
from dnsid import WebBotAuthConfig
```

WBA profile configuration (design doc 10 §Profile Configuration).

## `WebBotAuthSigningOptions`

```python
from dnsid import WebBotAuthSigningOptions
```

Per-request overrides for CreateWebBotAuthSignedRequest.

## `serve_http_message_signatures_directory`

```python
from dnsid import serve_http_message_signatures_directory
```

```python
serve_http_message_signatures_directory(req: HttpRequest, key_provider: KeyProvider, config: WebBotAuthConfig | None = None) -> WBADirectoryResponse
```

Return the active public signing key as a signed WBA directory response.

The body is a JWKS object served with the
``application/http-message-signatures-directory+json`` media type and one
HTTP Message Signature over ``"@authority";req``, ``content-type``,
``cache-control``, and ``content-digest`` with
``tag="http-message-signatures-directory"``.

**Arguments:**

- `req` (`HttpRequest`): The inbound directory request; its authority is covered by the response signature.
- `key_provider` (`KeyProvider`): Provides the Ed25519 signing key to publish and sign with.
- `config` (`WebBotAuthConfig | None`): Optional `WebBotAuthConfig`; controls the directory signature TTL. — default `None`

**Returns:**

- `WBADirectoryResponse` — A WBADirectoryResponse with status, headers, and JWKS body.

**Raises:**

- `ArgumentError`: If the signing key is not Ed25519.
