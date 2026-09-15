---
title: "Python: OIDC profile"
description: "OIDC token minting, exchange, and verification bound to DNSid identities (dnsid.oidc)."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

> Application profiles are **not part of the core DNSid protocol** — they are optional application-layer integrations built on top of it.

## `OIDCProfile`

```python
from dnsid import OIDCProfile
```

OIDC / OAuth JWT bearer helpers for a DNSid identity.

Implements the DNSid OIDC application profile: creating JWT bearer
assertions signed with the agent's operational key, exchanging them for
tokens at an OIDC issuer, and verifying issued tokens back to a DNSid
identity record. This is an application profile and is explicitly NOT part
of the core DNSid protocol.

### `OIDCProfile` constructor

```python
OIDCProfile(resolver: IdentityResolver, key_provider: KeyProvider | None, domain: str, config: OIDCConfig | None = None, transport_config: TransportConfig | None = None) -> None
```

Initialize the profile for one DNSid identity.

**Arguments:**

- `resolver` (`IdentityResolver`): Resolver used to verify DNSid token subjects.
- `key_provider` (`KeyProvider | None`): Provider of the agent's operational signing key.
- `domain` (`str`): The agent's FQDN; normalized on construction.
- `config` (`OIDCConfig | None`): OIDC configuration; defaults to ``OIDCConfig()``. — default `None`
- `transport_config` (`TransportConfig | None`): Optional HTTP transport configuration used when no explicit ``httpx.Client`` is supplied. — default `None`

### `from_identity_manager`

```python
OIDCProfile.from_identity_manager(manager: object, config: OIDCConfig | None = None) -> OIDCProfile
```

Build a profile from an IdentityManager.

Reuses the manager's resolver, key provider, domain, and transport
configuration so OIDC operations act for the same DNSid identity.

The inherited transport is the manager's validated snapshot: a manager
built with an injected ``https_fetcher`` rejects ``ca_bundle_path``, so
the clients this profile creates will not carry that bundle. Construct
the profile directly with ``transport_config=`` to supply one.

**Arguments:**

- `manager` (`object`): An ``IdentityManager`` instance to borrow collaborators from.
- `config` (`OIDCConfig | None`): Optional OIDC configuration; defaults to ``OIDCConfig()``. — default `None`

**Returns:**

- `OIDCProfile` — An ``OIDCProfile`` bound to the manager's domain and keys.

### `create_oidc_assertion`

```python
OIDCProfile.create_oidc_assertion(opts: OIDCAssertionOptions) -> str
```

Create a signed JWT bearer assertion for the given issuer.

The assertion is signed with the agent's operational key and carries
``iss``, ``sub``, and ``fqdn`` set to the agent's domain, the issuer as
the sole audience, and a unique ``jti``.

**Arguments:**

- `opts` (`OIDCAssertionOptions`): Assertion options; ``opts.issuer`` is required.

**Returns:**

- `str` — The compact-serialized signed JWT.

**Raises:**

- `ArgumentError`: If the issuer is invalid, the expiry is not positive or exceeds the maximum assertion lifetime, or ``additional_claims`` would override a reserved JWT claim.

### `discover_oidc_issuer`

```python
OIDCProfile.discover_oidc_issuer(issuer: str, discovery_url: str = '', http_client: httpx.Client | None = None, timeout: _Timeout | None = None) -> OIDCDiscoveryDocument
```

Fetch and validate the issuer's OIDC discovery document.

**Arguments:**

- `issuer` (`str`): Exact OIDC issuer URL (HTTPS, no trailing slash).
- `discovery_url` (`str`): Optional explicit discovery URL; defaults to the issuer's ``/.well-known/openid-configuration``. — default `''`
- `http_client` (`httpx.Client | None`): Optional HTTP client override. — default `None`
- `timeout` (`_Timeout | None`): Optional request timeout override. — default `None`

**Returns:**

- `OIDCDiscoveryDocument` — The validated discovery document.

**Raises:**

- `ArgumentError`: If the issuer or discovery URL is invalid.
- `NetworkError`: On transport failure, redirect, or non-200 response.
- `VerificationError`: With ``VerificationCode.RECORD_INVALID`` if the document is malformed, the discovered issuer mismatches, or the endpoints are not on the issuer origin.

### `exchange_oidc_token`

```python
OIDCProfile.exchange_oidc_token(opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse
```

Exchange a JWT bearer assertion for tokens at the issuer.

Resolves the issuer and token endpoint from the options, configured
defaults, or discovery; creates a fresh assertion when none is supplied;
and POSTs a ``jwt-bearer`` grant to the token endpoint.

**Arguments:**

- `opts` (`OIDCTokenExchangeOptions`): Exchange options; ``opts.audience`` is required.

**Returns:**

- `OIDCTokenResponse` — The parsed token response, annotated with the exchange context.

**Raises:**

- `ArgumentError`: If required options are missing or invalid, or a supplied assertion's audience does not exactly match the issuer.
- `NetworkError`: On transport failure or a disallowed redirect.
- `OAuthError`: If the token endpoint returns an OAuth error response.
- `VerificationError`: With ``VerificationCode.RECORD_INVALID`` if the response is malformed or lacks a Bearer access token.

### `mint_oidc_token`

```python
OIDCProfile.mint_oidc_token(opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse
```

Mint tokens using a freshly created assertion.

Behaves like `exchange_oidc_token` except that any caller-supplied
assertion in *opts* is ignored and a new one is always created. See
`exchange_oidc_token` for the raised exceptions.

**Arguments:**

- `opts` (`OIDCTokenExchangeOptions`): Exchange options; ``opts.audience`` is required.

**Returns:**

- `OIDCTokenResponse` — The parsed token response.

### `get_oidc_token`

```python
OIDCProfile.get_oidc_token(opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse
```

Get tokens for the given options.

Alias for `mint_oidc_token`: a fresh assertion is always created
and exchanged. See `exchange_oidc_token` for the raised
exceptions.

**Arguments:**

- `opts` (`OIDCTokenExchangeOptions`): Exchange options; ``opts.audience`` is required.

**Returns:**

- `OIDCTokenResponse` — The parsed token response.

### `verify_oidc_token`

```python
OIDCProfile.verify_oidc_token(token: str, opts: VerifyOIDCTokenOptions, peer_cert: TLSCertificate | None = None) -> VerifiedOIDCSubject
```

Verify an OIDC-issued token and optionally its DNSid subject.

Enforces the issuer allowlist and exact issuer/audience/azp claims,
restricts the JWT header and signing algorithm, fetches the issuer's
JWKS via discovery, verifies the signature, and validates the time
claims. When ``opts.verify_dnsid_subject`` is true, the token subject
is additionally verified as a DNSid identity via the resolver.

**Arguments:**

- `token` (`str`): Compact-serialized JWT issued by the OIDC issuer.
- `opts` (`VerifyOIDCTokenOptions`): Verification options; issuer and audience are required.
- `peer_cert` (`TLSCertificate | None`): Certificate from the current peer connection. Required when the DNSid subject record carries ``fl=mtls``. — default `None`

**Returns:**

- `VerifiedOIDCSubject` — The verified subject, its claims, and the optional DNSid
- `VerifiedOIDCSubject` — verification result.

**Raises:**

- `ArgumentError`: If the issuer is invalid or the audience is empty.
- `NetworkError`: On discovery or JWKS transport failure.
- `VerificationError`: With ``VerificationCode.RECORD_INVALID`` for disallowed-issuer, claim, or structural failures, and ``VerificationCode.SIGNATURE_INVALID`` for algorithm, key, or signature failures.

## `OIDCConfig`

```python
from dnsid import OIDCConfig
```

Configure OIDC assertion creation, token exchange, and token verification.

Controls assertion lifetimes, clock-skew tolerance, the allowed issuers and
token signing algorithms, default issuer/endpoint values, and HTTP transport
defaults shared by all OIDCProfile operations.

## `OIDCAssertionOptions`

```python
from dnsid import OIDCAssertionOptions
```

Specify how to build a signed OIDC JWT bearer assertion.

``issuer`` names the target OIDC issuer and becomes the assertion audience.
``expiry`` overrides the configured assertion lifetime, and
``additional_claims`` are merged into the JWT payload; reserved JWT claims
may not be overridden.

## `OIDCTokenExchangeOptions`

```python
from dnsid import OIDCTokenExchangeOptions
```

Specify how to exchange a DNSid assertion for tokens at an OIDC issuer.

``audience`` is required. The issuer may be given directly or derived from
``server_url`` or ``discovery_url``; a ``token_endpoint`` skips discovery.
Empty fields fall back to the corresponding ``OIDCConfig`` defaults. When
``assertion`` is empty, a fresh assertion is created for the exchange.

## `OIDCTokenResponse`

```python
from dnsid import OIDCTokenResponse
```

Hold the result of a successful OIDC JWT bearer token exchange.

Includes the issued tokens plus the exchange context: the issuer and token
endpoint used, the requested audience and scope, and the validity window of
the assertion that was presented.

## `OIDCDiscoveryDocument`

```python
from dnsid import OIDCDiscoveryDocument
```

Hold the validated subset of an OIDC discovery document.

Carries the issuer, token endpoint, and JWKS URI after same-origin and
issuer-match validation, plus the raw discovery response for access to any
additional metadata.

## `VerifyOIDCTokenOptions`

```python
from dnsid import VerifyOIDCTokenOptions
```

Specify how to verify a token issued by an OIDC issuer.

``issuer`` and ``audience`` are matched exactly against the token claims.
When ``verify_dnsid_subject`` is true, the token subject is additionally
resolved and verified as a DNSid identity.

## `VerifiedOIDCSubject`

```python
from dnsid import VerifiedOIDCSubject
```

Hold the verified subject extracted from an OIDC token.

``verified_domain`` carries the DNSid verification result for the subject
when subject verification was requested, otherwise ``None``. ``claims`` is
the full decoded claim set of the token.
