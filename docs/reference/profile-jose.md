---
title: "Python: JOSE profile"
description: "JWT and JWS helpers bound to DNSid identities (dnsid.jose)."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

> Application profiles are **not part of the core DNSid protocol** — they are optional application-layer integrations built on top of it.

## `JoseProfile`

```python
from dnsid import JoseProfile
```

JWT and JWS helpers for a DNSid identity.

An application profile layered on top of DNSid identity verification.
Application profiles are not part of the core DNSid protocol and are not
required for DNSid conformance.

### `JoseProfile` constructor

```python
JoseProfile(resolver: IdentityResolver, key_provider: KeyProvider | None = None, domain: str = '', config: JoseConfig | None = None) -> None
```

Initialize the profile for a local DNSid identity.

**Arguments:**

- `resolver` (`IdentityResolver`): Any object satisfying the IdentityResolver protocol (IdentityManager or a test double with a verify_domain method).
- `key_provider` (`KeyProvider | None`): Key management implementation for the local identity. — default `None`
- `domain` (`str`): FQDN of the local identity. Used as iss/sub in JWTs and as the domain portion of the ``{domain}#{kid}`` kid in JWS. Omit for verification-only use with an explicit expected audience. — default `''`
- `config` (`JoseConfig | None`): Optional freshness overrides. Defaults to 900 s lifetime / 60 s skew. — default `None`

### `from_identity_manager`

```python
JoseProfile.from_identity_manager(manager: object, config: JoseConfig | None = None) -> JoseProfile
```

Construct a JoseProfile from a fully-initialised IdentityManager.

Reads domain and key_provider from the manager so callers don't need to
repeat them.  Mirrors ``JoseProfile.fromIdentityManager(idm)`` in the
TypeScript SDK.

### `create_jwt`

```python
JoseProfile.create_jwt(opts: JWTOptions) -> str
```

Create a self-signed JWT for authenticating to a counterparty identity.

iss and sub are set to the local domain; aud is opts.audience.

**Arguments:**

- `opts` (`JWTOptions`): JWT creation options; ``audience`` is required.

**Returns:**

- `str` — The signed JWT in compact serialization.

**Raises:**

- `ArgumentError`: If ``audience`` is missing, the requested expiry exceeds the configured maximum lifetime, or ``additional_claims`` would override a reserved claim.

### `verify_jwt`

```python
JoseProfile.verify_jwt(jwt: str, *, expected_audience: str | None = None, peer_cert: TLSCertificate | None = None) -> VerifiedDomain
```

Verify a JWT received from a counterparty.

Validates the DNSid identity of the issuer, then verifies the JWT
signature against the issuer's verified signing key.

**Arguments:**

- `jwt` (`str`): The JWT compact serialization to verify.
- `expected_audience` (`str | None`): Trusted FQDN audience; defaults to the local domain. Required for a verification-only profile without a local domain. — default `None`
- `peer_cert` (`TLSCertificate | None`): Certificate from the current peer connection. Required when the issuer's DNSid record carries ``fl=mtls``. — default `None`

**Returns:**

- `VerifiedDomain` — The VerifiedDomain for the issuer's DNSid identity. The decoded claims payload is not returned — timing claims and the signature are validated internally; decode the JWT's payload segment separately if the application needs its claims.

**Raises:**

- `VerificationError`: If the JWT is malformed, a claim fails validation (iss/sub/aud/iat/exp/nbf), the alg is not in the application-layer allowlist, the kid is unknown, or the signature is invalid; also propagated from issuer identity verification. Carries a VerificationCode.

### `create_jws`

```python
JoseProfile.create_jws(payload: bytes) -> str
```

Produce a JWS compact serialization (RFC 7515).

kid is encoded as ``{domain}#{kid}`` to enable verify_jws to resolve
the signer.

**Arguments:**

- `payload` (`bytes`): Raw bytes to sign.

**Returns:**

- `str` — The JWS compact serialization.

**Raises:**

- `ArgumentError`: If the signing key kid contains ``'#'``.

### `verify_jws`

```python
JoseProfile.verify_jws(jws: str, *, peer_cert: TLSCertificate | None = None) -> tuple[bytes, VerifiedDomain]
```

Verify a JWS compact serialization from a counterparty (RFC 7515).

**Arguments:**

- `jws` (`str`): The JWS compact serialization to verify.
- `peer_cert` (`TLSCertificate | None`): Certificate from the current peer connection. Required when the signer's DNSid record carries ``fl=mtls``. — default `None`

**Returns:**

- `tuple[bytes, VerifiedDomain]` — ``(payload_bytes, verified_domain)`` — the decoded payload and the VerifiedDomain for the signer's DNSid identity.

**Raises:**

- `VerificationError`: If the JWS is malformed, the kid header is missing or unknown, the alg is not in the application-layer allowlist, or the signature is invalid; also propagated from signer identity verification. Carries a VerificationCode.

## `JoseConfig`

```python
from dnsid import JoseConfig
```

Freshness settings for the JOSE profile.

## `JWTOptions`

```python
from dnsid import JWTOptions
```

Options for JoseProfile.create_jwt.

**Attributes:**

- `audience` (`str`): Counterparty domain the token is minted for (required).
- `expiry` (`datetime.timedelta`): Token lifetime; defaults to 15 minutes and must not exceed the profile's configured maximum lifetime.
- `additional_claims` (`dict[str, Any]`): Extra claims merged into the payload; must not override the reserved iss/sub/aud/iat/exp/jti claims.
