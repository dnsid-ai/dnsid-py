# Quickstart Guide

Get up and running with the `dnsid` Python SDK in minutes.

## Installation

Install from PyPI:

```bash
pip install dnsid
```

For AWS KMS-backed signing keys:

```bash
pip install "dnsid[aws]"
```

If the release is not yet available on PyPI, install directly from GitHub.
Replace `main` with a [release tag](https://github.com/dnsid-ai/dnsid-py/releases)
to pin a version; the `[aws]` extra works the same way:

```bash
pip install "dnsid @ git+https://github.com/dnsid-ai/dnsid-py@main"
```

**Requirements:** Python 3.11+

## Prerequisites

Before using DNSid, you need:

1. **A domain name** — Your agent's FQDN (e.g. `my-agent.example.com`)
2. **A signing key** — An Ed25519 or P-256 key pair (the SDK can generate one for you)
3. **DNS TXT record** — A `_dnsid.<your-domain>` TXT record published in DNS
4. **JWKS endpoint** — Your public keys served at `https://<your-domain>/.well-known/jwks.json`
5. **Status endpoint** — An HTTPS URL returning your agent's lifecycle status

For local development and testing, use `LocalKeyProvider.generate()` for Ed25519 or
`LocalKeyProvider.generate("ES256")` for P-256.

## Core Workflows

### 1. Resolve — Look Up a DNSid Identity

Verify a remote agent's identity by resolving its DNS record and fetching its JWKS:

```python
from dnsid import DnsidConfig, IdentityManager, IdentityManagerDependencies, TrustedEntity, VerificationConfig
from dnsid.c2sp_tlog import create_dnsid_managed_verification_registry

# A verifier needs no local identity or keys. This explicitly trusts the
# SDK's pinned DNSid-managed public logs; other logs need their own reader.
manager = IdentityManager(
    DnsidConfig(verification=VerificationConfig(
        trusted_entities=[TrustedEntity("example.com")],
    )),
    deps=IdentityManagerDependencies(
        log_registry=create_dnsid_managed_verification_registry(),
    ),
)

# Resolve and verify a counterparty's DNSid identity
verified = manager.verify_domain("payments-agent.example.com")

print(f"Domain: {verified.domain}")
print(f"State: {verified.cached_state()}")
print(f"Governance ID: {verified.record.gi}")
print(f"JWKS keys: {len(verified.jwks.keys)}")
print(f"Cache expires: {verified.expiry()}")
```

`verify_domain` performs a full verification:
- Fetches the `_dnsid` TXT record from DNS
- Validates the record structure and signature
- Fetches the JWKS from the `ku` URL
- Checks the agent's status endpoint
- Caches identity evidence until `expiry()` (status is re-fetched on every call by default)

> **Note:** draft-01 (`v=dnsid-draft-01` or verification-only `v=DNSid1`)
> verification requires a capable log reader. The managed factory above supports
> only exact DNSid-managed public log references; for other logs, configure a
> matching reader or verification fails closed. The `trusted_entities` entry
> must match the counterparty's verified `gi`. See the
> [transparency-log reference](reference/transparency-log.md) for other setups.

### 2. Sign — Create a JWT with a DNSid Identity

Sign a JWT that a counterparty can verify against your DNS-published identity:

```python
from pathlib import Path
from dnsid import DnsidConfig, IdentityConfig, IdentityManager, LocalKeyProvider, JWTOptions
from dnsid.jose import JoseProfile

# Set up your identity
key_provider = LocalKeyProvider.load(Path.home() / ".dnsid" / "keys.json", create_if_missing=True)
config = DnsidConfig(
    identity=IdentityConfig(
        domain="billing-agent.example.com",
        governance_id="example.com",
        log_ref="microledger:abc123",
        status_url="https://billing-agent.example.com/status",
    ),
)
manager = IdentityManager(config, key_provider)

# Create the JOSE profile for JWT operations
jose = JoseProfile.from_identity_manager(manager)

# Sign a JWT for a specific audience
token = jose.create_jwt(JWTOptions(audience="payments-agent.example.com"))
print(f"Signed JWT: {token}")

# You can also include custom claims
token_with_claims = jose.create_jwt(
    JWTOptions(
        audience="payments-agent.example.com",
        additional_claims={"action": "charge", "amount": 100},
    )
)
```

The JWT contains:
- `iss` / `sub` — your domain
- `aud` — the counterparty's domain
- `iat`, `exp`, `jti` — standard timing and uniqueness claims

### 3. Verify — Validate a JWT Against Its DNSid Record

Verify a JWT received from a counterparty, confirming its signature matches the issuer's published DNSid identity:

```python
from pathlib import Path
from dnsid import DnsidConfig, IdentityConfig, IdentityManager, LocalKeyProvider
from dnsid.jose import JoseProfile, JoseConfig
from dnsid.exceptions import VerificationError

# Set up your identity (the verifier)
key_provider = LocalKeyProvider.load(
    Path.home() / ".dnsid" / "keys.json", create_if_missing=True
)
config = DnsidConfig(
    identity=IdentityConfig(
        domain="payments-agent.example.com",
        governance_id="example.com",
        log_ref="microledger:abc123",
        status_url="https://payments-agent.example.com/status",
    ),
)
manager = IdentityManager(config, key_provider)

# Create JOSE profile with custom freshness settings
jose = JoseProfile.from_identity_manager(manager, config=JoseConfig())

# Verify a JWT from a counterparty
incoming_token = "eyJ..."  # JWT received from the counterparty

try:
    verified = jose.verify_jwt(incoming_token)
    print(f"Verified issuer: {verified.domain}")
    print(f"Issuer state: {verified.cached_state()}")
    print(f"Governance: {verified.record.gi}")
except VerificationError as e:
    print(f"Verification failed: {e.code.name} — {e.message}")
    if e.transient:
        print("This error is transient; retrying may help.")
```

## Common Errors and How to Handle Them

The SDK raises specific exception types to help you diagnose issues:

```python
from dnsid.exceptions import (
    ParseError,
    ValidationError,
    VerificationError,
    ArgumentError,
)
from dnsid.enums import VerificationCode

try:
    verified = manager.verify_domain("some-agent.example.com")
except VerificationError as e:
    match e.code:
        case VerificationCode.DNS_RESOLUTION:
            # DNS lookup failed — network issue or domain doesn't exist
            print("DNS error (transient, may retry)")
        case VerificationCode.DNSSEC_FAILED:
            # DNSSEC validation failed — potential spoofing
            print("DNSSEC failure — do not trust this domain")
        case VerificationCode.RECORD_INVALID:
            # TXT record malformed or missing required fields
            print("Invalid DNSid record")
        case VerificationCode.SIGNATURE_INVALID:
            # Record signature doesn't match any JWKS key
            print("Signature verification failed")
        case VerificationCode.TLS_ERROR:
            # TLS certificate issue fetching JWKS or status
            print("TLS error on HTTPS fetch")
        case VerificationCode.STATUS_NOT_ACTIVE:
            # Agent status endpoint returned non-ACTIVE state
            print(f"Agent not active: {e.agent_state}")
        case VerificationCode.LOG_ERROR:
            # Ledger verification failed
            print("Log verification error")
        case VerificationCode.KEY_AGE_EXCEEDED:
            # Signing key is older than the ka policy allows
            print("Key age exceeded policy limit")

    # Check if retrying might help
    if e.transient:
        print("Retry recommended")
```

| Exception | When It's Raised |
|-----------|-----------------|
| `ParseError` | TXT record has invalid syntax (malformed tags, duplicates) |
| `ValidationError` | Record parses but violates semantic rules (e.g. malformed `gi`) |
| `VerificationError` | Live verification step failed (DNS, JWKS, signature, status) |
| `ArgumentError` | Invalid argument passed to an SDK method |

## Next Steps

- **[API Reference](reference/overview.md)** — generated documentation for every public class, function, and exception
- **[examples/](../examples/)** — Runnable example scripts
- **[README](../README.md)** — Installation, SDK usage, architecture overview, and configuration reference
