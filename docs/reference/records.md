---
title: "Python: Records and keys"
description: "The _dnsid TXT record model, JWK/JWKS key sets, agent status documents, and protocol constants."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

## `DnsIdTxtRecord`

```python
from dnsid import DnsIdTxtRecord
```

Parsed and validated _dnsid TXT record.

*identity_fqdn* is not a DNS tag — it is injected by the caller (from the DNS
owner name or via create_txt_record) so that validate() can enforce the gi
hierarchy and ku/ek host constraints.

**Attributes:**

- `v` (`str`): Protocol version selector; preserved exactly in signed bytes.
- `gi` (`str`): Governance ID — the registrant domain accountable for the agent.
- `ek` (`str`): Accountable-entity record-signing JWKS URL; required by draft 01, host must equal or be beneath gi.
- `ku` (`str`): Agent operational JWKS URL; host must equal the identity FQDN.
- `lr` (`str`): Log reference in ``"method:entry-ref"`` form.
- `su` (`str`): HTTPS status endpoint URL (not host-pinned; routinely on a registry host).
- `sg` (`str`): Entity signature over canonical(); draft 01 uses bare unpadded base64url raw signature bytes.
- `fl` (`str`): Comma-separated policy flags (e.g. ``"mtls,logchk"``).
- `ka` (`str`): Maximum operational-key age (``"24h"``, ``"7d"``, ``"30d"``, ``"90d"``).
- `cu` (`str`): Capabilities URL (AGENTS.md or Agent Card).
- `identity_fqdn` (`str`): The FQDN the record belongs to; caller-injected, never a DNS tag.
- `unknown_tags` (`dict[str, str]`): Unknown extension tags preserved verbatim (and included in signed canonical bytes).

### `parse`

```python
DnsIdTxtRecord.parse(raw: str) -> DnsIdTxtRecord
```

Parse the concatenated TXT RDATA into a DnsIdTxtRecord.

> **Raises ParseError on any structural violation:** - v= tag not first - v= value does not resolve to a supported profile - duplicate tag names - invalid tag name or value characters - missing required tags (per-version; ek only on two-key profiles) - a required tag present with an empty value

### `parse_unsigned_canonical`

```python
DnsIdTxtRecord.parse_unsigned_canonical(raw: str, identity_fqdn: str | None = None) -> DnsIdTxtRecord
```

Parse a canonical (pre-signature) string — no sg= tag expected.

Used in the publish_to_registry workflow to validate the registry-supplied
canonical form before signing. Raises ParseError if the input is not already
in canonical form (i.e. record.canonical() != raw). When *identity_fqdn* is
supplied the parsed record is also semantically validated against that FQDN.

### `validate`

```python
DnsIdTxtRecord.validate() -> None
```

Raise ValidationError on semantic constraint violations.

Requires *identity_fqdn* to be set. Called after parse() once the FQDN is known.
Validates: gi hierarchy, ek/ku/su/cu URI schemes and hosts, ka permitted values.

### `canonical`

```python
DnsIdTxtRecord.canonical() -> str
```

Produce the canonical signing form.

Draft 01 sorts all tags alphabetically. Returns a pure-ASCII string;
callers sign and verify its ASCII bytes.

### `known_tags_canonical`

```python
DnsIdTxtRecord.known_tags_canonical() -> str
```

Canonical form including only known protocol tags (excluding sg and unknown tags).

Used for registry publish validation: unknown registry-managed tags (e.g. exp) are
accepted as-is and must not be part of the comparison against the locally generated record.

### `serialize`

```python
DnsIdTxtRecord.serialize() -> str
```

Produce a DKIM-style tag=value string (RFC 6376 syntax).

v is always first; all other tags follow. Empty known optional tags are omitted.
Unknown extension tags (including empty-valued ones) are preserved.

### `policy_flags`

```python
DnsIdTxtRecord.policy_flags() -> frozenset[str]
```

Return the set of policy flag tokens from the fl tag.

## `TXTRecord`

```python
from dnsid import TXTRecord
```

A single TXT record returned by the DNS resolver.

### `concatenate_strings`

```python
TXTRecord.concatenate_strings() -> str
```

Concatenate all 255-octet DNS strings and decode as ASCII.

## `JWK`

```python
from dnsid import JWK
```

A single JSON Web Key (RFC 7517).

The SDK derives the JOSE algorithm from kty/crv; *alg*, if present, must be consistent
with the key binding.  At least one signing key must carry *kid*.

### `to_dict`

```python
JWK.to_dict() -> dict[str, Any]
```

Return an independent dictionary containing only public JWK members.

### `from_dict`

```python
JWK.from_dict(data: dict[str, Any]) -> JWK
```

Build a JWK from a raw JSON Web Key dict, e.g. one entry of a fetched JWKS.

The public counterpart of the SDK's internal parser: an integrator that
fetches a registry's ``ek`` key set to build a
`C2spVerificationContext` needs exactly this.

### `thumbprint`

```python
JWK.thumbprint() -> str
```

RFC 7638 JWK thumbprint (SHA-256, unpadded base64url).

Lifecycle log bindings MUST use thumbprints, not kid values.

### `signature_alg`

```python
JWK.signature_alg() -> str
```

Return the effective JOSE algorithm for this key (derived from kty/crv).

If *alg* is present on the key it must match the kty/crv binding; raises
VerificationError(RecordInvalid) otherwise.  Raises VerificationError(RecordInvalid)
for unsupported kty/crv combinations.

### `verify`

```python
JWK.verify(payload: bytes, signature: bytes) -> bool
```

Verify *signature* over *payload* using this public key.

Returns True on success, False on failure (never raises for a wrong signature).

## `JWKS`

```python
from dnsid import JWKS
```

A JSON Web Key Set (RFC 7517 §5).

### `to_dict`

```python
JWKS.to_dict() -> dict[str, list[dict[str, Any]]]
```

Return this public key set in RFC 7517 JSON-object form.

### `signing_keys`

```python
JWKS.signing_keys() -> list[JWK]
```

Return all keys suitable for signature verification.

A key is eligible when its kty/crv binding maps to a supported DNSid algorithm
(OKP/Ed25519 → EdDSA, EC/P-256 → ES256), any present alg is consistent, and its
*use* is absent or ``sig``.
Raises VerificationError(RecordInvalid) if no signing keys are present.

### `key_by_id`

```python
JWKS.key_by_id(kid: str) -> JWK | None
```

Return the key matching *kid*, or None if not found.

### `current_record_signing_key`

```python
JWKS.current_record_signing_key(profile: str | None = None) -> JWK
```

Return the single current record-signing key for *profile*.

The supported draft 01 profiles require exactly one eligible ``ek`` key
with ``kid`` and explicit, consistent ``alg`` metadata.

### `current_operational_signing_key`

```python
JWKS.current_operational_signing_key(profile: str | None = None) -> JWK
```

Return the single current draft 01 operational (ku) signing key.

The draft 01 operational JWKS must contain exactly one current signing
key (``use`` absent or ``sig``) carrying a ``kid`` and a supported
algorithm binding.  Raises VerificationError(RecordInvalid) otherwise.

### `validate_record_signing`

```python
JWKS.validate_record_signing(profile: str | None = None) -> None
```

Validate this set as the record-signing JWKS for *profile*.

### `validate_operational`

```python
JWKS.validate_operational(profile: str | None = None) -> None
```

Validate this set as the operational JWKS for *profile*.

### `validate`

```python
JWKS.validate() -> None
```

Raise VerificationError(RecordInvalid) if the key set is unusable.

> **Conditions checked:** - any key has a present alg that is inconsistent with its kty/crv binding - two keys share the same (non-empty) kid - no key is suitable for signing (unsupported key type, inconsistent alg fields, or use other than absent/``sig``) - no signing key has a kid field

## `check_ek_ku_distinctness`

```python
from dnsid import check_ek_ku_distinctness
```

```python
check_ek_ku_distinctness(ek: JWKS | None, ku: JWKS | None) -> None
```

Enforce draft-01 Two-Key Separation between the ek and ku JWK Sets.

No key published in *ek* may share an RFC 7638 JWK Thumbprint with any key
published in *ku*; a verifier MUST reject a record for which any such pairwise
thumbprint collision exists. This holds even for self-accounted DNSids —
self-accounting is the gi/agent-FQDN relationship, not key reuse, so a verifier
MUST NOT infer self-accounting from key equality.

A no-op when either set is absent or empty, since no collision is possible.

## `AgentStatus`

```python
from dnsid import AgentStatus
```

Concrete JSON response profile for the su (status) endpoint.

**Attributes:**

- `state` (`str`): One of the AgentState values (e.g. ``"ACTIVE"``, ``"REVOKED"``).
- `last_transition_at` (`datetime.datetime`): When the agent last changed state.
- `revocation_reason` (`str`): Reason code; required when *state* is ``"REVOKED"``, empty otherwise.

### `validate`

```python
AgentStatus.validate() -> None
```

Raise ValidationError if any field violates the status schema.

## `TLSCertificate`

```python
from dnsid import TLSCertificate
```

TLS certificate presented during a JWKS, status, or peer connection.

DNS identity validation uses only dNSName subjectAltName entries. Common
Name fallback and partial-label wildcards are intentionally unsupported.

### `validate_against_fqdn`

```python
TLSCertificate.validate_against_fqdn(fqdn: str) -> None
```

Validate a DNS name against this certificate's dNSName SANs.

A wildcard is accepted only as the complete left-most label and
matches exactly one label. Raises `ValidationError` when no SAN
matches; the caller is responsible for mapping that failure into its
verification error taxonomy.

## `active_status_document`

```python
from dnsid import active_status_document
```

```python
active_status_document(last_transition_at: datetime.datetime | None = None) -> dict[str, Any]
```

Return a minimal ACTIVE status document for demos and tests.

Suitable for serving directly from a ``/.well-known/status.json`` endpoint.
The returned dict is JSON-serializable.

**Arguments:**

- `last_transition_at` (`datetime.datetime | None`): Timestamp to record. Defaults to ``datetime.datetime.now(UTC)``. — default `None`

## `PROTOCOL_VERSION`

```python
from dnsid import PROTOCOL_VERSION
```

*Type:* `str`

*Value:* `IDENTITY_RECORD_VERSION`

Wire version string for the DNSid protocol implemented by this SDK.

Alias of IDENTITY_RECORD_VERSION — the current numbered publish profile.

## `IDENTITY_RECORD_VERSION`

```python
from dnsid import IDENTITY_RECORD_VERSION
```

*Value:* `_V_DRAFT01`

Exact numbered version selector written by newly published identity records.

Verification also accepts the exact pre-RFC ``DNSid1`` selector with the same
draft 01 behavior while preserving its wire value in signed bytes.  Dated and
aliased selectors are rejected.

## `DEFAULT_REGISTRY_URL`

```python
from dnsid import DEFAULT_REGISTRY_URL
```

*Type:* `str`

*Value:* `'http://127.0.0.1:7755'`

Default DNSid registry base URL: the local registry from ``dnsid local up``.

Hosted use requires an explicit URL (``DNSID_REGISTRY_URL``).

## `publish_allowed_version`

```python
from dnsid import publish_allowed_version
```

```python
publish_allowed_version(v: str) -> bool
```

True when this SDK is permitted to emit records with wire version *v*.
