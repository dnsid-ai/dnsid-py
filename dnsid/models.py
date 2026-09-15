"""All SDK data types: configuration, DNS record, JWKS, status, ledger events, and results."""
# Core config is DnsidConfig = {identity, verification, transport}.
# Registry settings are in RegistryConfig (owned by the registry client).
# Application-profile freshness settings are in JoseConfig and HttpMessageSignatureConfig.

from __future__ import annotations

import copy
import datetime
import functools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar, cast

from ._utils import (
    PERMITTED_KA_VALUES,
    is_domain_name,
    is_valid_tag_name,
    is_valid_tag_value,
    normalize_fqdn,
    parse_ledger_ref,
)
from .enums import AgentState, DNSSECMode, DNSSECState, EventType, RevocationReason
from .exceptions import ArgumentError, ParseError, ValidationError

if TYPE_CHECKING:
    from .interfaces import LogReader

_ZERO_TIME = datetime.datetime.min.replace(tzinfo=datetime.UTC)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


_ConfigT = TypeVar("_ConfigT")


def _config_errors_are_argument_errors(cls: type[_ConfigT]) -> type[_ConfigT]:
    """Report unknown or missing config fields as ArgumentError, not TypeError."""
    init = cls.__init__

    @functools.wraps(init)
    def __init__(self: _ConfigT, *args: Any, **kwargs: Any) -> None:
        try:
            init(self, *args, **kwargs)
        except TypeError as exc:
            raise ArgumentError(f"{cls.__name__}: {exc}") from exc

    cls.__init__ = __init__  # type: ignore[assignment,method-assign]
    return cls


@_config_errors_are_argument_errors
@dataclass
class IdentityConfig:
    """Local identity publication settings (``DnsidConfig.identity``).

    Contains only fields that appear in the _dnsid TXT record.  Verification
    policy lives in VerificationConfig; transport in TransportConfig.

    NormalizeFQDN is applied to *domain* and *governance_id* (when it is a domain
    name) during IdentityManager.__init__.

    Attributes:
        domain: Agent FQDN the identity record is published for (required).
        governance_id: Registrant domain — the gi tag (required).
        log_ref: Log reference in ``"method:entry-ref"`` form (required).
        status_url: HTTPS status (su) endpoint URL (required).
        policy_flags: Comma-separated policy flags (e.g. ``"mtls,logchk"``).
        max_key_age: Maximum operational-key age — the ka tag; one of
            ``"24h"``, ``"7d"``, ``"30d"``, ``"90d"``, or empty for no limit.
        ek_url: Accountable-entity JWKS URL — the ek tag.  Required for
            draft 01 publishing; the host must equal or be beneath gi.
        ku_url: Agent operational JWKS URL — the ku tag.  Required for
            draft 01 publishing; the host must equal the identity FQDN.
        capabilities_url: Optional URL for AGENTS.md or an Agent Card (cu tag).
        publish_profile: Wire profile emitted by create_txt_record and the
            registry publish workflow; empty selects the current numbered
            draft, ``dnsid-draft-01``.
    """

    domain: str
    governance_id: str
    log_ref: str
    status_url: str

    policy_flags: str = ""
    max_key_age: str = ""
    ek_url: str = ""
    ku_url: str = ""
    capabilities_url: str = ""
    # Wire profile emitted by create_txt_record / publish_to_registry. Empty
    # selects the current submitted numbered draft, ``dnsid-draft-01``.
    publish_profile: str = ""


@_config_errors_are_argument_errors
@dataclass(frozen=True)
class TrustedEntity:
    """One counterparty allowlist entry (``VerificationConfig.trusted_entities``).

    Attributes:
        governance_id: Accountable-entity domain that must equal the verified
            record's ``gi`` exactly (after NormalizeFQDN of this value only).
            No wildcard, suffix, or transitive matching.
        entity_key_thumbprints: Optional pins.  When present, must be a
            non-empty sequence of distinct RFC 7638 SHA-256 JWK thumbprints
            (unpadded base64url, 32 decoded bytes); the verified current
            record-signing key must match one of them.  Never learned or
            expanded automatically.
    """

    governance_id: str
    entity_key_thumbprints: tuple[str, ...] | None = None


@_config_errors_are_argument_errors
@dataclass
class VerificationConfig:
    """Protocol verification and counterparty acceptance settings.

    Identical defaults and behaviour for local-identity and verification-only
    managers.

    Attributes:
        status_check_interval: Maximum age of cached status before
            verify_domain re-fetches ``su``.  Zero (default) re-fetches on
            every invocation (spec-strict interactive verification).  Must be
            non-negative.
        dnssec_mode: DNSSEC enforcement mode; ``FAILED`` always aborts.
        trusted_entities: Optional counterparty allowlist.  ``None`` makes no
            acceptance decision; an empty list denies every counterparty.
    """

    status_check_interval: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(0))
    dnssec_mode: DNSSECMode = DNSSECMode.AUTO
    trusted_entities: list[TrustedEntity] | tuple[TrustedEntity, ...] | None = None


@_config_errors_are_argument_errors
@dataclass
class TransportConfig:
    """Optional deployment/runtime controls for SDK-managed DNS and HTTPS.

    These fields do not appear in TXT records and do not alter protocol semantics.
    Pass as ``DnsidConfig.transport``; the settings configure SDK-managed
    default components only and never mutate injected dependencies.

    Attributes:
        dns_server: Custom DNS server: ``"host:port"`` form (e.g.
            ``"8.8.8.8:53"``) for standard DNS, or an ``http(s)://`` URL for
            DNSid TXT lookups via DNS-over-HTTPS (which reports DNSSEC state
            from the AD bit); empty uses the system resolver. SDK-created HTTP
            clients use custom DNS only for ``"host:port"`` values; a DoH URL
            does not replace their system hostname resolver.
        ca_bundle_path: Path to a CA bundle used to augment TLS trust for
            SDK-managed HTTPS fetches.
        private_address_hosts: Hostnames permitted to resolve to non-public
            addresses. An exact entry (``"registry.dnsid.test"``) matches that
            host only; a leading-dot entry (``".dnsid.test"``) matches the
            domain and every name beneath it. Empty by default; use only for
            intended private services such as a loopback testnet zone.
    """

    dns_server: str = ""
    ca_bundle_path: str = ""
    #: Exact hostnames, or ``.suffix`` entries, permitted to resolve to non-public addresses.
    private_address_hosts: frozenset[str] = field(default_factory=frozenset)


@_config_errors_are_argument_errors
@dataclass
class DnsidConfig:
    """Single core configuration entry point for IdentityManager.

    Attributes:
        identity: Local identity publication settings.  Omit for a
            verification-only manager.
        verification: Protocol verification and counterparty acceptance.
        transport: SDK-managed DNS and HTTPS deployment settings.
    """

    identity: IdentityConfig | None = None
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    transport: TransportConfig = field(default_factory=TransportConfig)


DEFAULT_REGISTRY_URL: str = "https://api.dnsid.ai"
"""Default DNSid registry base URL, used when none is configured (matches the CLI)."""


@dataclass
class RegistryConfig:
    """Control-plane configuration for managing the local identity's registry records.

    Never used by VerifyDomain to validate external identities; verification always
    fetches the signed record.su endpoint.
    """

    registry_url: str = DEFAULT_REGISTRY_URL


# ---------------------------------------------------------------------------
# JWK / JWKS
# ---------------------------------------------------------------------------


@dataclass
class JWK:
    """A single JSON Web Key (RFC 7517).

    The SDK derives the JOSE algorithm from kty/crv; *alg*, if present, must be consistent
    with the key binding.  At least one signing key must carry *kid*.
    """

    kty: str
    alg: str
    kid: str = ""
    use: str = ""
    # Full raw parameters preserved for thumbprint computation and verification.
    _raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Return an independent dictionary containing only public JWK members."""
        return copy.deepcopy(
            {name: value for name, value in self._raw.items() if name not in _PRIVATE_JWK_MEMBERS}
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JWK:
        """Build a JWK from a raw JSON Web Key dict, e.g. one entry of a fetched JWKS.

        The public counterpart of the SDK's internal parser: an integrator that
        fetches a registry's ``ek`` key set to build a
        :class:`~dnsid.c2sp_tlog.C2spVerificationContext` needs exactly this.
        """
        return cls(
            kty=str(data.get("kty", "")),
            alg=str(data.get("alg", "")),
            kid=str(data.get("kid", "")),
            use=str(data.get("use", "")),
            _raw=dict(data),
        )

    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint (SHA-256, unpadded base64url).

        Lifecycle log bindings MUST use thumbprints, not kid values.
        """
        from ._crypto import compute_thumbprint

        return compute_thumbprint(self._raw)

    def signature_alg(self) -> str:
        """Return the effective JOSE algorithm for this key (derived from kty/crv).

        If *alg* is present on the key it must match the kty/crv binding; raises
        VerificationError(RecordInvalid) otherwise.  Raises VerificationError(RecordInvalid)
        for unsupported kty/crv combinations.
        """
        from ._crypto import signature_alg_from_raw
        from .enums import VerificationCode
        from .exceptions import VerificationError

        try:
            derived = signature_alg_from_raw(self._raw)
        except ValueError as exc:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                str(exc),
            ) from exc

        if self.alg and self.alg != derived:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"JWK alg {self.alg!r} is inconsistent with kty/crv binding (expected {derived!r})",
            )
        return derived

    def verify(self, payload: bytes, signature: bytes) -> bool:
        """Verify *signature* over *payload* using this public key.

        Returns True on success, False on failure (never raises for a wrong signature).
        """
        from ._crypto import verify_signature

        return verify_signature(self._raw, payload, signature)


@dataclass
class JWKS:
    """A JSON Web Key Set (RFC 7517 §5)."""

    keys: list[JWK] = field(default_factory=list)

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        """Return this public key set in RFC 7517 JSON-object form."""
        return {"keys": [key.to_dict() for key in self.keys]}

    def signing_keys(self) -> list[JWK]:
        """Return all keys suitable for signature verification.

        A key is eligible when its kty/crv binding maps to a supported DNSid algorithm
        (OKP/Ed25519 → EdDSA, EC/P-256 → ES256), any present alg is consistent, and its
        *use* is absent or ``sig``.
        Raises VerificationError(RecordInvalid) if no signing keys are present.
        """
        from .enums import VerificationCode
        from .exceptions import VerificationError

        result = []
        for k in self.keys:
            if k.use not in ("", "sig"):
                continue
            try:
                k.signature_alg()
                result.append(k)
            except Exception:
                pass
        if not result:
            raise VerificationError(
                VerificationCode.RECORD_INVALID, "JWKS contains no signing keys"
            )
        return result

    def key_by_id(self, kid: str) -> JWK | None:
        """Return the key matching *kid*, or None if not found."""
        for key in self.keys:
            if key.kid == kid:
                return key
        return None

    def current_record_signing_key(self, profile: str | None = None) -> JWK:
        """Return the single current record-signing key for *profile*.

        The supported draft 01 profiles require exactly one eligible ``ek`` key
        with ``kid`` and explicit, consistent ``alg`` metadata.
        """
        return self._current_protocol_signing_key("record-signing", profile)

    def current_operational_signing_key(self, profile: str | None = None) -> JWK:
        """Return the single current draft 01 operational (ku) signing key.

        The draft 01 operational JWKS must contain exactly one current signing
        key (``use`` absent or ``sig``) carrying a ``kid`` and a supported
        algorithm binding.  Raises VerificationError(RecordInvalid) otherwise.
        """
        return self._current_protocol_signing_key("operational", profile)

    def validate_record_signing(self, profile: str | None = None) -> None:
        """Validate this set as the record-signing JWKS for *profile*."""
        self.current_record_signing_key(profile)

    def validate_operational(self, profile: str | None = None) -> None:
        """Validate this set as the operational JWKS for *profile*."""
        self.current_operational_signing_key(profile)

    def _current_protocol_signing_key(self, role: str, profile: str | None) -> JWK:
        from .enums import VerificationCode
        from .exceptions import VerificationError

        selected_profile = profile or IDENTITY_RECORD_VERSION
        if selected_profile not in _SUPPORTED_VERSIONS:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"unsupported identity record profile: {selected_profile!r}",
            )

        self.validate()
        signing = [k for k in self.keys if not k.use or k.use == "sig"]
        if len(signing) != 1:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"draft 01 {role} JWKS must contain exactly one current signing key",
            )
        key = signing[0]
        if not key.kid:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"draft 01 {role} key missing kid",
            )
        # Draft 01 live-endpoint keys carry an explicit alg (design doc 01
        # §GetKeySet); a key without one is rejected rather than having its
        # algorithm inferred from kty/crv.
        if not key.alg:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"draft 01 {role} key must declare alg",
            )
        key.signature_alg()
        return key

    def validate(self) -> None:
        """Raise VerificationError(RecordInvalid) if the key set is unusable.

        Conditions checked:
          - any key has a present alg that is inconsistent with its kty/crv binding
          - two keys share the same (non-empty) kid
          - no key is suitable for signing (unsupported key type, inconsistent alg
            fields, or use other than absent/``sig``)
          - no signing key has a kid field
        """
        from .enums import VerificationCode
        from .exceptions import VerificationError

        # Reject keys with a present-but-inconsistent alg field.
        for key in self.keys:
            if key.alg:
                try:
                    key.signature_alg()
                except VerificationError:
                    raise
                except Exception as exc:
                    raise VerificationError(
                        VerificationCode.RECORD_INVALID,
                        f"JWKS key {key.kid!r} has unsupported kty/crv: {exc}",
                    ) from exc

        # Reject duplicate kid values; key_by_id would otherwise silently pick the first.
        seen: set[str] = set()
        for key in self.keys:
            if not key.kid:
                continue
            if key.kid in seen:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    f"JWKS: duplicate kid {key.kid!r}",
                )
            seen.add(key.kid)

        # Signing keys may have use absent or set to sig; all other uses are excluded.
        signing = []
        for k in self.keys:
            if k.use not in ("", "sig"):
                continue
            try:
                k.signature_alg()
                signing.append(k)
            except Exception:
                pass

        if not signing:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "JWKS contains no signing keys (unsupported key type, inconsistent alg "
                "fields, or use other than absent/sig)",
            )

        if not any(k.kid for k in signing):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "JWKS: no signing key has a kid field",
            )


def check_ek_ku_distinctness(ek: JWKS | None, ku: JWKS | None) -> None:
    """Enforce draft-01 Two-Key Separation between the ek and ku JWK Sets.

    No key published in *ek* may share an RFC 7638 JWK Thumbprint with any key
    published in *ku*; a verifier MUST reject a record for which any such pairwise
    thumbprint collision exists. This holds even for self-accounted DNSids —
    self-accounting is the gi/agent-FQDN relationship, not key reuse, so a verifier
    MUST NOT infer self-accounting from key equality.

    A no-op when either set is absent or empty, since no collision is possible.
    """
    from ._crypto import compute_thumbprint
    from .enums import VerificationCode
    from .exceptions import VerificationError

    if ek is None or ku is None or not ek.keys or not ku.keys:
        return

    ek_thumbprints = {compute_thumbprint(key._raw) for key in ek.keys}
    ku_thumbprints = {compute_thumbprint(key._raw) for key in ku.keys}

    if ek_thumbprints & ku_thumbprints:
        raise VerificationError(
            VerificationCode.RECORD_INVALID,
            "DNSid record rejected: ek and ku key sets share key material "
            "(RFC 7638 thumbprint collision)",
        )


# ---------------------------------------------------------------------------
# TLS Certificate (thin wrapper; populated from HTTPS connection)
# ---------------------------------------------------------------------------


@dataclass
class TLSCertificate:
    """TLS certificate presented during a JWKS, status, or peer connection.

    DNS identity validation uses only dNSName subjectAltName entries. Common
    Name fallback and partial-label wildcards are intentionally unsupported.
    """

    not_after: datetime.datetime = field(default_factory=lambda: _ZERO_TIME)
    san_dns_names: list[str] = field(default_factory=list)
    # Raw DER bytes for callers that need to inspect the full cert.
    der: bytes = field(default=b"", repr=False)

    def validate_against_fqdn(self, fqdn: str) -> None:
        """Validate a DNS name against this certificate's dNSName SANs.

        A wildcard is accepted only as the complete left-most label and
        matches exactly one label. Raises :class:`ValidationError` when no SAN
        matches; the caller is responsible for mapping that failure into its
        verification error taxonomy.
        """
        expected = normalize_fqdn(fqdn, agent_fqdn=True)
        expected_labels = expected.split(".")

        for presented in self.san_dns_names:
            if not isinstance(presented, str) or not presented:
                continue
            try:
                if presented.startswith("*.") and presented.count("*") == 1:
                    suffix = normalize_fqdn(presented[2:])
                    suffix_labels = suffix.split(".")
                    if (
                        len(expected_labels) == len(suffix_labels) + 1
                        and expected.endswith("." + suffix)
                    ):
                        return
                elif "*" not in presented and normalize_fqdn(presented) == expected:
                    return
            except ValidationError:
                # A malformed SAN does not prevent a different SAN from matching.
                continue

        raise ValidationError(
            f"TLS certificate dNSName SAN does not match {expected!r}"
        )


# ---------------------------------------------------------------------------
# Agent Status
# ---------------------------------------------------------------------------


@dataclass
class AgentStatus:
    """Concrete JSON response profile for the su (status) endpoint.

    Attributes:
        state: One of the AgentState values (e.g. ``"ACTIVE"``, ``"REVOKED"``).
        last_transition_at: When the agent last changed state.
        revocation_reason: Reason code; required when *state* is
            ``"REVOKED"``, empty otherwise.
    """

    state: str
    last_transition_at: datetime.datetime
    revocation_reason: str = ""

    VALID_STATES: ClassVar[frozenset[str]] = frozenset(s.value for s in AgentState)
    VALID_REVOCATION_REASONS: ClassVar[frozenset[str]] = frozenset(
        r.value for r in RevocationReason
    )

    def validate(self) -> None:
        """Raise ValidationError if any field violates the status schema."""
        if not isinstance(self.state, str) or self.state not in self.VALID_STATES:
            raise ValidationError(f"unknown agent status state: {self.state!r}")
        if (
            not isinstance(self.last_transition_at, datetime.datetime)
            or self.last_transition_at == _ZERO_TIME
        ):
            raise ValidationError("lastTransitionAt is required")
        if not isinstance(self.revocation_reason, str):
            raise ValidationError("revocationReason must be a string")
        if (
            self.state == AgentState.REVOKED.value
            and self.revocation_reason not in self.VALID_REVOCATION_REASONS
        ):
            raise ValidationError("valid revocationReason is required when state is REVOKED")


# ---------------------------------------------------------------------------
# DNS TXT record
# ---------------------------------------------------------------------------

_KNOWN_TAGS: frozenset[str] = frozenset({"v", "gi", "ek", "ku", "lr", "su", "sg", "fl", "ka", "cu"})

# Exact wire selectors. Both currently resolve to the immutable submitted
# draft-01 behavior, but the parsed selector is always preserved in signed bytes.
_V_DRAFT01 = "dnsid-draft-01"
_V_DNSID1 = "DNSid1"

# Pre-RFC releases publish only the current numbered selector. DNSid1 remains a
# moving verification-only selector until version 1 becomes an RFC.
IDENTITY_RECORD_VERSION = _V_DRAFT01
"""Exact numbered version selector written by newly published identity records.

Verification also accepts the exact pre-RFC ``DNSid1`` selector with the same
draft 01 behavior while preserving its wire value in signed bytes.  Dated and
aliased selectors are rejected.
"""
_PUBLISH_ALLOWED_VERSIONS: frozenset[str] = frozenset({_V_DRAFT01})
_SUPPORTED_VERSIONS: frozenset[str] = frozenset({_V_DRAFT01, _V_DNSID1})

def publish_allowed_version(v: str) -> bool:
    """True when this SDK is permitted to emit records with wire version *v*."""
    return v in _PUBLISH_ALLOWED_VERSIONS


_DRAFT01_REQUIRED: frozenset[str] = frozenset({"v", "gi", "ek", "ku", "lr", "su", "sg"})


def _is_supported_version(v: str) -> bool:
    return v in _SUPPORTED_VERSIONS


def _required_tags(v: str) -> frozenset[str]:
    """Return required tags for a resolved identity-record profile."""
    return _DRAFT01_REQUIRED


@dataclass
class DnsIdTxtRecord:
    """Parsed and validated _dnsid TXT record.

    *identity_fqdn* is not a DNS tag — it is injected by the caller (from the DNS
    owner name or via create_txt_record) so that validate() can enforce the gi
    hierarchy and ku/ek host constraints.

    Attributes:
        v: Protocol version selector; preserved exactly in signed bytes.
        gi: Governance ID — the registrant domain accountable for the agent.
        ek: Accountable-entity record-signing JWKS URL; required by draft 01,
            host must equal or be beneath gi.
        ku: Agent operational JWKS URL; host must equal the identity FQDN.
        lr: Log reference in ``"method:entry-ref"`` form.
        su: HTTPS status endpoint URL (not host-pinned; routinely on a
            registry host).
        sg: Entity signature over canonical(); draft 01 uses bare unpadded
            base64url raw signature bytes.
        fl: Comma-separated policy flags (e.g. ``"mtls,logchk"``).
        ka: Maximum operational-key age (``"24h"``, ``"7d"``, ``"30d"``,
            ``"90d"``).
        cu: Capabilities URL (AGENTS.md or Agent Card).
        identity_fqdn: The FQDN the record belongs to; caller-injected, never
            a DNS tag.
        unknown_tags: Unknown extension tags preserved verbatim (and included
            in signed canonical bytes).
    """

    v: str = IDENTITY_RECORD_VERSION
    gi: str = ""
    ek: str = ""
    ku: str = ""
    lr: str = ""
    su: str = ""
    sg: str = ""
    fl: str = ""
    ka: str = ""
    cu: str = ""
    identity_fqdn: str = ""
    unknown_tags: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @classmethod
    def parse(cls, raw: str) -> DnsIdTxtRecord:
        """Parse the concatenated TXT RDATA into a DnsIdTxtRecord.

        Raises ParseError on any structural violation:
          - v= tag not first
          - v= value does not resolve to a supported profile
          - duplicate tag names
          - invalid tag name or value characters
          - missing required tags (per-version; ek only on two-key profiles)
          - a required tag present with an empty value
        """
        from .exceptions import ParseError

        record = cls()
        pairs = raw.split(";")

        if not pairs or not pairs[0].strip().startswith("v="):
            raise ParseError("v= tag must be first")
        version = pairs[0].strip().split("=", 1)[1]
        if not _is_supported_version(version):
            raise ParseError(f"unsupported DNSid TXT record profile: {version!r}")
        required = _required_tags(version)

        seen: set[str] = set()
        for i, pair in enumerate(pairs):
            if pair == "":
                # Trailing semicolon is valid only as the very last element.
                if i == len(pairs) - 1:
                    continue
                raise ParseError("empty TXT tag element")

            # ABNF permits exactly one SP after semicolon (i > 0 elements).
            if i > 0 and pair.startswith(" "):
                pair = pair[1:]

            if "=" not in pair:
                raise ParseError(f"TXT element has no '=': {pair!r}")

            tag, _, value = pair.partition("=")

            if not is_valid_tag_name(tag):
                raise ParseError(f"invalid TXT tag name: {tag!r}")
            if not is_valid_tag_value(value):
                raise ParseError(f"invalid TXT tag value for tag {tag!r}")
            if tag in seen:
                raise ParseError(f"duplicate TXT tag: {tag!r}")
            seen.add(tag)

            if tag in _KNOWN_TAGS:
                # Empty optional tags are a no-op (field stays unset).
                if value or tag in required:
                    setattr(record, tag, value)
            else:
                record.unknown_tags[tag] = value

        missing = required - seen
        if missing:
            raise ParseError(f"missing required TXT tags: {sorted(missing)}")

        empty = sorted(t for t in required if not getattr(record, t))
        if empty:
            raise ParseError(f"required TXT tags have empty values: {empty}")

        return record

    @classmethod
    def parse_unsigned_canonical(cls, raw: str, identity_fqdn: str | None = None) -> DnsIdTxtRecord:
        """Parse a canonical (pre-signature) string — no sg= tag expected.

        Used in the publish_to_registry workflow to validate the registry-supplied
        canonical form before signing. Raises ParseError if the input is not already
        in canonical form (i.e. record.canonical() != raw). When *identity_fqdn* is
        supplied the parsed record is also semantically validated against that FQDN.
        """
        from .exceptions import ParseError

        record = cls()
        pairs = raw.split(";")

        seen: set[str] = set()
        parsed_pairs: list[tuple[str, str]] = []
        version = ""
        for i, pair in enumerate(pairs):
            if pair == "":
                if i == len(pairs) - 1:
                    continue
                raise ParseError("empty TXT tag element")

            if i > 0 and pair.startswith(" "):
                pair = pair[1:]

            if "=" not in pair:
                raise ParseError(f"TXT element has no '=': {pair!r}")

            tag, _, value = pair.partition("=")

            if not is_valid_tag_name(tag):
                raise ParseError(f"invalid TXT tag name: {tag!r}")
            if not is_valid_tag_value(value):
                raise ParseError(f"invalid TXT tag value for tag {tag!r}")
            if tag in seen:
                raise ParseError(f"duplicate TXT tag: {tag!r}")
            if tag == "sg":
                raise ParseError("sg= tag must not appear in unsigned canonical form")
            seen.add(tag)
            parsed_pairs.append((tag, value))
            if tag == "v":
                version = value

        if not version:
            raise ParseError("missing required TXT tags in canonical form: ['v']")
        if not _is_supported_version(version):
            raise ParseError(f"unsupported DNSid TXT record profile: {version!r}")
        # Unsigned canonical form is the required set without the sg signature.
        _REQUIRED_UNSIGNED = _required_tags(version) - {"sg"}

        for tag, value in parsed_pairs:
            if tag in _KNOWN_TAGS:
                if value or tag in _REQUIRED_UNSIGNED:
                    setattr(record, tag, value)
            else:
                record.unknown_tags[tag] = value

        missing = _REQUIRED_UNSIGNED - seen
        if missing:
            raise ParseError(f"missing required TXT tags in canonical form: {sorted(missing)}")

        if record.canonical() != raw:
            raise ParseError("unsigned TXT record is not in canonical form")

        if identity_fqdn is not None:
            record.identity_fqdn = identity_fqdn
            record.validate()

        return record

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Raise ValidationError on semantic constraint violations.

        Requires *identity_fqdn* to be set. Called after parse() once the FQDN is known.
        Validates: gi hierarchy, ek/ku/su/cu URI schemes and hosts, ka permitted values.
        """
        if not _is_supported_version(self.v):
            raise ValidationError(f"unsupported DNSid profile: {self.v!r}")

        identity = normalize_fqdn(self.identity_fqdn, agent_fqdn=True)

        gi_is_domain = is_domain_name(self.gi)
        # Draft 01 gi is signed content and must already be a normalized domain.
        if not gi_is_domain or self.gi != normalize_fqdn(self.gi):
            raise ValidationError("draft 01 gi must be a lowercase ASCII DNS domain")
        gi_domain = normalize_fqdn(self.gi) if gi_is_domain else ""

        # ku must be HTTPS with host == identity FQDN.
        ku_host = _parse_https_uri_host(self.ku, field_name="ku")
        if normalize_fqdn(ku_host) != identity:
            raise ValidationError("ku host must equal identity FQDN")

        ek_host = normalize_fqdn(_parse_https_uri_host(self.ek, field_name="ek"))
        if ek_host != gi_domain and not ek_host.endswith("." + gi_domain):
            raise ValidationError("ek host must equal or be beneath gi")

        # su is the registry-hosted status endpoint and is routinely on a
        # different host than the identity FQDN (e.g. the registry domain), so
        # it is validated as a well-formed HTTPS URL but not host-pinned.
        # SSRF exposure is bounded by the status fetch itself: HTTPS-only
        # redirects, public-address resolution, and a bounded response size.
        _parse_https_uri_host(self.su, field_name="su")

        # lr must be a well-formed ledger reference: '{method}:{entry_ref}'
        # where method matches [a-z][a-z0-9-]*.
        if self.lr:
            try:
                parse_ledger_ref(self.lr)
            except ParseError as exc:
                raise ValidationError(f"malformed lr value {self.lr!r}: {exc}") from exc

        if self.cu:
            _parse_https_uri_host(self.cu, field_name="cu")

        if self.ka and self.ka not in PERMITTED_KA_VALUES:
            raise ValidationError(f"ka must be one of: {sorted(PERMITTED_KA_VALUES)}")

    # ------------------------------------------------------------------
    # Canonical form and serialisation
    # ------------------------------------------------------------------

    def _all_tags(self) -> list[str]:
        """Return all set tag=value pairs (known + unknown), excluding empty known optionals."""
        items: list[str] = []
        for tag in ("v", "gi", "ek", "ku", "lr", "su", "sg", "fl", "ka", "cu"):
            value: str = getattr(self, tag)
            if value:
                items.append(f"{tag}={value}")
        for tag, value in self.unknown_tags.items():
            items.append(f"{tag}={value}")
        return items

    def canonical(self) -> str:
        """Produce the canonical signing form.

        Draft 01 sorts all tags alphabetically. Returns a pure-ASCII string;
        callers sign and verify its ASCII bytes.
        """
        return ";".join(sorted(t for t in self._all_tags() if not t.startswith("sg=")))

    def known_tags_canonical(self) -> str:
        """Canonical form including only known protocol tags (excluding sg and unknown tags).

        Used for registry publish validation: unknown registry-managed tags (e.g. exp) are
        accepted as-is and must not be part of the comparison against the locally generated record.
        """
        tags: list[str] = []
        for tag in ("v", "gi", "ek", "ku", "lr", "su", "fl", "ka", "cu"):
            value: str = getattr(self, tag)
            if value:
                tags.append(f"{tag}={value}")
        return ";".join(sorted(tags))

    def serialize(self) -> str:
        """Produce a DKIM-style tag=value string (RFC 6376 syntax).

        v is always first; all other tags follow. Empty known optional tags are omitted.
        Unknown extension tags (including empty-valued ones) are preserved.
        """
        all_tags = self._all_tags()
        non_v = [t for t in all_tags if not t.startswith("v=")]
        return f"v={self.v};" + ";".join(non_v)

    # ------------------------------------------------------------------
    # Policy flags
    # ------------------------------------------------------------------

    def policy_flags(self) -> frozenset[str]:
        """Return the set of policy flag tokens from the fl tag."""
        if not self.fl:
            return frozenset()
        return frozenset(token.strip() for token in self.fl.split(",") if token.strip())


# ---------------------------------------------------------------------------
# DNS resolver result
# ---------------------------------------------------------------------------


@dataclass
class TXTRecord:
    """A single TXT record returned by the DNS resolver."""

    strings: list[bytes] = field(default_factory=list)
    ttl: int = 0  # seconds

    def concatenate_strings(self) -> str:
        """Concatenate all 255-octet DNS strings and decode as ASCII."""
        return b"".join(self.strings).decode("ascii")


# ---------------------------------------------------------------------------
# Ledger types
# ---------------------------------------------------------------------------


@dataclass
class LogRef:
    """Structured log reference: '{method}:{entry_ref}'."""

    method: str
    entry_ref: str

    def __str__(self) -> str:
        """Return the ``{method}:{entry_ref}`` wire form of this log reference."""
        return f"{self.method}:{self.entry_ref}"

    @classmethod
    def parse(cls, lr: str) -> LogRef:
        """Raise ParseError if *lr* is malformed."""
        from ._utils import parse_ledger_ref

        method, entry_ref = parse_ledger_ref(lr)
        return cls(method=method, entry_ref=entry_ref)


# ------------------------------------------------------------------
# Ledger events — common base + per-type subclasses
# ------------------------------------------------------------------


@dataclass
class LogEvent:
    """Base class for all log events.

    Signature fields are populated by the IdentityManager signing facade
    (sign_event / sign_and_write_event); callers fill in all other
    (event-specific) fields before passing the event.  Canonicalization
    excludes every signature field (*signing_kid*, *sig*,
    *operational_countersig*), so adding one signature never changes the
    bytes covered by another.

    *sig* carries the primary role signature (Entity, Operational, or
    PreviousOperational depending on the event type);
    *operational_countersig* carries the ISSUANCE operational
    countersignature.
    """

    event_type: ClassVar[EventType]
    signing_kid: str = ""
    sig: str = ""
    operational_countersig: str = ""


@dataclass
class IssuanceEvent(LogEvent):
    """Initial bilateral registration of an agent identity."""

    event_type: ClassVar[EventType] = EventType.ISSUANCE

    domain: str = ""
    governance_id: str = ""
    entity_key: JWK | None = None
    operational_key: JWK | None = None
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )


@dataclass
class KeyRotationEvent(LogEvent):
    """Rotation to a new signing key; establishes continuity from previous key."""

    event_type: ClassVar[EventType] = EventType.KEY_ROTATION

    domain: str = ""
    previous_kid: str = ""
    previous_thumbprint: str = ""
    previous_public_key: JWK | None = None
    new_kid: str = ""
    new_thumbprint: str = ""
    new_public_key: JWK | None = None
    # Proof of possession: the new key's signature over the same canonical
    # event content (the c2sp-tlog envelope's sigs.new_op role).
    new_operational_proof: str = ""
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )


@dataclass
class RevocationEvent(LogEvent):
    """Permanent, forced termination."""

    event_type: ClassVar[EventType] = EventType.REVOCATION

    domain: str = ""
    reason: str = ""
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )


@dataclass
class RetirementEvent(LogEvent):
    """Graceful end-of-life."""

    event_type: ClassVar[EventType] = EventType.RETIREMENT

    domain: str = ""
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )


@dataclass
class MigrationEvent(LogEvent):
    """Transfer of agent identity history to a new ledger technology."""

    event_type: ClassVar[EventType] = EventType.MIGRATION

    domain: str = ""
    previous_log: str = ""
    new_log: str = ""
    final_entry_ref: str = ""
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )


@dataclass
class DelegationEvent(LogEvent):
    """Grants a delegatee agent permission to act within a defined scope."""

    event_type: ClassVar[EventType] = EventType.DELEGATION

    domain: str = ""
    delegatee: str = ""
    scope: str = ""
    expiry: datetime.datetime = field(default_factory=lambda: _ZERO_TIME)
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )


# Union type for any event (useful for LogReader return types).
AnyLogEvent = (
    IssuanceEvent
    | KeyRotationEvent
    | RevocationEvent
    | RetirementEvent
    | MigrationEvent
    | DelegationEvent
)


# ---------------------------------------------------------------------------
# VerifiedDomain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedCutoffHistory:
    """Method-neutral lifecycle history verified through an exact event reference."""

    events: list[AnyLogEvent]
    event_refs: list[str]
    response_bytes: int


@dataclass(frozen=True)
class LoggedStateEvidence:
    """Verified complete lifecycle-log state retained for an operation.

    ``logged_state`` describes lifecycle history, not current protocol status.
    ``complete_through`` and ``checkpoint`` are binding-specific evidence.

    Attributes:
        log_reference: Complete identity-instance log reference.
        logged_state: Verified lifecycle state through ``history_end``.
        history_start: Binding-specific genesis event reference.
        history_end: Binding-specific final applied event reference, if any.
        complete_through: Binding-specific completeness boundary.
        completeness_mode: Accepted binding-defined completeness mechanism.
        checkpoint: Accepted checkpoint or equivalent log-state evidence.
        freshness_time: Independently verified freshness timestamp.
    """

    log_reference: str
    logged_state: str
    history_start: str
    history_end: str | None
    complete_through: object
    completeness_mode: str
    checkpoint: object
    freshness_time: datetime.datetime


@dataclass
class VerifiedDomain:
    """Result of a successful VerifyDomain call.

    All fields are verified and immutable from the caller's perspective.

    Attributes:
        domain: Normalized FQDN that was verified.
        record: The parsed and validated identity record.
        jwks: The verified operational (ku) key set.
        signing_key: The entity (ek) key that verified the record's sg value.
        tls_cert: TLS certificate presented by the ku endpoint fetch.
        registry_status: Status document from the most recent su fetch.
        verified_at: When verification was performed.
        dns_ttl: DNS TTL of the TXT record, in seconds.
        key_bound_at: When the operational key was bound per the lifecycle
            log (zero time when the record carries no ka tag).
        last_status_check_at: When the su endpoint was last fetched.
        dnssec_state: DNSSEC validation result for the TXT lookup.
        log_reader: Log reader bound to the record's lr reference and used by
            ``IdentityManager.verify_log_evidence``.
        record_signing_jwks: The ek key set that verified the record
            signature (draft 01 evidence).
        record_signing_tls_cert: TLS certificate presented by the ek endpoint
            fetch; its NotAfter bounds expiry().
    """

    domain: str
    record: DnsIdTxtRecord
    jwks: JWKS
    signing_key: JWK
    tls_cert: TLSCertificate
    registry_status: AgentStatus
    verified_at: datetime.datetime
    dns_ttl: int  # seconds
    key_bound_at: datetime.datetime
    last_status_check_at: datetime.datetime
    dnssec_state: DNSSECState
    log_reader: LogReader
    # Record-signing evidence: the ek JWKS and TLS certificate presented by
    # the ek endpoint fetch.
    record_signing_jwks: JWKS | None = None
    record_signing_tls_cert: TLSCertificate | None = None
    dns_expires_at: datetime.datetime | None = None

    @functools.cached_property
    def signing_key_thumbprint(self) -> str:
        """RFC 7638 thumbprint of ``signing_key``, computed once and retained as evidence."""
        return self.signing_key.thumbprint()

    def cached_state(self) -> str:
        """Return the agent state from the most recent su fetch.

        This reflects lastStatusCheckAt, not necessarily right now. For a live
        status check before a new operation, call VerifyDomain again.
        """
        return self.registry_status.state

    def requires_log_check(self) -> bool:
        """Return whether the record carries the operation-level ``logchk`` flag."""
        return "logchk" in self.record.policy_flags()

    def expiry(self) -> datetime.datetime:
        """Return the earliest of all cache validity bounds.

        Candidates: DNS TTL, TLS cert NotAfter, key age (if ka set), JWK exp.
        """
        candidates: list[datetime.datetime] = []

        # DNS TTL: record may have changed (key rotation, re-sign, policy update).
        candidates.append(
            self.dns_expires_at or self.verified_at + datetime.timedelta(seconds=self.dns_ttl)
        )

        # TLS certificate: stale after NotAfter.
        if self.tls_cert.not_after != _ZERO_TIME:
            candidates.append(self.tls_cert.not_after)

        # Record-signing (ek) TLS certificate: the retained evidence chain is
        # stale once the ek endpoint's certificate expires.
        if (
            self.record_signing_tls_cert is not None
            and self.record_signing_tls_cert.not_after != _ZERO_TIME
        ):
            candidates.append(self.record_signing_tls_cert.not_after)

        # Key age bound: signing key rejected after keyBoundAt + ka duration.
        if self.record.ka and self.key_bound_at != _ZERO_TIME:
            ka_map = {
                "24h": datetime.timedelta(hours=24),
                "7d": datetime.timedelta(days=7),
                "30d": datetime.timedelta(days=30),
                "90d": datetime.timedelta(days=90),
            }
            if self.record.ka in ka_map:
                candidates.append(self.key_bound_at + ka_map[self.record.ka])

        return min(candidates)


# ---------------------------------------------------------------------------
# DomainLedger and DomainSnapshot
# ---------------------------------------------------------------------------


@dataclass
class DomainSnapshot:
    """Materialized state of a domain at a specific point in time.

    Derived from a DomainLedger — contains no live data.
    """

    domain: str
    historical_state: str
    active_key: JWK | None
    active_key_thumbprint: str
    key_bound_at: datetime.datetime
    governance_id: str
    snapshot_at: datetime.datetime
    events: list[LogEvent]


@dataclass
class DomainLog:
    """Full verified event history for a domain, loaded from the lifecycle log.

    All events have inclusion proofs verified before being stored here.
    snapshot_at() is pure computation — no I/O.
    """

    domain: str
    events: list[LogEvent]

    def snapshot_at(self, at: datetime.datetime) -> DomainSnapshot:
        """Derive domain state at *at* by replaying a verified lifecycle prefix.

        Preserves the verified lifecycle order supplied by the log binding —
        timestamps are signed lifecycle metadata, not the log method's ordering
        primitive.  Raises VerificationError if no events exist at or before
        *at*, if no ISSUANCE event precedes *at*, if the requested boundary is
        not a verified lifecycle prefix (an event past *at* is followed by a
        later event at or before *at*), or if lifecycle ordering is invalid
        (duplicate issuance, rotation/termination outside an ACTIVE issuance,
        or events after a terminal state).
        """
        from .enums import LifecycleErrorCategory, RevocationReason
        from .exceptions import LifecycleVerificationError

        def _log_error(
            category: LifecycleErrorCategory,
            message: str,
            index: int | None = None,
        ) -> LifecycleVerificationError:
            return LifecycleVerificationError(
                category, message, failing_event_index=index
            )

        if not self.events:
            raise _log_error(
                LifecycleErrorCategory.SNAPSHOT_EMPTY,
                f"no lifecycle events for {self.domain!r}",
            )

        state = ""
        entity_key: JWK | None = None
        active_key: JWK | None = None
        active_key_thumbprint = ""
        key_bound_at = _ZERO_TIME
        governance_id = ""
        events_up_to: list[LogEvent] = []
        past_snapshot_boundary = False

        for index, event in enumerate(self.events):
            if getattr(event, "domain", None) != self.domain:
                raise _log_error(
                    LifecycleErrorCategory.DOMAIN_MISMATCH,
                    f"lifecycle event domain mismatch for {self.domain!r}",
                    index,
                )
            event_time = getattr(event, "timestamp", None)
            if not isinstance(event_time, datetime.datetime):
                raise _log_error(
                    LifecycleErrorCategory.UNSUPPORTED_EVENT,
                    f"unsupported lifecycle event type {type(event).__name__}",
                    index,
                )
            if event_time > at:
                past_snapshot_boundary = True
                continue
            if past_snapshot_boundary:
                raise _log_error(
                    LifecycleErrorCategory.SNAPSHOT_NON_PREFIX,
                    f"snapshot time is not a verified lifecycle prefix for {self.domain!r}",
                    index,
                )
            events_up_to.append(event)

            if not state and not isinstance(event, IssuanceEvent):
                raise _log_error(
                    LifecycleErrorCategory.GENESIS_REQUIRED,
                    f"first lifecycle event must be ISSUANCE for {self.domain!r}",
                    index,
                )
            if state in ("REVOKED", "RETIRED"):
                raise _log_error(
                    LifecycleErrorCategory.TERMINAL_STATE,
                    f"event after terminal identity state for {self.domain!r}",
                    index,
                )

            if isinstance(event, IssuanceEvent):
                if state:
                    raise _log_error(
                        LifecycleErrorCategory.DUPLICATE_ISSUANCE,
                        f"duplicate ISSUANCE in one identity history for {self.domain!r}",
                        index,
                    )
                if (
                    event.entity_key is None
                    or event.operational_key is None
                    or event.entity_key.thumbprint()
                    == event.operational_key.thumbprint()
                ):
                    raise _log_error(
                        LifecycleErrorCategory.INVALID_ISSUANCE,
                        f"ISSUANCE key binding is invalid for {self.domain!r}",
                        index,
                    )
                state = "ACTIVE"
                entity_key = event.entity_key
                active_key = event.operational_key
                active_key_thumbprint = event.operational_key.thumbprint()
                key_bound_at = event.timestamp
                governance_id = event.governance_id
            elif isinstance(event, KeyRotationEvent):
                if (
                    active_key is None
                    or entity_key is None
                    or event.previous_thumbprint != active_key_thumbprint
                    or event.new_public_key is None
                    or event.new_thumbprint != event.new_public_key.thumbprint()
                    or event.new_thumbprint == active_key_thumbprint
                    or event.new_thumbprint == entity_key.thumbprint()
                ):
                    raise _log_error(
                        LifecycleErrorCategory.KEY_CONTINUITY,
                        f"KEY_ROTATION does not continue from the active key for {self.domain!r}",
                        index,
                    )
                active_key = event.new_public_key
                active_key_thumbprint = event.new_thumbprint
                key_bound_at = event.timestamp
            elif isinstance(event, RevocationEvent):
                if event.reason not in {reason.value for reason in RevocationReason}:
                    raise _log_error(
                        LifecycleErrorCategory.INVALID_REVOCATION_REASON,
                        f"invalid REVOCATION reason for {self.domain!r}",
                        index,
                    )
                state = "REVOKED"
            elif isinstance(event, RetirementEvent):
                state = "RETIRED"
            elif isinstance(event, MigrationEvent):
                if (
                    not event.previous_log
                    or not event.new_log
                    or not event.final_entry_ref
                    or event.previous_log == event.new_log
                ):
                    raise _log_error(
                        LifecycleErrorCategory.INVALID_MIGRATION,
                        f"invalid MIGRATION for {self.domain!r}",
                        index,
                    )
            elif isinstance(event, DelegationEvent):
                pass
            else:
                raise _log_error(
                    LifecycleErrorCategory.UNSUPPORTED_EVENT,
                    f"unsupported lifecycle event type {type(event).__name__}",
                    index,
                )

        if not events_up_to:
            raise _log_error(
                LifecycleErrorCategory.SNAPSHOT_EMPTY,
                f"no lifecycle events for {self.domain!r} at or before {at}",
            )

        if not state or active_key is None:
            raise _log_error(
                LifecycleErrorCategory.GENESIS_REQUIRED,
                f"no ISSUANCE event found for {self.domain!r} at or before {at}",
            )

        return DomainSnapshot(
            domain=self.domain,
            historical_state=state,
            active_key=active_key,
            active_key_thumbprint=active_key_thumbprint,
            key_bound_at=key_bound_at,
            governance_id=governance_id,
            snapshot_at=at,
            events=events_up_to,
        )

# ---------------------------------------------------------------------------
# Application-layer option types
# ---------------------------------------------------------------------------


@dataclass
class JWTOptions:
    """Options for JoseProfile.create_jwt.

    Attributes:
        audience: Counterparty domain the token is minted for (required).
        expiry: Token lifetime; defaults to 15 minutes and must not exceed
            the profile's configured maximum lifetime.
        additional_claims: Extra claims merged into the payload; must not
            override the reserved iss/sub/aud/iat/exp/jti claims.
    """

    audience: str
    expiry: datetime.timedelta = field(default_factory=lambda: datetime.timedelta(minutes=15))
    additional_claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class HttpSigningOptions:
    """Options for HttpSignatureProfile.create_signed_http_request.

    Attributes:
        additional_components: Extra covered components beyond the default
            ``@method``/``@authority``/``@target-uri`` (derived components or
            lowercase HTTP field names).
        label: Signature label used in Signature/Signature-Input headers.
        tag: RFC 9421 tag parameter identifying the signature's application.
        expires_in_seconds: Signature validity window from creation.
    """

    additional_components: list[str] = field(default_factory=list)
    label: str = "sig1"
    tag: str = ""
    expires_in_seconds: int = 300


@dataclass
class HttpVerificationOptions:
    """Options for HttpSignatureProfile.verify_signed_http_request.

    Attributes:
        required_components: Components the inbound signature must cover;
            verification fails if any is missing from the covered set.
        required_tag: When set, the signature's tag parameter must match.
    """

    required_components: list[str] = field(
        default_factory=lambda: ["@method", "@authority", "@target-uri"]
    )
    required_tag: str | None = None


@dataclass
class SignatureParams:
    """Parsed Signature-Input parameters (RFC 9421).

    ``parameters`` retains the RFC 8941 parameter order and unknown bare-item
    values.  The existing typed attributes remain available for compatibility.
    """

    label: str
    key_id: str
    alg: str
    created: int | None  # Unix timestamp
    expires: int | None  # Unix timestamp, optional
    nonce: str
    components: list[str]
    tag: str | None = None
    parameters: list[tuple[str, Any]] = field(default_factory=list)

    def value_string(self) -> str:
        """Return the structured-field value without the label prefix.

        Used in the RFC 9421 signature base as the @signature-params component value.
        Format: (components);keyid="...";alg="...";created=N;nonce="...";expires=N;tag="..."
        """
        import http_sf

        serialized = http_sf.ser(cast(Any, {"x": self._structured_value()}))
        return serialized.removeprefix("x=")

    def _structured_value(self) -> tuple[list[tuple[Any, dict[str, Any]]], dict[str, Any]]:
        items = [_component_structure(component) for component in self.components]
        ordered = self._ordered_parameters()
        names = [name for name, _ in ordered]
        if len(names) != len(set(names)):
            raise ValueError("duplicate Signature-Input parameter")
        parameters = dict(ordered)
        _reject_rfc9651_values(parameters)
        return items, parameters

    def _ordered_parameters(self) -> list[tuple[str, Any]]:
        known = {
            "keyid": self.key_id,
            "alg": self.alg,
            "created": self.created,
            "expires": self.expires,
            "nonce": self.nonce,
            "tag": self.tag,
        }
        if not self.parameters:
            return [
                (name, value)
                for name, value in known.items()
                if value is not None and not (isinstance(value, str) and not value)
            ]

        result: list[tuple[str, Any]] = []
        for name, value in self.parameters:
            if name in known:
                value = known[name]
                if value is None:
                    continue
            result.append((name, value))
        return result

    def serialize(self) -> str:
        """Serialize to Signature-Input header value: label=value_string."""
        import http_sf

        return http_sf.ser(cast(Any, {self.label: self._structured_value()}))

    @classmethod
    def parse(cls, sig_input: str) -> SignatureParams:
        """Parse a Signature-Input header value (e.g. 'sig1=(...);keyid="...";created=N').

        The header is split into RFC 8941 dictionary members (quote-aware) only
        far enough to reject duplicate labels and select the first member. Only
        that selected member is fully validated and returned; the syntax of
        non-selected members is NOT checked, since they are never used.

        Raises VerificationError(RecordInvalid) on malformed input.
        """
        from .enums import VerificationCode
        from .exceptions import VerificationError

        try:
            members = _parse_sf_dictionary(sig_input)
        except ValueError as exc:
            detail = str(exc).replace("duplicate dictionary key", "duplicate label")
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"malformed Signature-Input dictionary: {detail}",
            ) from exc
        if not members:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "Signature-Input has no members",
            )
        label, member = next(iter(members.items()))
        return cls._from_structured_member(label, member)

    @classmethod
    def _from_structured_member(cls, label: str, member: Any) -> SignatureParams:
        from .enums import VerificationCode
        from .exceptions import VerificationError

        if not (
            isinstance(member, tuple)
            and len(member) == 2
            and isinstance(member[0], list)
            and isinstance(member[1], dict)
        ):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"Signature-Input member {label!r} must be an Inner List",
            )
        raw_components, raw_parameters = member
        components: list[str] = []
        for item in raw_components:
            if not (
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], str)
                and isinstance(item[1], dict)
            ):
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "Signature-Input components must be RFC 8941 Strings",
                )
            components.append(_component_public_text(item[0], item[1]))
        parameters = list(raw_parameters.items())

        _validate_component_identifiers(components, request_context=None)

        known_names = {"keyid", "alg", "created", "expires", "nonce", "tag"}
        seen_known: set[str] = set()
        for name, _ in parameters:
            if name in known_names and name in seen_known:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    f"duplicate known Signature-Input parameter: {name!r}",
                )
            seen_known.add(name)
        param_values = dict(parameters)
        created_raw = param_values.get("created")
        expires_raw = param_values.get("expires")
        tag_raw = param_values.get("tag")

        # Validate integer parameters: created and expires must be integers per RFC 9421.
        created: int | None = None
        if created_raw is not None:
            if type(created_raw) is not int:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    f"Signature-Input 'created' must be an integer, got {created_raw!r}",
                )
            created = created_raw

        expires: int | None = None
        if expires_raw is not None:
            if type(expires_raw) is not int:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    f"Signature-Input 'expires' must be an integer, got {expires_raw!r}",
                )
            expires = expires_raw

        # String parameters: keyid, alg, nonce, tag must be strings.
        keyid_raw = param_values.get("keyid", "")
        alg_raw = param_values.get("alg", "")
        nonce_raw = param_values.get("nonce", "")
        string_values = (keyid_raw, alg_raw, nonce_raw, tag_raw)
        if any(value is not None and not isinstance(value, str) for value in string_values):
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                "Signature-Input keyid, alg, nonce, and tag parameters must be strings",
            )

        return cls(
            label=label,
            key_id=str(keyid_raw),
            alg=str(alg_raw),
            created=created,
            expires=expires,
            nonce=str(nonce_raw),
            components=components,
            tag=str(tag_raw) if tag_raw is not None else None,
            parameters=parameters,
        )

    @classmethod
    def parse_dictionary(cls, sig_input: str) -> dict[str, SignatureParams]:
        """Parse and validate every member of a Signature-Input dictionary."""
        from .enums import VerificationCode
        from .exceptions import VerificationError

        try:
            members = _parse_sf_dictionary(sig_input)
        except ValueError as exc:
            detail = str(exc).replace("duplicate dictionary key", "duplicate label")
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"malformed Signature-Input dictionary: {detail}",
            ) from exc

        return {
            label: cls._from_structured_member(label, member)
            for label, member in members.items()
        }


# ---------------------------------------------------------------------------
# HTTP request type for message signing helpers
# ---------------------------------------------------------------------------


@dataclass
class HttpRequest:
    """An HTTP request for use with create_signed_http_request / verify_signed_http_request."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None

    def get_header(self, name: str) -> str:
        """Case-insensitive header lookup; returns empty string if absent."""
        lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == lower:
                return v
        return ""

    def has_header(self, name: str) -> bool:
        """Return True if the header is present (case-insensitive)."""
        lower = name.lower()
        return any(k.lower() == lower for k, _ in self.headers.items())

    def set_header(self, name: str, value: str) -> None:
        """Set (or replace) a header; stored under the lowercased name."""
        lower = name.lower()
        self.headers = {k: v for k, v in self.headers.items() if k.lower() != lower}
        self.headers[lower] = value


# ---------------------------------------------------------------------------
# Registry types
# ---------------------------------------------------------------------------


@dataclass
class AgentRegistrationInput:
    """Input for registering an agent with the registry."""

    # Empty for server-assigned managed identities.
    domain: str = ""
    public_key_jwk: JWK | None = None
    environment: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    managed: bool = False
    capabilities_url: str = ""
    name: str = ""
    zone_id: str = ""
    idempotency_key: str = ""


@dataclass
class LiveAgentRegistrationInput:
    """Input for the dedicated managed Live registration operation."""

    public_key_jwk: JWK
    environment: str = ""
    capabilities_url: str = ""
    name: str = ""


@dataclass
class PublicationConfig:
    """Authoritative identity-record values returned by the registry."""

    publish_profile: str
    governance_id: str
    ku_url: str
    ek_url: str
    log_ref: str
    status_url: str
    capabilities_url: str = ""
    max_key_age: str = ""


@dataclass
class AgentRegistration:
    """Agent registration record returned by the registry."""

    domain: str
    publication_authority: str
    registry_status: str
    registry_url: str
    dns_published: bool | None = None
    protocol_status: AgentStatus | None = None
    publication_config: PublicationConfig | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)
    oidc_issuer_url: str = ""
    # Immutable registry agent ID, needed by revoke_agent for safe retries.
    # Last on purpose: the dataclass is public and positional callers exist.
    id: str = ""


@dataclass
class LiveChallengeTranscript:
    """Validated transcript encoded by a managed Live proof challenge."""

    protocol: str
    org_id: str
    agent_id: str
    fqdn: str
    key_id: str
    nonce: str
    expires_at: datetime.datetime


@dataclass
class LiveProvisioningResponse:
    """Proof challenge returned when managed Live provisioning starts."""

    request_id: str
    agent_id: str
    status: str
    challenge: str
    challenge_message: str
    domain: str = ""
    challenge_transcript: LiveChallengeTranscript | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class LiveProofRequest:
    """Signed proof submitted after managed Live registration."""

    request_id: str
    challenge: str
    public_key_jwk: JWK
    signature: str


@dataclass
class LiveProofResponse:
    """Durable handoff status returned after managed Live proof."""

    request_id: str
    agent_id: str
    status: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class LiveProofReissueRequest:
    """Request for a replacement managed Live proof challenge.

    The original public key is local validation context and is not sent to the
    registry.
    """

    request_id: str
    public_key_jwk: JWK


@dataclass
class LiveProofReissueResponse:
    """Replacement challenge returned for an expired managed Live proof."""

    request_id: str
    agent_id: str
    status: str
    challenge: str
    challenge_message: str
    domain: str
    challenge_transcript: LiveChallengeTranscript
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class LifecycleResult:
    """Lifecycle transition result.

    Returned by registry mutation endpoints such as ``submit_challenge_signature``.
    """

    id: str
    state: str
    status_note: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class RegistryAgentStatus:
    """Registry workflow status, kept separate from protocol ``AgentStatus``."""

    registry_status: str
    dns_published: bool | None
    protocol_status: AgentStatus | None
    ready_for_publication: bool
    published: bool
    failed: bool
    terminal: bool
    publication_config: PublicationConfig | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class CanonicalRecordContentResponse:
    """Registry-prepared canonical TXT record content for a local identity signing workflow."""

    canonical: str
    signing_kid: str


@dataclass
class PublishedRecord:
    """Record returned after a successful publish_to_registry call."""

    domain: str
    owner_name: str
    txt_record: str
    ttl: int
    publication_status: str
    protocol_status: AgentStatus | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class PreparedRegistryEvent:
    """Raw untrusted bytes and log context returned by a prepare endpoint."""

    entry_bytes: bytes
    log_reference: str


@dataclass
class KeyRotationPreparationRequest:
    """Input for RegistryClient.prepare_key_rotation.

    *previous_key_id* is the RFC 7638 thumbprint of the current operational
    key — the registry rejects a stale or concurrent rotation.  *public_key*
    is one pending public signing key including kid and alg; private JWK
    members are forbidden and never leave the SDK.
    """

    previous_key_id: str
    public_key: JWK


#: JWK members that carry private key material and must never be sent to a
#: registry (RFC 7518 §6).
_PRIVATE_JWK_MEMBERS: frozenset[str] = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})


@dataclass
class SubmissionResult:
    """Typed result of RegistryClient.submit_prepared_event.

    *state* is one of "pending", "accepted", or "rejected".  A pending or
    otherwise indeterminate submission is retried with the exact same entry
    bytes and idempotency key; the entry is never regenerated.
    """

    state: str
    entry_hash: str = ""
    index: int | None = None
    log_ref: LogRef | None = None
    key_id: str = ""
    error_code: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    VALID_STATES = frozenset({"pending", "accepted", "rejected"})

    @property
    def accepted(self) -> bool:
        """Return True when the registry reported the appended entry as accepted."""
        return self.state == "accepted"


@dataclass
class KeyRotationResult:
    """Durable recovery state for a managed operational-key rotation.

    Entry bytes, their hash, key bindings, and the idempotency key are fixed
    once first persisted. When *activated* is False, call
    ``IdentityManager.resume_key_rotation(registry_client, result)`` to retry
    the exact same bytes under the same idempotency key. Application signing
    remains paused until accepted submission, local activation/supersession,
    and durable state reconciliation all complete.
    """

    previous_kid: str
    new_kid: str
    entry_bytes: bytes = field(repr=False)
    domain: str = ""
    log_reference: str = ""
    previous_thumbprint: str = ""
    new_thumbprint: str = ""
    previous_public_key: JWK | None = field(default=None, repr=False)
    entry_hash: str = ""
    idempotency_key: str = ""
    submission: SubmissionResult | None = None
    activated: bool = False
    application_signing_paused: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _reject_rfc9651_values(value: Any) -> None:
    """Reject RFC 9651-only values from the RFC 8941 profile."""
    import datetime

    from http_sf import DisplayString

    if isinstance(value, (datetime.datetime, DisplayString)):
        raise ValueError("RFC 9651 Date and Display String values are unsupported")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_rfc9651_values(key)
            _reject_rfc9651_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_rfc9651_values(item)


def _parse_sf_dictionary(value: str) -> dict[str, Any]:
    """Parse a complete Structured Fields Dictionary with duplicate rejection."""
    import http_sf

    duplicates: list[tuple[str, str]] = []

    def record_duplicate(key: str, context: str) -> None:
        duplicates.append((key, context))

    try:
        parsed = http_sf.parse(
            value.encode("ascii"),
            tltype="dictionary",
            on_duplicate_key=record_duplicate,
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    profile_parameter_names = {
        "keyid",
        "alg",
        "created",
        "expires",
        "nonce",
        "tag",
        "req",
        "key",
        "name",
    }
    rejected_duplicate = next(
        (
            (key, context)
            for key, context in duplicates
            if context == "dictionary" or key in profile_parameter_names
        ),
        None,
    )
    if rejected_duplicate is not None:
        key, context = rejected_duplicate
        raise ValueError(f"duplicate {context} key {key!r}")
    if not isinstance(parsed, dict):
        raise ValueError("Structured Field value is not a Dictionary")
    _reject_rfc9651_values(parsed)
    return parsed


def _component_structure(component: str) -> tuple[str, dict[str, Any]]:
    """Parse the legacy string component API through the Structured Fields library."""
    import http_sf
    from http_sf import Token

    derived = {
        "@method",
        "@authority",
        "@target-uri",
        "@path",
        "@query",
        "@query-param",
        "@status",
        "@request-target",
        "@scheme",
    }
    serialized = component
    for name in derived:
        if component == name or component.startswith(f"{name};"):
            serialized = http_sf.ser(name) + component[len(name) :]
            break

    duplicates: list[tuple[str, str]] = []
    try:
        parsed = http_sf.parse(
            serialized.encode("ascii"),
            tltype="item",
            on_duplicate_key=lambda key, context: duplicates.append((key, context)),
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    if duplicates:
        key, context = duplicates[0]
        raise ValueError(f"duplicate {context} key {key!r}")
    if not (
        isinstance(parsed, tuple)
        and len(parsed) == 2
        and isinstance(parsed[1], dict)
        and isinstance(parsed[0], (str, Token))
    ):
        raise ValueError("component identifier must be a String or Token item")
    _reject_rfc9651_values(parsed)
    return str(parsed[0]), parsed[1]


def _component_public_text(name: str, parameters: dict[str, Any]) -> str:
    """Render a parsed component in the existing unquoted public string form."""
    import http_sf

    item = http_sf.ser((name, parameters))
    prefix = http_sf.ser(name)
    if not item.startswith(prefix):
        raise ValueError("invalid component serialization")
    return name + item[len(prefix) :]


def _serialize_sf_string(value: str) -> str:
    import http_sf

    return http_sf.ser(value)


def _serialize_sf_bare_item(value: Any) -> str:
    import http_sf

    _reject_rfc9651_values(value)
    return http_sf.ser(value)


def _parse_component_identifier(component: str) -> tuple[str, list[tuple[str, Any]]]:
    name, parameters = _component_structure(component)
    return name, list(parameters.items())


def _canonical_component_identifier(component: str) -> str:
    import http_sf

    name, parameters = _component_structure(component)
    return http_sf.ser((name, parameters))


def _validate_component_identifiers(
    components: list[str], *, request_context: bool | None
) -> None:
    from ._utils import is_lowercase_http_field_name
    from .enums import VerificationCode
    from .exceptions import VerificationError

    seen: set[tuple[str, frozenset[tuple[str, Any]]]] = set()
    simple_derived = {
        "@method",
        "@authority",
        "@target-uri",
        "@path",
        "@query",
        "@request-target",
        "@scheme",
    }
    for component in components:
        try:
            name, parameters = _parse_component_identifier(component)
        except ValueError as exc:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"malformed component identifier {component!r}: {exc}",
            ) from exc
        values = dict(parameters)
        allowed: set[str]
        if name in simple_derived:
            allowed = {"req"}
        elif name == "@query-param":
            allowed = {"name", "req"}
            if not isinstance(values.get("name"), str) or not values["name"]:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "@query-param requires a non-empty string name parameter",
                )
        elif name == "@status":
            allowed = set()
            if request_context is False:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "@status is unavailable for a request signature",
                )
        elif is_lowercase_http_field_name(name):
            allowed = {"key", "req"}
            if "key" in values and (
                not isinstance(values["key"], str) or not values["key"]
            ):
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "field component key parameter must be a non-empty string",
                )
        else:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"unsupported component identifier: {name!r}",
            )
        unknown = set(values) - allowed
        if unknown:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"unsupported component parameter: {sorted(unknown)[0]!r}",
            )
        if "req" in values:
            if values["req"] is not True:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "component req parameter must be Boolean true",
                )
            if request_context is False:
                raise VerificationError(
                    VerificationCode.RECORD_INVALID,
                    "component req parameter requires response request context",
                )
        identity = (name, frozenset(parameters))
        if identity in seen:
            raise VerificationError(
                VerificationCode.RECORD_INVALID,
                f"duplicate equivalent covered component: {component!r}",
            )
        seen.add(identity)


def _parse_https_uri_host(uri: str, *, field_name: str) -> str:
    """Parse *uri*, assert it is HTTPS with a non-empty host, return the host.

    Raises ValidationError on failure.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(uri)
    except Exception as exc:
        raise ValidationError(f"{field_name} is not a valid URI: {exc}") from exc

    if parsed.scheme != "https":
        raise ValidationError(f"{field_name} must use the https scheme")
    if not parsed.hostname:
        raise ValidationError(f"{field_name} must have a non-empty host")
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError(f"{field_name} must not contain credentials")
    if "#" in uri:
        raise ValidationError(f"{field_name} must not contain a fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValidationError(f"{field_name} is not a valid URI: {exc}") from exc
    return parsed.hostname
