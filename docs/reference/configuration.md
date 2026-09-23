---
title: "Python: Configuration"
description: "Protocol, transport, and registry configuration, plus loading from environment variables, deployment files, and DNSid CLI directories."
---

<!-- GENERATED FILE — do not edit. Regenerate with `python scripts/gen_docs.py` in dnsid-ai/dnsid-py. -->

## `DnsidConfig`

```python
from dnsid import DnsidConfig
```

Single core configuration entry point for IdentityManager.

**Attributes:**

- `identity` (`IdentityConfig | None`): Local identity publication settings. Omit for a verification-only manager.
- `verification` (`VerificationConfig`): Protocol verification and counterparty acceptance.
- `transport` (`TransportConfig`): SDK-managed DNS and HTTPS deployment settings.

## `IdentityConfig`

```python
from dnsid import IdentityConfig
```

Local identity publication settings (``DnsidConfig.identity``).

Contains only fields that appear in the _dnsid TXT record.  Verification
policy lives in VerificationConfig; transport in TransportConfig.

NormalizeFQDN is applied to *domain* and *governance_id* (when it is a domain
name) during IdentityManager.__init__.

Every field defaults to ``""`` (absent) so configuration loaders and code
overlays can carry a partial identity; the IdentityManager constructor
rejects an absent required field with ArgumentError naming it.

**Attributes:**

- `domain` (`str`): Agent FQDN the identity record is published for (required).
- `governance_id` (`str`): Registrant domain — the gi tag (required).
- `log_ref` (`str`): Log reference in ``"method:entry-ref"`` form (required).
- `status_url` (`str`): HTTPS status (su) endpoint URL (required).
- `policy_flags` (`str`): Comma-separated policy flags (e.g. ``"mtls,logchk"``).
- `max_key_age` (`str`): Maximum operational-key age — the ka tag; one of ``"24h"``, ``"7d"``, ``"30d"``, ``"90d"``, or empty for no limit.
- `ek_url` (`str`): Accountable-entity JWKS URL — the ek tag. Required for draft 01 publishing; the host must equal or be beneath gi.
- `ku_url` (`str`): Agent operational JWKS URL — the ku tag. Required for draft 01 publishing; the host must equal the identity FQDN.
- `capabilities_url` (`str`): Optional URL for AGENTS.md or an Agent Card (cu tag).
- `publish_profile` (`str`): Wire profile emitted by create_txt_record and the registry publish workflow; empty selects the current numbered draft, ``dnsid-draft-01``.

## `VerificationConfig`

```python
from dnsid import VerificationConfig
```

Protocol verification and counterparty acceptance settings.

Identical defaults and behaviour for local-identity and verification-only
managers.

**Attributes:**

- `status_check_interval` (`datetime.timedelta`): Maximum age of cached status before verify_domain re-fetches ``su``. Zero (default) re-fetches on every invocation (spec-strict interactive verification). Must be non-negative.
- `dnssec_mode` (`DNSSECMode`): DNSSEC enforcement mode; ``FAILED`` always aborts.
- `trusted_entities` (`list[TrustedEntity] | tuple[TrustedEntity, ...] | None`): Optional counterparty allowlist. ``None`` makes no acceptance decision; an empty list denies every counterparty.

## `TrustedEntity`

```python
from dnsid import TrustedEntity
```

One counterparty allowlist entry (``VerificationConfig.trusted_entities``).

**Attributes:**

- `governance_id` (`str`): Accountable-entity domain that must equal the verified record's ``gi`` exactly (after NormalizeFQDN of this value only). No wildcard, suffix, or transitive matching.
- `entity_key_thumbprints` (`tuple[str, ...] | None`): Optional pins. When present, must be a non-empty sequence of distinct RFC 7638 SHA-256 JWK thumbprints (unpadded base64url, 32 decoded bytes); the verified current record-signing key must match one of them. Never learned or expanded automatically.

## `TransportConfig`

```python
from dnsid import TransportConfig
```

Optional deployment/runtime controls for SDK-managed DNS and HTTPS.

These fields do not appear in TXT records and do not alter protocol semantics.
Pass as ``DnsidConfig.transport``; the settings configure SDK-managed
default components only and never mutate injected dependencies.

**Attributes:**

- `dns_server` (`str`): Custom DNS server: ``"host:port"`` form (e.g. ``"8.8.8.8:53"``) for standard DNS, or an ``http(s)://`` URL for DNSid TXT lookups via DNS-over-HTTPS (which reports DNSSEC state from the AD bit); empty uses the system resolver. SDK-created HTTP clients use custom DNS only for ``"host:port"`` values; a DoH URL does not replace their system hostname resolver.
- `ca_bundle_path` (`str`): Path to a CA bundle used to augment TLS trust for SDK-managed HTTPS fetches.
- `private_address_hosts` (`frozenset[str]`): Hostnames whose SDK-managed HTTPS destinations may resolve to loopback or private-use (RFC 1918/4193) addresses. An exact entry (``"registry.dnsid.test"``) matches that host only; a leading-dot entry (``".test"``) matches ``test`` and every name beneath it, label-bounded and case-insensitive. Link-local, multicast, reserved, and unspecified addresses stay rejected, as does a resolution mixing public and non-public addresses. IP-literal URLs are never exempted. Empty by default with no built-in exemption: ``.test`` is an ordinary suffix entry (the expected one for a local ``dnsid`` stack). Entries must be bare hostnames or leading-dot suffixes; IP literals, ports, schemes, paths, and credentials are rejected at construction. Applies to every fetch made with this config, including the C2SP default resource fetcher; ignored by injected fetchers.

## `RegistryConfig`

```python
from dnsid import RegistryConfig
```

Control-plane configuration for managing the local identity's registry records.

Never used by VerifyDomain to validate external identities; verification always
fetches the signed record.su endpoint.

**Attributes:**

- `registry_url` (`str`): Registry base URL. ``""`` (absent) lets the RegistryClient constructor default to ``DEFAULT_REGISTRY_URL``.

## `PublicationConfig`

```python
from dnsid import PublicationConfig
```

Authoritative identity-record values returned by the registry.

## `LoadedConfig`

```python
from dnsid import LoadedConfig
```

Partial configuration from one source, or the merge of several.

Sections are always present as values; a field equal to its default is absent.

**Attributes:**

- `registry_credential` (`str | None`): Registry bearer credential. Never placed in a loggable config object.

## `LogTrust`

```python
from dnsid import LogTrust
```

Lifecycle-log trust used to build ``deps.log_registry`` when the caller supplies none.

Exactly one variant must be set when `construct_identity_manager` uses it. Under
`merge_loaded_config` the section is replaced as a whole when the overlay sets any
variant.

**Attributes:**

- `managed` (`bool | None`): ``True`` selects the embedded DNSid-managed trust catalog.
- `profile` (`C2spTlogTrustProfile | None`): Parsed ``dnsid-c2sp-tlog-trust-profile@v1`` document.
- `policy_document` (`bytes | None`): Independently trusted C2SP ``tlog-policy`` bytes.
- `policy_url` (`str | None`): Independently trusted C2SP ``tlog-policy`` HTTPS URL.

## `KeySource`

```python
from dnsid import KeySource
```

Where local key material lives. Variants are not exclusive.

``cli_directory`` supplies the operational key when present, otherwise
``key_store_path``; ``entity_key_path`` supplies the entity key whenever set.

**Attributes:**

- `cli_directory` (`str | None`): DNSid CLI identity directory holding ``private.jwk`` or ``<domain>/private.jwk``.
- `entity_key_path` (`str | None`): Accountable-entity private JWK file.
- `key_store_path` (`str | None`): :meth:`LocalKeyProvider.load` key-store file; used only without ``cli_directory``.

## `load_environment`

```python
from dnsid import load_environment
```

```python
load_environment(env: Mapping[str, str] | None = None) -> LoadedConfig
```

Read the ``DNSID_*`` environment schema into a `LoadedConfig`.

Values are trimmed; unset, empty, or whitespace-only variables are absent.
Unknown ``DNSID_*`` variables (deployment tooling such as ``DNSID_PUBLIC_URL``)
are ignored. ``DNSID_LOG_POLICY_FILE`` is read as bytes and
``DNSID_LOG_TRUST_PROFILE_FILE`` is read and parsed here.

**Arguments:**

- `env` (`Mapping[str, str] | None`): Environment mapping. Defaults to ``os.environ``. — default `None`

**Raises:**

- `ArgumentError`: ``DNSID_DNSSEC_MODE`` is not ``auto``, ``validated``, or ``required``.

## `load_file`

```python
from dnsid import load_file
```

```python
load_file(path: Path | str) -> LoadedConfig
```

Read a JSON deployment file: ``{"dnsid"?, "logTrust"?, "registry"?}``.

Members are camelCase, the JSON encoding of `LoadedConfig` minus the
secret ``registryCredential`` and ``keySource``. Unknown members, mistyped
values, and duplicate members are rejected with ArgumentError; ``dnsid``
contents are otherwise validated by the IdentityManager constructor.

## `load_cli_directory`

```python
from dnsid import load_cli_directory
```

```python
load_cli_directory(directory: Path | str | None = None) -> LoadedConfig
```

Read ``<directory>/config.json`` written by the DNSid CLI.

*directory* defaults to ``~/.dnsid``; ``DNSID_CONFIG_DIR`` is not consulted
here (`load_environment` carries it as ``key_source.cli_directory``).
Persisted snake_case publication fields map into ``dnsid.identity`` exactly
as written: ``status_url`` is never derived from ``server_url`` and no log
reference is substituted. The directory becomes ``key_source.cli_directory``
and a relative ``entity_key_path`` resolves against it.

**Raises:**

- `FileNotFoundError`: ``config.json`` does not exist.
- `ArgumentError`: ``config.json`` is not a JSON object or a field is not a string.

## `merge_loaded_config`

```python
from dnsid import merge_loaded_config
```

```python
merge_loaded_config(base: LoadedConfig, overlay: LoadedConfig) -> LoadedConfig
```

Apply *overlay* onto *base* field-wise; a present overlay field wins.

Presence, not truthiness: ``trusted_entities=[]`` replaces a loaded list.
Lists replace, never concatenate. ``log_trust`` is replaced as a whole when
the overlay sets any variant. See the module docstring for the default
values that cannot express presence.

## `construct_identity_manager`

```python
from dnsid import construct_identity_manager
```

```python
construct_identity_manager(loaded: LoadedConfig, key_provider: KeyProvider | None = None, deps: IdentityManagerDependencies | None = None) -> IdentityManager
```

Build an `IdentityManager` from a merged `LoadedConfig`.

Caller dependencies win: ``deps.log_registry`` is built from ``log_trust``
only when absent (the trust section is then not inspected), and key
providers are built from ``key_source`` only when ``dnsid.identity`` is
present and the corresponding provider is absent. ``loaded.dnsid`` is
validated first so invalid configuration never reads a key file or fetches
a policy. Adds no configuration values.

## `identity_manager_from_environment`

```python
from dnsid import identity_manager_from_environment
```

```python
identity_manager_from_environment(env: Mapping[str, str] | None = None, overlay: DnsidConfig | None = None, key_provider: KeyProvider | None = None, deps: IdentityManagerDependencies | None = None) -> IdentityManager
```

Load → Merge → Construct over ``load_environment(env)``.

Without ``DNSID_DOMAIN`` the result is a verification-only manager; under
``dnsid local run``, ``DNSID_CONFIG_DIR`` supplies the key files.

## `identity_manager_from_dnsid`

```python
from dnsid import identity_manager_from_dnsid
```

```python
identity_manager_from_dnsid(directory: Path | str | None = None, overlay: DnsidConfig | None = None, key_provider: KeyProvider | None = None, deps: IdentityManagerDependencies | None = None) -> IdentityManager
```

Load → Merge → Construct over ``load_cli_directory(directory)``.

## `identity_manager_from_file`

```python
from dnsid import identity_manager_from_file
```

```python
identity_manager_from_file(path: Path | str, overlay: DnsidConfig | None = None, key_provider: KeyProvider | None = None, deps: IdentityManagerDependencies | None = None) -> IdentityManager
```

Load → Merge → Construct over ``load_file(path)``.

## `registry_client_from_environment`

```python
from dnsid import registry_client_from_environment
```

```python
registry_client_from_environment(env: Mapping[str, str] | None = None) -> RegistryClient
```

`RegistryClient` from ``DNSID_REGISTRY_URL`` and ``DNSID_API_KEY``.

The constructor applies the local-registry default when the URL is absent.
