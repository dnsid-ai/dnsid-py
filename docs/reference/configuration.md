---
title: "Python: Configuration"
description: "Protocol, transport, and registry configuration, plus CLI-directory and environment-variable config helpers."
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
- `private_address_hosts` (`frozenset[str]`): Hostnames permitted to resolve to non-public addresses. An exact entry (``"registry.dnsid.test"``) matches that host only; a leading-dot entry (``".dnsid.test"``) matches the domain and every name beneath it. Empty by default; use only for intended private services such as a loopback testnet zone.

## `RegistryConfig`

```python
from dnsid import RegistryConfig
```

Control-plane configuration for managing the local identity's registry records.

Never used by VerifyDomain to validate external identities; verification always
fetches the signed record.su endpoint.

## `PublicationConfig`

```python
from dnsid import PublicationConfig
```

Authoritative identity-record values returned by the registry.

## `config_from_cli_directory`

```python
from dnsid import config_from_cli_directory
```

```python
config_from_cli_directory(path: Path | str | None = None, config: DnsidConfig | None = None) -> CliConfigResult
```

Build SDK config objects from DNSid CLI identity files.

Reads the DNSid CLI identity directory (defaulting to ``~/.dnsid``) and
maps ``config.json`` publication fields into ``DnsidConfig.identity``.
Both snake_case and camelCase field names are accepted for every field,
matching the TypeScript SDK and the CLI config contract.

Two directory shapes are accepted:

* **Root identity directory** (e.g. ``~/.dnsid``): ``config.json`` at the
  root is the current-identity pointer; key files live under ``<domain>/``.
* **Per-identity directory** (e.g. ``~/.dnsid/agent.example.com``):
  ``config.json`` is read directly; key files are in the same directory.

CLI ``config.json`` → SDK mapping (snake_case / camelCase aliases):

* ``domain`` / ``fqdn``                       → ``identity.domain``
* ``governance_id`` / ``governanceId``         → ``identity.governance_id``
* ``status_url`` / ``statusUrl``               → ``identity.status_url``
* ``server_url`` / ``registry_url`` / ``registryUrl`` → ``RegistryConfig.registry_url``
  and used to derive ``status_url`` when absent
* ``log_ref`` / ``logRef``                     → ``identity.log_ref``
* ``ek_url`` / ``ekUrl``                       → ``identity.ek_url``
* ``ku_url`` / ``kuUrl``                       → ``identity.ku_url``
* ``capabilities_url`` / ``capabilitiesUrl``   → ``identity.capabilities_url``
* ``publish_profile`` / ``publishProfile``     → ``identity.publish_profile``
* ``max_key_age`` / ``maxKeyAge``              → ``identity.max_key_age``
* ``entity_key_path`` / ``entityKeyPath``      → accountable-entity key provider

Verification and transport settings are never read from the CLI files;
they come only from *config*.

**Arguments:**

- `path` (`Path | str | None`): Path to the DNSid identity directory. Defaults to ``DNSID_CONFIG_DIR`` when set, otherwise ``~/.dnsid``. — default `None`
- `config` (`DnsidConfig | None`): Optional caller configuration. Non-empty ``config.identity`` fields override the loaded values before normalization or derivation; ``verification`` and ``transport`` are used as-is. — default `None`

**Returns:**

- `CliConfigResult` — class:`CliConfigResult` with ``config``, ``registry_config``, and
- `CliConfigResult` — ``key_directory``.

**Raises:**

- `FileNotFoundError`: If ``config.json`` does not exist in *path*.
- `ValueError`: If ``config.json`` is not valid JSON, is not a JSON object, contains non-string values for expected string fields, or is missing required fields (``domain``, ``governance_id``).

## `identity_manager_from_cli_directory`

```python
from dnsid import identity_manager_from_cli_directory
```

```python
identity_manager_from_cli_directory(path: Path | str | None = None, config: DnsidConfig | None = None, deps: IdentityManagerDependencies | None = None) -> IdentityManager
```

Build a fully-initialized ``IdentityManager`` from DNSid CLI identity files.

Convenience wrapper that combines `config_from_cli_directory` and
`from_cli_directory` into a single call,
returning the same object as explicitly constructing
``IdentityManager(config, key_provider, deps)``.

When ``entity_key_path`` is configured, its private JWK is loaded as the
accountable-entity provider unless *deps* already supplies one.

**Arguments:**

- `path` (`Path | str | None`): Path to the DNSid identity directory. Defaults to ``DNSID_CONFIG_DIR`` when set, otherwise ``~/.dnsid``. — default `None`
- `config` (`DnsidConfig | None`): Optional caller configuration; see `config_from_cli_directory` for precedence. — default `None`
- `deps` (`IdentityManagerDependencies | None`): Optional `IdentityManagerDependencies` bundle. — default `None`

**Returns:**

- `IdentityManager` — A fully-initialized `IdentityManager`.

**Raises:**

- `FileNotFoundError`: If ``config.json`` or the key file does not exist.
- `ValueError`: If any config or key file is invalid.

## `CliConfigResult`

```python
from dnsid import CliConfigResult
```

Return value of `config_from_cli_directory`.

**Attributes:**

- `config` (`DnsidConfig`): Core config with ``identity`` populated from the CLI files (plus any caller overlay).
- `key_directory` (`Path`): Directory containing the identity's key files (``private.jwk``, ``private.pem``, etc.).
- `entity_key_path` (`Path | None`): Resolved accountable-entity private JWK path, when configured by the CLI.

## `config_from_environment`

```python
from dnsid import config_from_environment
```

```python
config_from_environment(env: dict[str, str] | None = None, require: list[str] = []) -> EnvironmentConfigResult
```

Build SDK config objects from ``DNSID_*`` environment variables.

Required variables:

* ``DNSID_DOMAIN`` — agent FQDN
* ``DNSID_GOVERNANCE_ID`` — governance domain or URI
* ``DNSID_STATUS_URL`` — direct agent status URL (if omitted, derived from
  ``DNSID_REGISTRY_URL`` which itself defaults to ``https://api.dnsid.ai``)

Optional variables:

* ``DNSID_LOG_REF`` — log reference (default: ``"noop:0"``)
* ``DNSID_REGISTRY_URL`` — registry base URL
* ``DNSID_KU_URL`` — explicit JWKS URL override
* ``DNSID_DNS_SERVER`` — custom DNS server in ``host:port`` form
* ``DNSID_CA_BUNDLE`` — path to a CA bundle for TLS trust augmentation
* ``DNSID_DNSSEC_MODE`` — ``"auto"`` | ``"validated"`` | ``"required"``
* ``DNSID_PUBLIC_URL`` — public base URL of the agent
* ``DNSID_KEY_STORE`` — local key-store file path
* ``DNSID_AGENT_NAME`` — display name for the agent
* ``DNSID_AGENT_PORT`` — HTTP port the agent listens on

**Arguments:**

- `env` (`dict[str, str] | None`): Mapping of environment variables. Defaults to ``os.environ``. — default `None`
- `require` (`list[str]`): List of field names from `dnsid_environment_variables` that must be present and non-empty. Raises `ValueError` if any are missing. — default `[]`

**Returns:**

- `EnvironmentConfigResult` — class:`EnvironmentConfigResult` with ``config`` (identity, verification,
- `EnvironmentConfigResult` — transport), ``registry_config``, and optional ``public_url``,
- `EnvironmentConfigResult` — ``key_store_path``, ``agent_name``, and ``agent_port``.

**Raises:**

- `ValueError`: If a required variable is missing or ``DNSID_DNSSEC_MODE`` is invalid.

## `identity_manager_from_environment`

```python
from dnsid import identity_manager_from_environment
```

```python
identity_manager_from_environment(env: dict[str, str] | None = None, deps: IdentityManagerDependencies | None = None) -> IdentityManager
```

Build an ``IdentityManager`` from ``DNSID_*`` environment variables.

``DNSID_CONFIG_DIR`` selects CLI/testnet key files when present; otherwise
``DNSID_KEY_STORE`` selects the SDK key store. Environment DNS/TLS settings
become ``config.transport``. Lifecycle-log trust remains an explicit
dependency; pass a ``LogRegistry`` through *deps*.

**Arguments:**

- `env` (`dict[str, str] | None`): Environment mapping. Defaults to ``os.environ``. — default `None`
- `deps` (`IdentityManagerDependencies | None`): Optional explicit manager dependencies. — default `None`

**Returns:**

- `IdentityManager` — A fully initialized ``IdentityManager``.

## `EnvironmentConfigResult`

```python
from dnsid import EnvironmentConfigResult
```

Return value of `config_from_environment`.

## `EnvironmentFieldName`

```python
from dnsid import EnvironmentFieldName
```

*Value:* `str`

## `dnsid_environment_variables`

```python
from dnsid import dnsid_environment_variables
```

*Type:* `dict[str, str]`

*Value:* `{'domain': 'DNSID_DOMAIN', 'governance_id': 'DNSID_GOVERNANCE_ID', 'registry_url': 'DNSID_REGISTRY_URL', 'status_url': 'DNSID_STATUS_URL', 'log_ref': 'DNSID_LOG_REF', 'ek_url': 'DNSID_EK_URL', 'ku_url': 'DNSID_KU_URL', 'publish_profile': 'DNSID_PUBLISH_PROFILE', 'dns_server': 'DNSID_DNS_SERVER', 'ca_bundle_path': 'DNSID_CA_BUNDLE', 'dnssec_mode': 'DNSID_DNSSEC_MODE', 'public_url': 'DNSID_PUBLIC_URL', 'key_store_path': 'DNSID_KEY_STORE', 'agent_port': 'DNSID_AGENT_PORT', 'agent_name': 'DNSID_AGENT_NAME'}`

## `key_store_path_from_environment`

```python
from dnsid import key_store_path_from_environment
```

```python
key_store_path_from_environment(env: dict[str, str] | None = None, default_path: str = '.dnsid/keys.json') -> str
```

Return the key-store file path from ``DNSID_KEY_STORE``, or *default_path*.
