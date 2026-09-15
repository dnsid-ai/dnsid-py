"""DNSid CLI config file → SDK config helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

from .models import (
    DEFAULT_REGISTRY_URL,
    DnsidConfig,
    IdentityConfig,
    RegistryConfig,
    TransportConfig,
    VerificationConfig,
)

if TYPE_CHECKING:
    from .manager import IdentityManager, IdentityManagerDependencies


@dataclass
class CliConfigResult:
    """Return value of :func:`config_from_cli_directory`."""

    config: DnsidConfig
    """Core config with ``identity`` populated from the CLI files (plus any caller overlay)."""
    registry_config: RegistryConfig
    key_directory: Path
    """Directory containing the identity's key files (``private.jwk``, ``private.pem``, etc.)."""
    entity_key_path: Path | None = None
    """Resolved accountable-entity private JWK path, when configured by the CLI."""


def config_from_cli_directory(
    path: Path | str | None = None,
    config: DnsidConfig | None = None,
) -> CliConfigResult:
    """Build SDK config objects from DNSid CLI identity files.

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

    Args:
        path: Path to the DNSid identity directory. Defaults to
            ``DNSID_CONFIG_DIR`` when set, otherwise ``~/.dnsid``.
        config: Optional caller configuration. Non-empty ``config.identity``
            fields override the loaded values before normalization or
            derivation; ``verification`` and ``transport`` are used as-is.

    Returns:
        :class:`CliConfigResult` with ``config``, ``registry_config``, and
        ``key_directory``.

    Raises:
        FileNotFoundError: If ``config.json`` does not exist in *path*.
        ValueError: If ``config.json`` is not valid JSON, is not a JSON object,
            contains non-string values for expected string fields, or is
            missing required fields (``domain``, ``governance_id``).
    """
    import os

    from ._utils import normalize_fqdn

    if path is not None:
        base = Path(path)
    else:
        # Testnet commands (e.g. `dnsid testnet run`) expose the identity
        # directory to child processes as DNSID_CONFIG_DIR; honor it before
        # falling back to the user's DNSid config directory.
        env_dir = os.environ.get("DNSID_CONFIG_DIR", "").strip()
        base = Path(env_dir) if env_dir else Path.home() / ".dnsid"

    config_path = base / "config.json"
    try:
        raw = json.loads(config_path.read_text())
    except FileNotFoundError:
        raise FileNotFoundError(
            f"DNSid CLI config not found: {config_path}; "
            "run the DNSid CLI to register your domain first"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"{config_path} must contain a JSON object, got {type(raw).__name__}")
    data: dict[str, object] = raw

    identity = IdentityConfig(
        domain=_str_field(data, config_path, "domain", "fqdn"),
        governance_id=_str_field(data, config_path, "governance_id", "governanceId"),
        log_ref=_str_field(data, config_path, "log_ref", "logRef"),
        status_url=_str_field(data, config_path, "status_url", "statusUrl"),
        ek_url=_str_field(data, config_path, "ek_url", "ekUrl"),
        ku_url=_str_field(data, config_path, "ku_url", "kuUrl"),
        capabilities_url=_str_field(data, config_path, "capabilities_url", "capabilitiesUrl"),
        publish_profile=_str_field(data, config_path, "publish_profile", "publishProfile"),
        max_key_age=_str_field(data, config_path, "max_key_age", "maxKeyAge"),
    )
    # Explicit caller settings win over persisted defaults, before any
    # normalization or derivation.
    if config is not None and config.identity is not None:
        overrides = {
            f.name: getattr(config.identity, f.name)
            for f in fields(IdentityConfig)
            if getattr(config.identity, f.name)
        }
        identity = replace(identity, **overrides)

    if not identity.domain:
        raise ValueError(f"'domain' is required in {config_path}")
    if not identity.governance_id:
        raise ValueError(f"'governance_id' / 'governanceId' is required in {config_path}")

    # Normalize early so status_url derivation and key directory lookup both
    # use the canonical form (lowercase, no trailing dot).
    normalized_domain = normalize_fqdn(identity.domain, agent_fqdn=True)

    server_url = (
        _str_field(data, config_path, "server_url", "registry_url", "registryUrl")
        or DEFAULT_REGISTRY_URL
    )
    if not identity.status_url:
        identity.status_url = _derive_status_url(server_url, normalized_domain)

    entity_key_raw = _str_field(data, config_path, "entity_key_path", "entityKeyPath")
    entity_key_path = Path(entity_key_raw).expanduser() if entity_key_raw else None
    if entity_key_path is not None and not entity_key_path.is_absolute():
        entity_key_path = config_path.parent / entity_key_path

    if (base / "private.jwk").exists() or (base / "private.pem").exists():
        key_directory = base
    else:
        domain_subdir = base / normalized_domain
        key_directory = domain_subdir if domain_subdir.is_dir() else base

    return CliConfigResult(
        config=DnsidConfig(
            identity=identity,
            verification=config.verification if config else VerificationConfig(),
            transport=config.transport if config else TransportConfig(),
        ),
        registry_config=RegistryConfig(registry_url=server_url),
        key_directory=key_directory,
        entity_key_path=entity_key_path,
    )


def identity_manager_from_cli_directory(
    path: Path | str | None = None,
    config: DnsidConfig | None = None,
    deps: IdentityManagerDependencies | None = None,
) -> IdentityManager:
    """Build a fully-initialized ``IdentityManager`` from DNSid CLI identity files.

    Convenience wrapper that combines :func:`config_from_cli_directory` and
    :meth:`~dnsid.LocalKeyProvider.from_cli_directory` into a single call,
    returning the same object as explicitly constructing
    ``IdentityManager(config, key_provider, deps)``.

    When ``entity_key_path`` is configured, its private JWK is loaded as the
    accountable-entity provider unless *deps* already supplies one.

    Args:
        path: Path to the DNSid identity directory. Defaults to
            ``DNSID_CONFIG_DIR`` when set, otherwise ``~/.dnsid``.
        config: Optional caller configuration; see
            :func:`config_from_cli_directory` for precedence.
        deps: Optional :class:`~dnsid.IdentityManagerDependencies` bundle.

    Returns:
        A fully-initialized :class:`~dnsid.IdentityManager`.

    Raises:
        FileNotFoundError: If ``config.json`` or the key file does not exist.
        ValueError: If any config or key file is invalid.
    """
    from .local_key_provider import LocalKeyProvider
    from .manager import IdentityManager, IdentityManagerDependencies

    result = config_from_cli_directory(path, config)
    key_provider = LocalKeyProvider.from_cli_directory(result.key_directory)
    if deps is None:
        deps = IdentityManagerDependencies()
    if deps.entity_key_provider is None and result.entity_key_path is not None:
        deps = replace(
            deps,
            entity_key_provider=LocalKeyProvider.from_private_jwk(result.entity_key_path),
        )
    return IdentityManager(result.config, key_provider, deps)


def _str_field(data: dict[str, object], config_path: Path, *keys: str) -> str:
    """Return the first non-empty string value found under any of the given keys.

    Raises ValueError (with config_path context) when a key is present but its
    value is not a string — catching JSON type errors (e.g. numeric domain)
    before they surface as AttributeError from .strip().
    """
    for key in keys:
        val = data.get(key)
        if val is None:
            continue
        if not isinstance(val, str):
            raise ValueError(
                f"{config_path}: field {key!r} must be a string, got {type(val).__name__}"
            )
        stripped = val.strip()
        if stripped:
            return stripped
    return ""


def _derive_status_url(registry_url: str, domain: str) -> str:
    return f"{registry_url.rstrip('/')}/api/v1/agent/{quote(domain, safe='')}/status"
