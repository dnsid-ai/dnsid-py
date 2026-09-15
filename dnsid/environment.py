"""Environment variable → config helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import quote

from .enums import DNSSECMode
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

# ---------------------------------------------------------------------------
# Env-var name map  (field name → DNSID_* variable name)
# Mirrors dnsidEnvironmentVariables in src/environment.ts
# ---------------------------------------------------------------------------

dnsid_environment_variables: dict[str, str] = {
    "domain": "DNSID_DOMAIN",
    "governance_id": "DNSID_GOVERNANCE_ID",
    "registry_url": "DNSID_REGISTRY_URL",
    "status_url": "DNSID_STATUS_URL",
    "log_ref": "DNSID_LOG_REF",
    "ek_url": "DNSID_EK_URL",
    "ku_url": "DNSID_KU_URL",
    "publish_profile": "DNSID_PUBLISH_PROFILE",
    "dns_server": "DNSID_DNS_SERVER",
    "ca_bundle_path": "DNSID_CA_BUNDLE",
    "dnssec_mode": "DNSID_DNSSEC_MODE",
    "public_url": "DNSID_PUBLIC_URL",
    "key_store_path": "DNSID_KEY_STORE",
    "agent_port": "DNSID_AGENT_PORT",
    "agent_name": "DNSID_AGENT_NAME",
}

EnvironmentFieldName = str  # one of the keys of dnsid_environment_variables


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class EnvironmentConfigResult:
    """Return value of :func:`config_from_environment`."""

    config: DnsidConfig
    registry_config: RegistryConfig
    public_url: str | None = None
    key_store_path: str | None = None
    agent_name: str | None = None
    agent_port: int | None = None


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def key_store_path_from_environment(
    env: dict[str, str] | None = None,
    default_path: str = ".dnsid/keys.json",
) -> str:
    """Return the key-store file path from ``DNSID_KEY_STORE``, or *default_path*."""
    if env is None:
        env = dict(os.environ)
    return env.get("DNSID_KEY_STORE", "").strip() or default_path


def identity_manager_from_environment(
    env: dict[str, str] | None = None,
    deps: IdentityManagerDependencies | None = None,
) -> IdentityManager:
    """Build an ``IdentityManager`` from ``DNSID_*`` environment variables.

    ``DNSID_CONFIG_DIR`` selects CLI/testnet key files when present; otherwise
    ``DNSID_KEY_STORE`` selects the SDK key store. Environment DNS/TLS settings
    become ``config.transport``. Lifecycle-log trust remains an explicit
    dependency; pass a ``LogRegistry`` through *deps*.

    Args:
        env: Environment mapping. Defaults to ``os.environ``.
        deps: Optional explicit manager dependencies.

    Returns:
        A fully initialized ``IdentityManager``.
    """
    from .local_key_provider import LocalKeyProvider
    from .manager import IdentityManager, IdentityManagerDependencies

    environment = dict(os.environ) if env is None else env
    result = config_from_environment(environment)
    config_dir = environment.get("DNSID_CONFIG_DIR", "").strip()
    key_provider = (
        LocalKeyProvider.from_cli_directory(config_dir)
        if config_dir
        else LocalKeyProvider.from_environment(environment)
    )

    return IdentityManager(result.config, key_provider, deps or IdentityManagerDependencies())


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def config_from_environment(
    env: dict[str, str] | None = None,
    *,
    require: list[str] = [],
) -> EnvironmentConfigResult:
    """Build SDK config objects from ``DNSID_*`` environment variables.

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

    Args:
        env: Mapping of environment variables. Defaults to ``os.environ``.
        require: List of field names from :data:`dnsid_environment_variables` that
            must be present and non-empty. Raises :exc:`ValueError` if any are missing.

    Returns:
        :class:`EnvironmentConfigResult` with ``config`` (identity, verification,
        transport), ``registry_config``, and optional ``public_url``,
        ``key_store_path``, ``agent_name``, and ``agent_port``.

    Raises:
        ValueError: If a required variable is missing or ``DNSID_DNSSEC_MODE`` is invalid.
    """
    if env is None:
        env = dict(os.environ)

    # Enforce caller-specified required fields before anything else.
    for field_name in require:
        var_name = dnsid_environment_variables.get(field_name)
        if var_name is None:
            raise ValueError(
                f"unknown field {field_name!r} in require list; "
                f"valid fields: {', '.join(dnsid_environment_variables)}"
            )
        if not env.get(var_name, "").strip():
            raise ValueError(f"{var_name} is required")

    domain = env.get("DNSID_DOMAIN", "").strip()
    if not domain:
        raise ValueError("DNSID_DOMAIN is required")

    governance_id = env.get("DNSID_GOVERNANCE_ID", "").strip()
    if not governance_id:
        raise ValueError("DNSID_GOVERNANCE_ID is required")

    registry_url = env.get("DNSID_REGISTRY_URL", "").strip() or DEFAULT_REGISTRY_URL
    status_url = env.get("DNSID_STATUS_URL", "").strip() or _registry_status_url(
        registry_url, domain
    )

    dnssec_mode_raw = env.get("DNSID_DNSSEC_MODE", "").strip()
    if dnssec_mode_raw:
        try:
            dnssec_mode = DNSSECMode(dnssec_mode_raw)
        except ValueError:
            valid = ", ".join(m.value for m in DNSSECMode)
            raise ValueError(
                f"invalid DNSID_DNSSEC_MODE {dnssec_mode_raw!r}; expected one of: {valid}"
            ) from None
    else:
        dnssec_mode = DNSSECMode.AUTO

    config = DnsidConfig(
        identity=IdentityConfig(
            domain=domain,
            governance_id=governance_id,
            log_ref=env.get("DNSID_LOG_REF", "").strip() or "noop:0",
            status_url=status_url,
            ek_url=_optional_url(env, "DNSID_EK_URL"),
            ku_url=_optional_url(env, "DNSID_KU_URL"),
            publish_profile=env.get("DNSID_PUBLISH_PROFILE", "").strip(),
        ),
        verification=VerificationConfig(dnssec_mode=dnssec_mode),
        transport=TransportConfig(
            dns_server=env.get("DNSID_DNS_SERVER", "").strip(),
            ca_bundle_path=env.get("DNSID_CA_BUNDLE", "").strip(),
        ),
    )

    registry_config = RegistryConfig(
        registry_url=registry_url,
    )

    agent_port: int | None = None
    agent_port_raw = env.get("DNSID_AGENT_PORT", "").strip()
    if agent_port_raw:
        try:
            parsed = int(agent_port_raw)
        except ValueError:
            raise ValueError("DNSID_AGENT_PORT must be a positive integer") from None
        if parsed <= 0:
            raise ValueError("DNSID_AGENT_PORT must be a positive integer")
        agent_port = parsed

    return EnvironmentConfigResult(
        config=config,
        registry_config=registry_config,
        public_url=env.get("DNSID_PUBLIC_URL", "").strip() or None,
        key_store_path=env.get("DNSID_KEY_STORE", "").strip() or None,
        agent_name=env.get("DNSID_AGENT_NAME", "").strip() or None,
        agent_port=agent_port,
    )


def _optional_url(env: dict[str, str], var_name: str) -> str:
    """Return a stripped optional URL override, or "" when the var is unset.

    An explicitly-set-but-blank value (e.g. ``DNSID_EK_URL=``) is a misconfiguration
    and raises, rather than silently falling back to the auto-derived default.
    """
    raw = env.get(var_name)
    if raw is None:
        return ""
    stripped = raw.strip()
    if not stripped:
        raise ValueError(
            f"{var_name} is set but blank; unset it to auto-derive the default, or provide a URL"
        )
    return stripped


def _registry_status_url(registry_url: str, domain: str) -> str:
    return f"{registry_url.rstrip('/')}/api/v1/agent/{quote(domain, safe='')}/status"
