"""Configuration loading: environment variables, deployment files, DNSid CLI directories.

Loaders parse; constructors default. Each loader returns a :class:`LoadedConfig`
holding only the fields present in its source: empty or whitespace-only values
are absent, nothing is defaulted or derived, and no second source is consulted.
:func:`merge_loaded_config` combines partial results field-wise (later wins; lists replace;
``log_trust`` is atomic). :func:`construct_identity_manager` fills the dependencies the caller
did not supply from ``log_trust`` and ``key_source``, then calls the ordinary
:class:`~dnsid.IdentityManager` constructor, which applies every default and
validation.

Presence is "differs from the dataclass default". Core config types cannot
express presence for their defaults, so in :func:`merge_loaded_config` an overlay value equal
to the default is absent and cannot reset a loaded value: ``""`` identity and
transport strings, ``status_check_interval=0``, and an
empty ``private_address_hosts``. ``trusted_entities=[]`` is present (deny all);
``None`` is absent.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from collections.abc import Mapping
from dataclasses import MISSING, dataclass, field, fields, is_dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from .enums import DNSSECMode
from .exceptions import ArgumentError
from .models import (
    DnsidConfig,
    IdentityConfig,
    RegistryConfig,
    TransportConfig,
    TrustedEntity,
    VerificationConfig,
)

if TYPE_CHECKING:
    from .c2sp_tlog import C2spTlogTrustProfile
    from .interfaces import KeyProvider
    from .manager import IdentityManager, IdentityManagerDependencies
    from .registry import LogRegistry
    from .registry_client import RegistryClient


@dataclass
class LogTrust:
    """Lifecycle-log trust used to build ``deps.log_registry`` when the caller supplies none.

    Exactly one variant must be set when :func:`construct_identity_manager` uses it. Under
    :func:`merge_loaded_config` the section is replaced as a whole when the overlay sets any
    variant.
    """

    managed: bool | None = None
    """``True`` selects the embedded DNSid-managed trust catalog."""
    profile: C2spTlogTrustProfile | None = None
    """Parsed ``dnsid-c2sp-tlog-trust-profile@v1`` document."""
    policy_document: bytes | None = None
    """Independently trusted C2SP ``tlog-policy`` bytes."""
    policy_url: str | None = None
    """Independently trusted C2SP ``tlog-policy`` HTTPS URL."""


@dataclass
class KeySource:
    """Where local key material lives. Variants are not exclusive.

    ``cli_directory`` supplies the operational key when present, otherwise
    ``key_store_path``; ``entity_key_path`` supplies the entity key whenever set.
    """

    cli_directory: str | None = None
    """DNSid CLI identity directory holding ``private.jwk`` or ``<domain>/private.jwk``."""
    entity_key_path: str | None = None
    """Accountable-entity private JWK file."""
    key_store_path: str | None = None
    """:meth:`LocalKeyProvider.load` key-store file; used only without ``cli_directory``."""


@dataclass
class LoadedConfig:
    """Partial configuration from one source, or the merge of several.

    Sections are always present as values; a field equal to its default is absent.
    """

    dnsid: DnsidConfig = field(default_factory=DnsidConfig)
    log_trust: LogTrust = field(default_factory=LogTrust)
    registry: RegistryConfig = field(default_factory=RegistryConfig)
    key_source: KeySource = field(default_factory=KeySource)


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

_IDENTITY_VARIABLES = {
    "DNSID_DOMAIN": "domain",
    "DNSID_GOVERNANCE_ID": "governance_id",
    "DNSID_STATUS_URL": "status_url",
    "DNSID_LOG_REF": "log_ref",
    "DNSID_EK_URL": "ek_url",
    "DNSID_KU_URL": "ku_url",
    "DNSID_PUBLISH_PROFILE": "publish_profile",
    "DNSID_CAPABILITIES_URL": "capabilities_url",
}


def load_environment(env: Mapping[str, str] | None = None) -> LoadedConfig:
    """Read the ``DNSID_*`` environment schema into a :class:`LoadedConfig`.

    Values are trimmed; unset, empty, or whitespace-only variables are absent.
    Unknown ``DNSID_*`` variables (deployment tooling such as ``DNSID_PUBLIC_URL``)
    are ignored. ``DNSID_LOG_POLICY_FILE`` is read as bytes and
    ``DNSID_LOG_TRUST_PROFILE_FILE`` is read and parsed here. The secret
    ``DNSID_API_KEY`` is read only by :func:`registry_client_from_environment`.

    Args:
        env: Environment mapping. Defaults to ``os.environ``.

    Raises:
        ArgumentError: ``DNSID_DNSSEC_MODE`` is not ``auto``, ``validated``, or ``required``.
    """
    source = os.environ if env is None else env

    def get(name: str) -> str | None:
        return (source.get(name) or "").strip() or None

    identity_fields = {f: v for var, f in _IDENTITY_VARIABLES.items() if (v := get(var))}
    mode = get("DNSID_DNSSEC_MODE")
    try:
        dnssec_mode = DNSSECMode(mode) if mode else None
    except ValueError:
        raise ArgumentError(
            f"invalid DNSID_DNSSEC_MODE {mode!r}; expected one of: "
            + ", ".join(m.value for m in DNSSECMode)
        ) from None
    hosts = [h.strip() for h in (get("DNSID_PRIVATE_HOSTS") or "").split(",") if h.strip()]

    policy_file = get("DNSID_LOG_POLICY_FILE")
    profile_file = get("DNSID_LOG_TRUST_PROFILE_FILE")
    profile = None
    if profile_file:
        from .c2sp_tlog import parse_c2sp_tlog_trust_profile

        profile = parse_c2sp_tlog_trust_profile(Path(profile_file).read_bytes())

    return LoadedConfig(
        dnsid=DnsidConfig(
            identity=IdentityConfig(**identity_fields) if identity_fields else None,
            verification=VerificationConfig(dnssec_mode=dnssec_mode),
            transport=TransportConfig(
                dns_server=get("DNSID_DNS_SERVER") or "",
                ca_bundle_path=get("DNSID_CA_BUNDLE") or "",
                private_address_hosts=frozenset(hosts),
            ),
        ),
        log_trust=LogTrust(
            profile=profile,
            policy_document=Path(policy_file).read_bytes() if policy_file else None,
            policy_url=get("DNSID_LOG_POLICY_URL"),
        ),
        registry=RegistryConfig(registry_url=get("DNSID_REGISTRY_URL") or ""),
        key_source=KeySource(
            cli_directory=get("DNSID_CONFIG_DIR"), key_store_path=get("DNSID_KEY_STORE")
        ),
    )


# ---------------------------------------------------------------------------
# Deployment file
# ---------------------------------------------------------------------------


def load_file(path: Path | str) -> LoadedConfig:
    """Read a JSON deployment file: ``{"dnsid"?, "logTrust"?, "registry"?}``.

    Members are camelCase, the JSON encoding of :class:`LoadedConfig` minus
    ``keySource``. Registry credentials are never part of loaded configuration.
    Unknown members, mistyped values, and duplicate members are rejected with
    ArgumentError; ``dnsid``
    contents are otherwise validated by the IdentityManager constructor.
    """
    source = str(path)
    root = _json_object(Path(path).read_bytes(), source)
    _reject_unknown(root, source, ("dnsid", "logTrust", "registry"))
    loaded = LoadedConfig()

    if "dnsid" in root:
        loaded.dnsid = _dnsid_from_json(_object(root["dnsid"], f"{source}: dnsid"), source)

    if "logTrust" in root:
        trust = _object(root["logTrust"], f"{source}: logTrust")
        _reject_unknown(trust, f"{source}: logTrust", ("managed", "profile", "policyUrl"))
        profile = None
        if "profile" in trust:
            from .c2sp_tlog import parse_c2sp_tlog_trust_profile

            document = _object(trust["profile"], f"{source}: logTrust.profile")
            profile = parse_c2sp_tlog_trust_profile(json.dumps(document).encode())
        loaded.log_trust = LogTrust(
            managed=_typed(trust, "managed", bool, f"{source}: logTrust"),
            profile=profile,
            policy_url=_typed(trust, "policyUrl", str, f"{source}: logTrust"),
        )
        if not _has_trust(loaded.log_trust):
            raise ArgumentError(f"{source}: logTrust requires one of managed, profile, policyUrl")

    if "registry" in root:
        registry = _object(root["registry"], f"{source}: registry")
        _reject_unknown(registry, f"{source}: registry", ("registryUrl",))
        loaded.registry = RegistryConfig(
            registry_url=_typed(registry, "registryUrl", str, f"{source}: registry") or ""
        )
    return loaded


def _dnsid_from_json(raw: dict[str, Any], source: str) -> DnsidConfig:
    """Build a partial DnsidConfig; unknown members raise via the config dataclasses."""
    data = _snake_keys(raw)
    identity = data.pop("identity", None)
    verification = data.pop("verification", None)
    transport = data.pop("transport", None)
    config = DnsidConfig(**data)  # rejects unknown sections
    if identity is not None:
        config.identity = IdentityConfig(**_object(identity, f"{source}: dnsid.identity"))
    if verification is not None:
        v = _object(verification, f"{source}: dnsid.verification")
        if "dnssec_mode" in v:
            try:
                v["dnssec_mode"] = DNSSECMode(v["dnssec_mode"])
            except ValueError:
                raise ArgumentError(
                    f"{source}: dnsid.verification.dnssecMode {v['dnssec_mode']!r} is invalid"
                ) from None
        if "status_check_interval" in v:
            seconds = v["status_check_interval"]
            if isinstance(seconds, bool) or not isinstance(seconds, int | float):
                raise ArgumentError(
                    f"{source}: dnsid.verification.statusCheckInterval must be a number"
                )
            v["status_check_interval"] = datetime.timedelta(seconds=seconds)
        if isinstance(v.get("trusted_entities"), list):
            v["trusted_entities"] = [
                TrustedEntity(**_object(e, f"{source}: dnsid.verification.trustedEntities"))
                for e in v["trusted_entities"]
            ]
        config.verification = VerificationConfig(**v)
    if transport is not None:
        t = _object(transport, f"{source}: dnsid.transport")
        if "private_address_hosts" in t:
            hosts = t["private_address_hosts"]
            if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
                raise ArgumentError(
                    f"{source}: dnsid.transport.privateAddressHosts must be a list of strings"
                )
            t["private_address_hosts"] = frozenset(hosts)
        config.transport = TransportConfig(**t)
    return config


# ---------------------------------------------------------------------------
# DNSid CLI directory
# ---------------------------------------------------------------------------

_CLI_IDENTITY_FIELDS = (
    "domain",
    "governance_id",
    "status_url",
    "log_ref",
    "ek_url",
    "ku_url",
    "capabilities_url",
    "publish_profile",
    "max_key_age",
)


def load_cli_directory(directory: Path | str | None = None) -> LoadedConfig:
    """Read ``<directory>/config.json`` written by the DNSid CLI.

    *directory* defaults to ``~/.dnsid``; ``DNSID_CONFIG_DIR`` is not consulted
    here (:func:`load_environment` carries it as ``key_source.cli_directory``).
    Persisted snake_case publication fields map into ``dnsid.identity`` exactly
    as written: ``status_url`` is never derived from ``server_url`` and no log
    reference is substituted. The directory becomes ``key_source.cli_directory``
    and a relative ``entity_key_path`` resolves against the directory of the
    ``config.json`` that carries it.

    The CLI treats a root ``config.json`` as the current-identity pointer: when
    it names a ``domain`` and ``<directory>/<domain>/config.json`` exists, that
    per-identity file is read instead. A leaf identity directory (no such
    subdirectory) is read as-is.

    Raises:
        FileNotFoundError: ``config.json`` does not exist.
        ArgumentError: ``config.json`` is not a JSON object or a field is not a string.
    """
    base = Path(directory) if directory is not None else Path.home() / ".dnsid"
    config_path = base / "config.json"
    try:
        raw = _json_object(config_path.read_bytes(), str(config_path))
    except FileNotFoundError:
        raise FileNotFoundError(
            f"DNSid CLI config not found: {config_path}; "
            "run the DNSid CLI to register your domain first"
        ) from None
    pointer = raw.get("domain")
    if isinstance(pointer, str) and pointer:
        from ._utils import normalize_fqdn

        identity_path = base / normalize_fqdn(pointer, agent_fqdn=True) / "config.json"
        if identity_path.is_file():
            config_path = identity_path
            raw = _json_object(config_path.read_bytes(), str(config_path))

    def get(key: str) -> str | None:
        return (_typed(raw, key, str, str(config_path)) or "").strip() or None

    identity_fields = {f: v for f in _CLI_IDENTITY_FIELDS if (v := get(f))}
    entity_key_path = get("entity_key_path")
    if entity_key_path is not None:
        entity_key_path = str(config_path.parent / Path(entity_key_path).expanduser())
    return LoadedConfig(
        dnsid=DnsidConfig(identity=IdentityConfig(**identity_fields) if identity_fields else None),
        key_source=KeySource(cli_directory=str(base), entity_key_path=entity_key_path),
    )


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

_T = TypeVar("_T")


def merge_loaded_config(base: LoadedConfig, overlay: LoadedConfig) -> LoadedConfig:
    """Apply *overlay* onto *base* field-wise; a present overlay field wins.

    Presence, not truthiness: ``trusted_entities=[]`` replaces a loaded list.
    Lists replace, never concatenate. ``log_trust`` is replaced as a whole when
    the overlay sets any variant. See the module docstring for the default
    values that cannot express presence.
    """
    return LoadedConfig(
        dnsid=_merge_fields(base.dnsid, overlay.dnsid),
        log_trust=replace(overlay.log_trust if _has_trust(overlay.log_trust) else base.log_trust),
        registry=_merge_fields(base.registry, overlay.registry),
        key_source=_merge_fields(base.key_source, overlay.key_source),
    )


def _merge_fields(base: _T, overlay: _T) -> _T:
    values: dict[str, Any] = {}
    for f in fields(base):  # type: ignore[arg-type]
        b, o = getattr(base, f.name), getattr(overlay, f.name)
        if is_dataclass(o) and is_dataclass(b) and not isinstance(o, type):
            values[f.name] = _merge_fields(b, o)
        else:
            default = f.default_factory() if f.default_factory is not MISSING else f.default
            values[f.name] = o if o != default else b
    return type(base)(**values)


def _has_trust(trust: LogTrust) -> bool:
    return any(getattr(trust, f.name) is not None for f in fields(trust))


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

_LOG_TRUST_FRESHNESS_MS = 10 * 60 * 1000


def construct_identity_manager(
    loaded: LoadedConfig,
    key_provider: KeyProvider | None = None,
    deps: IdentityManagerDependencies | None = None,
) -> IdentityManager:
    """Build an :class:`~dnsid.IdentityManager` from a merged :class:`LoadedConfig`.

    Caller dependencies win: ``deps.log_registry`` is built from ``log_trust``
    only when absent (the trust section is then not inspected), and key
    providers are built from ``key_source`` only when ``dnsid.identity`` is
    present and the corresponding provider is absent. ``loaded.dnsid`` is
    validated first so invalid configuration never reads a key file or fetches
    a policy. Adds no configuration values.
    """
    from .manager import IdentityManager, IdentityManagerDependencies, validate_dnsid_config

    deps = replace(deps) if deps is not None else IdentityManagerDependencies()
    validate_dnsid_config(
        loaded.dnsid,
        resolver_injected=deps.dns_resolver is not None,
        fetcher_injected=deps.https_fetcher is not None,
    )
    if deps.log_registry is None and _has_trust(loaded.log_trust):
        deps.log_registry = _log_registry_from_trust(loaded.log_trust, loaded.dnsid.transport)
    identity, source = loaded.dnsid.identity, loaded.key_source
    if identity is not None and any(getattr(source, f.name) for f in fields(source)):
        from .local_key_provider import LocalKeyProvider

        if key_provider is None:
            key_provider = _operational_key_provider(source, identity.domain)
        if deps.entity_key_provider is None and source.entity_key_path:
            deps.entity_key_provider = LocalKeyProvider.from_private_jwk(source.entity_key_path)
    return IdentityManager(loaded.dnsid, key_provider, deps)


def _log_registry_from_trust(trust: LogTrust, transport: TransportConfig) -> LogRegistry:
    from .c2sp_tlog import (
        C2spTlogVerificationOptions,
        create_c2sp_tlog_verification_registry,
        create_dnsid_managed_verification_registry,
    )

    variants = [f.name for f in fields(trust) if getattr(trust, f.name) is not None]
    if len(variants) != 1:
        raise ArgumentError(
            "log_trust requires exactly one of managed, profile, policy_document, "
            f"policy_url; got {variants or 'none'}"
        )
    if trust.managed is not None:
        if trust.managed is not True:
            raise ArgumentError("log_trust.managed must be true when present")
        return create_dnsid_managed_verification_registry()
    return create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            trust_profile=trust.profile,
            policy_document=trust.policy_document,
            policy_url=trust.policy_url,
            transport_config=transport,
            checkpoint_freshness_ms=_LOG_TRUST_FRESHNESS_MS,
            max_bundle_lifetime_ms=_LOG_TRUST_FRESHNESS_MS,
            max_clock_skew_ms=0,
        )
    )


def _operational_key_provider(source: KeySource, domain: str) -> KeyProvider | None:
    """``cli_directory`` wins over ``key_store_path``; neither leaves the constructor to reject."""
    from .local_key_provider import LocalKeyProvider

    if source.cli_directory:
        base = Path(source.cli_directory)
        if (base / "private.jwk").exists() or (base / "private.pem").exists():
            return LocalKeyProvider.from_cli_directory(base)
        return LocalKeyProvider.from_domain(domain, base)
    if source.key_store_path:
        return LocalKeyProvider.load(source.key_store_path)
    return None


# ---------------------------------------------------------------------------
# Convenience constructors: Load → Merge → Construct, nothing else.
# ---------------------------------------------------------------------------


def identity_manager_from_environment(
    env: Mapping[str, str] | None = None,
    overlay: DnsidConfig | None = None,
    key_provider: KeyProvider | None = None,
    deps: IdentityManagerDependencies | None = None,
) -> IdentityManager:
    """Load → Merge → Construct over ``load_environment(env)``.

    Without ``DNSID_DOMAIN`` the result is a verification-only manager; under
    ``dnsid local run``, ``DNSID_CONFIG_DIR`` supplies the key files.
    """
    return construct_identity_manager(
        merge_loaded_config(load_environment(env), _overlay(overlay)), key_provider, deps
    )


def identity_manager_from_dnsid(
    directory: Path | str | None = None,
    overlay: DnsidConfig | None = None,
    key_provider: KeyProvider | None = None,
    deps: IdentityManagerDependencies | None = None,
) -> IdentityManager:
    """Load → Merge → Construct over ``load_cli_directory(directory)``."""
    return construct_identity_manager(
        merge_loaded_config(load_cli_directory(directory), _overlay(overlay)), key_provider, deps
    )


def identity_manager_from_file(
    path: Path | str,
    overlay: DnsidConfig | None = None,
    key_provider: KeyProvider | None = None,
    deps: IdentityManagerDependencies | None = None,
) -> IdentityManager:
    """Load → Merge → Construct over ``load_file(path)``."""
    return construct_identity_manager(
        merge_loaded_config(load_file(path), _overlay(overlay)), key_provider, deps
    )


def _overlay(overlay: DnsidConfig | None) -> LoadedConfig:
    return LoadedConfig(dnsid=overlay) if overlay is not None else LoadedConfig()


def registry_client_from_environment(env: Mapping[str, str] | None = None) -> RegistryClient:
    """:class:`~dnsid.RegistryClient` from ``DNSID_REGISTRY_URL`` and ``DNSID_API_KEY``.

    The constructor applies the local-registry default when the URL is absent.
    """
    from .registry_client import RegistryClient

    loaded = load_environment(env)
    source = os.environ if env is None else env
    return RegistryClient(loaded.registry.registry_url or None, api_key=source.get("DNSID_API_KEY"))


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


def _json_object(data: bytes, source: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ArgumentError(f"{source}: duplicate JSON member {key!r}")
            out[key] = value
        return out

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArgumentError(f"{source}: invalid JSON: {exc}") from exc
    return _object(value, source)


def _object(value: Any, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ArgumentError(f"{source} must be a JSON object, got {type(value).__name__}")
    return value


def _reject_unknown(raw: Mapping[str, Any], source: str, allowed: tuple[str, ...]) -> None:
    for key in raw:
        if key not in allowed:
            raise ArgumentError(f"{source} has unknown member {key!r}")


def _typed(raw: Mapping[str, Any], key: str, kind: type[_T], source: str) -> _T | None:
    value = raw.get(key)
    if value is None:
        return None
    if type(value) is not kind:
        raise ArgumentError(f"{source}.{key} must be a {kind.__name__}")
    return value


def _snake_keys(value: Any) -> Any:
    """Map camelCase JSON members to snake_case dataclass fields, recursively."""
    if isinstance(value, list):
        return [_snake_keys(v) for v in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for key, v in value.items():
        if "_" in key:
            raise ArgumentError(f"deployment file member {key!r} must be camelCase")
        out[re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()] = _snake_keys(v)
    return out
