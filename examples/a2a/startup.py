"""Agent startup: load config from env, build IdentityManager, register with registry."""

from __future__ import annotations

import asyncio
import base64
import os
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from agent import echo_executor
from server import EchoAgent, EchoAgentOptions
from testnet_config import required_log_policy_url

from dnsid import (
    IdentityManager,
    IdentityManagerDependencies,
    LocalKeyProvider,
    RegistryClient,
    config_from_environment,
)
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    SafeC2spResourceFetcher,
    create_c2sp_tlog_verification_registry,
    parse_c2sp_tlog_lr,
)
from dnsid.models import (
    AgentRegistrationInput,
    RegistryAgentStatus,
    TransportConfig,
)
from dnsid.registry import LogRegistry


class PollAbortError(RuntimeError):
    """Raised inside a poll callback to stop retrying immediately."""


def _make_log_registry(
    log_ref: str, policy_url: str, transport_config: TransportConfig
) -> LogRegistry | None:
    """Register a c2sp-tlog reader using independently trusted testnet policy.

    The policy URL comes from trusted testnet configuration, independently of
    the log reference. The transport routes through the testnet DNS server and
    CA bundle. Returns None when the log_ref is not a c2sp-tlog reference.
    """
    if not log_ref.startswith("c2sp-tlog:"):
        return None
    parsed = parse_c2sp_tlog_lr(log_ref)
    fetcher = SafeC2spResourceFetcher(
        transport_config=replace(transport_config, private_address_hosts=frozenset()),
        allow_loopback_host=(
            urlsplit(policy_url).hostname if parsed.scope == "testnet" else None
        ),
    )
    return create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_url=policy_url,
            resource_fetcher=fetcher,
            max_clock_skew_ms=30_000,
            checkpoint_freshness_ms=5 * 60_000,
        )
    )


async def poll(label: str, fn) -> None:
    """Retry an async *fn* up to 60 times at 500 ms intervals."""
    last_exc: BaseException = RuntimeError("no attempts made")
    for _ in range(60):
        try:
            await fn()
            return
        except PollAbortError:
            raise
        except Exception as exc:
            last_exc = exc
            await asyncio.sleep(0.5)
    raise RuntimeError(f"{label} failed: {last_exc}")


async def _verify_with_challenge(
    key_provider: LocalKeyProvider,
    registry: RegistryClient,
    domain: str,
    status: RegistryAgentStatus,
) -> None:
    """Drive the registry VERIFICATION handshake.

    Request verification, wait for the challenge nonce on the status document,
    sign the decoded nonce bytes with the active key, submit the signature,
    then wait for the agent to reach VERIFIED.
    """
    if status.registry_status != "VERIFICATION":
        await asyncio.to_thread(registry.verify_agent, domain)

    nonce = ""

    async def _await_challenge() -> None:
        nonlocal nonce
        current = await asyncio.to_thread(registry.get_agent_status, domain)
        if current is None:
            raise RuntimeError("agent not found in registry")
        if current.failed or current.terminal:
            raise PollAbortError(f"registry status is {current.registry_status}")
        raw_nonce = current.raw.get("challenge")
        if not isinstance(raw_nonce, str) or not raw_nonce:
            raise RuntimeError(f"no challenge yet (status {current.registry_status})")
        nonce = raw_nonce

    await poll(f"registry challenge {domain}", _await_challenge)

    padding = "=" * (-len(nonce) % 4)
    signature = key_provider.sign(base64.urlsafe_b64decode(nonce + padding))
    await asyncio.to_thread(registry.submit_challenge_signature, domain, nonce, signature)

    async def _await_verified() -> None:
        current = await asyncio.to_thread(registry.get_agent_status, domain)
        if current is None:
            raise RuntimeError("agent not found in registry")
        if current.failed or current.terminal:
            raise PollAbortError(f"registry status is {current.registry_status}")
        if not current.ready_for_publication and not current.published:
            raise RuntimeError(f"still {current.registry_status}")

    await poll(f"registry verified {domain}", _await_verified)


async def _register_and_publish(
    idm: IdentityManager, key_provider: LocalKeyProvider, registry: RegistryClient
) -> None:
    domain = idm.local_domain
    status = await asyncio.to_thread(registry.get_agent_status, domain)

    if status is None:
        print(f"{domain} registering with registry")
        await asyncio.to_thread(
            registry.register_agent,
            AgentRegistrationInput(
                domain=domain,
                capabilities_url=idm.config.identity.capabilities_url or "",
            ),
        )
        status = await asyncio.to_thread(registry.get_agent_status, domain)
        if status is None:
            raise RuntimeError("agent not found in registry after registration")

    if not status.published and not status.ready_for_publication:
        await _verify_with_challenge(key_provider, registry, domain, status)
        status = await asyncio.to_thread(registry.get_agent_status, domain)

    if status is not None and status.ready_for_publication:
        published = await asyncio.to_thread(idm.publish_to_registry, registry)
        print(f"{domain} published {published.owner_name}")
    else:
        print(f"{domain} already published ({status.registry_status if status else 'unknown'})")


async def start_echo_agent() -> tuple[IdentityManager, EchoAgent, object]:
    env = dict(os.environ)

    result = config_from_environment(env, require=["registry_url", "agent_port"])
    protocol_config = result.config.identity
    transport_config = result.config.transport
    registry_config = result.registry_config
    policy_url = required_log_policy_url(env)

    # The CLI testnet resolves every name under the governance domain (this
    # agent's endpoints and every peer's) to the host's loopback proxy. Allow
    # that zone only; production verifiers keep this empty. `dnsid testnet run`
    # always emits a bare domain as DNSID_GOVERNANCE_ID and serves ek/ku/su
    # beneath it, so a suffix covers callers this server cannot enumerate.
    transport_config.private_address_hosts = frozenset({"." + protocol_config.governance_id})

    # Registry mutation calls (register/verify/publish) require a session
    # credential. `dnsid testnet run` injects DNSID_API_KEY; DNSID_REGISTRY_API_KEY
    # is accepted as a manual override. Fail fast before starting the server
    # rather than surfacing an HTTP 401 partway through registration.
    registry_api_key = (env.get("DNSID_API_KEY") or env.get("DNSID_REGISTRY_API_KEY") or "").strip()
    if not registry_api_key:
        raise SystemExit(
            "DNSID_API_KEY (or DNSID_REGISTRY_API_KEY) is required to register with "
            "the registry. Run via `dnsid testnet run` or export it before starting "
            "the agent (see examples/a2a/README.md)."
        )

    # Set capabilities_url to point at the agent card endpoint.
    public_url = result.public_url or f"https://{protocol_config.domain}"
    if not protocol_config.capabilities_url:
        protocol_config.capabilities_url = f"{public_url.rstrip('/')}/.well-known/agent-card.json"

    # Prefer the identity directory provisioned by `dnsid testnet run`
    # (DNSID_CONFIG_DIR): its private.jwk carries the RFC 7638 thumbprint kid
    # the registry requires. Fall back to a self-managed key store otherwise.
    config_dir = (env.get("DNSID_CONFIG_DIR") or "").strip()
    if config_dir:
        key_provider = LocalKeyProvider.from_cli_directory(config_dir)
    else:
        key_store_path = result.key_store_path or str(
            Path(".testnet") / "agents" / f"{protocol_config.domain.split('.')[0]}.keys.json"
        )
        key_provider = LocalKeyProvider.load(key_store_path, create_if_missing=True)
    log_registry = _make_log_registry(protocol_config.log_ref, policy_url, transport_config)
    idm = IdentityManager(
        result.config,
        key_provider,
        deps=IdentityManagerDependencies(log_registry=log_registry),
    )

    executor = echo_executor(protocol_config.domain)
    agent = await EchoAgent.create(
        executor, idm, result.agent_port, EchoAgentOptions(public_url=result.public_url)
    )
    await agent.start()

    print(f"{result.agent_name or protocol_config.domain} -> {agent.url}")
    await asyncio.sleep(1.0)

    registry = RegistryClient(registry_config.registry_url, api_key=registry_api_key)
    await _register_and_publish(idm, key_provider, registry)

    # CoreDNS reloads the generated zone every two seconds. Wait for that
    # reload before the first self-check so an initial NXDOMAIN isn't cached,
    # then retry until the freshly published record is resolvable.
    await asyncio.sleep(2.5)
    await poll(
        f"self-verify {protocol_config.domain}",
        lambda: asyncio.to_thread(idm.verify_domain, protocol_config.domain),
    )

    return idm, agent, agent.stop
