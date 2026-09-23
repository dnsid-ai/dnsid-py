"""Agent startup: load config from env, build IdentityManager, register with registry."""

from __future__ import annotations

import asyncio
import base64
import os

from agent import echo_executor
from server import EchoAgent, EchoAgentOptions

from dnsid import (
    IdentityConfig,
    IdentityManager,
    KeyProvider,
    LoadedConfig,
    RegistryClient,
    construct_identity_manager,
    load_environment,
    merge_loaded_config,
    registry_client_from_environment,
)
from dnsid.models import AgentRegistrationInput, RegistryAgentStatus


class PollAbortError(RuntimeError):
    """Raised inside a poll callback to stop retrying immediately."""


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
    key_provider: KeyProvider,
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
    idm: IdentityManager, key_provider: KeyProvider, registry: RegistryClient
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
    # `dnsid testnet run` exports the SDK environment: identity fields, DNS
    # routing (DNSID_DNS_SERVER), TLS trust (DNSID_CA_BUNDLE), the trusted C2SP
    # policy (DNSID_LOG_POLICY_URL), the key directory (DNSID_CONFIG_DIR), and
    # the registry credential (DNSID_API_KEY). The SDK loader reads all of it;
    # the example only adds the agent-card URL as a code overlay.
    public_url = os.environ.get("DNSID_PUBLIC_URL", "").strip() or None
    agent_port = int(os.environ["DNSID_AGENT_PORT"])
    if not os.environ.get("DNSID_API_KEY", "").strip():
        raise SystemExit(
            "DNSID_API_KEY is required to register with the registry. Run via "
            "`dnsid testnet run` or export it before starting the agent "
            "(see examples/a2a/README.md)."
        )

    # Load → Merge → Construct: point `cu` at the agent card unless the
    # environment already names a capabilities URL.
    loaded = load_environment()
    identity = loaded.dnsid.identity
    if identity is None:
        raise SystemExit("DNSID_DOMAIN is required; run via `dnsid testnet run`")
    overlay = LoadedConfig()
    if not identity.capabilities_url:
        base = (public_url or f"https://{identity.domain}").rstrip("/")
        overlay.dnsid.identity = IdentityConfig(
            capabilities_url=f"{base}/.well-known/agent-card.json"
        )
    idm = construct_identity_manager(merge_loaded_config(loaded, overlay))
    key_provider = idm.key_provider
    assert key_provider is not None

    executor = echo_executor(idm.local_domain)
    agent = await EchoAgent.create(
        executor, idm, agent_port, EchoAgentOptions(public_url=public_url)
    )
    await agent.start()

    print(f"{os.environ.get('DNSID_AGENT_NAME') or idm.local_domain} -> {agent.url}")
    await asyncio.sleep(1.0)

    registry = registry_client_from_environment()
    await _register_and_publish(idm, key_provider, registry)

    # CoreDNS reloads the generated zone every two seconds. Wait for that
    # reload before the first self-check so an initial NXDOMAIN isn't cached,
    # then retry until the freshly published record is resolvable.
    await asyncio.sleep(2.5)
    await poll(
        f"self-verify {idm.local_domain}",
        lambda: asyncio.to_thread(idm.verify_domain, idm.local_domain),
    )

    return idm, agent, agent.stop
