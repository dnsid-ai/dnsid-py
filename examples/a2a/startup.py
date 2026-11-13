"""Start an agent using the identity published and issued by the local CLI."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack

from agent import echo_executor
from server import EchoAgent, EchoAgentOptions

from dnsid import (
    IdentityConfig,
    IdentityManager,
    LoadedConfig,
    construct_identity_manager,
    load_environment,
    merge_loaded_config,
)


async def poll(label: str, fn) -> None:
    """Retry an async *fn* up to 60 times at 500 ms intervals."""
    last_exc: BaseException = RuntimeError("no attempts made")
    for _ in range(60):
        try:
            await fn()
            return
        except Exception as exc:
            last_exc = exc
            await asyncio.sleep(0.5)
    raise RuntimeError(f"{label} failed: {last_exc}")


async def start_echo_agent() -> tuple[IdentityManager, EchoAgent, Callable[[], Awaitable[None]]]:
    # `dnsid local run` exports the SDK environment: identity fields, DNS
    # routing (DNSID_DNS_SERVER), TLS trust (DNSID_CA_BUNDLE), the trusted C2SP
    # policy (DNSID_LOG_POLICY_URL), and the key directory (DNSID_CONFIG_DIR).
    # The CLI already owns registration and issuance; startup only verifies.
    # The example adds the agent-card URL as a code overlay.
    public_url = os.environ.get("DNSID_PUBLIC_URL", "").strip() or None
    agent_port = int(os.environ["DNSID_AGENT_PORT"])
    # Load → Merge → Construct: point `cu` at the agent card unless the
    # environment already names a capabilities URL.
    loaded = load_environment()
    identity = loaded.dnsid.identity
    if identity is None:
        raise SystemExit("DNSID_DOMAIN is required; run via `dnsid local run`")
    overlay = LoadedConfig()
    if not identity.capabilities_url:
        base = (public_url or f"https://{identity.domain}").rstrip("/")
        overlay.dnsid.identity = IdentityConfig(
            capabilities_url=f"{base}/.well-known/agent-card.json"
        )
    async with AsyncExitStack() as cleanup:
        idm = await cleanup.enter_async_context(
            construct_identity_manager(merge_loaded_config(loaded, overlay))
        )
        key_provider = idm.key_provider
        if key_provider is None:
            raise RuntimeError("A2A startup requires a key provider")

        executor = echo_executor(idm.local_domain)
        agent = await EchoAgent.create(
            executor, idm, agent_port, EchoAgentOptions(public_url=public_url)
        )
        cleanup.push_async_callback(agent.stop)
        await agent.start()

        print(f"{os.environ.get('DNSID_AGENT_NAME') or idm.local_domain} -> {agent.url}")
        await asyncio.sleep(1.0)

        # CoreDNS reloads the generated zone every two seconds. Wait for that
        # reload before the first self-check so an initial NXDOMAIN isn't cached,
        # then retry until the freshly published record is resolvable.
        await asyncio.sleep(2.5)
        await poll(
            f"self-verify {idm.local_domain}",
            lambda: idm.async_verify_domain(idm.local_domain),
        )
        resources = cleanup.pop_all()
    return idm, agent, resources.aclose
