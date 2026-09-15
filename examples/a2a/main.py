#!/usr/bin/env python3
"""
Agent-to-agent (A2A) example.

Starts an echo agent that:
  - Serves JWKS, status, and an A2A agent card over HTTP
  - Verifies RFC 9421 HTTP Message Signatures on every inbound POST
  - Echoes messages back with the verified sender identity

When a peer FQDN is given as an argument, Alice sends one signed message to
that peer then exits.  Without an argument the agent stays running (Bob mode).

Usage:
    dnsid testnet run bob --upstream http://localhost:3002 -- \
        python examples/a2a/main.py

    dnsid testnet run alice --upstream http://localhost:3001 -- \
        python examples/a2a/main.py bob.dev.dnsid.test

All DNSID_* variables must be present in the process environment before startup.
DNS routing and TLS trust are wired automatically from DNSID_DNS_SERVER and
DNSID_CA_BUNDLE — no boilerplate needed in application code.
"""

from __future__ import annotations

import asyncio
import signal
import sys
import uuid
from pathlib import Path

# Allow sibling-module imports regardless of working directory.
sys.path.insert(0, str(Path(__file__).parent))

from startup import start_echo_agent

from dnsid import async_retry_transient


async def main() -> None:
    idm, agent, stop = await start_echo_agent()

    peer_fqdn = sys.argv[1] if len(sys.argv) > 1 else None
    if peer_fqdn:
        await send_hello(idm, agent, peer_fqdn)
        await stop()
        return

    await wait_for_shutdown(stop)


async def send_hello(idm, agent, peer_fqdn: str) -> None:
    await async_retry_transient(
        lambda: asyncio.to_thread(idm.verify_domain, peer_fqdn),
        max_attempts=20,
        base_delay=0.5,
        max_delay=5.0,
    )
    print(f"verified: {idm.local_domain} -> {peer_fqdn}\n")

    client = agent.create_client(f"https://{peer_fqdn}")
    result = await client.send_message(
        {
            "messageId": str(uuid.uuid4()),
            "role": "ROLE_USER",
            "parts": [{"text": f"hello from {idm.local_domain}"}],
        }
    )
    reply = " ".join(p.get("text", "") for p in result.get("parts", []) if "text" in p)
    print(f'reply: "{reply}"')


async def wait_for_shutdown(stop) -> None:
    loop = asyncio.get_running_loop()
    shutdown = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown.set)
    await shutdown.wait()
    await stop()


if __name__ == "__main__":
    asyncio.run(main())
