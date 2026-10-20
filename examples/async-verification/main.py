"""Verify one published identity with an async deadline and owned-resource cleanup."""

import argparse
import asyncio
import sys

from dnsid import (
    DNSidError,
    IdentityManager,
    IdentityManagerDependencies,
    LogTrust,
    VerificationError,
    construct_identity_manager,
    load_environment,
    verification_budget,
)
from dnsid.c2sp_tlog import create_dnsid_managed_verification_registry


async def verify(manager: IdentityManager, domain: str) -> int:
    async with manager:
        try:
            with verification_budget(5):
                identity = await manager.async_verify_domain(domain)
        except VerificationError as error:
            print(f"{error.code.name}: {error.message}", file=sys.stderr)
            if error.transient:
                print("Verification is indeterminate; retrying may help.", file=sys.stderr)
            return 1
        print(f"{identity.domain}: {identity.cached_state()}")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="published DNSid identity to verify")
    args = parser.parse_args()
    try:
        # Load configuration/policy before the event loop; no local identity is needed.
        loaded = load_environment()
        loaded.dnsid.identity = None
        deps = IdentityManagerDependencies(log_registry=(
            create_dnsid_managed_verification_registry() if loaded.log_trust == LogTrust() else None
        ))
        manager = construct_identity_manager(loaded, deps=deps)
        return asyncio.run(verify(manager, args.domain))
    except DNSidError as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
