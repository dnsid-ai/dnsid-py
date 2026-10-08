"""Register and verify one managed dev sandbox identity through the SDK."""

import argparse
import os
import sys
from pathlib import Path

from dnsid import (
    FileRegistrationStore,
    LoadedConfig,
    LogTrust,
    ManagedRegistrationConfig,
    RegistryConfig,
    register_managed_identity,
)
from dnsid.exceptions import DNSidError

REGISTRY_URL = "https://api.dev.dnsid.ai"
GOVERNANCE_ID = "dev.dnsid.ai"
ENTITY_KEY_URL = "https://dnsid.dev.dnsid.ai/.well-known/dnsid-ek.json"


def run(name, directory, api_key):
    loaded = LoadedConfig(
        registry=RegistryConfig(REGISTRY_URL),
        log_trust=LogTrust(managed=True),
        registration=ManagedRegistrationConfig(GOVERNANCE_ID, ENTITY_KEY_URL),
    )
    result = register_managed_identity(
        name,
        loaded,
        credential=api_key,
        store=FileRegistrationStore(directory),
    )
    try:
        print(f"Registered: {result.registration.domain}")
        print(
            f"Verified: {result.registration.domain} "
            f"status={result.logged_state_evidence.logged_state}"
        )
    finally:
        result.manager.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="Stable organization-scoped identity name")
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    api_key = os.environ.get("DNSID_API_KEY", "").strip()
    try:
        if not api_key or any(character.isspace() for character in api_key):
            raise ValueError("Set DNSID_API_KEY to one API token")
        run(args.name, args.state_dir.expanduser(), api_key)
    except (DNSidError, OSError, ValueError) as error:
        message = str(error).replace(api_key, "[REDACTED]") if api_key else str(error)
        print(f"Stopped: {message}\nKeep the state directory for recovery.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
