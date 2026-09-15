import sys

from dnsid import IdentityManager, IdentityManagerDependencies
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    create_c2sp_tlog_verification_registry,
)

# Trusted configuration for the public log used by the DNSid sandbox. Production
# applications should select their own independently trusted policy.
POLICY_URL = "https://log.dnsid.dev/dnsid-policy"

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} <dnsid-domain>", file=sys.stderr)
    raise SystemExit(2)

domain = sys.argv[1]

try:
    registry = create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(policy_url=POLICY_URL)
    )
    idm = IdentityManager.for_verification(IdentityManagerDependencies(log_registry=registry))
    verified = idm.verify_domain(domain)
    print(verified)
except Exception as err:
    print(f"verification failed: {err}", file=sys.stderr)
    raise SystemExit(1) from err
