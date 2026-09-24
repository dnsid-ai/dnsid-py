import sys

from dnsid import (
    IdentityManagerDependencies,
    LogTrust,
    construct_identity_manager,
    load_environment,
)
from dnsid.c2sp_tlog import create_dnsid_managed_verification_registry

# `dnsid local env` exports DNSID_LOG_POLICY_URL, DNSID_DNS_SERVER, DNSID_CA_BUNDLE
# and DNSID_PRIVATE_HOSTS for the local registry; the SDK loader wires all of
# them, including the policy fetch, into a verification-only manager. Without
# loaded log trust the example trusts DNSid's managed production log
# (log.dnsid.ai), whose embedded trust profile enables signed per-domain stream
# bundles instead of a full scan.
domain = sys.argv[1] if len(sys.argv) == 2 else "2a7bcd5330fd.sandbox.dnsid.ai"

try:
    loaded = load_environment()
    deps = IdentityManagerDependencies(
        log_registry=(
            None if loaded.log_trust != LogTrust() else create_dnsid_managed_verification_registry()
        )
    )
    idm = construct_identity_manager(loaded, deps=deps)
    print(idm.verify_domain(domain))
except Exception as err:
    print(f"verification failed: {err}", file=sys.stderr)
    raise SystemExit(1) from err
