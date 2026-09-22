import os
import sys

from dnsid import IdentityManager, IdentityManagerDependencies, TransportConfig
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    create_c2sp_tlog_verification_registry,
    create_dnsid_managed_verification_registry,
)

# `dnsid local env` exports DNSID_LOG_POLICY_URL, DNSID_DNS_SERVER and
# DNSID_CA_BUNDLE for the local registry. When the policy URL is unset the
# example trusts DNSid's managed production log (log.dnsid.ai), whose embedded
# trust profile enables signed per-domain stream bundles instead of a full scan.
POLICY_URL = os.environ.get("DNSID_LOG_POLICY_URL", "")

domain = sys.argv[1] if len(sys.argv) == 2 else "2a7bcd5330fd.sandbox.dnsid.ai"

try:
    if POLICY_URL:
        transport = TransportConfig(
            dns_server=os.environ.get("DNSID_DNS_SERVER", ""),
            ca_bundle_path=os.environ.get("DNSID_CA_BUNDLE", ""),
        )
        registry = create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(policy_url=POLICY_URL, transport_config=transport)
        )
    else:
        transport = TransportConfig()
        registry = create_dnsid_managed_verification_registry()
    idm = IdentityManager.for_verification(
        IdentityManagerDependencies(log_registry=registry), transport=transport
    )
    print(idm.verify_domain(domain))
except Exception as err:
    print(f"verification failed: {err}", file=sys.stderr)
    raise SystemExit(1) from err
