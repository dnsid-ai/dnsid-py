import os
import sys
from urllib.parse import urlsplit

from dnsid import IdentityManager, IdentityManagerDependencies, TransportConfig
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    DnsidManagedVerificationOptions,
    SafeC2spResourceFetcher,
    create_c2sp_tlog_verification_registry,
    create_dnsid_managed_verification_registry,
)

# `dnsid local env` exports DNSID_LOG_POLICY_URL for the local registry. When it
# is unset the example trusts DNSid's managed production log (log.dnsid.ai),
# whose embedded trust profile enables signed per-domain stream bundles instead
# of a full log scan.
POLICY_URL = os.environ.get("DNSID_LOG_POLICY_URL", "")

domain = sys.argv[1] if len(sys.argv) == 2 else "2a7bcd5330fd.sandbox.dnsid.ai"

# Local registry only (`eval "$(dnsid local env)"`): route DNS to its CoreDNS,
# trust its CA, and allow its loopback zone. All empty in production.
dns_server = os.environ.get("DNSID_DNS_SERVER", "")
transport = TransportConfig(
    dns_server=dns_server,
    ca_bundle_path=os.environ.get("DNSID_CA_BUNDLE", ""),
    private_address_hosts=frozenset(
        {"." + os.environ["DNSID_GOVERNANCE_ID"]} if dns_server else ()
    ),
)

try:
    if POLICY_URL:
        registry = create_c2sp_tlog_verification_registry(
            C2spTlogVerificationOptions(
                policy_url=POLICY_URL,
                resource_fetcher=SafeC2spResourceFetcher(
                    transport_config=transport,
                    allow_loopback_host=urlsplit(POLICY_URL).hostname if dns_server else None,
                ),
            )
        )
    else:
        registry = create_dnsid_managed_verification_registry(
            DnsidManagedVerificationOptions(
                resource_fetcher=SafeC2spResourceFetcher(transport_config=transport),
            )
        )
    idm = IdentityManager.for_verification(
        IdentityManagerDependencies(log_registry=registry), transport=transport
    )
    verified = idm.verify_domain(domain)
    print(verified)
except Exception as err:
    print(f"verification failed: {err}", file=sys.stderr)
    raise SystemExit(1) from err
