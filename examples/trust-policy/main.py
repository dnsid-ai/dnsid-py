import sys
from datetime import timedelta
from pathlib import Path

from dnsid import (
    DnsidConfig,
    IdentityManager,
    IdentityManagerDependencies,
    TrustedEntity,
    VerificationConfig,
)
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    create_c2sp_tlog_verification_registry,
    parse_c2sp_tlog_trust_profile,
)


def main() -> None:
    if len(sys.argv) != 5:
        raise ValueError(
            "usage: trust-policy <domain> <trusted-profile.json> <gi> <ek-thumbprint>"
        )
    domain, profile_path, governance_id, thumbprint = sys.argv[1:]
    profile = parse_c2sp_tlog_trust_profile(Path(profile_path).read_bytes())
    registry = create_c2sp_tlog_verification_registry(C2spTlogVerificationOptions(
        trust_profile=profile,
        checkpoint_freshness_ms=10 * 60_000,
        max_bundle_lifetime_ms=5 * 60_000,
    ))
    verifier = IdentityManager(
        DnsidConfig(verification=VerificationConfig(
            status_check_interval=timedelta(seconds=30),
            trusted_entities=[TrustedEntity(
                governance_id=governance_id,
                entity_key_thumbprints=(thumbprint,),
            )],
        )),
        deps=IdentityManagerDependencies(log_registry=registry),
    )
    vd = verifier.verify_domain(domain)
    print(vd.domain, vd.cached_state())


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(err, file=sys.stderr)
        raise SystemExit(1) from err
