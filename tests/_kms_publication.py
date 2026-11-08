"""Cloud-neutral signed publication and public JOSE checks for KMS tests."""

from __future__ import annotations

import base64
import datetime
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dnsid import DnsIdTxtRecord, HTTPSFetcher, IdentityManagerDependencies, VerificationError
from dnsid._crypto import jwk_from_dict
from dnsid._utils import b64url_decode, b64url_encode
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    canonical_json,
    create_c2sp_tlog_verification_registry,
    encode_entry_bundle,
    merkle_root_from_entries,
    prepare_event,
)
from dnsid.jose import JoseProfile
from dnsid.models import IssuanceEvent, TLSCertificate, TXTRecord
from tests.conftest import MockDNSResolver
from tests.test_c2sp_migration import _Fetcher, _verifier_key
from tests.test_c2sp_verification_registry import _checkpoint_cosignature, _checkpoint_signature

# RFC 8032 test 1 seed; independent of cloud providers and SDK output.
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
DOMAIN = "agent.example"
LR = "c2sp-tlog:testnet:https://functional.example#existing"


def public_key(private):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
           "x": b64url_encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}
    raw["kid"] = jwk_from_dict(raw).thumbprint()
    return jwk_from_dict(raw)


def publication(tmp_path, *, key_source, corrupt=None):
    """Independent signed A evidence: expected values never come from provider."""
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    entity = Ed25519PrivateKey.from_private_bytes(bytes([11]) * 32)
    log = Ed25519PrivateKey.from_private_bytes(bytes([12]) * 32)
    witness = Ed25519PrivateKey.from_private_bytes(bytes([13]) * 32)
    key, ek = public_key(private), public_key(entity)
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    event = IssuanceEvent(domain=DOMAIN, governance_id="example", entity_key=ek,
                          operational_key=key, timestamp=now - datetime.timedelta(minutes=5))
    prepared = prepare_event(event, LR)
    envelope = dict(prepared.envelope)
    envelope["sigs"] = {
        "ae": {"kid": ek.kid, "sig": b64url_encode(entity.sign(prepared.signed_bytes))},
        "op": {"kid": key.kid, "sig": b64url_encode(private.sign(prepared.signed_bytes))},
    }
    entry = canonical_json(envelope).encode()
    # One per-publication clock sample drives event/status/cert/checkpoint.
    # Do not reuse test_c2sp_migration's module-import timestamp: a full suite
    # can take longer than its 60-second checkpoint freshness window.
    root = base64.b64encode(merkle_root_from_entries([entry])).decode()
    signed = f"functional.example\n1\n{root}\n"
    checkpoint = (signed + "\n"
        + _checkpoint_signature("functional.example", signed, log) + "\n"
        + _checkpoint_cosignature("migration-witness", signed, witness, int(now.timestamp()))
        + "\n").encode()
    resources = _Fetcher({
        "https://functional.example/checkpoint": checkpoint,
        "https://functional.example/tile/entries/000.p/1": encode_entry_bundle([entry]),
    })
    policy = ("log " + _verifier_key("functional.example", b"\x01", log)
              + "\nwitness migration-witness " + _verifier_key("migration-witness", b"\x04", witness)
              + "\nquorum migration-witness\n").encode()
    registry = create_c2sp_tlog_verification_registry(C2spTlogVerificationOptions(
        policy_document=policy, resource_fetcher=resources, checkpoint_freshness_ms=600_000,
    ))
    record = DnsIdTxtRecord(
        v="dnsid-draft-01", identity_fqdn=DOMAIN, gi="example", lr=LR,
        ek="https://example/entity.jwks", ku=f"https://{DOMAIN}/jwks",
        su=f"https://{DOMAIN}/status",
    )
    record.sg = b64url_encode(entity.sign(record.canonical().encode("ascii")))
    if corrupt == "record":
        record.sg = b64url_encode(bytes(64))
    if corrupt == "log":
        resources.resources["https://functional.example/tile/entries/000.p/1"] = encode_entry_bundle([entry + b" "])
    cert = TLSCertificate(not_after=now + datetime.timedelta(days=1), san_dns_names=[DOMAIN, "example"])
    responses = {
        record.ek: ({"keys": [ek.to_dict()]}, cert),
        record.ku: ({"keys": [key.to_dict()]}, cert),
        record.su: ({"state": "REVOKED" if corrupt == "status" else "ACTIVE",
                     "lastTransitionAt": now.isoformat()}, cert),
    }
    calls = []

    class Fetcher(HTTPSFetcher):
        def fetch_strict_json(self, url, allowed_host=None, domain_boundary=False, *, revalidate=False):
            calls.append(url)
            assert url in responses, f"unexpected external fetch: {url}"
            return responses[url]

    resolver = MockDNSResolver({f"_dnsid.{DOMAIN}": [TXTRecord([record.serialize().encode()], ttl=60)]})
    if corrupt == "dns":
        resolver = MockDNSResolver()
    deps = IdentityManagerDependencies(dns_resolver=resolver, https_fetcher=Fetcher(), log_registry=registry)
    document = {
        "dnsid": {"identity": {
            "domain": DOMAIN, "governanceId": "example", "logRef": LR,
            "ekUrl": record.ek, "kuUrl": record.ku, "statusUrl": record.su,
        }},
        "keySource": key_source,
    }
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(document))
    return SimpleNamespace(path=path, deps=deps, key=key, calls=calls, resources=resources)


def checked_profile(manager, payload=b"functional profile payload", *, profile=None):
    profile = profile or JoseProfile.from_identity_manager(manager)
    token = profile.create_jws(payload)
    recovered, verified = profile.verify_jws(token)
    assert recovered == payload and verified.domain == DOMAIN
    header, body, signature = token.split(".")
    kid = manager.key_provider.signing_key().kid
    assert json.loads(b64url_decode(header))["kid"] == f"{DOMAIN}#{kid}"
    assert verified.jwks.key_by_id(kid).verify(f"{header}.{body}".encode(), b64url_decode(signature))
    with pytest.raises(VerificationError):
        profile.verify_jws(f"{header}.{b64url_encode(payload + b'tampered')}.{signature}")
    return token
