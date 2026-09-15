"""Runtime regressions for compliance commit 5e5c783's JOSE/cache corrections."""

import datetime as dt
import json
from unittest.mock import MagicMock, patch

import pytest

from dnsid import JWKS, IdentityManager, IdentityManagerDependencies
from dnsid._utils import b64url_encode
from dnsid.enums import DNSSECMode, VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.http_signatures import HttpSignatureProfile
from dnsid.jose import JoseConfig, JoseProfile
from dnsid.manager import _InMemoryCache, _PrivateCache
from dnsid.models import HttpRequest, JWTOptions
from dnsid.oidc import OIDCConfig, OIDCProfile, _validate_token_times
from tests.test_verification_coalescing import _manager_fixture


def test_jose_strict_boundaries_and_expiry(ec_provider):
    instant = dt.datetime.fromtimestamp(100.25, dt.UTC)
    resolver = MagicMock()
    resolver.verify_domain.return_value.jwks = JWKS(keys=[ec_provider.signing_key()])
    profile = JoseProfile(resolver, config=JoseConfig(clock_skew=dt.timedelta(0)))
    claims = {
        "iss": "agent.example",
        "sub": "agent.example",
        "aud": "rp.example",
        "iat": 0,
        "exp": 100.5,
    }
    header = {"alg": "ES256", "kid": ec_provider.signing_key().kid}

    def token(h=header, c=claims):
        parts = [
            b64url_encode((v if isinstance(v, str) else json.dumps(v)).encode()) for v in (h, c)
        ]
        signed = ".".join(parts)
        return signed + "." + b64url_encode(ec_provider.sign(signed.encode()))

    with patch("dnsid.jose._now", return_value=instant):
        with pytest.raises(ArgumentError, match="audience"):
            profile.verify_jwt(token())
        assert (
            profile.verify_jwt(token(), expected_audience="rp.example")
            is resolver.verify_domain.return_value
        )
        for field in ("iat", "exp", "nbf"):
            for value in (None, True, "1", float("nan"), float("inf")):
                resolver.reset_mock()
                with pytest.raises(VerificationError):
                    profile.verify_jwt(
                        token(c={**claims, field: value}), expected_audience="rp.example"
                    )
                resolver.verify_domain.assert_not_called()
        for c in (
            {**claims, "aud": ["rp.example", 1]},
            {**claims, "exp": 100.25},
            {**claims, "iat": 100.3},
            {**claims, "nbf": 100.3},
            '{"iss":"a","iss":"b"}',
        ):
            with pytest.raises(VerificationError):
                profile.verify_jwt(token(c=c), expected_audience="rp.example")
        for h in (
            {**header, "crit": []},
            {**header, "b64": False},
            {**header, "b64": 1},
            {**header, "typ": None},
            {**header, "alg": "none"},
            '{"alg":"ES256","alg":"ES256"}',
        ):
            resolver.reset_mock()
            with pytest.raises(VerificationError):
                profile.verify_jwt(token(h=h), expected_audience="rp.example")
            with pytest.raises(VerificationError):
                profile.verify_jws(token(h=h))
            resolver.verify_domain.assert_not_called()
    with patch("dnsid.jose._now", side_effect=[instant, instant + dt.timedelta(seconds=1)]):
        with pytest.raises(VerificationError, match="expired during"):
            profile.verify_jwt(token(), expected_audience="rp.example")
    for value in (dt.timedelta(0), dt.timedelta(seconds=-1), float("nan"), "900"):
        with pytest.raises(ArgumentError):
            JoseProfile(resolver, config=JoseConfig(max_lifetime=value))
        with pytest.raises(ArgumentError):
            OIDCProfile(resolver, None, "agent.example", OIDCConfig(assertion_lifetime=value))
        with pytest.raises(ArgumentError):
            JoseProfile(resolver, ec_provider, "agent.example").create_jwt(
                JWTOptions(audience="rp.example", expiry=value)
            )
    with patch("dnsid.oidc._now", return_value=instant):
        _validate_token_times(claims, dt.timedelta(0))
        for c in ({**claims, "exp": 100.25}, {**claims, "nbf": None}):
            with pytest.raises(VerificationError):
                _validate_token_times(c, dt.timedelta(seconds=60))


def test_http_limits_reject_before_discovery():
    resolver = MagicMock()
    profile = HttpSignatureProfile(resolver, None, "rp.example")
    for headers, body in (
        ({"signature": "s=:AA==:", "signature-input": "x" * 65537}, None),
        ({"signature": "s=:AA==:", "signature-input": "s=()"}, b"x" * (8 * 1024 * 1024 + 1)),
        (
            {
                "signature": ", ".join(f"s{i}=:AA==:" for i in range(17)),
                "signature-input": ", ".join(f's{i}=("@method")' for i in range(17)),
            },
            None,
        ),
    ):
        request = HttpRequest(method="GET", url="https://rp.example/", body=body)
        for name, value in headers.items():
            request.set_header(name, value)
        with pytest.raises(VerificationError, match="too large|limits exceeded"):
            profile.verify_signed_http_request(request)
    resolver.verify_domain.assert_not_called()


def test_dns_acquisition_expiry_zero_ttl_and_status_refresh(ec_pair):
    manager, resolver, counts, domain, keys, status, _ = _manager_fixture(ec_pair)
    acquired = dt.datetime.now(dt.UTC)
    clock = [acquired]
    record = resolver.records[f"_dnsid.{domain}"]

    def delayed_status(*args, **kwargs):
        clock[0] += dt.timedelta(seconds=35)
        return status(*args, **kwargs)

    with (
        manager,
        patch("dnsid.manager._now", side_effect=lambda: clock[0]),
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=delayed_status),
    ):
        record.ttl = 30
        with pytest.raises(VerificationError) as error:
            manager.verify_domain(domain)
        assert error.value.code == VerificationCode.DNS_RESOLUTION
        assert manager._cache.get(domain) is None
        record.ttl = 0
        manager.verify_domain(domain)
        manager.verify_domain(domain)
        assert counts["dns"] == 3
        assert manager._cache.get(domain) is None
        record.ttl = 60
        evidence = manager.verify_domain(domain)
        assert evidence.dns_expires_at == clock[0] + dt.timedelta(seconds=25)
        # Force a required refresh without changing its absolute DNS expiry.
        evidence.last_status_check_at -= dt.timedelta(hours=1)
        with pytest.raises(VerificationError):
            manager.verify_domain(domain)
        assert manager._cache.get(domain) is None
        # Zero TTL exempts DNS lifetime only, not TLS expiry.
        record.ttl = 0
        clock[0] += dt.timedelta(days=2)
        with pytest.raises(VerificationError) as error:
            manager.verify_domain(domain)
        assert error.value.code == VerificationCode.TLS_ERROR


def test_shared_cache_is_private_and_configuration_is_snapshotted(ec_pair):
    first, resolver, _, domain, keys, status, _ = _manager_fixture(ec_pair)
    backend = _InMemoryCache()
    first._cache = _PrivateCache(backend)
    config = first.config
    config.verification.dnssec_mode = DNSSECMode.REQUIRED
    with (
        first,
        IdentityManager(
            config,
            deps=IdentityManagerDependencies(
                cache=backend, dns_resolver=resolver, log_registry=first._log_registry
            ),
        ) as second,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
    ):
        config.verification.dnssec_mode = DNSSECMode.AUTO
        second.config.verification.dnssec_mode = DNSSECMode.AUTO
        assert first.verify_domain(domain).domain == domain
        with pytest.raises(VerificationError) as error:
            second.verify_domain(domain)
        assert error.value.code == VerificationCode.DNSSEC_FAILED
        assert second._cache.get(domain) is None
