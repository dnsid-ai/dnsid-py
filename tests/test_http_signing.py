"""Tests for HttpSignatureProfile.create_signed_http_request and verify_signed_http_request."""

from __future__ import annotations

import datetime
import hashlib
import time
from unittest.mock import MagicMock, patch

import pytest

from dnsid import (
    JWKS,
    HttpRequest,
    IdentityManager,
    IdentityManagerDependencies,
    TLSCertificate,
    VerifiedDomain,
)
from dnsid._utils import b64_std_decode, b64_std_encode
from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.http_signatures import (
    HttpMessageSignatureConfig,
    HttpSignatureProfile,
    _build_signature_base,
)
from dnsid.models import HttpSigningOptions, HttpVerificationOptions
from tests._config import make_config
from tests.conftest import MockDNSResolver


def _build_profile(provider, domain="agent.example.com", http_config=None):
    with patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s):
        mgr = IdentityManager(
            make_config(
                domain=domain,
                governance_id="example.com",
                log_ref="microledger:abc",
                status_url=f"https://{domain}/status",
            ),
            provider,
            deps=IdentityManagerDependencies(dns_resolver=MockDNSResolver()),
        )
    return HttpSignatureProfile(
        resolver=mgr, key_provider=provider, domain=domain, config=http_config
    )


class TestCreateSignedHttpRequest:
    def test_configuration_bounds_rejected(self):
        with pytest.raises(ArgumentError, match="max_age"):
            HttpMessageSignatureConfig(max_age=datetime.timedelta(0))
        with pytest.raises(ArgumentError, match="clock_skew"):
            HttpMessageSignatureConfig(clock_skew=datetime.timedelta(seconds=-1))

    def test_verification_only_profile_rejects_signing_cleanly(self):
        manager = IdentityManager.for_verification(
            IdentityManagerDependencies(dns_resolver=MockDNSResolver())
        )
        profile = HttpSignatureProfile.from_identity_manager(manager)

        with pytest.raises(ArgumentError, match="verification-only"):
            profile.create_signed_http_request(
                HttpRequest(method="GET", url="https://service.example.com/api")
            )

    def test_sets_signature_input_header(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/api")
        signed = profile.create_signed_http_request(req)
        assert signed.get_header("signature-input") != ""

    def test_sets_signature_header(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/api")
        signed = profile.create_signed_http_request(req)
        assert signed.get_header("signature") != ""

    def test_signature_input_contains_required_components(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="POST", url="https://service.example.com/api")
        signed = profile.create_signed_http_request(req)
        sig_input = signed.get_header("signature-input")
        assert '"@method"' in sig_input
        assert '"@authority"' in sig_input
        assert '"@target-uri"' in sig_input

    def test_body_adds_content_digest(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="POST", url="https://service.example.com/api", body=b"hello")
        signed = profile.create_signed_http_request(req)
        assert signed.get_header("content-digest") != ""
        assert '"content-digest"' in signed.get_header("signature-input")

    def test_content_digest_is_correct_sha256(self, ec_provider):
        profile = _build_profile(ec_provider)
        body = b"request body"
        req = HttpRequest(method="POST", url="https://service.example.com/api", body=body)
        signed = profile.create_signed_http_request(req)
        expected_digest = b64_std_encode(hashlib.sha256(body).digest())
        cd_header = signed.get_header("content-digest")
        assert expected_digest in cd_header

    def test_supplied_empty_content_is_hashed_and_covered(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="POST", url="https://service.example.com/api", body=b"")
        signed = profile.create_signed_http_request(req)
        assert signed.get_header("content-digest") == (
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        )
        assert '"content-digest"' in signed.get_header("signature-input")

    def test_absent_content_ignores_content_length_for_digest_presence(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(
            method="POST",
            url="https://service.example.com/api",
            headers={"content-length": "0"},
            body=None,
        )
        signed = profile.create_signed_http_request(req)
        assert signed.get_header("content-digest") == ""
        assert '"content-digest"' not in signed.get_header("signature-input")

    def test_signed_http_client_distinguishes_empty_from_absent_content(self, ec_provider):
        import httpx

        captured: list[httpx.Request] = []

        def handle(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200)

        profile = _build_profile(ec_provider)
        base_client = httpx.Client(transport=httpx.MockTransport(handle))
        client = profile.create_signed_http_client(base_client)
        try:
            client.post("https://service.example.com/api")
            client.post("https://service.example.com/api", content=b"")
        finally:
            client.close()
            base_client.close()

        assert captured[0].headers.get("content-digest") is None
        assert captured[1].headers.get("content-digest") == (
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        )

    def test_kid_with_hash_raises(self, ec_pair, ec_provider):
        _, pub = ec_pair
        pub.kid = "bad#kid"
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        with pytest.raises(ArgumentError):
            profile.create_signed_http_request(req)

    def test_unknown_component_raises(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        with pytest.raises(ArgumentError):
            profile.create_signed_http_request(
                req, HttpSigningOptions(additional_components=["Unknown-Header"])
            )

    def test_known_additional_component_included(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(
            method="GET",
            url="https://service.example.com/",
            headers={"authorization": "Bearer token"},
        )
        signed = profile.create_signed_http_request(
            req, HttpSigningOptions(additional_components=["authorization"])
        )
        assert '"authorization"' in signed.get_header("signature-input")

    def test_keyid_uses_domain_hash_kid(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        signed = profile.create_signed_http_request(req)
        assert 'keyid="agent.example.com#k1"' in signed.get_header("signature-input")

    def test_signature_bytes_are_valid_base64(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        signed = profile.create_signed_http_request(req)
        sig_header = signed.get_header("signature")
        assert sig_header.startswith("sig1=:")
        assert sig_header.endswith(":")
        b64_std_decode(sig_header[6:-1])  # should not raise

    def test_default_label_is_sig1(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        signed = profile.create_signed_http_request(req)
        params = SignatureParams.parse(signed.get_header("signature-input"))
        assert params.label == "sig1"

    def test_default_tag_is_absent(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        signed = profile.create_signed_http_request(req)
        params = SignatureParams.parse(signed.get_header("signature-input"))
        assert params.tag is None

    def test_default_expires_is_set(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        signed = profile.create_signed_http_request(req)
        params = SignatureParams.parse(signed.get_header("signature-input"))
        assert params.expires is not None
        assert params.expires == params.created + 300

    def test_custom_label_via_options(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        signed = profile.create_signed_http_request(req, HttpSigningOptions(label="mysig"))
        assert signed.get_header("signature").startswith("mysig=:")
        assert SignatureParams.parse(signed.get_header("signature-input")).label == "mysig"

    def test_signing_preserves_other_valid_dictionary_members(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(
            method="GET",
            url="https://service.example.com/",
            headers={
                "signature-input": 'other=("@method");created=1;extension=?1',
                "signature": "other=:dGVzdA==:",
            },
        )
        signed = profile.create_signed_http_request(req)
        assert signed.get_header("signature-input").startswith(
            'other=("@method");created=1;extension, sig1='
        )
        assert signed.get_header("signature").startswith("other=:dGVzdA==:, sig1=:")

    def test_custom_expires_in_seconds(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/")
        signed = profile.create_signed_http_request(req, HttpSigningOptions(expires_in_seconds=60))
        params = SignatureParams.parse(signed.get_header("signature-input"))
        assert params.expires == params.created + 60

    def test_authority_prefers_host_header(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(
            method="GET",
            url="https://service.example.com:8443/path",
            headers={"host": "service.example.com:8443"},
        )
        signed = profile.create_signed_http_request(req)
        params = SignatureParams.parse(signed.get_header("signature-input"))
        base = _build_signature_base(req, params).decode("utf-8")
        assert '"@authority": service.example.com:8443' in base

    def test_authority_falls_back_to_url(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com/path")
        signed = profile.create_signed_http_request(req)
        params = SignatureParams.parse(signed.get_header("signature-input"))
        assert "@authority" in params.components

    def test_authority_includes_nonstandard_port(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://service.example.com:9000/path")
        signed = profile.create_signed_http_request(req)
        params = SignatureParams.parse(signed.get_header("signature-input"))
        base = _build_signature_base(req, params).decode("utf-8")
        assert '"@authority": service.example.com:9000' in base


class TestVerifySignedHttpRequest:
    def _sign_and_get_verifier(self, ec_pair, ec_provider, body=None, domain="signer.example.com"):
        _, pub_jwk = ec_pair
        signer = _build_profile(ec_provider, domain=domain)
        req = HttpRequest(method="POST", url="https://verifier.example.com/api", body=body)
        signed = signer.create_signed_http_request(
            req, HttpSigningOptions(tag="a2a-dnsid-http-sig-v1")
        )

        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk

        verifier = _build_profile(ec_provider, domain="verifier.example.com")
        return signed, verifier, mock_vd

    def test_valid_signature_returns_verified_domain(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_get_verifier(ec_pair, ec_provider)
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            result = verifier.verify_signed_http_request(signed)
        assert result is mock_vd

    def test_forwards_peer_certificate_to_identity_verification(
        self, ec_pair, ec_provider
    ):
        signed, verifier, mock_vd = self._sign_and_get_verifier(ec_pair, ec_provider)
        peer_cert = TLSCertificate(san_dns_names=["signer.example.com"])
        with patch.object(
            verifier._resolver, "verify_domain", return_value=mock_vd
        ) as verify_domain:
            result = verifier.verify_signed_http_request(signed, peer_cert=peer_cert)
        assert result is mock_vd
        verify_domain.assert_called_once_with(
            "signer.example.com", peer_cert=peer_cert
        )

    def test_missing_headers_raises(self, ec_provider):
        profile = _build_profile(ec_provider)
        req = HttpRequest(method="GET", url="https://example.com/")
        with pytest.raises(VerificationError) as exc_info:
            profile.verify_signed_http_request(req)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID

    def test_tampered_body_fails(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_get_verifier(
            ec_pair, ec_provider, body=b"original body"
        )
        signed.body = b"tampered body"
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError) as exc_info:
                verifier.verify_signed_http_request(signed)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID

    def test_supplied_empty_content_verifies(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_get_verifier(ec_pair, ec_provider, body=b"")
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            assert verifier.verify_signed_http_request(signed) is mock_vd

    def test_supplied_empty_content_is_not_equivalent_to_absent_content(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_get_verifier(ec_pair, ec_provider, body=b"")
        signed.body = None
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError, match="request has no body"):
                verifier.verify_signed_http_request(signed)

    def test_expired_signature_raises(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_get_verifier(ec_pair, ec_provider)
        from dnsid.models import SignatureParams

        old_params = SignatureParams.parse(signed.get_header("signature-input"))
        old_params.created = int(time.time()) - 400
        signed.set_header("signature-input", old_params.serialize())
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError) as exc_info:
                verifier.verify_signed_http_request(signed)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_missing_required_component_raises(self, ec_pair, ec_provider):
        signed, verifier, _ = self._sign_and_get_verifier(ec_pair, ec_provider)
        from dnsid.models import SignatureParams

        params = SignatureParams.parse(signed.get_header("signature-input"))
        params.components = [c for c in params.components if c != "@method"]
        signed.set_header("signature-input", params.serialize())
        with pytest.raises(VerificationError) as exc_info:
            verifier.verify_signed_http_request(signed)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID
        assert "@method" in exc_info.value.message

    def test_body_without_content_digest_coverage_raises(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        signer = _build_profile(ec_provider)
        req = HttpRequest(method="POST", url="https://verifier.example.com/api", body=b"some body")
        signed = signer.create_signed_http_request(req)

        from dnsid.models import SignatureParams

        params = SignatureParams.parse(signed.get_header("signature-input"))
        params.components = [c for c in params.components if c != "content-digest"]
        signed.set_header("signature-input", params.serialize())

        mock_vd = MagicMock()
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk
        verifier = _build_profile(ec_provider, domain="verifier.example.com")
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError) as exc_info:
                verifier.verify_signed_http_request(signed)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID


class TestVerificationOptions:
    def _sign_and_verifier(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        signer = _build_profile(ec_provider, domain="signer.example.com")
        req = HttpRequest(method="POST", url="https://verifier.example.com/api", body=b"body")
        signed = signer.create_signed_http_request(
            req, HttpSigningOptions(tag="a2a-dnsid-http-sig-v1")
        )

        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk

        verifier = _build_profile(ec_provider, domain="verifier.example.com")
        return signed, verifier, mock_vd

    def test_required_tag_passes_when_correct(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        opts = HttpVerificationOptions(required_tag="a2a-dnsid-http-sig-v1")
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            result = verifier.verify_signed_http_request(signed, opts)
        assert result is mock_vd

    def test_required_tag_wrong_value_raises(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        opts = HttpVerificationOptions(required_tag="wrong-tag")
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError) as exc_info:
                verifier.verify_signed_http_request(signed, opts)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID
        assert "tag mismatch" in exc_info.value.message

    def test_required_tag_missing_raises(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        from dnsid.models import SignatureParams

        params = SignatureParams.parse(signed.get_header("signature-input"))
        params.tag = None
        signed.set_header("signature-input", params.serialize())
        opts = HttpVerificationOptions(required_tag="a2a-dnsid-http-sig-v1")
        with pytest.raises(VerificationError) as exc_info:
            verifier.verify_signed_http_request(signed, opts)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "tag" in exc_info.value.message

    def test_no_required_tag_accepts_any_tag(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        opts = HttpVerificationOptions(required_tag=None)
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            result = verifier.verify_signed_http_request(signed, opts)
        assert result is mock_vd

    def test_required_tag_selects_one_complete_signature(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        original_input = signed.get_header("signature-input")
        original_signature = signed.get_header("signature")
        unrelated_input = original_input.replace("sig1=", "other=", 1).replace(
            'tag="a2a-dnsid-http-sig-v1"', 'tag="other-profile"'
        )
        unrelated_signature = original_signature.replace("sig1=", "other=", 1)
        signed.set_header("signature-input", f"{unrelated_input}, {original_input}")
        signed.set_header("signature", f"{unrelated_signature}, {original_signature}")

        opts = HttpVerificationOptions(required_tag="a2a-dnsid-http-sig-v1")
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            result = verifier.verify_signed_http_request(signed, opts)
        assert result is mock_vd

    def test_no_required_tag_rejects_multiple_valid_signatures(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        original_input = signed.get_header("signature-input")
        original_signature = signed.get_header("signature")
        signed.set_header(
            "signature-input", f"{original_input}, {original_input.replace('sig1=', 'other=', 1)}"
        )
        signed.set_header(
            "signature", f"{original_signature}, {original_signature.replace('sig1=', 'other=', 1)}"
        )
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError, match="multiple valid"):
                verifier.verify_signed_http_request(signed)

    def test_ignores_invalid_coexisting_signature(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        original_input = signed.get_header("signature-input")
        original_signature = signed.get_header("signature")
        signed.set_header(
            "signature-input",
            f"{original_input.replace('sig1=', 'proxy=', 1)}, {original_input}",
        )
        signed.set_header("signature", f"proxy=:Ym9ndXM=:, {original_signature}")

        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            result = verifier.verify_signed_http_request(signed)
        assert result is mock_vd

    def test_signature_base_preserves_unknown_parameter_order(self, ec_pair, ec_provider):
        from dnsid.models import SignatureParams

        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        params = SignatureParams.parse(signed.get_header("signature-input"))
        params.parameters.append(("extension", "preserved"))
        assert params.value_string().endswith(';extension="preserved"')

    def _make_minimal_signed_request(self, ec_pair) -> HttpRequest:
        from dnsid._crypto import ec_sign

        private, pub_jwk = ec_pair
        created = int(time.time())
        key_id = f"signer.example.com#{pub_jwk.kid}"
        url = "https://verifier.example.com/api"
        sig_params_value = (
            f'("@method" "@authority" "@target-uri")'
            f';keyid="{key_id}";alg="ecdsa-p256-sha256";created={created}'
        )
        sig_base = "\n".join(
            [
                '"@method": GET',
                '"@authority": verifier.example.com',
                f'"@target-uri": {url}',
                f'"@signature-params": {sig_params_value}',
            ]
        ).encode("utf-8")
        sig_bytes = ec_sign(private, "ES256", sig_base)
        return HttpRequest(
            method="GET",
            url=url,
            headers={
                "signature-input": f"a2a={sig_params_value}",
                "signature": f"a2a=:{b64_std_encode(sig_bytes)}:",
            },
        )

    def test_accepts_signature_without_optional_params(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        signed = self._make_minimal_signed_request(ec_pair)
        assert "expires" not in signed.get_header("signature-input")
        assert "nonce" not in signed.get_header("signature-input")
        assert "tag" not in signed.get_header("signature-input")

        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk

        verifier = _build_profile(ec_provider, domain="verifier.example.com")
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            result = verifier.verify_signed_http_request(signed)
        assert result is mock_vd

    def test_missing_authority_rejected_by_default(self, ec_pair, ec_provider):
        signed, verifier, mock_vd = self._sign_and_verifier(ec_pair, ec_provider)
        from dnsid.models import SignatureParams

        params = SignatureParams.parse(signed.get_header("signature-input"))
        params.components = [c for c in params.components if c != "@authority"]
        signed.set_header("signature-input", params.serialize())
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError) as exc_info:
                verifier.verify_signed_http_request(signed)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID
        assert "@authority" in exc_info.value.message

    def test_signature_lifetime_exceeds_max_raises(self, ec_pair, ec_provider):
        signed, verifier, _ = self._sign_and_verifier(ec_pair, ec_provider)
        from dnsid.models import SignatureParams

        params = SignatureParams.parse(signed.get_header("signature-input"))
        params.expires = params.created + 36000
        signed.set_header("signature-input", params.serialize())
        with pytest.raises(VerificationError) as exc_info:
            verifier.verify_signed_http_request(signed)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "lifetime" in exc_info.value.message

    def test_custom_required_components(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        signer = _build_profile(ec_provider, domain="signer.example.com")
        req = HttpRequest(
            method="POST",
            url="https://verifier.example.com/api",
            headers={"authorization": "Bearer tok"},
            body=b"body",
        )
        signed = signer.create_signed_http_request(
            req, HttpSigningOptions(additional_components=["authorization"])
        )
        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk
        verifier = _build_profile(ec_provider, domain="verifier.example.com")
        opts = HttpVerificationOptions(
            required_components=["@method", "@target-uri", "authorization"]
        )
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            result = verifier.verify_signed_http_request(signed, opts)
        assert result is mock_vd

    def test_absent_required_header_raises_on_verify(self, ec_pair, ec_provider):
        """RFC 9421: signature base generation must fail when a covered header is absent."""
        _, pub_jwk = ec_pair
        signer = _build_profile(ec_provider, domain="signer.example.com")
        # Sign with authorization present
        req = HttpRequest(
            method="POST",
            url="https://verifier.example.com/api",
            headers={"authorization": "Bearer tok"},
            body=b"body",
        )
        signed = signer.create_signed_http_request(
            req, HttpSigningOptions(additional_components=["authorization"])
        )
        # Now remove the authorization header to simulate an absent covered component
        del signed.headers["authorization"]

        mock_vd = MagicMock(spec=VerifiedDomain)
        mock_vd.jwks = JWKS(keys=[pub_jwk])
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk
        verifier = _build_profile(ec_provider, domain="verifier.example.com")
        opts = HttpVerificationOptions(required_components=["authorization"])
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError) as exc_info:
                verifier.verify_signed_http_request(signed, opts)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "authorization" in exc_info.value.message


class TestStructuredFieldsParsing:
    """Tests for RFC 8941 Structured Fields parsing conformance."""

    def test_sf_key_grammar_accepts_valid_labels(self):
        """RFC 8941 sf-key: (lcalpha / '*') *(lcalpha / DIGIT / '_' / '-' / '.' / '*')."""
        from dnsid.models import SignatureParams

        # Valid labels per RFC 8941
        for label in ["sig1", "*sig", "sig_1", "sig.1", "a", "*"]:
            raw = f'{label}=("@method");keyid="test";alg="ed25519";created=1000'
            params = SignatureParams.parse(raw)
            assert params.label == label

    def test_sf_key_grammar_rejects_invalid_labels(self):
        """Uppercase and non-conforming characters should be rejected."""
        from dnsid.models import SignatureParams

        for label in ["Sig1", "SIG", "1sig", "-sig"]:
            raw = f'{label}=("@method");keyid="test";alg="ed25519";created=1000'
            with pytest.raises(VerificationError) as exc_info:
                SignatureParams.parse(raw)
            assert exc_info.value.code == VerificationCode.RECORD_INVALID

    def test_sf_params_with_semicolon_in_quoted_value(self):
        """Semicolons inside quoted parameter values must not split the param."""
        from dnsid.models import SignatureParams

        raw = 'sig1=("@method");keyid="domain.example;extra";alg="ed25519";created=1000'
        params = SignatureParams.parse(raw)
        assert params.key_id == "domain.example;extra"
        assert params.alg == "ed25519"
        assert params.created == 1000

    def test_created_param_must_be_integer(self):
        """created parameter as a quoted string should be rejected."""
        from dnsid.models import SignatureParams

        raw = 'sig1=("@method");keyid="test";alg="ed25519";created="notanint"'
        with pytest.raises(VerificationError) as exc_info:
            SignatureParams.parse(raw)
        assert exc_info.value.code == VerificationCode.RECORD_INVALID
        assert "created" in exc_info.value.message

    def test_unknown_signature_boolean_is_canonicalized(self):
        from dnsid.models import SignatureParams

        params = SignatureParams.parse('sig1=("@method");created=1;extension=?1')
        assert params.value_string() == '("@method");created=1;extension'

    @pytest.mark.parametrize("extension", ["@123", '%"display"'])
    def test_rfc9651_only_signature_parameter_values_rejected(self, extension):
        from dnsid.models import SignatureParams

        with pytest.raises(VerificationError, match="RFC 9651"):
            SignatureParams.parse(f'sig1=("@method");created=1;extension={extension}')

    def test_duplicate_known_signature_parameter_rejected_by_library_parser(self):
        from dnsid.models import SignatureParams

        with pytest.raises(VerificationError, match="duplicate parameter"):
            SignatureParams.parse('sig1=("@method");created=1;created=2')

    def test_query_param_reserved_characters_vector(self):
        from dnsid.models import SignatureParams

        params = SignatureParams.parse('sig1=("@query-param";name="a%21");created=1')
        req = HttpRequest(method="GET", url="https://api.example/search?a!=v!")
        assert _build_signature_base(req, params).decode() == (
            '"@query-param";name="a%21": v%21\n'
            '"@signature-params": ("@query-param";name="a%21");created=1'
        )

    @pytest.mark.parametrize(
        "raw,match",
        [
            ('sig1=("@method" "@method");created=1', "duplicate"),
            ('sig1=("@method";unknown);created=1', "unsupported component parameter"),
            ('sig1=("@authority";req);created=1', "request context"),
            ('sig1=("example-dict";sf);created=1', "unsupported component parameter"),
        ],
    )
    def test_component_profile_rejections(self, raw, match):
        from dnsid.models import SignatureParams

        with pytest.raises(VerificationError, match=match):
            params = SignatureParams.parse(raw)
            _build_signature_base(HttpRequest(method="GET", url="https://api.example/"), params)

    def test_duplicate_signature_label_rejected(self, ec_pair, ec_provider):
        """Duplicate labels in Signature header must be rejected per RFC 9421."""
        from dnsid.http_signatures import _extract_signature_bytes

        sig_header = "sig1=:dGVzdA==:, sig1=:b3RoZXI=:"
        with pytest.raises(VerificationError) as exc_info:
            _extract_signature_bytes(sig_header, "sig1")
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID
        assert "duplicate" in exc_info.value.message.lower()


class TestParity:
    def test_unsupported_content_digest_algorithm_raises(self, ec_pair, ec_provider):
        _, pub_jwk = ec_pair
        signer = _build_profile(ec_provider)
        req = HttpRequest(method="POST", url="https://verifier.example.com/api", body=b"body")
        signed = signer.create_signed_http_request(req)
        signed.set_header("content-digest", "sha3-256=:fakedigest:")

        mock_vd = MagicMock()
        mock_vd.jwks.key_by_id = lambda kid: pub_jwk
        verifier = _build_profile(ec_provider, domain="verifier.example.com")
        with patch.object(verifier._resolver, "verify_domain", return_value=mock_vd):
            with pytest.raises(VerificationError) as exc_info:
                verifier.verify_signed_http_request(signed)
        assert exc_info.value.code == VerificationCode.SIGNATURE_INVALID
        assert "sha3-256" in exc_info.value.message

    def test_authority_uses_host_header_when_present(self, ec_provider):
        from dnsid.models import SignatureParams

        profile = _build_profile(ec_provider)
        req = HttpRequest(
            method="GET",
            url="https://service.example.com:8443/path",
            headers={"host": "service.example.com:8443"},
        )
        signed = profile.create_signed_http_request(req)
        params = SignatureParams.parse(signed.get_header("signature-input"))
        base = _build_signature_base(req, params).decode("utf-8")
        assert '"@authority": service.example.com:8443' in base

    def test_mtls_missing_peer_cert_raises(self, ec_pair, ec_provider):
        """fl=mtls with no peer_cert raises VerificationError(TLSError)."""
        import datetime

        from dnsid import JWKS, DnsIdTxtRecord
        from dnsid._crypto import ec_sign
        from dnsid._utils import b64url_encode
        from dnsid.models import AgentStatus, TLSCertificate, TXTRecord
        from tests.conftest import MockDNSResolver

        private, pub_jwk = ec_pair
        target = "service.example.com"

        record = DnsIdTxtRecord(
            v="dnsid-draft-01",
            gi="example.com",
            ek="https://example.com/.well-known/jwks.json",
            ku=f"https://{target}/.well-known/jwks.json",
            lr="microledger:abc",
            su=f"https://{target}/status",
            fl="mtls",
            identity_fqdn=target,
        )
        canonical = record.canonical().encode("ascii")
        record.sg = b64url_encode(ec_sign(private, pub_jwk.alg, canonical))
        txt_raw = record.serialize()

        dns_resolver = MockDNSResolver(
            {
                f"_dnsid.{target}": [TXTRecord(strings=[txt_raw.encode("ascii")], ttl=300)],
            }
        )
        now = datetime.datetime.now(datetime.UTC)
        from tests.conftest import make_ec_p256_pair
        from tests.test_verify_domain import _stub_log_registry

        ek_jwks = JWKS(keys=[pub_jwk])
        _, ku_jwk = make_ec_p256_pair("ku-key")
        ku_jwks = JWKS(keys=[ku_jwk])
        tls_cert = TLSCertificate(
            not_after=now + datetime.timedelta(days=365),
            san_dns_names=[target],
        )

        def fake_fetch_jwks(uri, allowed_host, transport=None, **kwargs):
            return (
                (ku_jwks, tls_cert) if uri.startswith(f"https://{target}/") else (ek_jwks, tls_cert)
            )

        active_status = AgentStatus(state="ACTIVE", last_transition_at=now)

        with patch("dnsid.manager.normalize_fqdn", side_effect=lambda s, **_: s):
            mgr = IdentityManager(
                make_config(
                    domain="verifier.example.com",
                    governance_id="example.com",
                    log_ref="microledger:abc",
                    status_url="https://verifier.example.com/status",
                ),
                ec_provider,
                deps=IdentityManagerDependencies(
                    dns_resolver=dns_resolver, log_registry=_stub_log_registry()
                ),
            )

        with (
            patch("dnsid.manager._fetch_jwks", side_effect=fake_fetch_jwks),
            patch("dnsid.manager._fetch_strict_json_status", return_value=active_status),
            patch("dnsid.manager._maybe_normalize_fqdn", side_effect=lambda s: s),
        ):
            with pytest.raises(VerificationError) as exc_info:
                mgr.verify_domain(target)  # no peer_cert supplied
        assert exc_info.value.code == VerificationCode.TLS_ERROR
