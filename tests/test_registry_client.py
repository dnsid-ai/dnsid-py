"""Tests for RegistryClient registry workflow methods."""

from __future__ import annotations

import datetime
import json
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dnsid import (
    JWK,
    LiveAgentRegistrationInput,
    PreparedRegistryEvent,
    RegistryRevocationReason,
    RevocationReason,
)
from dnsid._crypto import compute_thumbprint, jwk_from_dict
from dnsid._utils import b64url_encode
from dnsid.exceptions import ArgumentError, ValidationError, VerificationError
from dnsid.interfaces import AbstractRegistryClient
from dnsid.models import (
    AgentRegistration,
    AgentRegistrationInput,
    LiveProofReissueRequest,
    LiveProofRequest,
    LiveProvisioningResponse,
    RegistryAgentStatus,
)
from dnsid.registry_client import RegistryClient

_VALID_CANONICAL = (
    "ek=https://example.com/.well-known/jwks.json;"
    "gi=example.com;"
    "ku=https://agent.example.com/.well-known/jwks.json;"
    "lr=microledger:abc123;"
    "su=https://agent.example.com/status;"
    "v=dnsid-draft-01"
)

_DOMAIN = "agent.example.com"
# Synthetic placeholder credential for auth-path tests (not a real key).
_FAKE_API_KEY = "test-key-placeholder"


def _make_client() -> RegistryClient:
    return RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)


_REGISTER_RESPONSE = {"domain": _DOMAIN, "status": "PENDING"}


def _registration(
    *, authority: str = "client", registry_status: str = "PENDING"
) -> AgentRegistration:
    return AgentRegistration(
        domain=_DOMAIN,
        publication_authority=authority,
        registry_status=registry_status,
        registry_url="https://registry.example.com",
    )


def _post_capturing(response: dict):
    """Patch _post to capture the request body and return a fixed response."""
    captured: list[dict] = []

    def _post(self, path: str, body=None, extra_headers=None, expected_status=None):
        captured.append(
            {"path": path, "body": body or {}, "headers": extra_headers}
        )
        return response

    return patch.object(RegistryClient, "_post", _post), captured


def _live_key(**changes: str) -> JWK:
    raw = {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "x": b64url_encode(bytes(range(32))),
    }
    raw["kid"] = compute_thumbprint(raw)
    raw.update(changes)
    return jwk_from_dict(raw)


def _live_challenge_response(
    key: JWK,
    *,
    domain: str = "live.example",
    challenge: str = "proof-challenge",
    agent_id: str = "agent-123",
) -> dict:
    transcript = {
        "protocol": "dnsid-live-provisioning-pop/v1",
        "org_id": "org-123",
        "agent_id": agent_id,
        "fqdn": domain,
        "key_id": key.thumbprint(),
        "nonce": challenge,
        "expires_at": "2026-09-03T14:00:00Z",
    }
    return {
        "request_id": "live-1",
        "agent_id": agent_id,
        "status": "challenge_pending",
        "challenge": challenge,
        "challenge_message": b64url_encode(
            json.dumps(transcript, separators=(",", ":")).encode()
        ),
    }


class TestRegisterAgent:
    def test_capabilities_url_included_when_set(self):
        ctx, captured = _post_capturing(_REGISTER_RESPONSE)
        with ctx, patch.object(RegistryClient, "get_registration", return_value=_registration()):
            _make_client().register_agent(
                AgentRegistrationInput(
                    domain=_DOMAIN,
                    environment="production",
                    capabilities_url="https://agent.example.com/.well-known/agent-card.json",
                )
            )
        assert captured[0]["body"]["capabilities_url"] == (
            "https://agent.example.com/.well-known/agent-card.json"
        )

    def test_register_agent_adopts_the_created_agent_id(self):
        ctx, _ = _post_capturing(dict(_REGISTER_RESPONSE, id="agent-123"))
        with ctx, patch.object(RegistryClient, "get_registration", return_value=_registration()):
            reg = _make_client().register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="production")
            )
        assert reg.id == "agent-123"

    def test_register_agent_rejects_a_status_view_naming_another_agent(self):
        ctx, _ = _post_capturing(dict(_REGISTER_RESPONSE, id="agent-123"))
        other = replace(_registration(), id="agent-999")
        with (
            ctx,
            patch.object(RegistryClient, "get_registration", return_value=other),
            pytest.raises(ValidationError, match="different agent"),
        ):
            _make_client().register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="production")
            )

    def test_agent_registration_keeps_its_positional_layout(self):
        # ``raw`` stays where public callers have always passed it; ``id`` is last.
        reg = AgentRegistration(_DOMAIN, "client", "READY", "https://r", None, None, None, {"k": 1})
        assert reg.raw == {"k": 1}
        assert reg.id == ""

    def test_capabilities_url_omitted_when_not_set(self):
        ctx, captured = _post_capturing(_REGISTER_RESPONSE)
        with ctx, patch.object(RegistryClient, "get_registration", return_value=_registration()):
            _make_client().register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="production")
            )
        assert "capabilities_url" not in captured[0]["body"]

    def test_live_registration_uses_dedicated_operation_and_derives_domain(self):
        key = _live_key()
        response = _live_challenge_response(key)
        ctx, captured = _post_capturing(response)
        with ctx:
            result = _make_client().register_live_agent(
                LiveAgentRegistrationInput(public_key_jwk=key), "live-1"
            )

        assert isinstance(result, LiveProvisioningResponse)
        assert result.domain == "live.example"
        assert result.challenge_transcript is not None
        assert result.challenge_transcript.nonce == "proof-challenge"
        assert captured[0] == {
            "path": "/api/v1/agent",
            "body": {
                "public_key": key.to_dict(),
                "environment": "production",
                "tier": "live",
                "managed": True,
            },
            "headers": {"Idempotency-Key": "live-1"},
        }

    def test_live_registration_replay_allows_empty_challenge_fields(self):
        key = _live_key()
        response = {
            "request_id": "live-1",
            "agent_id": "agent-123",
            "status": "provider_deferred",
            "challenge": "",
            "challenge_message": "",
        }
        ctx, _ = _post_capturing(response)
        with ctx:
            result = _make_client().register_live_agent(
                LiveAgentRegistrationInput(public_key_jwk=key), "live-1"
            )

        assert result.challenge == ""
        assert result.domain == ""
        assert result.challenge_transcript is None

    def test_live_registration_rejects_mismatched_challenge_transcript(self):
        key = _live_key()
        response = _live_challenge_response(key)
        response["challenge"] = "different"
        ctx, _ = _post_capturing(response)
        with ctx:
            with pytest.raises(VerificationError, match="challenge transcript"):
                _make_client().register_live_agent(
                    LiveAgentRegistrationInput(public_key_jwk=key), "live-1"
                )

    @pytest.mark.parametrize(
        "key",
        [
            _live_key(kty="EC", crv="P-256", alg="ES256"),
            _live_key(x="abc"),
            _live_key(d="private"),
            JWK(
                kty="OKP",
                alg="EdDSA",
                _raw={"keys": [{"kty": "OKP", "crv": "Ed25519", "d": "private"}]},
            ),
        ],
    )
    def test_live_registration_rejects_non_ed25519_malformed_or_private_keys(self, key):
        client = _make_client()
        with patch.object(client, "_post") as post:
            with pytest.raises(ArgumentError, match="public|Ed25519"):
                client.register_live_agent(
                    LiveAgentRegistrationInput(public_key_jwk=key), "live-1"
                )
        post.assert_not_called()

    def test_standard_registration_rejects_private_key_material(self):
        key = _live_key(d="private")
        client = _make_client()
        with patch.object(client, "_post") as post:
            with pytest.raises(ArgumentError, match="private JWK"):
                client.register_agent(
                    AgentRegistrationInput(zone_id="zone-1", public_key_jwk=key)
                )
        post.assert_not_called()

    def test_live_registration_rejects_sandbox_environment(self):
        with pytest.raises(ArgumentError, match="production"):
            _make_client().register_live_agent(
                LiveAgentRegistrationInput(
                    public_key_jwk=_live_key(), environment="sandbox"
                ),
                "live-1",
            )

    def test_returns_publication_snapshot_from_create_response(self):
        publication_config = {
            "publish_profile": "dnsid-draft-01",
            "governance_id": "example.com",
            "ku_url": f"https://{_DOMAIN}/jwks.json",
            "ek_url": "https://example.com/entity.jwks.json",
            "log_ref": f"c2sp-tlog:testnet:https://log.example#{_DOMAIN}",
            "status_url": f"https://registry.example.com/api/v1/agent/{_DOMAIN}/status",
        }
        response = {**_REGISTER_RESPONSE, "publication_config": publication_config}
        detail = _registration()
        ctx, _ = _post_capturing(response)
        with ctx, patch.object(RegistryClient, "get_registration", return_value=detail):
            result = _make_client().register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="production")
            )

        assert result.publication_config is not None
        assert result.publication_config.log_ref == publication_config["log_ref"]

    def test_preserves_oidc_issuer_url_from_create_response(self):
        response = {
            **_REGISTER_RESPONSE,
            "oidc_issuer_url": "https://issuer.example.com/live",
        }
        ctx, _ = _post_capturing(response)
        with ctx, patch.object(RegistryClient, "get_registration", return_value=_registration()):
            result = _make_client().register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="production")
            )

        assert isinstance(result, AgentRegistration)
        assert result.oidc_issuer_url == "https://issuer.example.com/live"

    def test_omitted_environment_defaults_to_self_managed_production(self):
        ctx, captured = _post_capturing(_REGISTER_RESPONSE)
        with ctx, patch.object(RegistryClient, "get_registration", return_value=_registration()):
            _make_client().register_agent(AgentRegistrationInput(domain=_DOMAIN))
        assert captured[0]["body"]["domain"] == _DOMAIN
        assert captured[0]["body"]["environment"] == "production"

    def test_omitted_environment_without_domain_is_rejected(self):
        with pytest.raises(ArgumentError, match="requires a domain"):
            _make_client().register_agent(AgentRegistrationInput())

    def test_self_managed_sends_explicit_production_environment(self):
        ctx, captured = _post_capturing(_REGISTER_RESPONSE)
        with ctx, patch.object(RegistryClient, "get_registration", return_value=_registration()):
            _make_client().register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="production")
            )
        assert captured[0]["body"]["domain"] == _DOMAIN
        assert captured[0]["body"]["environment"] == "production"

    def test_sandbox_environment_is_rejected(self):
        with pytest.raises(ArgumentError, match='must be "production"'):
            _make_client().register_agent(AgentRegistrationInput(environment="sandbox"))

    def test_managed_without_zone_is_rejected(self):
        with pytest.raises(ArgumentError, match="requires zone_id"):
            _make_client().register_agent(
                AgentRegistrationInput(managed=True, public_key_jwk=_live_key())
            )

    def test_server_assigned_managed_omits_domain(self):
        key = _live_key()
        ctx, captured = _post_capturing(_REGISTER_RESPONSE)
        with ctx, patch.object(
            RegistryClient, "get_registration", return_value=_registration(authority="registry")
        ):
            _make_client().register_agent(
                AgentRegistrationInput(managed=True, zone_id="zone-1", public_key_jwk=key)
            )
        assert "domain" not in captured[0]["body"]
        assert captured[0]["body"]["managed"] is True
        assert captured[0]["body"]["zone_id"] == "zone-1"
        assert captured[0]["body"]["environment"] == "production"

    def test_managed_rejects_client_supplied_domain(self):
        key = _live_key()
        with pytest.raises(ArgumentError, match="cannot both be supplied"):
            _make_client().register_agent(
                AgentRegistrationInput(
                    domain=_DOMAIN, managed=True, zone_id="zone-1", public_key_jwk=key
                )
            )

    def test_self_managed_rejects_sandbox_environment(self):
        with pytest.raises(ArgumentError, match='must be "production"'):
            _make_client().register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="sandbox")
            )

    def test_zone_managed_defaults_to_production_environment(self):
        ctx, captured = _post_capturing(_REGISTER_RESPONSE)
        with ctx, patch.object(
            RegistryClient,
            "get_registration",
            return_value=_registration(authority="registry"),
        ):
            _make_client().register_agent(AgentRegistrationInput(zone_id="zone-1"))

        assert captured[0]["body"]["zone_id"] == "zone-1"
        assert captured[0]["body"]["environment"] == "production"

    def test_zone_managed_accepts_production_environment(self):
        ctx, captured = _post_capturing(_REGISTER_RESPONSE)
        with ctx, patch.object(
            RegistryClient,
            "get_registration",
            return_value=_registration(authority="registry"),
        ):
            _make_client().register_agent(
                AgentRegistrationInput(zone_id="zone-1", environment="production")
            )

        assert captured[0]["body"]["environment"] == "production"

    @pytest.mark.parametrize("environment", ["staging", "development", "prod"])
    def test_rejects_unknown_explicit_environment(self, environment):
        with pytest.raises(ArgumentError, match="environment must be"):
            _make_client().register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment=environment)
            )

    @pytest.mark.parametrize(
        ("reason", "wire_value"),
        [
            (RegistryRevocationReason.OWNER_REQUEST, "owner_request"),
            (RegistryRevocationReason.KEY_COMPROMISE, "key_compromise"),
        ],
    )
    def test_revoke_agent_sends_typed_reason_to_registry(self, reason, wire_value):
        ctx, captured = _post_capturing(
            {"id": "event-1", "status": "REVOKED", "status_note": "done"}
        )
        with ctx:
            result = _make_client().revoke_agent(_DOMAIN, "agent-123", reason)

        assert captured[0]["path"] == f"/api/v1/agent/{_DOMAIN}/revoke"
        assert captured[0]["body"] == {
            "agent_id": "agent-123",
            "reason": wire_value,
        }
        assert result.id == "event-1"
        assert result.state == "REVOKED"
        assert result.status_note == "done"

    def test_retire_agent_posts_immutable_agent_id(self):
        ctx, captured = _post_capturing({"id": "agent-123", "status": "RETIRED"})
        with ctx:
            result = _make_client().retire_agent(_DOMAIN, "agent-123")

        assert captured[0]["path"] == f"/api/v1/agent/{_DOMAIN}/retire"
        assert captured[0]["body"] == {"agent_id": "agent-123"}
        assert result.id == "agent-123"
        assert result.state == "RETIRED"

    def test_revoke_agent_rejects_protocol_reason(self):
        with pytest.raises(ArgumentError, match="RegistryRevocationReason"):
            _make_client().revoke_agent(  # type: ignore[arg-type]
                _DOMAIN, "agent-123", RevocationReason.KEY_COMPROMISE
            )

    def test_registration_idempotency_key_is_forwarded(self):
        ctx, captured = _post_capturing(_REGISTER_RESPONSE)
        with ctx, patch.object(RegistryClient, "get_registration", return_value=_registration()):
            _make_client().register_agent(
                AgentRegistrationInput(
                    domain=_DOMAIN,
                    environment="production",
                    idempotency_key="create-1",
                )
            )
        assert captured[0]["headers"] == {"Idempotency-Key": "create-1"}


class TestPrepareIssuance:
    @staticmethod
    def _response(
        entry: bytes = b'{"kind":"dnsid.lifecycle"}',
        log_reference: str | None = "c2sp-tlog:testnet:https://log.example#agent.example.com",
    ) -> MagicMock:
        response = MagicMock()
        response.status_code = 200
        response.is_success = True
        response.content = entry
        response.headers = (
            {"DNSID-Log-Reference": log_reference} if log_reference is not None else {}
        )
        return response

    def test_posts_no_body_and_returns_exact_untrusted_transport_result(self):
        entry = b' {"signed":"bytes are not reserialized"}\n'
        response = self._response(entry)
        captured: dict = {}

        def fake_post(url, headers=None, timeout=None):
            captured.update(url=url, headers=headers, timeout=timeout)
            return response

        with patch("httpx.post", fake_post):
            result = _make_client().prepare_issuance(_DOMAIN, "issuance-1")

        assert isinstance(result, PreparedRegistryEvent)
        assert result.entry_bytes == entry
        assert result.log_reference == (
            "c2sp-tlog:testnet:https://log.example#agent.example.com"
        )
        assert captured["url"].endswith(
            f"/api/v1/agent/{_DOMAIN}/tlog/issuance/prepare"
        )
        assert captured["headers"] == {
            "Authorization": f"Bearer {_FAKE_API_KEY}",
            "Content-Type": "application/json",
            "Idempotency-Key": "issuance-1",
        }

    def test_domain_is_path_escaped(self):
        response = self._response()
        with patch("httpx.post", return_value=response) as post:
            _make_client().prepare_issuance("agent+dev.example.com", "issuance-1")
        assert "/agent/agent%2Bdev.example.com/tlog/issuance/prepare" in post.call_args.args[0]

    @pytest.mark.parametrize(
        "key",
        ["", " leading", "trailing ", "x" * 201, "é" * 101],
    )
    def test_rejects_product_invalid_idempotency_keys_before_transport(self, key):
        with patch("httpx.post") as post:
            with pytest.raises(ArgumentError, match="1 to 200 bytes"):
                _make_client().prepare_issuance(_DOMAIN, key)
        post.assert_not_called()


class TestPreparedEventTransport:
    @staticmethod
    def _response(
        entry: bytes = b'{"prepared":"exact bytes"}',
        log_reference: str | None = (
            "c2sp-tlog:testnet:https://log.example#instance_AAAAAAAAAAAAAAAAAAAAAA"
        ),
    ) -> MagicMock:
        response = MagicMock()
        response.status_code = 200
        response.is_success = True
        response.content = entry
        response.headers = (
            {"DNSID-Log-Reference": log_reference}
            if log_reference is not None
            else {}
        )
        return response

    def test_submit_uses_the_same_idempotency_validation(self):
        with pytest.raises(ArgumentError, match="1 to 200 bytes"):
            _make_client().submit_prepared_event(_DOMAIN, b"entry", " trailing")

    def test_missing_log_reference_is_rejected_without_parsing_body(self):
        with patch("httpx.post", return_value=self._response(b"not-json", None)):
            with pytest.raises(VerificationError, match="DNSID-Log-Reference"):
                _make_client().prepare_issuance(_DOMAIN, "issuance-1")

    def test_http_failure_does_not_surface_response_body(self):
        response = self._response(b"secret response body")
        response.status_code = 500
        response.is_success = False
        with patch("httpx.post", return_value=response):
            with pytest.raises(VerificationError) as exc_info:
                _make_client().prepare_issuance(_DOMAIN, "issuance-1")
        assert "secret response body" not in str(exc_info.value)
        assert exc_info.value.transient


class TestGetAgentStatusDnsPublished:
    def _status_for(self, body: dict):
        resp = _http_response(200, json_body=body)
        with patch("httpx.get", return_value=resp):
            return _make_client().get_agent_status(_DOMAIN)

    def test_ready_with_dns_published_false_is_ready_for_publication(self):
        # The registry can reach READY before the agent publishes its TXT
        # record; dns_published=false means publication is still pending.
        status = self._status_for({"status": "READY", "dns_published": False})
        assert status.ready_for_publication
        assert not status.published

    def test_ready_with_dns_published_true_is_published(self):
        status = self._status_for({"status": "READY", "dns_published": True})
        assert status.published
        assert not status.ready_for_publication

    def test_ready_without_dns_published_falls_back_to_status(self):
        status = self._status_for({"status": "READY"})
        assert not status.published
        assert not status.ready_for_publication

    def test_protocol_status_is_only_present_when_complete(self):
        status = self._status_for(
            {
                "status": "READY",
                "dns_published": True,
                "protocolStatus": {
                    "state": "ACTIVE",
                    "lastTransitionAt": "2026-01-01T00:00:00Z",
                },
            }
        )
        assert status.protocol_status is not None
        assert status.protocol_status.state == "ACTIVE"
        assert status.protocol_status.last_transition_at == _NOW

    def test_does_not_fabricate_protocol_status_or_transition_time(self):
        status = self._status_for({"status": "READY", "updated_at": "not-a-time"})
        assert status.protocol_status is None

    def test_retired_is_terminal(self):
        status = self._status_for({"status": "RETIRED", "dns_published": False})
        assert status.terminal


class TestGetRegistration:
    def test_parses_current_product_authority_and_status_namespaces(self):
        body = {
            "domain": _DOMAIN,
            "managed": "dnsid",
            "status": "READY",
            "serverStatus": "READY",
            "dns_published": True,
            "protocolStatus": {
                "state": "ACTIVE",
                "lastTransitionAt": "2026-01-01T00:00:00Z",
            },
        }
        with patch("httpx.get", return_value=_http_response(200, json_body=body)):
            result = _make_client().get_registration(_DOMAIN)
        assert result is not None
        assert result.publication_authority == "registry"
        assert result.registry_status == "READY"
        assert result.dns_published is True
        assert result.protocol_status is not None
        assert result.protocol_status.state == "ACTIVE"

    def test_exposes_authoritative_publication_config(self):
        publication_config = {
            "publish_profile": "dnsid-draft-01",
            "governance_id": "example.com",
            "ku_url": f"https://{_DOMAIN}/jwks.json",
            "ek_url": "https://example.com/entity.jwks.json",
            "log_ref": f"c2sp-tlog:testnet:https://log.example#{_DOMAIN}",
            "status_url": f"https://registry.example.com/api/v1/agent/{_DOMAIN}/status",
            "capabilities_url": f"https://{_DOMAIN}/agent.json",
            "max_key_age": "30d",
        }
        body = {
            "domain": _DOMAIN,
            "managed": "self",
            "serverStatus": "READY",
            "publication_config": publication_config,
        }
        with patch("httpx.get", return_value=_http_response(200, json_body=body)):
            result = _make_client().get_registration(_DOMAIN)

        assert result is not None
        assert result.publication_config is not None
        assert result.publication_config.publish_profile == "dnsid-draft-01"
        assert result.publication_config.log_ref == publication_config["log_ref"]
        assert result.publication_config.max_key_age == "30d"

    def test_rejects_incomplete_publication_config(self):
        body = {
            "domain": _DOMAIN,
            "managed": "self",
            "serverStatus": "READY",
            "publication_config": {"publish_profile": "dnsid-draft-01"},
        }
        with patch("httpx.get", return_value=_http_response(200, json_body=body)):
            with pytest.raises(ValidationError, match="publication_config"):
                _make_client().get_registration(_DOMAIN)

    def test_rejects_missing_authority_instead_of_guessing(self):
        body = {"domain": _DOMAIN, "status": "READY", "dns_published": True}
        with patch("httpx.get", return_value=_http_response(200, json_body=body)):
            with pytest.raises(ValidationError, match="publication authority"):
                _make_client().get_registration(_DOMAIN)

    def test_rejects_non_string_oidc_issuer(self):
        body = {
            "domain": _DOMAIN,
            "managed": "self",
            "serverStatus": "READY",
            "oidc_issuer_url": 123,
        }
        with patch("httpx.get", return_value=_http_response(200, json_body=body)):
            with pytest.raises(VerificationError, match="oidc_issuer_url"):
                _make_client().get_registration(_DOMAIN)


class TestRegistryAgentStatusPublicationConfig:
    def test_exposes_authoritative_publication_config(self):
        publication_config = {
            "publish_profile": "dnsid-draft-01",
            "governance_id": "example.com",
            "ku_url": f"https://{_DOMAIN}/jwks.json",
            "ek_url": "https://example.com/entity.jwks.json",
            "log_ref": f"c2sp-tlog:testnet:https://log.example#{_DOMAIN}",
            "status_url": f"https://registry.example.com/api/v1/agent/{_DOMAIN}/status",
        }
        body = {
            "status": "READY",
            "managed": "self",
            "publication_config": publication_config,
        }
        with patch("httpx.get", return_value=_http_response(200, json_body=body)):
            result = _make_client().get_agent_status(_DOMAIN)

        assert result is not None
        assert result.publication_config is not None
        assert result.publication_config.ek_url == publication_config["ek_url"]

class TestPublishedRecordModel:
    def test_keeps_publication_status_separate_without_fabricating_protocol_status(self):
        response = {
            "fqdn": _DOMAIN,
            "status": "publishing",
            "records": [
                {
                    "name": f"_dnsid.{_DOMAIN}",
                    "value": "v=dnsid-draft-01;...",
                    "ttl": 300,
                }
            ],
        }
        ctx, _ = _post_capturing(response)
        with ctx:
            result = _make_client().publish_signature(_DOMAIN, "c2ln")
        assert result.publication_status == "publishing"
        assert result.protocol_status is None
        assert not hasattr(result, "status")

    def test_accepts_complete_authoritative_protocol_status_when_supplied(self):
        response = {
            "fqdn": _DOMAIN,
            "status": "ready_for_publication",
            "records": [],
            "protocolStatus": {
                "state": "ACTIVE",
                "lastTransitionAt": "2026-01-01T00:00:00Z",
            },
        }
        ctx, _ = _post_capturing(response)
        with ctx:
            result = _make_client().publish_signature(_DOMAIN, "c2ln")
        assert result.protocol_status is not None
        assert result.protocol_status.state == "ACTIVE"


class TestLiveProof:
    def test_submits_proof_with_matching_idempotency_key(self):
        key = _live_key()
        ctx, captured = _post_capturing(
            {"request_id": "live-1", "agent_id": "agent-123", "status": "provider_deferred"}
        )
        with ctx:
            result = _make_client().submit_live_proof(
                _DOMAIN,
                LiveProofRequest(
                    request_id="live-1",
                    challenge="challenge",
                    public_key_jwk=key,
                    signature="c2ln",
                ),
            )

        assert captured[0] == {
            "path": f"/api/v1/agent/{_DOMAIN}/proof",
            "body": {
                "request_id": "live-1",
                "challenge": "challenge",
                "public_key": key.to_dict(),
                "signature": "c2ln",
            },
            "headers": {"Idempotency-Key": "live-1"},
        }
        assert result.status == "provider_deferred"

    def test_reissues_proof_with_matching_key_and_idempotency_key(self):
        key = _live_key()
        response = _live_challenge_response(
            key, domain=_DOMAIN, challenge="replacement"
        )
        ctx, captured = _post_capturing(response)
        with ctx:
            result = _make_client().reissue_live_proof(
                _DOMAIN,
                LiveProofReissueRequest(request_id="live-1", public_key_jwk=key),
            )

        assert captured[0] == {
            "path": f"/api/v1/agent/{_DOMAIN}/proof/reissue",
            "body": {"request_id": "live-1"},
            "headers": {"Idempotency-Key": "live-1"},
        }
        assert "public_key" not in captured[0]["body"]
        assert result.challenge == "replacement"
        assert result.domain == _DOMAIN
        assert result.challenge_transcript.nonce == "replacement"

    def test_reissue_rejects_transcript_for_another_key(self):
        other_key = _live_key()
        other_key._raw["x"] = b64url_encode(bytes(range(1, 33)))
        response = _live_challenge_response(
            other_key, domain=_DOMAIN, challenge="replacement"
        )
        ctx, _ = _post_capturing(response)
        with ctx, pytest.raises(VerificationError, match="challenge transcript"):
            _make_client().reissue_live_proof(
                _DOMAIN,
                LiveProofReissueRequest(
                    request_id="live-1", public_key_jwk=_live_key()
                ),
            )

    @pytest.mark.parametrize("key", [_live_key(x="abc"), _live_key(d="private")])
    def test_reissue_rejects_invalid_or_private_key_before_post(self, key):
        client = _make_client()
        with patch.object(client, "_post") as post:
            with pytest.raises(ArgumentError, match="public|Ed25519"):
                client.reissue_live_proof(
                    _DOMAIN,
                    LiveProofReissueRequest(
                        request_id="live-1", public_key_jwk=key
                    ),
                )
        post.assert_not_called()

    def test_proof_rejects_private_key_material(self):
        client = _make_client()
        request = LiveProofRequest(
            request_id="live-1",
            challenge="challenge",
            public_key_jwk=_live_key(d="private"),
            signature="c2ln",
        )
        with patch.object(client, "_post") as post:
            with pytest.raises(ArgumentError, match="private JWK"):
                client.submit_live_proof(_DOMAIN, request)
        post.assert_not_called()


class TestExactRegistrationStatuses:
    @pytest.mark.parametrize(
        ("status", "call", "expected"),
        [
            (
                202,
                lambda client: client.register_agent(
                    AgentRegistrationInput(domain=_DOMAIN, environment="production")
                ),
                201,
            ),
            (
                200,
                lambda client: client.register_live_agent(
                    LiveAgentRegistrationInput(public_key_jwk=_live_key()), "live-1"
                ),
                202,
            ),
            (
                200,
                lambda client: client.submit_live_proof(
                    _DOMAIN,
                    LiveProofRequest(
                        request_id="live-1",
                        challenge="challenge",
                        public_key_jwk=_live_key(),
                        signature="c2ln",
                    ),
                ),
                202,
            ),
            (
                200,
                lambda client: client.reissue_live_proof(
                    _DOMAIN,
                    LiveProofReissueRequest(
                        request_id="live-1", public_key_jwk=_live_key()
                    ),
                ),
                202,
            ),
        ],
    )
    def test_rejects_unexpected_success_status(self, status, call, expected):
        with patch("httpx.post", return_value=_http_response(status, json_body={})):
            with pytest.raises(VerificationError, match=f"expected HTTP {expected}"):
                call(_make_client())


class TestVerifyAgent:
    def test_fqdn_falls_back_to_domain_when_omitted(self):
        # The current registry omits fqdn from the verify response; it is
        # optional and falls back to the requested domain.
        ctx, _ = _post_capturing({"status": "VERIFICATION"})
        with ctx, patch.object(RegistryClient, "get_registration", return_value=_registration(registry_status="VERIFICATION")):
            result = _make_client().verify_agent(_DOMAIN)
        assert result.domain == _DOMAIN
        assert result.registry_status == "VERIFICATION"

    def test_fqdn_used_when_present(self):
        ctx, _ = _post_capturing({"fqdn": "other.example.com", "status": "VERIFICATION"})
        registration = AgentRegistration(
            domain="other.example.com",
            publication_authority="client",
            registry_status="VERIFICATION",
            registry_url="https://registry.example.com",
        )
        with ctx, patch.object(RegistryClient, "get_registration", return_value=registration):
            result = _make_client().verify_agent(_DOMAIN)
        assert result.domain == "other.example.com"


_CHALLENGE_RESPONSE = {"id": "ag-123", "status": "VERIFICATION"}


def _http_response(status_code: int = 202, json_body: dict | None = None) -> MagicMock:
    """Build a mock httpx response; json_body=None simulates an empty 202 body."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.is_success = 200 <= status_code < 300
    if json_body is None:
        resp.json.side_effect = ValueError("empty body")
    else:
        resp.json.return_value = json_body
    return resp


class TestSubmitChallengeSignature:
    def _submit(self, resp: MagicMock, signature: bytes | str = "c2lnbmF0dXJl"):
        with patch("httpx.post", return_value=resp) as mock_post:
            result = _make_client().submit_challenge_signature(_DOMAIN, "bm9uY2U", signature)
        return result, mock_post

    def test_posts_nonce_and_signature_to_challenge_endpoint(self):
        _, mock_post = self._submit(_http_response(json_body=_CHALLENGE_RESPONSE))
        url = mock_post.call_args.args[0]
        assert url.endswith(f"/api/v1/agent/{_DOMAIN}/challenge")
        assert mock_post.call_args.kwargs["json"] == {
            "nonce": "bm9uY2U",
            "signature": "c2lnbmF0dXJl",
        }

    def test_bytes_signature_is_base64url_encoded(self):
        _, mock_post = self._submit(
            _http_response(json_body=_CHALLENGE_RESPONSE), signature=b"\xfb\xef\xbe"
        )
        # base64url alphabet, unpadded — not standard base64 ("++++" / trailing "=").
        assert mock_post.call_args.kwargs["json"]["signature"] == "----"

    def test_returns_lifecycle_result_with_mapped_state(self):
        result, _ = self._submit(_http_response(json_body=_CHALLENGE_RESPONSE))
        assert result.id == "ag-123"
        assert result.state == "VERIFICATION"
        assert result.raw == _CHALLENGE_RESPONSE

    def test_status_note_captured_when_present(self):
        result, _ = self._submit(
            _http_response(json_body={**_CHALLENGE_RESPONSE, "status_note": "checking DNS"})
        )
        assert result.status_note == "checking DNS"

    def test_empty_202_body_returns_minimal_result(self):
        # The registry may accept the challenge with 202 and no body.
        result, _ = self._submit(_http_response(202, json_body=None))
        assert result.id == ""
        assert result.state == ""
        assert result.raw == {}

    def test_http_error_raises(self):
        with pytest.raises(VerificationError, match="HTTP 409"):
            self._submit(_http_response(409, json_body=None))


# ---------------------------------------------------------------------------
# Helpers for wait_for_status tests
# ---------------------------------------------------------------------------

_NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)


def _status(
    registry_status: str,
    *,
    published: bool = False,
    failed: bool = False,
    terminal: bool = False,
) -> RegistryAgentStatus:
    return RegistryAgentStatus(
        registry_status=registry_status,
        dns_published=published,
        protocol_status=None,
        ready_for_publication=False,
        published=published,
        failed=failed,
        terminal=terminal,
    )


class TestWaitForStatus:
    def test_returns_immediately_when_already_published(self):
        client = _make_client()
        active = _status("ACTIVE", published=True)
        with patch.object(client, "get_agent_status", return_value=active):
            with patch("time.sleep") as mock_sleep:
                result = client.wait_for_status(_DOMAIN)
        assert result.registry_status == "ACTIVE"
        mock_sleep.assert_not_called()

    def test_polls_until_published(self):
        client = _make_client()
        pending = _status("PENDING")
        active = _status("ACTIVE", published=True)
        with patch.object(client, "get_agent_status", side_effect=[pending, pending, active]):
            with patch("time.sleep"):
                result = client.wait_for_status(_DOMAIN, interval=0.0)
        assert result.registry_status == "ACTIVE"

    def test_returns_on_target_state(self):
        client = _make_client()
        pending = _status("PENDING")
        verified = _status("VERIFIED")
        with patch.object(client, "get_agent_status", side_effect=[pending, verified]):
            with patch("time.sleep"):
                result = client.wait_for_status(_DOMAIN, target_state="VERIFIED", interval=0.0)
        assert result.registry_status == "VERIFIED"

    def test_raises_on_failed_state_before_target(self):
        client = _make_client()
        failed = _status("ERROR", failed=True)
        with patch.object(client, "get_agent_status", return_value=failed):
            with patch("time.sleep"):
                with pytest.raises(VerificationError, match="ERROR"):
                    client.wait_for_status(_DOMAIN, target_state="VERIFIED")

    def test_returns_retired_terminal_state_without_target(self):
        client = _make_client()
        retired = _status("RETIRED", terminal=True)
        with patch.object(client, "get_agent_status", return_value=retired):
            with patch("time.sleep") as sleep:
                result = client.wait_for_status(_DOMAIN)
        assert result.registry_status == "RETIRED"
        sleep.assert_not_called()

    def test_raises_when_agent_not_found(self):
        client = _make_client()
        with patch.object(client, "get_agent_status", return_value=None):
            with pytest.raises(VerificationError, match="not found"):
                client.wait_for_status(_DOMAIN)

    def test_raises_on_timeout(self):
        client = _make_client()
        pending = _status("PENDING")
        # monotonic returns deadline-exceeded on the second call
        times = iter([0.0, 200.0])
        with patch.object(client, "get_agent_status", return_value=pending):
            with patch("time.sleep"):
                with patch("time.monotonic", side_effect=times):
                    with pytest.raises(VerificationError, match="Timed out"):
                        client.wait_for_status(_DOMAIN, timeout=100.0)


class TestAsyncWaitForStatus:
    @pytest.mark.asyncio
    async def test_returns_when_published(self):
        client = _make_client()
        active = _status("ACTIVE", published=True)
        with patch.object(client, "get_agent_status", return_value=active):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await client.async_wait_for_status(_DOMAIN)
        assert result.registry_status == "ACTIVE"

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self):
        client = _make_client()
        pending = _status("PENDING")
        times = iter([0.0, 200.0])
        with patch.object(client, "get_agent_status", return_value=pending):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with patch("time.monotonic", side_effect=times):
                    with pytest.raises(VerificationError, match="Timed out"):
                        await client.async_wait_for_status(_DOMAIN, timeout=100.0)

    @pytest.mark.asyncio
    async def test_polls_until_target_state(self):
        client = _make_client()
        pending = _status("PENDING")
        verified = _status("VERIFIED")
        with patch.object(client, "get_agent_status", side_effect=[pending, verified]):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await client.async_wait_for_status(
                    _DOMAIN, target_state="VERIFIED", interval=0.0
                )
        assert result.registry_status == "VERIFIED"


class TestRegistryClientDefaultBaseUrl:
    """RegistryClient defaults base_url to the local registry."""

    def test_defaults_to_local_registry(self):
        client = RegistryClient()
        assert client._base_url == "http://127.0.0.1:7755"
        assert client._api_key is None

    def test_accepts_explicit_base_url(self):
        client = RegistryClient("https://custom.example.com/")
        assert client._base_url == "https://custom.example.com"

    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
    def test_accepts_loopback_http_for_local_testnets(self, host):
        client = RegistryClient(f"http://{host}:7755/")
        assert client._base_url == f"http://{host}:7755"

    def test_empty_string_falls_back_to_default(self):
        client = RegistryClient("")
        assert client._base_url == "http://127.0.0.1:7755"

    def test_connection_refused_on_loopback_hints_at_local_registry(self):
        import httpx

        client = RegistryClient(api_key=_FAKE_API_KEY)
        with patch("httpx.get", side_effect=httpx.ConnectError("Connection refused")):
            with pytest.raises(
                Exception,
                match=r"no registry at 127.0.0.1:7755; run `dnsid local up` or set DNSID_REGISTRY_URL",
            ) as exc_info:
                client.get_agent_status(_DOMAIN)
        assert _FAKE_API_KEY not in str(exc_info.value)

    def test_connection_refused_on_hosted_registry_keeps_transport_error(self):
        import httpx

        client = RegistryClient("https://registry.example.com")
        with patch("httpx.get", side_effect=httpx.ConnectError("Connection refused")):
            with pytest.raises(Exception, match="Connection refused"):
                client.get_agent_status(_DOMAIN)

    @pytest.mark.parametrize(
        "base_url",
        [
            "http://registry.example.com",
            "https://user:secret@registry.example.com",
            "https://registry.example.com?token=secret",
            "https://registry.example.com#fragment",
        ],
    )
    def test_rejects_unsafe_base_url(self, base_url):
        with pytest.raises(ValueError):
            RegistryClient(base_url)

    def test_concrete_client_implements_full_abstract_rotation_contract(self):
        assert not RegistryClient.__abstractmethods__
        assert {
            "prepare_key_rotation",
            "submit_prepared_event",
        }.issubset(AbstractRegistryClient.__abstractmethods__)


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload
        self.is_success = 200 <= status_code < 300
        self.text = ""

    def json(self):
        return self._payload


# Every mutation entry point, exercised without credentials. A regression that
# drops the auth preflight from any one of these fails the parametrized tests below.
_MUTATION_CALLS = [
    lambda c: c.register_agent(
        AgentRegistrationInput(domain=_DOMAIN, environment="production")
    ),
    lambda c: c.register_live_agent(
        LiveAgentRegistrationInput(public_key_jwk=_live_key()), "live-1"
    ),
    lambda c: c.verify_agent(_DOMAIN),
    lambda c: c.revoke_agent(
        _DOMAIN, "agent-123", RegistryRevocationReason.KEY_COMPROMISE
    ),
    lambda c: c.retire_agent(_DOMAIN, "agent-123"),
    lambda c: c.submit_challenge_signature(_DOMAIN, "bm9uY2U", "c2ln"),
    lambda c: c.submit_live_proof(
        _DOMAIN,
        LiveProofRequest(
            request_id="live-1",
            challenge="challenge",
            public_key_jwk=_live_key(),
            signature="c2ln",
        ),
    ),
    lambda c: c.reissue_live_proof(
        _DOMAIN,
        LiveProofReissueRequest(request_id="live-1", public_key_jwk=_live_key()),
    ),
    lambda c: c.unregister_agent(_DOMAIN),
    lambda c: c.publish_signature(_DOMAIN, "EdDSA:sig"),
    lambda c: c.canonical_record_content(_DOMAIN, "kid-1"),
    lambda c: c.prepare_issuance(_DOMAIN, "issuance-1"),
]


class TestAuthentication:
    """Credential header handling on mutation and legacy status paths."""

    def test_register_agent_sends_bearer_header(self):
        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)
        captured: dict = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured["headers"] = headers
            return _FakeResponse(201, _REGISTER_RESPONSE)

        with patch("httpx.post", fake_post), patch.object(
            client, "get_registration", return_value=_registration()
        ):
            client.register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="production")
            )

        assert captured["headers"]["Authorization"] == f"Bearer {_FAKE_API_KEY}"

    def test_unregister_agent_sends_bearer_header(self):
        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)
        captured: dict = {}

        def fake_request(method, url, headers=None, timeout=None):
            captured["headers"] = headers
            return _FakeResponse(200, {})

        with patch("httpx.request", fake_request):
            client.unregister_agent(_DOMAIN)

        assert captured["headers"]["Authorization"] == f"Bearer {_FAKE_API_KEY}"

    @pytest.mark.parametrize("call", _MUTATION_CALLS)
    def test_mutation_without_credentials_raises(self, call):
        client = RegistryClient("https://registry.example.com")
        with pytest.raises(ArgumentError, match="requires registry credentials"):
            call(client)

    @pytest.mark.parametrize("call", _MUTATION_CALLS)
    def test_mutation_without_credentials_makes_no_request(self, call):
        client = RegistryClient("https://registry.example.com")
        # Patch every HTTP verb a mutation path could reach (post/request/get).
        with patch("httpx.post") as mock_post, patch("httpx.request") as mock_request:
            with pytest.raises(ArgumentError):
                call(client)
        mock_post.assert_not_called()
        mock_request.assert_not_called()

    @pytest.mark.parametrize("reader", ["get_status", "get_agent_status"])
    def test_legacy_status_read_works_without_credentials(self, reader):
        client = RegistryClient("https://registry.example.com")
        captured: dict = {}

        def fake_get(url, headers=None, timeout=None):
            captured["headers"] = headers
            return _FakeResponse(200, {"status": "ACTIVE"})

        with patch("httpx.get", fake_get):
            assert getattr(client, reader)(_DOMAIN) is not None

        assert "Authorization" not in captured["headers"]

    @pytest.mark.parametrize("reader", ["get_status", "get_agent_status"])
    def test_authenticated_read_sends_header(self, reader):
        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)
        captured: dict = {}

        def fake_get(url, headers=None, timeout=None):
            captured["headers"] = headers
            return _FakeResponse(200, {"status": "ACTIVE"})

        with patch("httpx.get", fake_get):
            getattr(client, reader)(_DOMAIN)

        assert captured["headers"]["Authorization"] == f"Bearer {_FAKE_API_KEY}"

    def test_credential_not_leaked_in_repr(self):
        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)
        assert _FAKE_API_KEY not in repr(client)
        assert _FAKE_API_KEY not in str(client)
        assert "authenticated=True" in repr(client)

    def test_whitespace_only_credential_treated_as_missing(self):
        client = RegistryClient("https://registry.example.com", api_key="   ")
        assert "authenticated=False" in repr(client)
        with patch("httpx.post") as mock_post:
            with pytest.raises(ArgumentError, match="requires registry credentials"):
                client.register_agent(
                    AgentRegistrationInput(domain=_DOMAIN, environment="production")
                )
        mock_post.assert_not_called()

    @pytest.mark.parametrize(
        "bad", ["a\rb", "a\nb", "a\x00b", "tok\r\nInjected: x", "tok\x7fx", "a\x01b"]
    )
    def test_control_characters_rejected(self, bad):
        # Malformed credentials must be caught in __init__, before HTTPX can raise
        # a LocalProtocolError echoing the illegal header value.
        with pytest.raises(ValueError, match="illegal control characters"):
            RegistryClient("https://registry.example.com", api_key=f"key{bad}")

    def test_error_body_not_leaked_in_exception(self):
        """An error body echoing the Bearer token must not reach the exception message."""
        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)

        def fake_post(url, json=None, headers=None, timeout=None):
            resp = _FakeResponse(400, {})
            resp.text = f"bad request: Authorization: Bearer {_FAKE_API_KEY}"
            return resp

        with patch("httpx.post", fake_post):
            with pytest.raises(VerificationError) as excinfo:
                client.register_agent(
                    AgentRegistrationInput(domain=_DOMAIN, environment="production")
                )
        assert _FAKE_API_KEY not in str(excinfo.value)

    def test_transport_error_text_not_leaked_in_exception(self):
        """An HTTPX transport error echoing the Bearer credential must be redacted.

        Defense in depth for the LocalProtocolError/SSL path: even if HTTPX raises
        with the illegal header value in the text, the credential must not survive
        into the VerificationError message.
        """
        import httpx

        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)

        def boom(url, json=None, headers=None, timeout=None):
            raise httpx.LocalProtocolError(f"Illegal header value b'Bearer {_FAKE_API_KEY}'")

        with patch("httpx.post", boom):
            with pytest.raises(VerificationError) as excinfo:
                client.register_agent(
                    AgentRegistrationInput(domain=_DOMAIN, environment="production")
                )
        assert _FAKE_API_KEY not in str(excinfo.value)
        assert _FAKE_API_KEY not in repr(excinfo.value)
        # Exception chain must not expose the original transport error either.
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    def test_connect_error_does_not_leak_bearer_token(self):
        """A ConnectError from HTTPX transport must not include Bearer token.

        This covers the case where the transport layer itself (e.g. DNS resolution,
        TCP connect) fails and HTTPX includes URL/header metadata in the error.
        """
        import httpx

        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)

        def boom(url, json=None, headers=None, timeout=None):
            raise httpx.ConnectError(
                f"Failed to connect with headers Authorization: Bearer {_FAKE_API_KEY}"
            )

        with patch("httpx.post", boom):
            with pytest.raises(VerificationError) as excinfo:
                client.register_agent(
                    AgentRegistrationInput(domain=_DOMAIN, environment="production")
                )
        # Message must be sanitised.
        assert _FAKE_API_KEY not in str(excinfo.value)
        assert _FAKE_API_KEY not in repr(excinfo.value)
        # No chained exception leaking the raw ConnectError.
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    def test_get_status_transport_error_does_not_leak_credential(self):
        """GET status path: transport error must not expose Bearer token."""
        import httpx

        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)

        def boom(url, headers=None, timeout=None):
            raise httpx.ConnectError(
                f"Connection refused; sent Authorization: Bearer {_FAKE_API_KEY}"
            )

        with patch("httpx.get", boom):
            with pytest.raises(VerificationError) as excinfo:
                client.get_status(_DOMAIN)
        assert _FAKE_API_KEY not in str(excinfo.value)
        assert _FAKE_API_KEY not in repr(excinfo.value)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    def test_get_agent_status_transport_error_does_not_leak_credential(self):
        """GET agent_status path: transport error must not expose Bearer token."""
        import httpx

        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)

        def boom(url, headers=None, timeout=None):
            raise httpx.ConnectError(
                f"Connection refused; sent Authorization: Bearer {_FAKE_API_KEY}"
            )

        with patch("httpx.get", boom):
            with pytest.raises(VerificationError) as excinfo:
                client.get_agent_status(_DOMAIN)
        assert _FAKE_API_KEY not in str(excinfo.value)
        assert _FAKE_API_KEY not in repr(excinfo.value)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    def test_unregister_transport_error_does_not_leak_credential(self):
        """DELETE unregister path: transport error must not expose Bearer token."""
        import httpx

        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)

        def boom(method, url, headers=None, timeout=None):
            raise httpx.ConnectError(
                f"Connection refused; sent Authorization: Bearer {_FAKE_API_KEY}"
            )

        with patch("httpx.request", boom):
            with pytest.raises(VerificationError) as excinfo:
                client.unregister_agent(_DOMAIN)
        assert _FAKE_API_KEY not in str(excinfo.value)
        assert _FAKE_API_KEY not in repr(excinfo.value)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    def test_exception_chain_suppressed_even_within_caller_except_block(self):
        """Verify __suppress_context__ is True so traceback never shows chained HTTPX error.

        Even if the caller invokes register_agent within their own except block
        (which could set __context__ on the raised exception), the
        __suppress_context__ flag must be True to prevent Python from printing
        the exception chain in tracebacks.
        """
        import httpx

        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)

        def boom(url, json=None, headers=None, timeout=None):
            raise httpx.ConnectError(f"Connection refused; Authorization: Bearer {_FAKE_API_KEY}")

        with patch("httpx.post", boom):
            err: VerificationError | None = None
            try:
                # Simulate calling from within an active except handler
                try:
                    raise RuntimeError("unrelated caller error")
                except RuntimeError:
                    client.register_agent(
                        AgentRegistrationInput(domain=_DOMAIN, environment="production")
                    )
            except VerificationError as exc:
                err = exc

        assert err is not None
        assert _FAKE_API_KEY not in str(err)
        assert err.__cause__ is None
        # __suppress_context__ ensures traceback rendering never shows the chain
        assert err.__suppress_context__ is True


class TestRegistrationCarriesAgentId:
    def test_register_agent_keeps_created_id(self):
        client = RegistryClient("https://registry.example.com", api_key=_FAKE_API_KEY)
        created = dict(_REGISTER_RESPONSE, id="agent-123")

        def fake_post(url, json=None, headers=None, timeout=None):
            return _FakeResponse(201, created)

        with patch("httpx.post", fake_post), patch.object(
            client, "get_registration", return_value=_registration()
        ):
            reg = client.register_agent(
                AgentRegistrationInput(domain=_DOMAIN, environment="production")
            )
        assert reg.id == "agent-123"

    def test_registration_from_status_reads_id(self):
        from dnsid.registry_client import _registration_from_response

        data = {"domain": _DOMAIN, "status": "READY", "id": "agent-456", "managed": "dnsid"}
        reg = _registration_from_response(_DOMAIN, "https://registry.example.com", data)
        assert reg.id == "agent-456"
