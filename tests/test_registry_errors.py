from unittest.mock import patch

import pytest

from dnsid import RegistryClient, RegistryRequestError, VerificationError

_KEY = "dnsid_test_key"


class _Resp:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.is_success = 200 <= status_code < 300
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _post(resp):
    return lambda url, json=None, headers=None, timeout=None: resp


def test_registry_error_carries_status_and_code_but_not_the_body():
    client = RegistryClient("https://registry.example.com", api_key=_KEY)
    body = {"error": "INVALID_TRANSITION", "message": "secret-ish detail token=abc"}
    with patch("httpx.post", _post(_Resp(409, body))), pytest.raises(RegistryRequestError) as ei:
        client.cancel_agent("a.example")
    err = ei.value
    assert isinstance(err, VerificationError)  # existing handlers still catch it
    assert err.status_code == 409
    assert err.error_code == "INVALID_TRANSITION"
    assert "secret-ish" not in str(err) and "abc" not in str(err)
    assert "HTTP 409 (INVALID_TRANSITION)" in str(err)


def test_registry_error_ignores_free_text_codes_and_non_json():
    client = RegistryClient("https://registry.example.com", api_key=_KEY)
    with (
        patch("httpx.post", _post(_Resp(500, {"error": "something went wrong: token=abc"}))),
        pytest.raises(RegistryRequestError) as ei,
    ):
        client.cancel_agent("a.example")
    assert ei.value.error_code == "" and ei.value.transient
    with (
        patch("httpx.post", _post(_Resp(502, None, "<html>bad gateway</html>"))),
        pytest.raises(RegistryRequestError) as ei,
    ):
        client.cancel_agent("a.example")
    assert ei.value.error_code == "" and "html" not in str(ei.value)


def test_cancel_agent_posts_to_cancel_and_returns_lifecycle_result():
    client = RegistryClient("https://registry.example.com", api_key=_KEY)
    seen = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen["url"], seen["auth"] = url, headers.get("Authorization")
        return _Resp(200, {"id": "agent-1", "status": "cancelled"})

    with patch("httpx.post", fake_post):
        res = client.cancel_agent("a.example")
    assert seen["url"].endswith("/api/v1/agent/a.example/cancel")
    assert seen["auth"] == f"Bearer {_KEY}"
    assert res.id == "agent-1" and res.state == "CANCELLED"


def test_error_code_must_be_the_whole_value():
    from dnsid.registry_client import _registry_error_code

    assert _registry_error_code(_Resp(409, {"error": "INVALID_TRANSITION"})) == "INVALID_TRANSITION"
    assert _registry_error_code(_Resp(409, {"error": "INVALID_TRANSITION\n"})) == ""
    assert _registry_error_code(_Resp(409, {"error": "bad code"})) == ""
