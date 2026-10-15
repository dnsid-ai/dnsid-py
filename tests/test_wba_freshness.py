"""HTTP directory freshness on acquisition and throughout verification."""

import datetime
from dataclasses import replace
from email.utils import format_datetime

import pytest

from dnsid import JWKS
from dnsid.exceptions import VerificationError
from dnsid.local_key_provider import LocalKeyProvider
from tests.test_wba_contracts import _resign_directory
from tests.test_wba_verifier import setup as setup


@pytest.mark.parametrize("control,age,date_offset,valid", [
    ("max-age=295, must-revalidate", "295", 0, False),
    ("max-age=295, must-revalidate", "294", 0, True),
    ("max-age=295", None, -295, False),
    ("max-age=295", None, -294, True),
    ("max-age=295", None, None, True),
    ("max-age=0", "0", -295, True),
    ("max-age=0", "1", 0, False),
    ("no-store", None, None, True),
    ("no-cache", None, None, True),
    ("no-store, max-age=0", None, None, True),
    ('private="x, y", max-age=295', None, None, True),
    ("max-age=295", "-1", 0, False),
    ("max-age=295", "invalid", 0, False),
    ("max-age=295", "2147483648", 0, False),
    ("max-age=invalid", None, None, False),
    ("max-age=295, extension=\"unterminated", None, None, False),
])
def test_directory_http_age_metadata(setup, monkeypatch, control, age, date_offset, valid):
    provider, resolver, verifier, req, opts, hook, _ = setup
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    monkeypatch.setattr("dnsid.wba_signer._now", lambda: now)
    monkeypatch.setattr("dnsid.wba_verifier._now", lambda: now)

    def metadata(response):
        response.headers["cache-control"] = control
        if age is not None:
            response.headers["age"] = age
        if date_offset is not None:
            response.headers["date"] = format_datetime(
                now + datetime.timedelta(seconds=date_offset), usegmt=True,
            )
        return _resign_directory(response, provider)

    hook.side_effect = metadata
    if valid:
        verifier.verify_web_bot_auth_signed_request(req, opts)
    else:
        with pytest.raises(VerificationError, match="HTTP-stale|invalid directory"):
            verifier.verify_web_bot_auth_signed_request(req, opts)
        resolver.verify_domain.assert_not_called()
    resolver.refresh_domain.assert_not_called()


@pytest.mark.parametrize("phase", ["fetch", "read", "identity", "refresh", "replay"])
def test_directory_http_deadline_cannot_be_extended_by_network_or_callbacks(setup, monkeypatch, phase):
    from dnsid.wba_verifier import _read_limited

    provider, resolver, verifier, req, opts, hook, _ = setup
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    clock = [now]
    monkeypatch.setattr("dnsid.wba_signer._now", lambda: now)
    monkeypatch.setattr("dnsid.wba_verifier._now", lambda: clock[0])
    fresh = resolver.verify_domain.return_value

    def advance(result):
        clock[0] += datetime.timedelta(seconds=2)
        return result

    def metadata(response):
        response.headers["cache-control"] = "max-age=1, must-revalidate"
        if phase == "fetch":
            advance(None)
        return _resign_directory(response, provider)

    hook.side_effect = metadata
    if phase == "read":
        monkeypatch.setattr("dnsid.wba_verifier._read_limited",
                            lambda *args, **kwargs: advance(_read_limited(*args, **kwargs)))
    elif phase == "identity":
        resolver.verify_domain.side_effect = lambda *args, **kwargs: advance(fresh)
    elif phase == "refresh":
        resolver.verify_domain.return_value = replace(
            fresh, jwks=JWKS(keys=[LocalKeyProvider.generate().signing_key()])
        )
        resolver.refresh_domain.side_effect = lambda *args, **kwargs: advance(fresh)
    elif phase == "replay":
        opts.replay_policy = lambda *args: advance(True)
    with pytest.raises(VerificationError, match="HTTP-stale"):
        verifier.verify_web_bot_auth_signed_request(req, opts)
    assert resolver.refresh_domain.call_count == (phase == "refresh")
