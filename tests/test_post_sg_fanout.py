"""Post-sg fan-out: ku/log work and the su fetch run concurrently, safely."""

from __future__ import annotations

import threading
from unittest.mock import patch

import pytest

from dnsid import JWKS
from dnsid._verification_budget import BudgetExhausted, remaining_seconds, verification_budget
from dnsid.enums import VerificationCode
from dnsid.exceptions import VerificationError
from dnsid.models import AgentStatus
from tests.test_verification_coalescing import _manager_fixture, _now


def _run_in_thread(fn):
    box: dict[str, object] = {}

    def target() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=target)
    thread.start()
    return thread, box


def test_status_is_fetched_concurrently_with_ku_but_only_after_ek(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(ec_pair)
    ku_started, ku_release, order = threading.Event(), threading.Event(), []

    def gated_jwks(uri, allowed_host, **kwargs):
        with resolver.lock:
            order.append("ku" if uri.startswith(f"https://{domain}/") else "ek")
        if uri.startswith(f"https://{domain}/"):
            ku_started.set()
            assert ku_release.wait(5)
        return fetch_jwks(uri, allowed_host, **kwargs)

    def ordered_status(su, **kwargs):
        with resolver.lock:
            order.append("status")
        return fetch_status(su, **kwargs)

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=gated_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=ordered_status),
    ):
        thread, box = _run_in_thread(lambda: manager.verify_domain(domain))
        assert ku_started.wait(5)
        # su was requested while ku was still outstanding.
        for _ in range(100):
            if "status" in order:
                break
            threading.Event().wait(0.01)
        assert order.index("ek") < order.index("status")
        assert "ku" in order
        ku_release.set()
        thread.join(5)
    manager.close()
    assert "error" not in box, box.get("error")
    assert counters["status"] == 1 and counters["ku"] == 1


def test_status_is_never_fetched_when_sg_fails(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(ec_pair)
    _, wrong_ek = ec_pair
    from tests.conftest import make_ec_p256_pair

    _, other_ek = make_ec_p256_pair("other-ek")

    def wrong_key_jwks(uri, allowed_host, **kwargs):
        if uri.startswith(f"https://{domain}/"):
            return fetch_jwks(uri, allowed_host, **kwargs)
        keys = JWKS(keys=[other_ek])
        return keys, fetch_jwks(uri, allowed_host, **kwargs)[1]

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=wrong_key_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=fetch_status),
    ):
        with pytest.raises(VerificationError) as info:
            manager.verify_domain(domain)
    manager.close()
    assert info.value.code == VerificationCode.SIGNATURE_INVALID
    assert counters["status"] == 0
    del wrong_ek


def test_identity_failure_wins_and_does_not_wait_for_blocked_status(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(ec_pair)
    _, ek_key = ec_pair
    status_started, status_release = threading.Event(), threading.Event()
    status_saw_cancel = threading.Event()

    def collision_jwks(uri, allowed_host, **kwargs):
        # ku serves the entity key: two-key separation failure (RECORD_INVALID).
        return JWKS(keys=[ek_key]), fetch_jwks(uri, allowed_host, **kwargs)[1]

    def blocked_status(su, **kwargs):
        status_started.set()
        assert status_release.wait(5)
        try:
            remaining_seconds()
        except BudgetExhausted:
            status_saw_cancel.set()
            raise
        return fetch_status(su, **kwargs)

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=collision_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=blocked_status),
    ):
        thread, box = _run_in_thread(lambda: manager.verify_domain(domain))
        assert status_started.wait(5)
        thread.join(5)  # returns without waiting for the abandoned status branch
        assert not thread.is_alive()
        status_release.set()
        assert status_saw_cancel.wait(5)
    manager.close()
    error = box["error"]
    assert isinstance(error, VerificationError)
    assert error.code == VerificationCode.RECORD_INVALID
    assert not error.transient


def test_status_failure_wins_and_cancels_blocked_identity_work(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(ec_pair)
    ku_started, ku_release = threading.Event(), threading.Event()
    ku_saw_cancel = threading.Event()

    def blocked_ku(uri, allowed_host, **kwargs):
        if uri.startswith(f"https://{domain}/"):
            ku_started.set()
            assert ku_release.wait(5)
            try:
                remaining_seconds()
            except BudgetExhausted:
                ku_saw_cancel.set()
                raise
        return fetch_jwks(uri, allowed_host, **kwargs)

    def revoked_status(su, **kwargs):
        assert ku_started.wait(5)
        return AgentStatus(
            state="REVOKED", last_transition_at=_now(), revocation_reason="superseded"
        )

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=blocked_ku),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=revoked_status),
    ):
        thread, box = _run_in_thread(lambda: manager.verify_domain(domain))
        assert ku_started.wait(5)
        # Let the status branch fail first, then release ku; the blocked branch
        # must observe cancellation and the caller must see the status code.
        threading.Event().wait(0.1)
        ku_release.set()
        thread.join(5)
        assert not thread.is_alive()
    manager.close()
    error = box["error"]
    assert isinstance(error, VerificationError)
    assert error.code == VerificationCode.STATUS_NOT_ACTIVE
    assert error.agent_state == "REVOKED"
    assert ku_saw_cancel.is_set()


def test_status_branch_inherits_and_cannot_extend_the_invocation_budget(ec_pair):
    manager, resolver, counters, domain, fetch_jwks, fetch_status, _ = _manager_fixture(ec_pair)
    observed: list[float] = []

    def measuring_status(su, **kwargs):
        observed.append(remaining_seconds())
        return fetch_status(su, **kwargs)

    with (
        patch("dnsid.manager._fetch_jwks", side_effect=fetch_jwks),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=measuring_status),
        verification_budget(2.0),
    ):
        manager.verify_domain(domain)
    manager.close()
    assert observed and observed[0] <= 2.0
