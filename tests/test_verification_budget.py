"""Shared monotonic deadlines, transport propagation, and independent waiters."""

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import httpx
import pytest

from dnsid import remaining_seconds, verification_budget
from dnsid._verification_budget import verification_operation
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.oidc import _get_json
from tests.test_verification_coalescing import _manager_fixture


def test_nested_operations_share_budget_and_never_return_late(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("dnsid._verification_budget.time.monotonic", lambda: clock[0])
    timeouts = []

    def response(request):
        timeouts.append(request.extensions["timeout"]["read"])
        clock[0] += 6
        return httpx.Response(200, json={"ok": True})

    @verification_operation
    def verify(client):
        _get_json("https://issuer.example/first", http_client=client)
        return _get_json("https://issuer.example/second", http_client=client)

    with httpx.Client(transport=httpx.MockTransport(response)) as client:
        with pytest.raises(VerificationError, match="deadline"):
            with verification_budget(10):
                verify(client)
    assert timeouts == [10, 4]
    with verification_budget(60):

        @verification_operation
        def child():
            return remaining_seconds(100)

        assert child() == 60
        with verification_budget(120):
            assert remaining_seconds(100) == 60
    for timeout in (0, -1, True, float("inf"), float("nan")):
        with pytest.raises(ArgumentError):
            with verification_budget(timeout):
                pass
    cancelled = threading.Event()
    with pytest.raises(VerificationError, match="cancelled"):
        with verification_budget(cancelled=cancelled):
            with verification_budget():
                cancelled.set()
                remaining_seconds()


def test_waiter_deadline_does_not_cancel_shared_verification(ec_pair):
    manager, resolver, _, domain, keys, status, _ = _manager_fixture(ec_pair)
    resolver.started = threading.Event()
    resolver.release = threading.Event()
    with (
        manager,
        patch("dnsid.manager._fetch_jwks", side_effect=keys),
        patch("dnsid.manager._fetch_strict_json_status", side_effect=status),
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        leader = pool.submit(manager.verify_domain, domain)
        assert resolver.started.wait(1)
        try:
            with pytest.raises(VerificationError, match="deadline"):
                with verification_budget(0.02):
                    manager.verify_domain(domain)
        finally:
            resolver.release.set()
        result = leader.result(timeout=2)
        assert manager.verify_domain(domain) is result


def test_socket_operations_receive_remaining_budget(monkeypatch):
    from unittest.mock import MagicMock

    from dnsid.safe_transport import _BudgetStream

    clock = [1.0]
    monkeypatch.setattr("dnsid._verification_budget.time.monotonic", lambda: clock[0])
    underlying = MagicMock()
    stream = _BudgetStream(underlying)
    with pytest.raises(VerificationError, match="deadline"):
        with verification_budget(5):
            stream.read(32, 10)
            underlying.read.assert_called_once_with(32, 5)
            clock[0] = 4
            stream.write(b"x", 10)
            underlying.write.assert_called_once_with(b"x", 2)
            clock[0] = 6
            stream.read(32, 10)
    assert underlying.read.call_count == 1
