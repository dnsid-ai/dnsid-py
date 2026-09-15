"""Tests for retry_transient and async_retry_transient."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dnsid.enums import VerificationCode
from dnsid.exceptions import ArgumentError, VerificationError
from dnsid.retry import async_retry_transient, retry_transient


def _transient(msg: str = "flaky") -> VerificationError:
    return VerificationError(VerificationCode.DNS_RESOLUTION, msg, transient=True)


def _permanent(msg: str = "bad record") -> VerificationError:
    return VerificationError(VerificationCode.RECORD_INVALID, msg, transient=False)


class TestRetryTransient:
    def test_returns_result_on_first_success(self):
        result = retry_transient(lambda: 42)
        assert result == 42

    def test_retries_on_transient_error_then_succeeds(self):
        calls = iter([_transient(), _transient(), "ok"])

        def fn():
            v = next(calls)
            if isinstance(v, Exception):
                raise v
            return v

        with patch("time.sleep"):
            result = retry_transient(fn, max_attempts=3)
        assert result == "ok"

    def test_raises_immediately_on_non_transient_error(self):
        calls = 0

        def fn():
            nonlocal calls
            calls += 1
            raise _permanent()

        with pytest.raises(VerificationError, match="bad record"):
            retry_transient(fn, max_attempts=3)
        assert calls == 1

    def test_raises_non_verification_error_immediately(self):
        def fn():
            raise ArgumentError("bad arg")

        with pytest.raises(ArgumentError):
            retry_transient(fn, max_attempts=3)

    def test_raises_last_transient_after_max_attempts(self):
        def fn():
            raise _transient("still flaky")

        with patch("time.sleep"):
            with pytest.raises(VerificationError, match="still flaky"):
                retry_transient(fn, max_attempts=3)

    def test_sleeps_between_retries_with_backoff(self):
        def fn():
            raise _transient()

        sleep_calls: list[float] = []
        with patch("time.sleep", side_effect=lambda d: sleep_calls.append(d)):
            with pytest.raises(VerificationError):
                retry_transient(fn, max_attempts=3, base_delay=1.0, max_delay=30.0)

        assert len(sleep_calls) == 2
        # Second sleep should be longer than first (exponential growth).
        assert sleep_calls[1] > sleep_calls[0]

    def test_no_sleep_on_last_attempt(self):
        def fn():
            raise _transient()

        sleep_calls: list[float] = []
        with patch("time.sleep", side_effect=lambda d: sleep_calls.append(d)):
            with pytest.raises(VerificationError):
                retry_transient(fn, max_attempts=1)

        assert len(sleep_calls) == 0

    def test_delay_capped_at_max_delay(self):
        def fn():
            raise _transient()

        sleep_calls: list[float] = []
        with patch("time.sleep", side_effect=lambda d: sleep_calls.append(d)):
            with pytest.raises(VerificationError):
                retry_transient(fn, max_attempts=3, base_delay=100.0, max_delay=5.0)

        # Both delays should be <= max_delay + 1 (jitter cap).
        for d in sleep_calls:
            assert d <= 6.0


class TestAsyncRetryTransient:
    @pytest.mark.asyncio
    async def test_returns_result_on_first_success(self):
        async def fn():
            return 99

        result = await async_retry_transient(fn)
        assert result == 99

    @pytest.mark.asyncio
    async def test_retries_on_transient_then_succeeds(self):
        results = iter([_transient(), "done"])

        async def fn():
            v = next(results)
            if isinstance(v, Exception):
                raise v
            return v

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await async_retry_transient(fn, max_attempts=2)
        assert result == "done"

    @pytest.mark.asyncio
    async def test_raises_immediately_on_non_transient(self):
        calls = 0

        async def fn():
            nonlocal calls
            calls += 1
            raise _permanent()

        with pytest.raises(VerificationError):
            await async_retry_transient(fn, max_attempts=3)
        assert calls == 1

    @pytest.mark.asyncio
    async def test_raises_after_max_attempts(self):
        async def fn():
            raise _transient("async flaky")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(VerificationError, match="async flaky"):
                await async_retry_transient(fn, max_attempts=3)
