"""Async adapter capabilities supplement the existing synchronous contracts."""

import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest

from dnsid import (
    AsyncDNSResolver,
    AsyncHTTPSFetcher,
    AsyncLogReader,
    DNSResolver,
    HTTPSFetcher,
    LogReader,
)


@pytest.mark.parametrize("sync,async_contract", [
    (DNSResolver, AsyncDNSResolver),
    (HTTPSFetcher, AsyncHTTPSFetcher),
    (LogReader, AsyncLogReader),
])
def test_async_capabilities_are_optional_and_preserve_signatures(sync, async_contract):
    adapter = MagicMock(spec=sync)
    assert not isinstance(adapter, async_contract)
    for name, method in inspect.getmembers(async_contract, inspect.iscoroutinefunction):
        sync_name = name.removeprefix("async_")
        if sync_name != "preload_history":
            assert inspect.signature(method) == inspect.signature(getattr(sync, sync_name))
        setattr(adapter, name, AsyncMock())
    assert isinstance(adapter, async_contract)
    assert not any(name.startswith("async_") for name in sync.__abstractmethods__)
