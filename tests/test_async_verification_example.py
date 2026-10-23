"""The async verification example reports typed failures and closes its manager."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from dnsid import (
    IdentityConfig,
    IdentityManager,
    LoadedConfig,
    LogTrust,
    VerificationCode,
    VerificationError,
)
from dnsid.exceptions import ArgumentError


@pytest.fixture
def example():
    path = Path(__file__).parents[1] / "examples" / "async-verification" / "main.py"
    spec = importlib.util.spec_from_file_location("_async_verification_example", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manager():
    manager = MagicMock(spec=IdentityManager)
    manager.__aenter__.return_value = manager
    manager.async_verify_domain.return_value = SimpleNamespace(
        domain="agent.test", cached_state=lambda: "ACTIVE"
    )
    return manager


@pytest.mark.asyncio
async def test_success_reports_identity_and_closes_manager(example, capsys):
    manager = _manager()
    assert await example.verify(manager, "agent.test") == 0
    assert capsys.readouterr().out == "agent.test: ACTIVE\n"
    manager.async_verify_domain.assert_awaited_once_with("agent.test")
    manager.__aexit__.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("code,transient", [
    (VerificationCode.DEADLINE_EXCEEDED, True),
    (VerificationCode.STATUS_UNAVAILABLE, True),
    (VerificationCode.SIGNATURE_INVALID, False),
])
async def test_failure_reports_retry_semantics_and_closes_manager(example, capsys, code, transient):
    manager = _manager()
    manager.async_verify_domain.side_effect = VerificationError(code, "failed", transient=transient)
    assert await example.verify(manager, "agent.test") == 1
    error = capsys.readouterr().err
    assert code.name in error
    assert ("retrying may help" in error) == transient
    manager.__aexit__.assert_awaited_once()


def test_main_loads_config_and_uses_verification_only_manager(example, monkeypatch, capsys):
    loaded, manager = LoadedConfig(), _manager()
    loaded.dnsid.identity = IdentityConfig(domain="local.test")
    construct = MagicMock(return_value=manager)
    monkeypatch.setattr(example.sys, "argv", ["main.py", "agent.test"])
    monkeypatch.setattr(example, "load_environment", lambda: loaded)
    monkeypatch.setattr(example, "construct_identity_manager", construct)
    assert example.main() == 0
    assert loaded.dnsid.identity is None
    construct.assert_called_once_with(loaded)
    assert loaded.log_trust == LogTrust(managed=True)
    assert "ACTIVE" in capsys.readouterr().out
    manager.__aexit__.assert_awaited_once()


def test_main_reports_configuration_errors(example, monkeypatch, capsys):
    monkeypatch.setattr(example.sys, "argv", ["main.py", "agent.test"])
    monkeypatch.setattr(example, "load_environment", MagicMock(side_effect=ArgumentError("bad config")))
    assert example.main() == 1
    assert "bad config" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_cancelled_example_still_closes_manager(example):
    import asyncio

    manager, started = _manager(), asyncio.Event()

    async def verify(*args):
        started.set()
        await asyncio.sleep(10)

    manager.async_verify_domain = AsyncMock(side_effect=verify)
    task = asyncio.create_task(example.verify(manager, "agent.test"))
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    manager.__aexit__.assert_awaited_once()
