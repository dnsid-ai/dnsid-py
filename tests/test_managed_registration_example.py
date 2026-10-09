"""The example delegates setup and recovery to the SDK workflow."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from dnsid import ManagedRegistrationConfig
from dnsid.exceptions import DNSidError


def test_managed_example_uses_sdk_workflow(tmp_path, monkeypatch, capsys):
    path = Path(__file__).parents[1] / "examples/managed-registration/main.py"
    spec = importlib.util.spec_from_file_location("managed_registration_example", path)
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)
    monkeypatch.setenv("DNSID_REGISTRY_URL", "https://other.test")
    monkeypatch.setenv("DNSID_DOMAIN", "ignored.test")
    monkeypatch.setenv("DNSID_KEY_STORE", "/ignored/key.json")
    manager = Mock()
    workflow = Mock(
        return_value=SimpleNamespace(
            registration=SimpleNamespace(domain="agent.sandbox.dev.dnsid.ai"),
            manager=manager,
            logged_state_evidence=SimpleNamespace(logged_state="ACTIVE"),
        )
    )
    monkeypatch.setattr(example, "register_managed_identity", workflow)
    example.run("billing-agent", tmp_path, "secret-api-key")
    assert workflow.call_args.args[0] == "billing-agent"
    loaded = workflow.call_args.args[1]
    options = workflow.call_args.kwargs
    assert loaded.registry.registry_url == example.REGISTRY_URL
    assert loaded.dnsid.identity is None
    assert loaded.key_source == example.LoadedConfig().key_source
    assert loaded.log_trust.managed
    assert loaded.registration == ManagedRegistrationConfig(
        example.GOVERNANCE_ID, example.ENTITY_KEY_URL
    )
    assert options["store"].directory == tmp_path.resolve()
    assert options["credential"] == "secret-api-key"
    assert "input" not in options  # Name/public-key only selects the default sandbox.
    manager.close.assert_called_once()
    assert "status=ACTIVE" in capsys.readouterr().out

    monkeypatch.setenv("DNSID_API_KEY", "secret-api-key")
    monkeypatch.setattr(
        example.sys,
        "argv",
        [str(path), "billing-agent", "--state-dir", str(tmp_path)],
    )
    assert example.main() == 0
    assert workflow.call_args.args[0] == "billing-agent"
    assert workflow.call_args.kwargs["credential"] == "secret-api-key"
    capsys.readouterr()
    for token in ("", "invalid token"):
        monkeypatch.setenv("DNSID_API_KEY", token)
        workflow.reset_mock()
        assert example.main() == 1
        workflow.assert_not_called()
        assert "Set DNSID_API_KEY" in capsys.readouterr().err

    monkeypatch.setenv("DNSID_API_KEY", "secret-api-key")
    workflow.side_effect = DNSidError("failed with secret-api-key")
    assert example.main() == 1
    error = capsys.readouterr().err
    assert "secret-api-key" not in error
    assert "[REDACTED]" in error
    assert "Keep the state directory" in error
