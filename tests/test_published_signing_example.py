import json
import runpy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dnsid import JWKS, HttpSignatureProfile, IdentityManager, LocalKeyProvider, load_file
from dnsid.exceptions import ArgumentError

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "published-signing"


@pytest.mark.parametrize("deployment", ["aws-kms", "file"])
@pytest.mark.parametrize("publication", ["matching", "wrong-key", "wrong-kid", "empty", "unverified"])
def test_example_checks_publication_before_signing(tmp_path, monkeypatch, deployment, publication):
    source = EXAMPLE / f"{deployment}.json"
    template = json.loads(source.read_text())
    template["dnsid"]["identity"]["logRef"] = "c2sp-tlog:public:https://log.example#existing"
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(template))
    loaded = load_file(path)
    assert loaded.key_source.provider == deployment
    assert loaded.key_source.key_ref == template["keySource"]["keyRef"]
    assert loaded.log_trust.managed is True
    assert loaded.dnsid.identity.ek_url == template["dnsid"]["identity"]["ekUrl"]
    assert loaded.dnsid.identity.ku_url == template["dnsid"]["identity"]["kuUrl"]

    provider = LocalKeyProvider.generate()
    selected = provider.signing_key()
    current = selected
    if publication == "wrong-key":
        current = replace(LocalKeyProvider.generate().signing_key(), kid=selected.kid)
    elif publication == "wrong-kid":
        current = replace(selected, kid="different-published-kid")
    evidence = SimpleNamespace(jwks=JWKS([] if publication == "empty" else [current]))
    manager = IdentityManager(loaded.dnsid, provider)
    manager.verify_domain = Mock(return_value=evidence)
    if publication == "unverified":
        manager.verify_domain.side_effect = ArgumentError("publication verification failed")
    provider.sign = Mock(wraps=provider.sign)

    sign_request = runpy.run_path(str(EXAMPLE / "main.py"))["sign_request"]
    constructor = Mock(return_value=manager)
    monkeypatch.setitem(sign_request.__globals__, "construct_identity_manager", constructor)
    if publication == "matching":
        request = sign_request(str(path))
        manager.verify_domain.assert_called_once_with("agent.example")
        provider.sign.assert_called_once()
        assert request.method == "GET"
        assert request.url == "https://receiver.example/resource"
        assert request.get_header("signature")
        assert f'keyid="agent.example#{selected.kid}"' in request.get_header("signature-input")
        assert HttpSignatureProfile.from_identity_manager(manager).verify_signed_http_request(
            request
        ) is evidence
    else:
        with pytest.raises(ArgumentError):
            sign_request(str(path))
        provider.sign.assert_not_called()
    constructor.assert_called_once_with(loaded)
    assert manager._closed
