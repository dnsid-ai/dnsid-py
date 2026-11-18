"""Generation-failure characterization of the pending-key contract (#56).

No retries, polling, manager persistence or recovery policy is invented here.
"""

import pytest

from dnsid import ArgumentError
from tests.test_google_kms_lifecycle_contract import PARENT, SUCCESSOR, VersionKms
from tests.test_google_kms_runtime_contract import VERSION, provider


class GenerationDenied(Exception):
    """Independent fake KMS failure used at either external boundary."""


@pytest.mark.parametrize("failure", ["create", "generated_public"])
def test_given_generation_failure_when_operator_generates_then_existing_signer_is_preserved(failure):
    """**Mode**: fake-only (KMS). Given/When/Then: failure never replaces active state."""
    client = VersionKms()
    signer = provider(client)
    previous = signer.signing_key().to_dict()
    attempted = []
    denied_error = GenerationDenied(
        "fixture denies version creation" if failure == "create"
        else "fixture cannot read generated public key"
    )
    if failure == "create":
        def denied(request):
            attempted.append(("create", request["parent"]))
            raise denied_error

        client.create_crypto_key_version = denied
    else:
        original = client.get_public_key

        def denied(request):
            if request["name"] == SUCCESSOR:
                attempted.append(("generated_public", request["name"]))
                raise denied_error
            return original(request)

        client.get_public_key = denied
    with pytest.raises(GenerationDenied if failure == "create" else ArgumentError) as caught:
        signer.generate_key()
    if failure == "create":
        assert caught.value is denied_error
    else:
        assert SUCCESSOR in str(caught.value)
        assert caught.value.__cause__ is denied_error
    expected = [("create", PARENT)] if failure == "create" else [
        ("generated_public", SUCCESSOR),
    ]
    assert attempted == expected
    assert signer.signing_key().to_dict() == previous
    assert signer.list_key_ids() == [previous["kid"]]
    payload = b"existing signing remains usable after failed generation"
    client.keys[VERSION].public_key().verify(signer.sign(payload), payload)
    # An independently reopened configured version stays the established signer.
    reopened = provider(client)
    assert reopened.signing_key().to_dict() == previous
    assert reopened.list_key_ids() == [previous["kid"]]
