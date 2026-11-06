"""One application-signing boundary shared by a Foundry handle and its profiles."""

from __future__ import annotations

import copy
import inspect
import time
from collections.abc import Callable
from typing import Any, TypeVar

from .._verification_budget import remaining_seconds
from ..interfaces import KeyProvider
from ..models import JWK
from .errors import SigningPaused

_T = TypeVar("_T")


def provider_call(function: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Pass a supported deadline; otherwise check the budget on both sides."""
    remaining = remaining_seconds()
    parameters = inspect.signature(function).parameters
    if "deadline" in parameters:
        kwargs["deadline"] = time.monotonic() + remaining
    elif "timeout" in parameters:
        kwargs["timeout"] = remaining
    result = function(*args, **kwargs)
    remaining_seconds()
    return result


class ApplicationSigner(KeyProvider):
    """Pin signing to a verified public key without a provider read per signature."""

    def __init__(self, provider: KeyProvider, key: JWK) -> None:
        self.provider = provider
        self._key = copy.deepcopy(key)
        self.paused = True

    def enable(self, key: JWK) -> None:
        """Record a binding checked at setup/recovery, then enable signing."""
        self._key = copy.deepcopy(key)
        self.paused = False

    def signing_key(self) -> JWK:
        if self.paused:
            raise SigningPaused("application signing is paused; call active()")
        return copy.deepcopy(self._key)

    def sign(self, payload: bytes) -> bytes:
        key = self.signing_key()
        return self.provider.sign_key(key.kid, payload)

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        key = self.signing_key()
        if kid != key.kid:
            raise SigningPaused("application signing key does not match the enabled binding")
        return self.provider.sign_key(kid, payload)

    def jwk(self, kid: str) -> JWK:
        key = self.signing_key()
        if kid != key.kid:
            raise SigningPaused("application signing key does not match the enabled binding")
        return key

    def list_key_ids(self) -> list[str]:
        return [self.signing_key().kid]

    def generate_key(self) -> str:
        raise SigningPaused("Foundry rotation is not supported by create")

    def activate(self, kid: str) -> None:
        raise SigningPaused("Foundry rotation is not supported by create")

    def supersede(self, kid: str, *, allow_active: bool = False) -> None:
        raise SigningPaused("Foundry rotation is not supported by create")


class WorkflowKeyProvider(KeyProvider):
    """Budget provider calls made by the shared issuance binding."""

    def __init__(self, provider: KeyProvider) -> None:
        self.provider = provider

    def signing_key(self) -> JWK:
        return provider_call(self.provider.signing_key)

    def jwk(self, kid: str) -> JWK:
        return provider_call(self.provider.jwk, kid)

    def sign(self, payload: bytes) -> bytes:
        return provider_call(self.provider.sign, payload)

    def sign_key(self, kid: str, payload: bytes) -> bytes:
        return provider_call(self.provider.sign_key, kid, payload)

    def list_key_ids(self) -> list[str]:
        return provider_call(self.provider.list_key_ids)

    def generate_key(self) -> str:
        raise SigningPaused("workflow cannot generate replacement keys")

    def activate(self, kid: str) -> None:
        raise SigningPaused("workflow cannot activate replacement keys")

    def supersede(self, kid: str, *, allow_active: bool = False) -> None:
        raise SigningPaused("workflow cannot supersede keys")
