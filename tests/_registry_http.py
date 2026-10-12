"""Mock registry wire calls without replacing its public workflow methods."""

from contextlib import contextmanager
from unittest.mock import patch

import httpx

from dnsid import RegistryClient


def _request(method, url, **kwargs):
    if method == "DELETE":
        return httpx.request(method, url, **kwargs)
    return getattr(httpx, method.lower())(url, **kwargs)


@contextmanager
def patch_registry_http(target, *args, **kwargs):
    with (
        patch(target, *args, **kwargs) as mocked,
        patch.object(RegistryClient, "_http_request", side_effect=_request),
    ):
        yield mocked
