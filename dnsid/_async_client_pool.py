"""Owned HTTP clients, isolated and closed on their respective event loops."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import Future

import httpx

from ._verification_budget import async_wait_for_verification


class _AsyncClientPool:
    def __init__(self, factory: Callable[[], httpx.AsyncClient]) -> None:
        self._factory = factory
        self._lock = threading.Lock()
        self._clients: dict[asyncio.AbstractEventLoop, httpx.AsyncClient] = {}
        self._close_futures: dict[asyncio.AbstractEventLoop, Future[None]] = {}
        self._closing = False

    def get(self) -> httpx.AsyncClient:
        """Reuse a client only on the loop that created it."""
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._closing:
                raise RuntimeError("async HTTP pool is closing or closed")
            client = self._clients.get(loop)
            if client is None:
                client = self._factory()
                self._clients[loop] = client
            return client

    def close(self) -> None:
        """Reject synchronous shutdown while async connections remain open."""
        with self._lock:
            if self._clients:
                raise RuntimeError("async HTTP connections are open; use await aclose()")
            self._closing = True

    async def aclose(self) -> None:
        """Close clients on their owning loops; cancelled waits can be retried.

        Callers must finish requests first and keep every owning loop running
        until shutdown completes. Cancellation does not interrupt client cleanup.
        """
        with self._lock:
            if any(not loop.is_running() for loop in self._clients):
                raise RuntimeError("keep HTTP client event loops running until aclose() completes")
            self._closing = True
            for loop, client in self._clients.items():
                if loop not in self._close_futures:
                    coroutine = self._close_client(loop, client)
                    try:
                        self._close_futures[loop] = asyncio.run_coroutine_threadsafe(
                            coroutine, loop,
                        )
                    except BaseException:
                        coroutine.close()
                        raise
            futures = list(self._close_futures.values())
        await asyncio.gather(*(async_wait_for_verification(future) for future in futures))

    async def _close_client(
        self, loop: asyncio.AbstractEventLoop, client: httpx.AsyncClient,
    ) -> None:
        await client.aclose()
        with self._lock:
            del self._clients[loop]
