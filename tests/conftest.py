"""Shared pytest configuration.

The suite must be hermetic: no test may reach the network. Rather than trusting
every test to mock what it needs, sockets are blocked globally here so an
unmocked call fails loudly and immediately instead of hanging or, worse,
quietly hitting a real server.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any

import pytest


class NetworkAccessDeniedError(RuntimeError):
    """Raised when a test tries to open a real network connection."""


@pytest.fixture(autouse=True, scope="session")
def _block_network() -> Iterator[None]:
    """Refuse outbound connections for the whole session.

    ``responses`` intercepts at the ``requests`` layer and the module tests
    patch ``socket.create_connection`` directly, so nothing legitimate needs a
    real connection. Any test that tries is relying on the live internet and
    would be flaky in CI.
    """
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def deny(self, address: Any, *args: Any, **kwargs: Any):
        raise NetworkAccessDeniedError(
            f"test attempted a real network connection to {address!r}; "
            "mock it instead so the suite stays offline"
        )

    def deny_ex(self, address: Any, *args: Any, **kwargs: Any):
        raise NetworkAccessDeniedError(
            f"test attempted a real network connection to {address!r}; "
            "mock it instead so the suite stays offline"
        )

    def deny_resolution(host: Any, port: Any, *args: Any, **kwargs: Any):
        raise NetworkAccessDeniedError(
            f"test attempted real DNS resolution of {host!r}; "
            "mock it instead so the suite stays offline"
        )

    socket.socket.connect = deny  # type: ignore[method-assign]
    socket.socket.connect_ex = deny_ex  # type: ignore[method-assign]
    socket.getaddrinfo = deny_resolution  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket.connect = real_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = real_connect_ex  # type: ignore[method-assign]
        socket.getaddrinfo = real_getaddrinfo  # type: ignore[assignment]
