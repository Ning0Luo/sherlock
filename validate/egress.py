"""EgressGuard: during a validation run, block any socket connection to a host
that is not loopback, so a test fleet can never send a canary (or anything
else) to the real world. It is a safety backstop: sinks should be LocalSinks,
and this catches a real network tool that was left in by mistake.
"""

from __future__ import annotations

import socket

_LOOPBACK_NAMES = {"localhost", "ip6-localhost", "ip6-loopback"}


class BlockedEgress(Exception):
    def __init__(self, host, port):
        self.host, self.port = host, port
        super().__init__(f"blocked connection to {host}:{port}")


def _dest(address):
    """(host, port) for an AF_INET/AF_INET6 address; a unix socket path is local."""
    if isinstance(address, (str, bytes)):          # AF_UNIX: a local file path
        return None, None
    try:
        return address[0], address[1]
    except (TypeError, IndexError, KeyError):
        return str(address), None


def _is_local(host) -> bool:
    if host is None:                               # unix socket
        return True
    h = str(host).lower().strip("[]")
    if h in _LOOPBACK_NAMES or h.endswith(".localhost"):
        return True
    if h.startswith("127.") or h in ("::1", "0.0.0.0", "::", ""):
        return True
    return False


def _check(address):
    host, port = _dest(address)
    if not _is_local(host):
        raise BlockedEgress(host, port)


class EgressGuard:
    """Context manager. While active, socket.connect / connect_ex to a
    non-loopback host raises BlockedEgress. Originals are restored on exit."""

    def __enter__(self):
        self._orig_connect = socket.socket.connect
        self._orig_connect_ex = socket.socket.connect_ex
        orig_connect, orig_connect_ex = self._orig_connect, self._orig_connect_ex

        def connect(sock, address, *a, **k):
            _check(address)
            return orig_connect(sock, address, *a, **k)

        def connect_ex(sock, address, *a, **k):
            _check(address)
            return orig_connect_ex(sock, address, *a, **k)

        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        return self

    def __exit__(self, *exc):
        socket.socket.connect = self._orig_connect
        socket.socket.connect_ex = self._orig_connect_ex
        return False
