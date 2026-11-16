"""RFC 6455 HTTP Upgrade handshake.

The opening handshake is plain HTTP/1.1: the client asks to upgrade, and
the server answers ``101 Switching Protocols`` with an
``Sec-WebSocket-Accept`` value derived from the client's nonce:

    accept = base64( SHA1( key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) )

Validation follows RFC 6455 §4.2: the request must be a GET at
HTTP/1.1, carry ``Upgrade: websocket`` and ``Connection: Upgrade``, a
well-formed 16-byte ``Sec-WebSocket-Key``, and (if present)
``Sec-WebSocket-Version: 13``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Dict, Tuple

#: RFC 6455 magic GUID mixed into the accept hash.
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#: Maximum accepted handshake size in bytes.
MAX_HANDSHAKE = 16 * 1024


class HandshakeError(Exception):
    """The opening handshake failed.

    Attributes:
        status: HTTP status code for the rejection response.
        message: reason text included in the rejection body.
        headers: extra response headers (e.g. ``Sec-WebSocket-Version``).
    """

    def __init__(self, status: int, message: str, headers=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = list(headers or [])


class UpgradeRequest:
    """A validated client opening handshake."""

    __slots__ = ("method", "path", "version", "headers", "key", "protocol")

    def __init__(
        self,
        method: str,
        path: str,
        version: str,
        headers: Dict[str, str],
        key: str,
        protocol: str = "",
    ):
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers
        self.key = key
        self.protocol = protocol

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<UpgradeRequest {self.method} {self.path} key={self.key!r}>"


def compute_accept(key: str) -> str:
    """Return the ``Sec-WebSocket-Accept`` value for a client ``key``."""
    digest = hashlib.sha1((key + WEBSOCKET_GUID).encode("latin-1")).digest()
    return base64.b64encode(digest).decode("ascii")


def _header_value(headers: Dict[str, str], name: str) -> str:
    return headers.get(name.lower(), "")


def _has_token(value: str, token: str) -> bool:
    parts = [p.strip().lower() for p in value.split(",")]
    return token in parts


def parse_upgrade_request(head: bytes) -> UpgradeRequest:
    """Parse and validate a raw request head (through ``\\r\\n\\r\\n``).

    Args:
        head: raw bytes of the request line and header block, including
            the terminating blank line.

    Returns:
        The validated :class:`UpgradeRequest`.

    Raises:
        HandshakeError: with an HTTP status code when invalid.
        ValueError: when the bytes are not decodable at all.
    """
    try:
        text = head.decode("latin-1")
    except UnicodeDecodeError as exc:  # pragma: no cover - latin-1 never fails
        raise HandshakeError(400, "undecodable handshake") from exc
    lines = text.split("\r\n")
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise HandshakeError(400, "malformed request line")
    method, path, version = parts
    if method != "GET":
        raise HandshakeError(400, "websocket handshake must be a GET request")
    if version != "HTTP/1.1":
        raise HandshakeError(400, "websocket handshake requires HTTP/1.1")

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise HandshakeError(400, "malformed header line")
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    if not _has_token(_header_value(headers, "upgrade"), "websocket"):
        raise HandshakeError(400, "Upgrade: websocket header required")
    if not _has_token(_header_value(headers, "connection"), "upgrade"):
        raise HandshakeError(400, "Connection: Upgrade header required")

    version_value = _header_value(headers, "sec-websocket-version")
    if version_value and version_value.strip() != "13":
        raise HandshakeError(
            426,
            "unsupported websocket version",
            [("Sec-WebSocket-Version", "13")],
        )

    key = _header_value(headers, "sec-websocket-key")
    if not key:
        raise HandshakeError(400, "Sec-WebSocket-Key header required")
    try:
        decoded = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        raise HandshakeError(400, "Sec-WebSocket-Key is not valid base64") from None
    if len(decoded) != 16:
        raise HandshakeError(400, "Sec-WebSocket-Key must decode to 16 bytes")

    protocol = _header_value(headers, "sec-websocket-protocol").split(",")[0].strip()
    return UpgradeRequest(method, path, version, headers, key, protocol)


def build_response(key: str, protocol: str = "") -> bytes:
    """Build the ``101 Switching Protocols`` response bytes."""
    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {compute_accept(key)}",
    ]
    if protocol:
        lines.append(f"Sec-WebSocket-Protocol: {protocol}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def build_rejection(status: int, message: str, headers=None) -> bytes:
    """Build a plain HTTP rejection response for a failed handshake."""
    lines = [f"HTTP/1.1 {status} {'Rejected' if status != 426 else 'Upgrade Required'}"]
    lines.append("Content-Type: text/plain; charset=utf-8")
    body = message.encode("utf-8") + b"\n"
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    for name, value in headers or []:
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def read_handshake_head(read_exact, limit: int = MAX_HANDSHAKE) -> bytes:
    """Read bytes via ``read_exact(1)`` until ``\\r\\n\\r\\n`` is seen.

    ``read_exact`` must raise ``ConnectionError`` at EOF.  Raises
    :class:`HandshakeError` (400) when the head exceeds ``limit``.
    """
    buf = bytearray()
    while not buf.endswith(b"\r\n\r\n"):
        if len(buf) >= limit:
            raise HandshakeError(400, "handshake too large")
        try:
            buf.extend(read_exact(1))
        except ConnectionError:
            raise HandshakeError(400, "connection closed during handshake") from None
    return bytes(buf)


def read_handshake_head_buffered(sock, limit: int = MAX_HANDSHAKE) -> Tuple[bytes, bytes]:
    """Read the handshake head from a socket, returning (head, leftover).

    Any bytes received after ``\\r\\n\\r\\n`` (a client that pipelines its
    first frame with the handshake) are returned as ``leftover`` so the
    frame reader can consume them without loss.
    """
    buf = bytearray()
    while not buf.endswith(b"\r\n\r\n"):
        if len(buf) >= limit:
            raise HandshakeError(400, "handshake too large")
        try:
            chunk = sock.recv(4096)
        except OSError:
            raise HandshakeError(400, "connection error during handshake") from None
        if not chunk:
            raise HandshakeError(400, "connection closed during handshake")
        buf.extend(chunk)
    marker = buf.find(b"\r\n\r\n") + 4
    return bytes(buf[:marker]), bytes(buf[marker:])
