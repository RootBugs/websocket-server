"""Raw-socket WebSocket client used by the live tests.

Hand-rolled on purpose: frames are built and parsed by the test client
itself (masked on the way out, unmasked on the way in), so the server's
wire behavior is what gets exercised.
"""

from __future__ import annotations

import base64
import os
import socket
from typing import Optional, Tuple

from websocket_server.frame import (
    OP_BINARY,
    OP_CLOSE,
    OP_TEXT,
    Frame,
    FrameReader,
    encode_close_payload,
    encode_frame,
    parse_close_payload,
)

TIMEOUT = 5.0

#: The RFC 6455 §1.3 example key and its well-known accept value.
RFC_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
RFC_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


class HandshakeFailed(AssertionError):
    """Raised when the server did not complete the upgrade."""


class WSClient:
    """A minimal client: handshake once, then exchange frames."""

    def __init__(
        self,
        host: str,
        port: int,
        path: str = "/",
        key: Optional[str] = None,
        extra_headers: Optional[dict] = None,
        expect_upgrade: bool = True,
    ):
        self.sock = socket.create_connection((host, port), timeout=TIMEOUT)
        self._buf = bytearray()
        self.key = key if key is not None else base64.b64encode(os.urandom(16)).decode("ascii")
        headers = {
            "Host": f"{host}:{port}",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": self.key,
            "Sec-WebSocket-Version": "13",
        }
        headers.update(extra_headers or {})
        request = f"GET {path} HTTP/1.1\r\n"
        request += "".join(f"{name}: {value}\r\n" for name, value in headers.items())
        request += "\r\n"
        self.sock.sendall(request.encode("latin-1"))
        head = self._read_until(b"\r\n\r\n")
        self.handshake_response = head.decode("latin-1")
        self.status = int(self.handshake_response.split(" ")[1])
        self.response_headers = self._parse_headers(self.handshake_response)
        if expect_upgrade and self.status != 101:
            raise HandshakeFailed(f"expected 101, got {self.status}: {head!r}")
        self._reader = FrameReader(self.read_exact, require_mask=False)

    # -- low-level ---------------------------------------------------------
    @staticmethod
    def _parse_headers(head: str) -> dict:
        headers = {}
        for line in head.split("\r\n")[1:]:
            if not line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return headers

    def _recv_some(self) -> None:
        data = self.sock.recv(65536)
        if not data:
            raise ConnectionError("server closed the connection")
        self._buf.extend(data)

    def _read_until(self, marker: bytes) -> bytes:
        while True:
            idx = self._buf.find(marker)
            if idx != -1:
                data = bytes(self._buf[: idx + len(marker)])
                del self._buf[: idx + len(marker)]
                return data
            self._recv_some()

    def read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._recv_some()
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    # -- sending -----------------------------------------------------------
    def send_raw(self, data: bytes) -> None:
        self.sock.sendall(data)

    def send_frame(self, opcode: int, payload: bytes = b"", fin: bool = True,
                   masked: bool = True, mask_key: Optional[bytes] = None) -> None:
        """Send one frame (masked by default, as RFC 6455 requires)."""
        frame = Frame(opcode, payload, fin=fin, masked=masked)
        self.sock.sendall(encode_frame(frame, mask=masked, mask_key=mask_key))

    def send_text(self, text: str, fin: bool = True) -> None:
        self.send_frame(OP_TEXT, text.encode("utf-8"), fin=fin)

    def send_binary(self, data: bytes, fin: bool = True) -> None:
        self.send_frame(OP_BINARY, data, fin=fin)

    def send_close(self, code: int = 1000, reason: str = "") -> None:
        self.send_frame(OP_CLOSE, encode_close_payload(code, reason))

    # -- receiving ---------------------------------------------------------
    def recv_frame(self) -> Frame:
        """Read one server frame (must be unmasked)."""
        return self._reader.read()

    def recv_close(self) -> Tuple[Optional[int], str]:
        frame = self.recv_frame()
        if frame.opcode != OP_CLOSE:
            raise AssertionError(f"expected close frame, got {frame!r}")
        return parse_close_payload(frame.payload)

    def is_eof(self) -> bool:
        """True when the server has closed the connection (no data pending)."""
        self.sock.settimeout(2.0)
        try:
            return self.sock.recv(1) == b""
        except (socket.timeout, TimeoutError, OSError):
            return False
        finally:
            self.sock.settimeout(TIMEOUT)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "WSClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def connect(server, **kwargs) -> WSClient:
    return WSClient("127.0.0.1", server.port, **kwargs)
