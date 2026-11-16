"""RFC 6455 frame encode/decode.

Frame layout (big-endian)::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-------+-+-------------+-------------------------------+
    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    |I|S|S|S|  (4)  |A|     (7)    |             (16/64)           |
    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    | |1|2|3|       |K|             |                               |
    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    |     Extended payload length continued, if payload len == 127  |
    + - - - - - - - - - - - - - - - +-------------------------------+
    |                               |Masking-key, if MASK set to 1  |
    +-------------------------------+-------------------------------+
    |                     Masking-key (continued)                   |
    +-------------------------------+-------------------------------+
    |                     Masked payload data ...                   |
    +---------------------------------------------------------------+

Payload length: 0–125 inline, 126 → 16-bit, 127 → 64-bit.  Every
client-to-server frame must be masked with a 4-byte key; server frames
are never masked.
"""

from __future__ import annotations

import os
import struct
from typing import Callable, Optional, Tuple

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

CONTROL_OPCODES = frozenset({OP_CLOSE, OP_PING, OP_PONG})
DATA_OPCODES = frozenset({OP_CONT, OP_TEXT, OP_BINARY})
KNOWN_OPCODES = CONTROL_OPCODES | DATA_OPCODES

OPCODE_NAMES = {
    OP_CONT: "continuation",
    OP_TEXT: "text",
    OP_BINARY: "binary",
    OP_CLOSE: "close",
    OP_PING: "ping",
    OP_PONG: "pong",
}

#: Largest legal control-frame payload (RFC 6455 §5.5).
MAX_CONTROL_PAYLOAD = 125
#: Close codes that may appear on the wire (§7.4.1-7.4.4).
_VALID_CLOSE_CODES = frozenset(
    {1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014}
)


class FrameError(Exception):
    """Protocol violation while encoding or decoding a frame.

    Attributes:
        close_code: WebSocket close code the server should send before
            dropping the connection.
    """

    def __init__(self, message: str, close_code: int = 1002):
        super().__init__(message)
        self.close_code = close_code


class Frame:
    """One WebSocket frame."""

    __slots__ = ("fin", "opcode", "payload", "masked")

    def __init__(self, opcode: int, payload: bytes = b"", fin: bool = True, masked: bool = False):
        self.fin = fin
        self.opcode = opcode
        self.payload = payload
        self.masked = masked

    @property
    def is_control(self) -> bool:
        return self.opcode in CONTROL_OPCODES

    @property
    def name(self) -> str:
        return OPCODE_NAMES.get(self.opcode, f"0x{self.opcode:x}")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Frame {self.name} fin={self.fin} len={len(self.payload)} "
            f"masked={self.masked}>"
        )


def apply_mask(payload: bytes, key: bytes) -> bytes:
    """XOR ``payload`` with the repeating 4-byte masking key."""
    if len(key) != 4:
        raise ValueError("masking key must be exactly 4 bytes")
    key4 = key * (len(payload) // 4 + 1)
    return bytes(b ^ k for b, k in zip(payload, key4[: len(payload)]))


def encode_frame(frame: Frame, mask: bool = False, mask_key: Optional[bytes] = None) -> bytes:
    """Serialize a frame to wire bytes.

    Args:
        frame: the frame to encode.
        mask: apply a masking key (clients must pass ``True``).
        mask_key: explicit 4-byte key; random when omitted.

    Raises:
        FrameError: fragmented control frames or payloads over 125 bytes
            for control frames.
    """
    if frame.is_control:
        if not frame.fin:
            raise FrameError("control frames must not be fragmented")
        if len(frame.payload) > MAX_CONTROL_PAYLOAD:
            raise FrameError("control frame payload exceeds 125 bytes", close_code=1009)
    first = (0x80 if frame.fin else 0x00) | (frame.opcode & 0x0F)
    length = len(frame.payload)
    mask_bit = 0x80 if mask else 0x00
    if length <= 125:
        header = bytes([first, mask_bit | length])
    elif length <= 0xFFFF:
        header = bytes([first, mask_bit | 126]) + struct.pack(">H", length)
    else:
        header = bytes([first, mask_bit | 127]) + struct.pack(">Q", length)
    payload = frame.payload
    if mask:
        key = mask_key if mask_key is not None else os.urandom(4)
        if len(key) != 4:
            raise ValueError("masking key must be exactly 4 bytes")
        header += key
        payload = apply_mask(payload, key)
    return header + payload


def parse_header(two: bytes) -> Tuple[bool, int, bool, int]:
    """Parse the first two frame bytes.

    Returns:
        ``(fin, opcode, masked, length)`` where ``length`` is still the
        *inline* length (0–127); extended lengths are read by the caller.

    Raises:
        FrameError: reserved bits set (no extensions negotiated) or an
            unknown opcode.
    """
    if len(two) != 2:
        raise FrameError("truncated frame header")
    first, second = two
    if first & 0x70:
        raise FrameError("reserved bits set but no extension negotiated")
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    if opcode not in KNOWN_OPCODES:
        raise FrameError(f"unknown opcode 0x{opcode:x}")
    masked = bool(second & 0x80)
    return fin, opcode, masked, second & 0x7F


def encode_close_payload(code: Optional[int] = 1000, reason: str = "") -> bytes:
    """Build a close frame payload: 2-byte status code + UTF-8 reason."""
    if code is None:
        if reason:
            raise ValueError("a close reason requires a status code")
        return b""
    if not _is_valid_close_code(code):
        raise ValueError(f"invalid close code {code}")
    return struct.pack(">H", code) + reason.encode("utf-8")


def _is_valid_close_code(code: int) -> bool:
    if code in _VALID_CLOSE_CODES:
        return True
    return 3000 <= code <= 4999


def parse_close_payload(payload: bytes) -> Tuple[Optional[int], str]:
    """Parse a close frame payload into ``(code, reason)``.

    Raises:
        FrameError: 1-byte payloads, invalid codes, or bad UTF-8.
    """
    if len(payload) == 0:
        return None, ""
    if len(payload) == 1:
        raise FrameError("close payload must not be a single byte")
    code = struct.unpack(">H", payload[:2])[0]
    if not _is_valid_close_code(code):
        raise FrameError(f"invalid close code {code}")
    try:
        reason = payload[2:].decode("utf-8")
    except UnicodeDecodeError:
        raise FrameError("close reason is not valid UTF-8", close_code=1007) from None
    return code, reason


class FrameReader:
    """Incrementally reads frames from an exact-read byte source.

    Args:
        read_exact: callable returning exactly ``n`` bytes; it must
            raise ``ConnectionError`` when the peer closes.
        require_mask: ``True`` on the server (every client frame must be
            masked), ``False`` on the client (server frames must not be
            masked), ``None`` to accept either (used by unit tests).
    """

    def __init__(self, read_exact: Callable[[int], bytes], require_mask: Optional[bool] = None):
        self._read = read_exact
        self._require_mask = require_mask

    def read(self) -> Frame:
        """Read one complete frame; raises FrameError/ConnectionError."""
        two = self._read(2)
        fin, opcode, masked, inline_len = parse_header(two)
        if inline_len == 126:
            inline_len = struct.unpack(">H", self._read(2))[0]
        elif inline_len == 127:
            raw = self._read(8)
            if raw[0] & 0x80:
                raise FrameError("64-bit payload length has its high bit set")
            inline_len = struct.unpack(">Q", raw)[0]
        length = inline_len
        if opcode in CONTROL_OPCODES:
            if length > MAX_CONTROL_PAYLOAD:
                raise FrameError("control frame payload exceeds 125 bytes", close_code=1009)
            if not fin:
                raise FrameError("control frames must not be fragmented")
        if self._require_mask is True and not masked:
            raise FrameError("client frames must be masked")
        if self._require_mask is False and masked:
            raise FrameError("server frames must not be masked")
        key = self._read(4) if masked else None
        payload = self._read(length) if length else b""
        if key is not None:
            payload = apply_mask(payload, key)
        return Frame(opcode, payload, fin=fin, masked=masked)
