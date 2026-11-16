"""Connection-level WebSocket logic: messages, fragmentation, ping/pong, close."""

from __future__ import annotations

import socket
import struct
from typing import Optional, Tuple, Union

from .frame import (
    OP_BINARY,
    OP_CLOSE,
    OP_CONT,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    Frame,
    FrameError,
    FrameReader,
    encode_close_payload,
    encode_frame,
    parse_close_payload,
)

#: Default cap on a reassembled message (16 MiB).
DEFAULT_MAX_MESSAGE = 16 * 1024 * 1024


class ConnectionClosed(Exception):
    """The close handshake finished (or the peer went away).

    Attributes:
        code: close status code, or ``None`` when the socket just died.
        reason: close reason text.
    """

    def __init__(self, code: Optional[int] = None, reason: str = ""):
        super().__init__(f"websocket closed (code={code}, reason={reason!r})")
        self.code = code
        self.reason = reason


class Message:
    """A complete application message (text or binary)."""

    __slots__ = ("opcode", "data")

    def __init__(self, opcode: int, data: bytes):
        self.opcode = opcode
        self.data = data

    @property
    def is_text(self) -> bool:
        return self.opcode == OP_TEXT

    @property
    def is_binary(self) -> bool:
        return self.opcode == OP_BINARY

    @property
    def text(self) -> str:
        return self.data.decode("utf-8")

    def __eq__(self, other) -> bool:
        if not isinstance(other, Message):
            return NotImplemented
        return self.opcode == other.opcode and self.data == other.data

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        kind = "text" if self.is_text else "binary"
        return f"<Message {kind} {self.data!r}>"


class WebSocketConnection:
    """One established WebSocket connection.

    The connection owns framing: masking is enforced on reads, text
    payloads are validated as UTF-8, fragmented messages are reassembled,
    pings are answered with pongs (configurable), and the close handshake
    is completed automatically when the peer initiates it.

    Args:
        sock: the connected socket after the HTTP upgrade.
        read_exact: exact-read callable (normally the connection's
            :class:`SocketReader`); leftover handshake bytes are folded in
            by the caller.
        max_message: reassembly cap; exceeding it closes with 1009.
        auto_pong: reply to ping frames with a pong inside ``receive``.
    """

    def __init__(
        self,
        sock: socket.socket,
        read_exact,
        max_message: int = DEFAULT_MAX_MESSAGE,
        auto_pong: bool = True,
    ):
        self.sock = sock
        self.max_message = max_message
        self.auto_pong = auto_pong
        self._reader = FrameReader(read_exact, require_mask=True)
        self._closed = False
        self._close_sent = False
        self._close_code: Optional[int] = None

    # -- state ------------------------------------------------------------
    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def close_code(self) -> Optional[int]:
        return self._close_code

    # -- sending ----------------------------------------------------------
    def send_frame(self, opcode: int, payload: bytes = b"", fin: bool = True) -> None:
        """Send one unmasked (server-side) frame."""
        if self._closed:
            raise ConnectionClosed(self._close_code, "connection already closed")
        data = encode_frame(Frame(opcode, payload, fin=fin), mask=False)
        try:
            self.sock.sendall(data)
        except OSError as exc:
            self._closed = True
            raise ConnectionClosed(None, f"send failed: {exc}") from None

    def send_text(self, text: str) -> None:
        """Send a complete UTF-8 text message."""
        self.send_frame(OP_TEXT, text.encode("utf-8"))

    def send_binary(self, data: bytes) -> None:
        """Send a complete binary message."""
        self.send_frame(OP_BINARY, data)

    def send_ping(self, payload: bytes = b"") -> None:
        """Send a ping control frame (payload ≤ 125 bytes)."""
        self.send_frame(OP_PING, payload)

    def send_pong(self, payload: bytes = b"") -> None:
        """Send a pong control frame (payload ≤ 125 bytes)."""
        self.send_frame(OP_PONG, payload)

    def send(self, message: Union[Message, str, bytes]) -> None:
        """Echo-friendly send: Message, str (text) or bytes (binary)."""
        if isinstance(message, Message):
            if message.is_text:
                self.send_text(message.text)
            else:
                self.send_binary(message.data)
        elif isinstance(message, str):
            self.send_text(message)
        else:
            self.send_binary(bytes(message))

    # -- receiving --------------------------------------------------------
    def receive(self) -> Optional[Message]:
        """Read the next complete message.

        Control frames are handled transparently: pings are answered with
        pongs (when ``auto_pong``), pongs are discarded, and a close
        frame completes the close handshake.

        Returns:
            The next text/binary message, or ``None`` when the close
            handshake completed (the caller should stop).

        Raises:
            FrameError: protocol violation (caller should close with the
                error's ``close_code``).
            ConnectionClosed: the socket died without a clean close.
        """
        fragment_opcode: Optional[int] = None
        fragments = bytearray()
        while True:
            try:
                frame = self._reader.read()
            except ConnectionError as exc:
                self._closed = True
                raise ConnectionClosed(None, "socket closed") from exc

            if frame.opcode == OP_PING:
                if self.auto_pong and not self._closed:
                    self.send_pong(frame.payload)
                continue
            if frame.opcode == OP_PONG:
                continue
            if frame.opcode == OP_CLOSE:
                code, reason = parse_close_payload(frame.payload)
                self._close_code = code
                if not self._close_sent:
                    # Echo the peer's code and reason (RFC 6455 §5.5.1).
                    echo_code = code if code is not None else 1000
                    try:
                        self.send_frame(OP_CLOSE, encode_close_payload(echo_code, reason))
                        self._close_sent = True
                    except (FrameError, ConnectionClosed):
                        pass
                self._closed = True
                return None

            if frame.opcode in (OP_TEXT, OP_BINARY):
                if fragment_opcode is not None:
                    raise FrameError("new data frame while a message is being reassembled")
                if frame.fin:
                    return self._assemble(frame.opcode, bytes(frame.payload))
                fragment_opcode = frame.opcode
                fragments.extend(frame.payload)
                continue

            if frame.opcode == OP_CONT:
                if fragment_opcode is None:
                    raise FrameError("continuation frame without a started message")
                fragments.extend(frame.payload)
                if len(fragments) > self.max_message:
                    raise FrameError("message exceeds max size", close_code=1009)
                if frame.fin:
                    return self._assemble(fragment_opcode, bytes(fragments))
                continue

            raise FrameError(f"unexpected opcode {frame.opcode}")  # pragma: no cover

    def _assemble(self, opcode: int, payload: bytes) -> Message:
        if len(payload) > self.max_message:
            raise FrameError("message exceeds max size", close_code=1009)
        if opcode == OP_TEXT:
            try:
                payload.decode("utf-8")
            except UnicodeDecodeError:
                raise FrameError("text message is not valid UTF-8", close_code=1007) from None
        return Message(opcode, payload)

    # -- closing ----------------------------------------------------------
    def close(self, code: int = 1000, reason: str = "") -> None:
        """Initiate the close handshake (send close frame, mark closed)."""
        if self._close_sent or self._closed:
            return
        try:
            self.send_frame(OP_CLOSE, encode_close_payload(code, reason))
            self._close_sent = True
        except (FrameError, ConnectionClosed, OSError):
            pass
        self._closed = True
        self._close_code = code


class SocketReader:
    """Exact-length reads over a socket with a carry-over buffer.

    The carry-over lets bytes that arrived with the handshake (a
    pipelined first frame) be consumed without loss.
    """

    def __init__(self, sock: socket.socket, initial: bytes = b""):
        self._sock = sock
        self._buf = bytearray(initial)

    def read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            try:
                chunk = self._sock.recv(max(65536, n - len(self._buf)))
            except OSError as exc:
                raise ConnectionError(f"socket read failed: {exc}") from None
            if not chunk:
                raise ConnectionError("peer closed the connection")
            self._buf.extend(chunk)
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data
