"""Threaded WebSocket server: HTTP upgrade, then frames.

Flow per accepted TCP connection::

    read HTTP request head ──► parse_upgrade_request()
        │ invalid                       │ valid
        ▼                               ▼
    400/426 rejection, close     101 Switching Protocols
                                          │
                                          ▼
                               handler(WebSocketConnection)
                               (echo_handler by example)

The server binds an ephemeral port by default, tracks connection counts,
and shuts down cleanly by closing the listener and all client sockets
before joining its threads.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, List, Optional, Tuple

from .connection import (
    DEFAULT_MAX_MESSAGE,
    ConnectionClosed,
    SocketReader,
    WebSocketConnection,
)
from .frame import OP_CLOSE, FrameError, encode_close_payload
from .handshake import (
    HandshakeError,
    build_rejection,
    build_response,
    parse_upgrade_request,
    read_handshake_head_buffered,
)

logger = logging.getLogger("websocket_server")

#: Handler signature: receives the established connection.
Handler = Callable[[WebSocketConnection], None]


def echo_handler(conn: WebSocketConnection) -> None:
    """The canonical example handler: echo every message back.

    Returns when the peer completes the close handshake.
    """
    while True:
        message = conn.receive()
        if message is None:
            return
        conn.send(message)


class WebSocketServer:
    """A threading WebSocket server.

    Args:
        handler: called with each established :class:`WebSocketConnection`
            in its own thread; defaults to :func:`echo_handler`.
        host: bind address (default ``127.0.0.1``).
        port: bind port; ``0`` selects an ephemeral port.
        max_message: reassembly cap handed to each connection.
    """

    def __init__(
        self,
        handler: Handler = echo_handler,
        host: str = "127.0.0.1",
        port: int = 0,
        max_message: int = DEFAULT_MAX_MESSAGE,
    ):
        self.handler = handler
        self.host = host
        self.max_message = max_message
        self._sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._clients: List[socket.socket] = []
        self._threads: List[threading.Thread] = []
        self._bound_port = 0
        self.connection_count = 0

    # -- lifecycle ---------------------------------------------------------
    @property
    def port(self) -> int:
        return self._bound_port

    @property
    def address(self) -> Tuple[str, int]:
        return (self.host, self._bound_port)

    @property
    def running(self) -> bool:
        return self._sock is not None and not self._stop.is_set()

    def start(self) -> "WebSocketServer":
        if self._sock is not None:
            raise RuntimeError("server already started")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, 0))
        sock.listen(32)
        self._sock = sock
        self._bound_port = sock.getsockname()[1]
        self._stop.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="ws-accept", daemon=True
        )
        self._accept_thread.start()
        return self

    def shutdown(self, timeout: float = 5.0) -> None:
        if self._sock is None:
            return
        self._stop.set()
        sock, self._sock = self._sock, None
        try:
            sock.close()
        except OSError:
            pass
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            for fn in (lambda s=client: s.shutdown(socket.SHUT_RDWR), lambda s=client: s.close()):
                try:
                    fn()
                except OSError:
                    pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout)
            self._accept_thread = None
        with self._lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout)
        with self._lock:
            self._threads.clear()

    def __enter__(self) -> "WebSocketServer":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.shutdown()

    # -- internals ---------------------------------------------------------
    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            with self._lock:
                self.connection_count += 1
                index = self.connection_count
                self._clients.append(conn)
                thread = threading.Thread(
                    target=self._serve_client,
                    args=(conn, addr),
                    name=f"ws-conn-{index}",
                    daemon=True,
                )
                self._threads.append(thread)
            thread.start()

    def _serve_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        conn.settimeout(30.0)
        try:
            try:
                head, leftover = read_handshake_head_buffered(conn)
                upgrade = parse_upgrade_request(head)
            except HandshakeError as exc:
                try:
                    conn.sendall(build_rejection(exc.status, exc.message, exc.headers))
                except OSError:
                    pass
                return
            conn.sendall(build_response(upgrade.key, upgrade.protocol))
            reader = SocketReader(conn, initial=leftover)
            ws = WebSocketConnection(conn, reader.read_exact, max_message=self.max_message)
            try:
                self.handler(ws)
            except FrameError as exc:
                try:
                    ws.send_frame(OP_CLOSE, _close_payload(exc.close_code))
                except (FrameError, ConnectionClosed, OSError):
                    pass
                logger.debug("protocol error from %s: %s", addr, exc)
            except ConnectionClosed:
                pass
            except Exception:  # pragma: no cover - defensive
                logger.exception("handler crashed for %s", addr)
        finally:
            with self._lock:
                if conn in self._clients:
                    self._clients.remove(conn)
            try:
                conn.close()
            except OSError:
                pass


def _close_payload(code: int) -> bytes:
    """Encode a bare close code without a reason (1000 when unknown)."""
    try:
        return encode_close_payload(code)
    except ValueError:
        return encode_close_payload(1000)
