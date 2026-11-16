"""Runnable example: start an echo server, talk to it, shut down.

Run with:  python demo.py
"""

import base64
import os
import socket

from websocket_server import (
    OP_CLOSE,
    OP_PING,
    OP_TEXT,
    Frame,
    FrameReader,
    WebSocketServer,
    compute_accept,
    encode_close_payload,
    encode_frame,
    parse_close_payload,
)


def client_session(host: str, port: int) -> None:
    sock = socket.create_connection((host, port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    sock.sendall(
        (
            f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("latin-1")
    )
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        head += sock.recv(4096)
    print("handshake ->", head.decode("latin-1").split("\r\n")[0])
    print("accept ok ->", compute_accept(key) in head.decode("latin-1"))

    buf = bytearray()

    def read_exact(n: int) -> bytes:
        while len(buf) < n:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            buf.extend(chunk)
        data = bytes(buf[:n])
        del buf[:n]
        return data

    reader = FrameReader(read_exact, require_mask=False)

    sock.sendall(encode_frame(Frame(OP_TEXT, b"hello, websocket"), mask=True))
    frame = reader.read()
    print("echo      ->", frame.payload.decode())

    sock.sendall(encode_frame(Frame(OP_PING, b"tick"), mask=True))
    frame = reader.read()
    print("ping/pong ->", frame.payload.decode())

    sock.sendall(encode_frame(Frame(OP_CLOSE, encode_close_payload(1000, "bye")), mask=True))
    code, reason = parse_close_payload(reader.read().payload)
    print(f"close     -> code={code} reason={reason!r}")
    sock.close()


def main() -> None:
    with WebSocketServer() as server:
        print(f"listening on ws://127.0.0.1:{server.port}/")
        client_session("127.0.0.1", server.port)
        print(f"connections={server.connection_count}")


if __name__ == "__main__":
    main()
