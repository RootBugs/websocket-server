# websocket-server

A from-scratch RFC 6455 WebSocket implementation: the HTTP Upgrade
handshake, the frame format (masking, extended lengths, control frames),
fragmented message reassembly, ping/pong, and the close handshake — all
on `socket` + threads, standard library only.

## Why it's special

WebSockets are usually consumed through libraries that hide the 2-byte
header and the XOR masking trick. Here everything is visible and tested:
`Sec-WebSocket-Accept` is computed with SHA-1 + base64 against the RFC's
own worked example, client frames **must** be masked (unmasked frames
close the connection with 1002), server frames must *not* be masked, and
payload lengths exercise all three encodings (7-bit, 16-bit, 64-bit).

## Architecture

```
websocket_server/
├── handshake.py    Upgrade parsing/validation, accept-value derivation
├── frame.py        Frame codec: encode/decode, masking, close payloads
├── connection.py   Message assembly, UTF-8 checks, ping/pong, close state
└── server.py       Threaded server: 101 upgrade → handler per connection
```

Design notes:

- **Strict validation.** Reserved bits (no extensions negotiated), unknown
  opcodes, fragmented control frames, control payloads > 125 bytes, 64-bit
  lengths with the high bit set, 1-byte close payloads, invalid close
  codes, and non-UTF-8 text all raise `FrameError` with the correct close
  code (1002 / 1007 / 1009) — the server then sends that close frame.
- **Reassembly.** `receive()` buffers continuation frames across a
  fragmented message and returns one complete `Message`; a new data frame
  arriving mid-message is a protocol error.
- **Close handshake.** When the peer sends close, the server echoes code
  *and* reason, marks the connection closed, and returns `None` from
  `receive()` so handlers exit cleanly.
- **Carry-over reads.** Bytes that arrive pipelined with the handshake
  are folded into the frame reader without loss.

## Runnable example

`demo.py` starts an echo server on an ephemeral port and drives a full
session — handshake, text echo, ping/pong, close:

```python
import base64, os, socket
from websocket_server import (
    OP_TEXT, Frame, FrameReader, WebSocketServer,
    compute_accept, encode_frame,
)

with WebSocketServer() as server:
    print(f"listening on ws://127.0.0.1:{server.port}/")

    sock = socket.create_connection(("127.0.0.1", server.port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((
        f"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n").encode())
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        head += sock.recv(4096)
    print("handshake ->", head.decode().split("\r\n")[0])
    print("accept ok ->", compute_accept(key) in head.decode())

    # ... then exchange masked frames and read the unmasked echoes
    sock.sendall(encode_frame(Frame(OP_TEXT, b"hello, websocket"), mask=True))
    print("echo      ->", ...)
```

Actual output of `python demo.py` (port varies per run):

```
listening on ws://127.0.0.1:52668/
handshake -> HTTP/1.1 101 Switching Protocols
accept ok -> True
echo      -> hello, websocket
ping/pong -> tick
close     -> code=1000 reason='bye'
connections=1
```

The complete, copy-pasteable session (including ping/pong and close) lives
in [`demo.py`](demo.py).

## Test coverage highlights

- `Sec-WebSocket-Accept` matches the RFC 6455 §1.3 example exactly
  (`dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`).
- Masked roundtrip; unmasked client frame → close 1002 (live socket).
- 16-bit (300-byte) and 64-bit (70 000-byte) payload paths, unit + live.
- Three-fragment message reassembled and echoed as a single FIN frame.
- Ping answered with a pong carrying the same payload.
- Close frame completes the handshake: echoed code/reason, then EOF.
- Plain HTTP and bad keys rejected with 400 during the upgrade.

## Tests

```
python -m unittest discover -s tests -v
```

36 tests. All networking tests bind port 0, run the server on threads
with clean shutdown, and drive it with a hand-rolled raw-socket client
(`tests/helpers.py`) that builds masked frames itself.

## License

MIT — see [LICENSE](LICENSE).
