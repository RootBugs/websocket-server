"""Opening handshake tests: RFC vector, validation, live upgrade."""

import unittest

from websocket_server import (
    HandshakeError,
    build_response,
    compute_accept,
    parse_upgrade_request,
)
from websocket_server.handshake import build_rejection, read_handshake_head
from tests.helpers import RFC_ACCEPT, RFC_KEY, WSClient, connect


def sample_head(**overrides) -> bytes:
    headers = {
        "Host": "example.com",
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": RFC_KEY,
        "Sec-WebSocket-Version": "13",
    }
    headers.update(overrides)
    lines = ["GET /chat?room=7 HTTP/1.1"]
    lines.extend(f"{name}: {value}" for name, value in headers.items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


class HandshakeUnitTests(unittest.TestCase):
    def test_rfc_example_accept_value(self):
        # RFC 6455 §1.3 worked example — the canonical acceptance vector.
        self.assertEqual(compute_accept(RFC_KEY), RFC_ACCEPT)
        self.assertEqual(compute_accept(RFC_KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_parse_upgrade_request_fields(self):
        upgrade = parse_upgrade_request(sample_head())
        self.assertEqual(upgrade.method, "GET")
        self.assertEqual(upgrade.path, "/chat?room=7")
        self.assertEqual(upgrade.version, "HTTP/1.1")
        self.assertEqual(upgrade.key, RFC_KEY)
        self.assertEqual(compute_accept(upgrade.key), RFC_ACCEPT)

    def test_parse_rejects_missing_or_invalid_pieces(self):
        cases = [
            (sample_head(**{"Sec-WebSocket-Key": ""}), 400),
            (sample_head(**{"Sec-WebSocket-Key": "bm90IDE2IGJ5dGVzIQ=="}), 400),
            (sample_head(**{"Upgrade": "h2c"}), 400),
            (sample_head(**{"Connection": "keep-alive"}), 400),
            (sample_head(**{"Sec-WebSocket-Version": "8"}), 426),
        ]
        for head, expected_status in cases:
            with self.assertRaises(HandshakeError) as ctx:
                parse_upgrade_request(head)
            self.assertEqual(ctx.exception.status, expected_status, msg=head)
        # non-GET methods are refused outright
        bad_method = sample_head().replace(b"GET ", b"POST ")
        with self.assertRaises(HandshakeError) as ctx:
            parse_upgrade_request(bad_method)
        self.assertEqual(ctx.exception.status, 400)
        # version 8 rejection advertises the version we do speak
        with self.assertRaises(HandshakeError) as ctx:
            parse_upgrade_request(sample_head(**{"Sec-WebSocket-Version": "8"}))
        self.assertIn(("Sec-WebSocket-Version", "13"), ctx.exception.headers)

    def test_response_and_rejection_bytes(self):
        response = build_response(RFC_KEY, protocol="chat")
        text = response.decode("latin-1")
        self.assertIn("HTTP/1.1 101 Switching Protocols", text)
        self.assertIn(f"Sec-WebSocket-Accept: {RFC_ACCEPT}", text)
        self.assertIn("Sec-WebSocket-Protocol: chat", text)
        self.assertTrue(response.endswith(b"\r\n\r\n"))

        rejection = build_rejection(400, "nope")
        self.assertIn(b"HTTP/1.1 400", rejection)
        self.assertIn(b"Content-Length: 5", rejection)  # "nope\n"
        self.assertIn(b"Connection: close", rejection)

    def test_read_handshake_head_reads_exact_bytes(self):
        raw = sample_head() + b"LEFTOVER-FRAME-BYTES"
        chunks = iter(raw.decode("latin-1"))
        collected = bytearray()

        def read_exact(n: int) -> bytes:
            for _ in range(n):
                collected.extend(next(chunks).encode("latin-1"))
            return bytes(collected[-n:])

        head = read_handshake_head(read_exact)
        self.assertTrue(head.endswith(b"\r\n\r\n"))
        self.assertEqual(head, sample_head())


class LiveHandshakeTests(unittest.TestCase):
    def setUp(self):
        from websocket_server import WebSocketServer

        self.server = WebSocketServer().start()
        self.addCleanup(self.server.shutdown)

    def test_live_upgrade_computes_rfc_accept(self):
        client = connect(self.server, key=RFC_KEY, extra_headers={"Sec-WebSocket-Protocol": "chat"})
        self.assertEqual(client.status, 101)
        self.assertEqual(client.response_headers.get("sec-websocket-accept"), RFC_ACCEPT)
        self.assertEqual(client.response_headers.get("upgrade"), "websocket")
        self.assertEqual(
            client.response_headers.get("sec-websocket-protocol"), "chat"
        )
        # the connection is now usable for frames
        client.send_text("ping-after-upgrade")
        frame = client.recv_frame()
        self.assertEqual(frame.payload, b"ping-after-upgrade")
        client.close()

    def test_plain_http_request_is_rejected(self):
        import socket

        sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        try:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = sock.recv(4096).decode("latin-1")
        finally:
            sock.close()
        self.assertIn("HTTP/1.1 400", response)
        self.assertNotIn("101", response.split("\r\n")[0])

    def test_invalid_key_is_rejected_with_400(self):
        client = WSClient(
            "127.0.0.1",
            self.server.port,
            key="c2hvcnQta2V5",  # decodes to 9 bytes, not 16
            expect_upgrade=False,
        )
        self.assertEqual(client.status, 400)
        self.assertIn("Connection: close", client.handshake_response)
        client.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
