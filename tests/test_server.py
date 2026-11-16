"""Live echo-server tests over real sockets: echo, fragments, ping/pong, close."""

import unittest

from websocket_server import (
    OP_BINARY,
    OP_CLOSE,
    OP_CONT,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    WebSocketServer,
)
from tests.helpers import connect


class EchoServerTests(unittest.TestCase):
    def setUp(self):
        self.server = WebSocketServer().start()
        self.addCleanup(self.server.shutdown)

    def test_text_message_echo_roundtrip(self):
        client = connect(self.server)
        self.addCleanup(client.close)
        client.send_text("hello websocket")
        frame = client.recv_frame()
        self.assertTrue(frame.fin)
        self.assertEqual(frame.opcode, OP_TEXT)
        self.assertFalse(frame.masked)  # server frames are never masked
        self.assertEqual(frame.payload, b"hello websocket")

    def test_binary_message_echo_roundtrip(self):
        client = connect(self.server)
        self.addCleanup(client.close)
        payload = bytes(range(256))
        client.send_binary(payload)
        frame = client.recv_frame()
        self.assertEqual(frame.opcode, OP_BINARY)
        self.assertEqual(frame.payload, payload)

    def test_fragmented_message_reassembled_into_one_frame(self):
        client = connect(self.server)
        self.addCleanup(client.close)
        # three fragments: "Hel" + "lo, " + "fragments!"
        client.send_frame(OP_TEXT, b"Hel", fin=False)
        client.send_frame(OP_CONT, b"lo, ", fin=False)
        client.send_frame(OP_CONT, b"fragments!", fin=True)
        echoed = client.recv_frame()
        self.assertTrue(echoed.fin, "server must echo a single complete frame")
        self.assertEqual(echoed.opcode, OP_TEXT)
        self.assertEqual(echoed.payload, b"Hello, fragments!")

    def test_ping_is_answered_with_matching_pong(self):
        client = connect(self.server)
        self.addCleanup(client.close)
        client.send_frame(OP_PING, b"are-you-there")
        pong = client.recv_frame()
        self.assertEqual(pong.opcode, OP_PONG)
        self.assertEqual(pong.payload, b"are-you-there")
        # connection still alive afterwards
        client.send_text("still-here")
        self.assertEqual(client.recv_frame().payload, b"still-here")

    def test_close_frame_completes_handshake(self):
        client = connect(self.server)
        self.addCleanup(client.close)
        client.send_close(1000, "bye")
        code, reason = client.recv_close()
        self.assertEqual(code, 1000)
        self.assertEqual(reason, "bye")
        # after echoing close, the server drops the TCP connection
        self.assertTrue(client.is_eof())

    def test_large_messages_use_both_extended_length_paths(self):
        client = connect(self.server)
        self.addCleanup(client.close)
        # 16-bit path (256..65535)
        medium = b"m" * 5000
        client.send_text(medium.decode())
        self.assertEqual(client.recv_frame().payload, medium)
        # 64-bit path (>65535)
        large = b"L" * 70000
        client.send_binary(large)
        frame = client.recv_frame()
        self.assertEqual(len(frame.payload), 70000)
        self.assertEqual(frame.payload, large)

    def test_unmasked_client_frame_triggers_close_1002(self):
        client = connect(self.server)
        self.addCleanup(client.close)
        client.send_frame(OP_TEXT, b"not-masked", masked=False)
        code, _ = client.recv_close()
        self.assertEqual(code, 1002)
        self.assertTrue(client.is_eof())

    def test_connection_count_tracked_per_socket(self):
        first = connect(self.server)
        second = connect(self.server)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        first.send_text("a")
        second.send_text("b")
        self.assertEqual(first.recv_frame().payload, b"a")
        self.assertEqual(second.recv_frame().payload, b"b")
        self.assertEqual(self.server.connection_count, 2)
        self.assertTrue(self.server.running)


class CustomHandlerTests(unittest.TestCase):
    def test_custom_handler_runs_per_connection(self):
        seen = []

        def handler(conn):
            while True:
                message = conn.receive()
                if message is None:
                    return
                seen.append(message.text)
                conn.send_text(f"got:{message.text}")

        server = WebSocketServer(handler=handler).start()
        self.addCleanup(server.shutdown)
        client = connect(server)
        self.addCleanup(client.close)
        client.send_text("alpha")
        self.assertEqual(client.recv_frame().payload, b"got:alpha")
        client.send_text("beta")
        self.assertEqual(client.recv_frame().payload, b"got:beta")
        self.assertEqual(seen, ["alpha", "beta"])


class ServerLifecycleTests(unittest.TestCase):
    def test_graceful_shutdown_stops_server(self):
        server = WebSocketServer().start()
        client = connect(server)
        client.send_text("last")
        self.assertEqual(client.recv_frame().payload, b"last")
        server.shutdown()
        self.assertFalse(server.running)
        with self.assertRaises(OSError):
            import socket

            probe = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            probe.close()
        client.close()
        server.shutdown()  # idempotent

    def test_two_clients_do_not_share_messages(self):
        server = WebSocketServer().start()
        self.addCleanup(server.shutdown)
        alice = connect(server)
        bob = connect(server)
        self.addCleanup(alice.close)
        self.addCleanup(bob.close)
        alice.send_text("private-for-alice")
        self.assertEqual(alice.recv_frame().payload, b"private-for-alice")
        # if messages were broadcast, bob's next frame would be alice's
        # message instead of the echo of his own
        bob.send_text("mine")
        self.assertEqual(bob.recv_frame().payload, b"mine")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
