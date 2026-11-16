"""Frame codec tests: masking, length encodings, control-frame rules."""

import struct
import unittest

from websocket_server import (
    OP_CLOSE,
    OP_PING,
    OP_TEXT,
    Frame,
    FrameError,
    FrameReader,
    apply_mask,
    encode_close_payload,
    encode_frame,
    parse_close_payload,
    parse_header,
)


def reader_for(data: bytes, require_mask=None) -> FrameReader:
    """FrameReader over an in-memory byte string."""
    state = {"offset": 0}

    def read_exact(n: int) -> bytes:
        start = state["offset"]
        if start + n > len(data):
            raise ConnectionError("out of bytes")
        state["offset"] = start + n
        return data[start : start + n]

    return FrameReader(read_exact, require_mask=require_mask)


class MaskingTests(unittest.TestCase):
    def test_mask_roundtrip_is_involutory(self):
        key = b"\x12\x34\x56\x78"
        payload = bytes(range(50))
        once = apply_mask(payload, key)
        self.assertNotEqual(once, payload)
        self.assertEqual(apply_mask(once, key), payload)

    def test_masked_frame_roundtrip(self):
        payload = b"hello, masked world"
        raw = encode_frame(Frame(OP_TEXT, payload), mask=True, mask_key=b"\xaa\xbb\xcc\xdd")
        # header: FIN+text, mask bit set, inline length
        self.assertEqual(raw[0], 0x81)
        self.assertEqual(raw[1] & 0x80, 0x80)
        self.assertEqual(raw[1] & 0x7F, len(payload))
        self.assertEqual(raw[2:6], b"\xaa\xbb\xcc\xdd")
        # masked bytes on the wire differ from the plaintext
        self.assertNotEqual(raw[6:], payload)

        frame = reader_for(raw, require_mask=True).read()
        self.assertTrue(frame.fin)
        self.assertEqual(frame.opcode, OP_TEXT)
        self.assertTrue(frame.masked)
        self.assertEqual(frame.payload, payload)

    def test_unmasked_client_frame_rejected_when_mask_required(self):
        raw = encode_frame(Frame(OP_TEXT, b"plain"), mask=False)
        with self.assertRaises(FrameError) as ctx:
            reader_for(raw, require_mask=True).read()
        self.assertIn("masked", str(ctx.exception))

    def test_masked_server_frame_rejected_when_mask_forbidden(self):
        raw = encode_frame(Frame(OP_TEXT, b"x"), mask=True, mask_key=b"1234")
        with self.assertRaises(FrameError) as ctx:
            reader_for(raw, require_mask=False).read()
        self.assertIn("not be masked", str(ctx.exception))


class LengthEncodingTests(unittest.TestCase):
    def test_inline_length_encoding(self):
        raw = encode_frame(Frame(OP_TEXT, b"short"), mask=False)
        self.assertEqual(raw[0], 0x81)
        self.assertEqual(raw[1], 5)
        self.assertEqual(raw[2:], b"short")

    def test_16_bit_length_path(self):
        payload = b"a" * 300
        raw = encode_frame(Frame(OP_TEXT, payload), mask=True, mask_key=b"\x01\x02\x03\x04")
        self.assertEqual(raw[0], 0x81)
        self.assertEqual(raw[1] & 0x7F, 126)
        self.assertEqual(struct.unpack(">H", raw[2:4])[0], 300)
        frame = reader_for(raw, require_mask=True).read()
        self.assertEqual(frame.payload, payload)
        self.assertEqual(len(frame.payload), 300)

    def test_64_bit_length_path(self):
        payload = bytes(range(256)) * 274  # 70144 bytes > 65535
        raw = encode_frame(Frame(OP_TEXT, payload), mask=False)
        self.assertEqual(raw[0], 0x81)
        self.assertEqual(raw[1] & 0x7F, 127)
        length = struct.unpack(">Q", raw[2:10])[0]
        self.assertEqual(length, len(payload))
        self.assertEqual(length >> 63, 0)  # high bit must be clear
        frame = reader_for(raw).read()
        self.assertEqual(frame.payload, payload)

    def test_high_bit_in_64_bit_length_rejected(self):
        bogus = bytes([0x81, 0x7F]) + b"\x80" + b"\x00" * 7 + b"xx"
        with self.assertRaises(FrameError):
            reader_for(bogus).read()


class ControlFrameTests(unittest.TestCase):
    def test_oversized_control_frame_rejected(self):
        # 200-byte ping: inline length byte 126, extended length 200
        raw = bytes([0x89, 0x7E]) + struct.pack(">H", 200) + b"p" * 200
        with self.assertRaises(FrameError) as ctx:
            reader_for(raw).read()
        self.assertEqual(ctx.exception.close_code, 1009)

    def test_fragmented_control_frame_rejected(self):
        raw = bytes([0x09, 0x00])  # FIN=0, ping
        with self.assertRaises(FrameError):
            reader_for(raw).read()

    def test_reserved_bits_rejected(self):
        raw = bytes([0xC1, 0x00])  # FIN + RSV1 + text
        with self.assertRaises(FrameError) as ctx:
            reader_for(raw).read()
        self.assertIn("reserved", str(ctx.exception))

    def test_unknown_opcode_rejected(self):
        raw = bytes([0x83, 0x00])  # opcode 0x3 is not defined
        with self.assertRaises(FrameError) as ctx:
            reader_for(raw).read()
        self.assertIn("unknown opcode", str(ctx.exception))


class ClosePayloadTests(unittest.TestCase):
    def test_close_payload_roundtrip(self):
        payload = encode_close_payload(1000, "bye now")
        self.assertEqual(payload[:2], b"\x03\xe8")
        code, reason = parse_close_payload(payload)
        self.assertEqual((code, reason), (1000, "bye now"))

    def test_empty_close_payload_means_no_code(self):
        self.assertEqual(parse_close_payload(b""), (None, ""))
        self.assertEqual(encode_close_payload(None), b"")

    def test_malformed_close_payloads_rejected(self):
        with self.assertRaises(FrameError):
            parse_close_payload(b"\x03")  # single byte
        with self.assertRaises(ValueError):
            encode_close_payload(1005)  # 1005 may never be sent
        with self.assertRaises(ValueError):
            encode_close_payload(999)  # below the valid range

    def test_parse_header_bits(self):
        fin, opcode, masked, length = parse_header(bytes([0x81, 0x80 | 7]))
        self.assertTrue(fin)
        self.assertEqual(opcode, OP_TEXT)
        self.assertTrue(masked)
        self.assertEqual(length, 7)

    def test_truncated_header_rejected(self):
        with self.assertRaises(FrameError):
            parse_header(b"\x81")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
