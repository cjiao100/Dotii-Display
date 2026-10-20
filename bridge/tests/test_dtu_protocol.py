from __future__ import annotations

import struct
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dtu_protocol import (  # noqa: E402
    MAGIC_ZLIB, MAX_INFLATED, DeviceError, DtuSession, FrameDecoder, encode_compressed_frame, encode_frame,
    handle_bambu_event,
)


class CompressedFramingTests(unittest.TestCase):
    def test_compressed_round_trip_and_mixed_stream(self):
        snapshot = {"id": 3, "op": "snapshot", "text": "中文内容" * 200}
        wire = b"noise" + encode_compressed_frame(snapshot) + encode_frame({"id": 4}) + encode_compressed_frame({"id": 5})
        decoder = FrameDecoder()
        decoded = []
        for index in range(0, len(wire), 7):
            decoded.extend(decoder.feed(wire[index:index + 7]))
        self.assertEqual(decoded, [snapshot, {"id": 4}, {"id": 5}])

    def test_compressed_frame_is_smaller_and_declares_inflated_length(self):
        payload = {"text": "abc" * 1000}
        frame = encode_compressed_frame(payload)
        self.assertEqual(frame[:4], MAGIC_ZLIB)
        length, crc = struct.unpack_from("<II", frame, 4)
        inner = frame[12:]
        self.assertEqual(len(inner), length)
        self.assertEqual(zlib.crc32(inner), crc)
        self.assertEqual(struct.unpack_from("<I", inner)[0], len(encode_frame(payload)) - 12)
        self.assertLess(len(frame), len(encode_frame(payload)) // 5)

    def test_inflated_length_mismatch_and_oversize_are_dropped(self):
        body = b'{"id":1}'
        lying = struct.pack("<I", len(body) + 1) + zlib.compress(body)
        bad = MAGIC_ZLIB + struct.pack("<II", len(lying), zlib.crc32(lying)) + lying
        huge_body = b"x" * (MAX_INFLATED + 10)
        huge = struct.pack("<I", len(huge_body)) + zlib.compress(huge_body)
        oversize = MAGIC_ZLIB + struct.pack("<II", len(huge), zlib.crc32(huge)) + huge
        self.assertEqual(FrameDecoder().feed(bad + oversize + encode_frame({"id": 2})), [{"id": 2}])
        with self.assertRaises(ValueError):
            encode_compressed_frame({"data": "x" * MAX_INFLATED})


class SessionTests(unittest.TestCase):
    def test_request_ids_tokens_and_reply_matching(self):
        events = []
        session = DtuSession(lambda: "local-test-token", events.append)
        seq, packet = session.request("hello", language="en")
        self.assertEqual(packet, {"id": 1, "op": "hello", "token": "local-test-token", "language": "en"})
        seq2, packet2 = session.request("auth", include_token=False, mac="00")
        self.assertNotIn("token", packet2)
        reply = session.dispatch([{"id": 99, "ok": True}, {"event": "want_data", "want_data": True},
                                  {"id": seq2, "ok": True}], seq2)
        self.assertEqual(reply, {"id": seq2, "ok": True})
        self.assertEqual(events, [{"event": "want_data", "want_data": True}])
        self.assertIsNone(session.dispatch([{"id": seq, "ok": True}], seq2))

    def test_device_error_is_a_value_error_with_stable_code(self):
        with self.assertRaisesRegex(ValueError, "binding_mismatch"):
            DtuSession.check({"ok": False, "error": "binding_mismatch"})
        self.assertTrue(issubclass(DeviceError, ValueError))

    def test_bambu_event_is_forwarded_once_and_errors_are_contained(self):
        calls = []

        class Bambu:
            def command(self, action):
                calls.append(action)
                raise OSError("printer offline")

        server = type("Server", (), {"bambu": Bambu()})()
        handle_bambu_event(server, {"event": "bambu_command", "action": "pause"})
        handle_bambu_event(server, {"event": "want_data"})
        self.assertEqual(calls, ["pause"])


if __name__ == "__main__":
    unittest.main()
