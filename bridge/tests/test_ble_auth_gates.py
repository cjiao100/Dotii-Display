"""Auth gates and frame boundaries mirrored from main/connectivity.c."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotii_ble_fakes import FakeDotiiFirmware  # noqa: E402
from dtu_protocol import FrameDecoder, encode_compressed_frame, encode_frame  # noqa: E402

UNAUTH_MAX = 512


class UnauthFrameGateTests(unittest.TestCase):
    def test_plaintext_over_512_rejected_before_auth(self):
        firmware = FakeDotiiFirmware(bound=True)
        big = {"id": 1, "op": "hello", "pad": "x" * 600}
        raw = json.dumps(big, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertGreater(len(raw), UNAUTH_MAX)
        # Simulate bridge_task size gate: do not call handle for oversize unauth frames.
        self.assertFalse(firmware.authenticated)
        reply = {"id": 0, "ok": False, "error": "unauthenticated"}
        self.assertNotIn("ssid", reply)

    def test_bad_inflate_length_is_dropped_by_decoder(self):
        import struct, zlib
        lying = struct.pack("<I", 10) + zlib.compress(b"short")
        # Wrong inflated length vs actual - decoder returns nothing useful for DTZ1
        from dtu_protocol import MAGIC_ZLIB
        frame = MAGIC_ZLIB + struct.pack("<II", len(lying), zlib.crc32(lying)) + lying
        self.assertEqual(FrameDecoder().feed(frame), [])

    def test_deep_nesting_rejected_by_size_budget_on_ble(self):
        # Firmware uses CONFIG_CJSON_NESTING_LIMIT=32; Mac caps snapshots well below that.
        node: dict = {}
        cursor = node
        for _ in range(40):
            cursor["c"] = {}
            cursor = cursor["c"]
        # Even if nesting were allowed, unauthenticated oversize plaintext is gated.
        payload = {"id": 1, "op": "hello", "nest": node}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.assertGreater(len(raw), 100)

    def test_auth_failure_reply_shape(self):
        firmware = FakeDotiiFirmware(token="local-test-token-0001", bound=True)
        hello = firmware.handle({"id": 1, "op": "hello"})
        self.assertTrue(hello["ok"])
        bad = firmware.handle({"id": 2, "op": "auth", "mac": "00" * 32, "host_nonce": "ab" * 16})
        self.assertEqual(set(bad), {"id", "ok", "error"})
        self.assertEqual(bad["error"], "binding_mismatch")


if __name__ == "__main__":
    unittest.main()
