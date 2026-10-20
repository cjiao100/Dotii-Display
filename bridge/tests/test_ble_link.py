from __future__ import annotations

import asyncio
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ble_link import (  # noqa: E402
    PKT_BENCH, PKT_CREDIT, PKT_DATA, PKT_NAK, PKT_RESET, BleLink, BleLinkError, CreditWindow, packetize,
    parse_credit, payload_size,
)
from dotii_ble_fakes import FakeDotiiFirmware  # noqa: E402
from dtu_protocol import encode_compressed_frame, encode_frame  # noqa: E402


class PacketTests(unittest.TestCase):
    def test_payload_size_uses_mtu_and_write_without_response_limit(self):
        self.assertEqual(payload_size(247), 242)
        self.assertEqual(payload_size(185), 180)
        self.assertEqual(payload_size(527, 512), 510)
        self.assertEqual(payload_size(23), 18)
        self.assertEqual(payload_size(10), 18)  # never below the 23-byte ATT minimum

    def test_packetize_sequences_wrap_and_preserve_stream(self):
        stream = bytes(range(256)) * 5
        packets, next_seq = packetize(stream, 100, 250)
        self.assertEqual([p[1] for p in packets[:8]], [250, 251, 252, 253, 254, 255, 0, 1])
        self.assertEqual(next_seq, (250 + len(packets)) & 0xFF)
        self.assertTrue(all(p[0] == PKT_DATA for p in packets))
        self.assertEqual(b"".join(p[2:] for p in packets), stream)
        self.assertTrue(all(len(p) <= 102 for p in packets))

    def test_credit_parsing(self):
        credit = parse_credit(bytes((0x10, 0x27, 0, 0, 7, 3)))
        self.assertEqual((credit.received, credit.expected_seq, credit.queue_free), (10000, 7, 3))
        with self.assertRaises(ValueError):
            parse_credit(b"\x00")


class CreditWindowTests(unittest.TestCase):
    def test_window_limits_in_flight_and_ignores_stale_credits(self):
        window = CreditWindow(500)
        self.assertTrue(window.can_send(600))  # one packet always allowed when idle
        window.on_sent(300)
        self.assertTrue(window.can_send(200))
        self.assertFalse(window.can_send(201))
        window.on_credit(400)  # ahead of what was sent: ignored
        self.assertEqual(window.in_flight, 300)
        window.on_credit(250)
        self.assertEqual(window.in_flight, 50)
        window.on_credit(100)  # older than the last credit: ignored
        self.assertEqual(window.in_flight, 50)

    def test_counter_wraps_at_32_bits(self):
        window = CreditWindow(1000)
        window.sent = window.acked = 0xFFFFFF00
        window.on_sent(0x200)
        self.assertEqual(window.in_flight, 0x200)
        window.on_credit(0x80)
        self.assertEqual(window.in_flight, 0x80)


class LinkTests(unittest.IsolatedAsyncioTestCase):
    async def test_write_without_response_never_exceeds_window(self):
        firmware = FakeDotiiFirmware(credit_delay=0.001)
        link = BleLink(firmware.write, chunk=242, window=242 * 4)
        firmware.attach(link.on_notify)
        await link.reset()
        frame = encode_compressed_frame({"id": 1, "op": "ble_diag", "pad": "x" * 30000})
        await link.send_stream(frame)
        await link.drain()
        self.assertLessEqual(firmware.max_in_flight, 242 * 4)
        self.assertEqual(firmware.requests[-1]["op"], "ble_diag")
        self.assertEqual(firmware.received_bytes, len(frame))
        self.assertFalse(firmware.used_response_for_data)

    async def test_write_with_response_mode(self):
        firmware = FakeDotiiFirmware()
        link = BleLink(firmware.write, chunk=100, with_response=True)
        firmware.attach(link.on_notify)
        await link.reset()
        await link.send_stream(encode_frame({"id": 1, "op": "ble_diag"}))
        self.assertTrue(firmware.used_response_for_data)
        self.assertEqual(firmware.requests[-1]["op"], "ble_diag")

    async def test_credit_stall_raises(self):
        firmware = FakeDotiiFirmware(send_credits=False)
        link = BleLink(firmware.write, chunk=50, window=100)
        firmware.attach(link.on_notify)
        await link.reset()
        with self.assertRaisesRegex(BleLinkError, "credit_timeout"):
            await asyncio.wait_for(link.send_stream(b"x" * 500), 10)

    async def test_nak_aborts_stream(self):
        writes = []

        async def write(packet, response):
            writes.append(packet)

        link = BleLink(write, chunk=10, window=10_000)
        link.on_notify(None, bytes((PKT_NAK, 0, 3, 5)))
        with self.assertRaisesRegex(BleLinkError, "sequence_gap"):
            await link.send_stream(b"y" * 50)
        await link.reset()
        self.assertEqual(writes[-1], bytes((PKT_RESET, 0)))
        self.assertIsNone(link.error)

    async def test_notifications_reassemble_and_gap_drops_partial_frame(self):
        received = []
        link = BleLink(lambda *_: None, chunk=20, on_frames=received.extend)
        first, seq = packetize(encode_frame({"id": 1, "ok": True}), 7, 0)
        second, seq = packetize(encode_frame({"id": 2, "ok": True}), 7, seq)
        third, _ = packetize(encode_frame({"id": 3, "ok": True}), 7, seq + 1)  # one packet lost
        for packet in first + second[:2] + third:
            link.on_notify(None, packet)
        link.on_notify(None, bytes((PKT_CREDIT, 0, 0, 0, 0, 0, 0, 3)))
        self.assertEqual([item["id"] for item in received], [1, 3])
        self.assertEqual(link.rx_gaps, 1)

    async def test_bench_packets_are_counted_by_the_device(self):
        firmware = FakeDotiiFirmware()
        link = BleLink(firmware.write, chunk=200, window=800)
        firmware.attach(link.on_notify)
        await link.reset(bench=True)
        await link.send_stream(b"\0" * 4000, kind=PKT_BENCH)
        await link.drain()
        self.assertEqual(firmware.bench_bytes, 4000)
        self.assertEqual(firmware.requests, [])


    async def test_late_credit_from_previous_epoch_is_ignored(self):
        writes = []

        async def write(packet, response):
            writes.append(packet)

        link = BleLink(write, chunk=50, window=200)
        await link.reset()
        # Firmware would send CREDIT with epoch=1 after RESET; lock onto it.
        link.on_notify(None, bytes((PKT_CREDIT, 1)) + struct.pack("<I", 0) + bytes((0, 3)))
        self.assertEqual(link.credit_epoch, 1)
        link.credits.on_sent(100)
        # Late CREDIT from epoch 0 must not advance the window.
        link.on_notify(None, bytes((PKT_CREDIT, 0)) + struct.pack("<I", 100) + bytes((0, 3)))
        self.assertEqual(link.credits.in_flight, 100)
        link.on_notify(None, bytes((PKT_CREDIT, 1)) + struct.pack("<I", 100) + bytes((0, 3)))
        self.assertEqual(link.credits.in_flight, 0)


if __name__ == "__main__":
    unittest.main()
