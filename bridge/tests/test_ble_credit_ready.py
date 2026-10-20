"""Credit tail flush / window hint, STATUS ble_ready wait and hello retry."""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import bluetooth_bridge  # noqa: E402
from ble_link import PKT_BENCH, PKT_BENCH_RESET, BleLink, BleLinkError  # noqa: E402
from bluetooth_bridge import AsyncDtuClient, BleSyncError, ble_hello, wait_link_ready  # noqa: E402
from dotii_ble_fakes import FakeDotiiFirmware  # noqa: E402
from dotii_test_support import temporary_directory  # noqa: E402
from dtu_protocol import DtuSession  # noqa: E402
from test_ble_sync import FAST, TOKEN, Harness, wait_until  # noqa: E402

CHUNK = 242
TOTAL = 65536  # 271 packets of 242 B: a 3-packet tail after every 4th-packet credit


async def bench_stream(firmware: FakeDotiiFirmware, window_packets: int) -> BleLink:
    link = BleLink(firmware.write, chunk=CHUNK, window=CHUNK * window_packets)
    firmware.attach(link.on_notify)
    await link.reset(bench=True)
    await asyncio.wait_for(link.send_stream(b"\xa5" * TOTAL, kind=PKT_BENCH), 10)
    await link.drain(timeout=1.0)
    return link


class CreditTailTests(unittest.IsolatedAsyncioTestCase):
    async def test_271_packets_drain_for_every_window(self):
        for window in (2, 4, 8, 16):
            with self.subTest(window=window):
                firmware = FakeDotiiFirmware(credit_delay=0.001)
                link = await bench_stream(firmware, window)
                self.assertEqual(firmware.bench_bytes, TOTAL)
                self.assertEqual(link.credits.in_flight, 0)
                self.assertLessEqual(firmware.max_in_flight, CHUNK * window)
                self.assertEqual(firmware.credit_every, max(1, min(4, window // 2)))

    async def test_tail_flush_alone_unblocks_older_hosts(self):
        # Firmware ignoring the hint (credits every 4): the 20 ms flush keeps
        # window 2 moving and acknowledges the 3-packet tail.
        for window in (2, 4, 8, 16):
            with self.subTest(window=window):
                firmware = FakeDotiiFirmware(honor_window_hint=False)
                await bench_stream(firmware, window)
                self.assertEqual(firmware.bench_bytes, TOTAL)
                self.assertGreater(firmware.flushes, 0)

    async def test_without_flush_the_tail_stalls(self):
        # Documents the bug on the board before this fix (credits every 4, no flush).
        firmware = FakeDotiiFirmware(honor_window_hint=False, flush_ms=None)
        with self.assertRaisesRegex(BleLinkError, "credit_timeout"):
            await bench_stream(firmware, 8)
        self.assertEqual(firmware.bench_bytes, TOTAL)

    async def test_window_hint_is_sent_in_reset(self):
        writes = []

        async def write(packet, response):
            writes.append(bytes(packet))

        link = BleLink(write, chunk=CHUNK, window=CHUNK * 2)
        await link.reset(bench=True)
        self.assertEqual(writes[-1], bytes((PKT_BENCH_RESET, 0, 2)))
        link.credits.window = CHUNK * 16
        await link.reset()
        self.assertEqual(writes[-1][2], 16)

    async def test_reset_without_hint_restores_default(self):
        firmware = FakeDotiiFirmware()
        await firmware.write(bytes((PKT_BENCH_RESET, 0, 2)), True)
        self.assertEqual(firmware.credit_every, 1)
        await firmware.write(bytes((PKT_BENCH_RESET, 0)), True)
        self.assertEqual(firmware.credit_every, 4)


class ReadyTests(unittest.IsolatedAsyncioTestCase):
    async def test_waits_for_ble_ready(self):
        firmware = FakeDotiiFirmware(ready_after_reads=3)

        async def read():
            return bytearray(firmware.status())

        self.assertIs(await wait_link_ready(read, timeout=2, interval=0.01), True)
        self.assertEqual(firmware.status_reads, 4)

    async def test_times_out_when_never_ready(self):
        firmware = FakeDotiiFirmware(ready_after_reads=10_000)

        async def read():
            return bytearray(firmware.status())

        self.assertIs(await wait_link_ready(read, timeout=0.1, interval=0.01), False)

    async def test_legacy_firmware_settles(self):
        firmware = FakeDotiiFirmware(legacy_status=True)

        async def read():
            return bytearray(firmware.status())

        self.assertIsNone(await wait_link_ready(read, timeout=2, interval=0.01, legacy_settle=0.01))
        self.assertEqual(firmware.status_reads, 1)

    async def test_read_errors_are_retried(self):
        firmware = FakeDotiiFirmware()
        calls = []

        async def read():
            calls.append(1)
            if len(calls) < 3:
                raise OSError("Encryption is insufficient")
            return bytearray(firmware.status())

        self.assertIs(await wait_link_ready(read, timeout=2, interval=0.01), True)
        self.assertEqual(len(calls), 3)


def drop_first_hello_reply(firmware: FakeDotiiFirmware, drops: int = 1) -> list[int]:
    original = firmware._send
    dropped: list[int] = []

    def send(message):
        if "challenge" in message and len(dropped) < drops:
            dropped.append(message.get("id", 0))
            return
        original(message)

    firmware._send = send  # type: ignore[method-assign]
    return dropped


class HelloRetryTests(unittest.IsolatedAsyncioTestCase):
    async def rpc(self, firmware: FakeDotiiFirmware) -> AsyncDtuClient:
        link = BleLink(firmware.write, chunk=CHUNK)
        firmware.attach(link.on_notify)
        await link.reset()
        return AsyncDtuClient(link, DtuSession(), timeout=0.2)

    async def test_hello_is_retried_once_on_timeout(self):
        firmware = FakeDotiiFirmware()
        dropped = drop_first_hello_reply(firmware)
        hello = await ble_hello(await self.rpc(firmware))
        self.assertEqual(len(dropped), 1)
        self.assertEqual(hello["device_id"], "AABBCCDDEEFF")
        self.assertEqual([r["op"] for r in firmware.requests], ["hello", "hello"])

    async def test_second_timeout_is_reported(self):
        firmware = FakeDotiiFirmware()
        drop_first_hello_reply(firmware, drops=2)
        with self.assertRaisesRegex(BleSyncError, "timeout"):
            await ble_hello(await self.rpc(firmware))
        self.assertEqual(len(firmware.requests), 2)


class WorkerReadyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder_context = temporary_directory()
        self.folder = Path(self.folder_context.__enter__())
        self.patches = [mock.patch.object(bluetooth_bridge, name, value) for name, value in FAST.items()]
        for patch in self.patches:
            patch.start()

    async def asyncTearDown(self):
        for patch in self.patches:
            patch.stop()
        self.folder_context.__exit__(None, None, None)

    async def run_worker(self, harness: Harness):
        task = asyncio.create_task(harness.worker._main())

        async def stop():
            harness.worker.stop_event.set()
            harness.worker.poke()
            await asyncio.wait_for(task, 5)

        self.addAsyncCleanup(stop)

    async def test_worker_sends_hello_only_after_ble_ready(self):
        firmware = FakeDotiiFirmware(token=TOKEN, ready_after_reads=3)
        reads_at_hello = []
        original = firmware.handle

        def handle(request):
            if request.get("op") == "hello":
                reads_at_hello.append(firmware.status_reads)
            return original(request)

        firmware.handle = handle  # type: ignore[method-assign]
        harness = Harness(self.folder, firmware=firmware)
        await self.run_worker(harness)
        await wait_until(lambda: harness.worker.status()["state"] == "connected", timeout=5)
        self.assertEqual(reads_at_hello[0], 4)

    async def test_worker_survives_one_lost_hello_reply(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        dropped = drop_first_hello_reply(firmware)
        harness = Harness(self.folder, firmware=firmware)
        await self.run_worker(harness)
        await wait_until(lambda: harness.worker.status()["state"] == "connected", timeout=8)
        self.assertEqual(len(dropped), 1)
        self.assertEqual(harness.worker.status()["reconnects"], 1)  # same connection, no reconnect cycle


if __name__ == "__main__":
    unittest.main()
