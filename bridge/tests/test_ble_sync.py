from __future__ import annotations

import asyncio
import re
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

BRIDGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import bluetooth_bridge  # noqa: E402
from bluetooth_bridge import BLEAK_REQUIREMENT, BluetoothBridge, BleSyncWorker, ble_auth_mac  # noqa: E402
from connection_settings import ConnectionSettings  # noqa: E402
from dotii_ble_fakes import FakeBleakClient, FakeDotiiFirmware  # noqa: E402
from dotii_test_support import temporary_directory  # noqa: E402
from platforms.macos import MacOSPlatformAdapter  # noqa: E402
from platforms.windows import WindowsPlatformAdapter  # noqa: E402

TOKEN = "local-test-token-0001"
FAST = {
    "SYNC_HEARTBEAT_SECONDS": 0.15,
    "SYNC_MIN_SNAPSHOT_SECONDS": 0.0,
    "SYNC_FULL_REFRESH_SECONDS": 30.0,
    "SYNC_STATUS_SECONDS": 0.1,
    "SYNC_TICK_SECONDS": 0.02,
    "SYNC_REQUEST_TIMEOUT": 2.0,
}


def sample_snapshot(text: str = "hello") -> dict:
    return {
        "generated_at_epoch": int(time.time() * 1000),
        "codex": {"task": {"title": "Build", "last_user_message": text}, "tasks": []},
        "custom": {"image_available": True},
    }


class Harness:
    def __init__(self, folder: Path, *, firmware: FakeDotiiFirmware, mode: str = "auto", device_id: str = ""):
        self.connections = ConnectionSettings(folder / "connection.json")
        self.connections.write({"mode": mode, "device_id": device_id})
        self.server = SimpleNamespace(
            token=TOKEN,
            connections=self.connections,
            usb=SimpleNamespace(snapshot=lambda: {"state": "idle", "last_sync": 0}),
            wifi_data_seen={},
            snapshot=lambda: self.current,
            bambu=SimpleNamespace(command=lambda action: None),
        )
        self.current = sample_snapshot()
        self.bridge = BluetoothBridge(folder, platform_adapter=MacOSPlatformAdapter())
        self.bridge.last_address = "8F3D0000-AAAA-BBBB-CCCC-000000000001"
        self.bridge.dependency_ready = lambda: True
        FakeBleakClient.firmware = firmware
        FakeBleakClient.instances = []
        self.bridge._bleak = lambda: (FakeBleakClient, None)
        self.bridge.attach_sync(self.server, start=False)
        self.worker: BleSyncWorker = self.bridge.sync


async def wait_until(predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)


class AuthTests(unittest.TestCase):
    def test_hmac_matches_firmware_message_layout(self):
        mac = ble_auth_mac("abc", "AABBCCDDEEFF", "00" * 16)
        self.assertRegex(mac, r"^[0-9a-f]{64}$")
        import hashlib, hmac
        expected = hmac.new(b"abc", b"dotii-ble-auth-v1|AABBCCDDEEFF|" + b"00" * 16, hashlib.sha256).hexdigest()
        self.assertEqual(mac, expected)
        self.assertNotEqual(mac, ble_auth_mac("abc", "AABBCCDDEEFF", "01" * 16))

    def test_bleak_constraint_is_unified(self):
        root = BRIDGE.parent
        self.assertIn(BLEAK_REQUIREMENT, (BRIDGE / "requirements.txt").read_text())
        for path in (root / "packaging" / "requirements-build.txt", root / "packaging" / "macos" / "requirements.txt"):
            if path.exists():
                pins = re.findall(r"^bleak==([0-9.]+)", path.read_text(), re.M)
                self.assertEqual(pins, ["3.0.2"], path)
        self.assertNotIn("bleak>=1.0", (BRIDGE / "bluetooth_bridge.py").read_text())

    def test_connection_settings_accept_ble_mode(self):
        with temporary_directory() as folder:
            settings = ConnectionSettings(Path(folder) / "c.json")
            self.assertEqual(settings.write({"mode": "ble"})["mode"], "ble")
            self.assertEqual(settings.device()["connection_mode"], "ble")
            with self.assertRaises(ValueError):
                settings.write({"mode": "zigbee"})


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.folder_context = temporary_directory()
        self.folder = Path(self.folder_context.__enter__())
        self.harness = Harness(self.folder, firmware=FakeDotiiFirmware(), device_id="AABBCCDDEEFF")

    def tearDown(self):
        self.folder_context.__exit__(None, None, None)

    def test_priority_usb_then_wifi_then_ble(self):
        worker, server = self.harness.worker, self.harness.server
        self.assertEqual(worker.desired(), (True, ""))
        server.wifi_data_seen["AABBCCDDEEFF"] = time.time()
        self.assertEqual(worker.desired(), (False, "wifi_active"))
        worker.connected = True  # an established session is not dropped for a Wi-Fi blip
        self.assertEqual(worker.desired(), (True, ""))
        server.usb.snapshot = lambda: {"state": "connected", "last_sync": time.time()}
        self.assertEqual(worker.desired(), (False, "usb_active"))
        server.usb.snapshot = lambda: {"state": "connected", "last_sync": time.time() - 60}
        self.assertEqual(worker.desired(), (True, ""))

    def test_explicit_modes(self):
        worker, server, connections = self.harness.worker, self.harness.server, self.harness.connections
        server.usb.snapshot = lambda: {"state": "connected", "last_sync": time.time()}
        connections.write({"mode": "ble"})
        self.assertEqual(worker.desired(), (True, ""))
        for mode in ("usb", "wifi"):
            connections.write({"mode": mode})
            self.assertEqual(worker.desired(), (False, "mode_disabled"))

    def test_preconditions(self):
        worker, bridge = self.harness.worker, self.harness.bridge
        bridge.last_address = ""
        self.assertEqual(worker.desired(), (False, "no_device"))
        bridge.last_address = "x"
        bridge.dependency_ready = lambda: False
        self.assertEqual(worker.desired(), (False, "bluetooth_component_missing"))
        windows = BluetoothBridge(self.folder / "w", platform_adapter=WindowsPlatformAdapter())
        self.assertFalse(windows.sync_supported)
        windows.attach_sync(self.harness.server)
        self.assertIsNone(windows.sync.thread)
        self.assertEqual(windows.snapshot()["sync"]["state"], "idle")


class SessionTests(unittest.IsolatedAsyncioTestCase):
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

    async def start(self, harness: Harness):
        task = asyncio.create_task(harness.worker._main())
        self.addAsyncCleanup(self.stop, harness, task)
        return task

    async def stop(self, harness: Harness, task: asyncio.Task):
        harness.worker.stop_event.set()
        harness.worker.poke()
        await asyncio.wait_for(task, 5)
        self.assertFalse(harness.bridge.operation_lock.locked())

    async def test_handshake_snapshot_heartbeat_and_status(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        harness = Harness(self.folder, firmware=firmware)
        await self.start(harness)
        await wait_until(lambda: firmware.snapshots and firmware.heartbeats >= 2)
        status = harness.worker.status()
        self.assertEqual(status["state"], "connected")
        self.assertEqual((status["device_id"], status["mtu"], status["chunk"]), ("AABBCCDDEEFF", 247, 242))
        self.assertEqual(harness.connections.read()["device_id"], "AABBCCDDEEFF")  # bound on first auth
        sent = firmware.snapshots[0]
        self.assertFalse(sent["snapshot"]["custom"]["image_available"])
        self.assertEqual(sent["connection_mode"], "auto")
        self.assertTrue(all("token" not in request for request in firmware.requests))
        self.assertEqual([r["op"] for r in firmware.requests[:3]], ["hello", "auth", "snapshot"])
        self.assertTrue(harness.bridge.operation_lock.locked())
        await wait_until(lambda: harness.bridge.snapshot()["device_connected"])

    async def test_send_on_change_only(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        harness = Harness(self.folder, firmware=firmware)
        await self.start(harness)
        await wait_until(lambda: firmware.heartbeats >= 2)
        self.assertEqual(len(firmware.snapshots), 1)
        harness.current = {**sample_snapshot("hello"), "generated_at_epoch": 1}  # timestamp only
        await wait_until(lambda: firmware.heartbeats >= 4)
        self.assertEqual(len(firmware.snapshots), 1)
        harness.current = sample_snapshot("changed")
        await wait_until(lambda: len(firmware.snapshots) == 2)
        self.assertEqual(firmware.snapshots[1]["snapshot"]["codex"]["task"]["last_user_message"], "changed")

    async def test_want_data_event_gates_snapshots(self):
        firmware = FakeDotiiFirmware(token=TOKEN, want_data=False)
        harness = Harness(self.folder, firmware=firmware)
        await self.start(harness)
        await wait_until(lambda: firmware.heartbeats >= 2)
        self.assertEqual(firmware.snapshots, [])
        firmware.want_data = True
        firmware.push_event(event="want_data", want_data=True, mode="auto")
        await wait_until(lambda: len(firmware.snapshots) == 1)
        self.assertTrue(harness.worker.status()["want_data"])

    async def test_auth_failures_are_reported_and_backed_off(self):
        cases = [
            (dict(token="another-token-000000"), "", "binding_mismatch"),
            (dict(token=TOKEN, bound=False), "", "not_bound"),
            (dict(token=TOKEN), "112233445566", "different_device"),
        ]
        for options, device_id, code in cases:
            with self.subTest(code=code):
                firmware = FakeDotiiFirmware(**options)
                harness = Harness(self.folder / code, firmware=firmware, device_id=device_id)
                task = await self.start(harness)
                await wait_until(lambda: harness.worker.status()["state"] == "error")
                self.assertEqual(harness.worker.status()["detail"], code)
                self.assertEqual(firmware.snapshots, [])
                await asyncio.sleep(0.3)
                self.assertEqual(len(FakeBleakClient.instances), 1)  # 2 s backoff, no reconnect storm
                self.assertFalse(FakeBleakClient.instances[0].is_connected)
                await self.stop(harness, task)

    async def test_old_firmware_without_data_characteristics(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        harness = Harness(self.folder, firmware=firmware)
        with mock.patch.object(FakeBleakClient, "has_data_characteristics", False):
            await self.start(harness)
            await wait_until(lambda: harness.worker.status()["state"] == "error")
        self.assertEqual(harness.worker.status()["detail"], "firmware_update_required")

    async def test_disconnect_reconnects(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        harness = Harness(self.folder, firmware=firmware)
        await self.start(harness)
        await wait_until(lambda: harness.worker.status()["state"] == "connected")
        await FakeBleakClient.instances[0].disconnect()
        await wait_until(lambda: len(FakeBleakClient.instances) == 2, timeout=6)
        await wait_until(lambda: harness.worker.status()["state"] == "connected")
        self.assertEqual(harness.worker.status()["reconnects"], 2)

    async def test_usb_takes_over_in_auto(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        harness = Harness(self.folder, firmware=firmware)
        await self.start(harness)
        await wait_until(lambda: harness.worker.status()["state"] == "connected")
        harness.server.usb.snapshot = lambda: {"state": "connected", "last_sync": time.time()}
        await wait_until(lambda: harness.worker.status()["detail"] == "usb_active")
        await wait_until(lambda: not harness.bridge.operation_lock.locked())
        self.assertFalse(FakeBleakClient.instances[0].is_connected)

    async def test_scan_and_configure_preempt_session(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        harness = Harness(self.folder, firmware=firmware)
        await self.start(harness)
        await wait_until(lambda: harness.worker.status()["state"] == "connected")
        entered = threading.Event()

        def exclusive():
            with harness.bridge._exclusive(timeout=5):
                entered.set()
                self.assertEqual(harness.worker.desired(), (False, "paused"))

        await asyncio.wait_for(asyncio.to_thread(exclusive), 6)
        self.assertTrue(entered.is_set())
        self.assertFalse(FakeBleakClient.instances[0].is_connected)
        await wait_until(lambda: len(FakeBleakClient.instances) == 2, timeout=6)

    async def test_mutual_auth_rejects_impostor_without_device_mac(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        original = firmware.handle

        def broken_handle(request):
            reply = original(request)
            reply.pop("device_mac", None)
            return reply

        firmware.handle = broken_handle  # type: ignore[method-assign]
        harness = Harness(self.folder / "impostor", firmware=firmware)
        await self.start(harness)
        await wait_until(lambda: harness.worker.status()["state"] == "error")
        self.assertEqual(harness.worker.status()["detail"], "device_impersonation")
        self.assertFalse(harness.worker.authenticated)
        self.assertEqual(firmware.snapshots, [])

    async def test_mutual_auth_rejects_wrong_device_mac(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        original = firmware.handle

        def forged(request):
            reply = original(request)
            if "device_mac" in reply:
                reply["device_mac"] = "00" * 32
            return reply

        firmware.handle = forged  # type: ignore[method-assign]
        harness = Harness(self.folder / "forged", firmware=firmware)
        await self.start(harness)
        await wait_until(lambda: harness.worker.status()["state"] == "error")
        self.assertEqual(harness.worker.status()["detail"], "device_impersonation")

    async def test_events_ignored_before_authentication(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        harness = Harness(self.folder / "early-event", firmware=firmware)
        calls: list[str] = []
        harness.server.bambu = SimpleNamespace(command=lambda action: calls.append(action))
        real_attach = firmware.attach

        def attach_and_inject(notify):
            real_attach(notify)
            firmware.push_event(event="bambu_command", action="pause")

        firmware.attach = attach_and_inject  # type: ignore[method-assign]
        await self.start(harness)
        await wait_until(lambda: harness.worker.status()["state"] == "connected")
        await asyncio.sleep(0.2)
        self.assertEqual(calls, [])
        firmware.push_event(event="bambu_command", action="pause")
        await wait_until(lambda: calls == ["pause"])

    async def test_unauthenticated_error_reply_is_minimal(self):
        firmware = FakeDotiiFirmware(token=TOKEN, bound=True)
        reply = firmware.handle({"id": 7, "op": "snapshot", "snapshot": {}})
        self.assertEqual(reply, {"id": 7, "ok": False, "error": "unauthenticated"})
        self.assertNotIn("ssid", reply)
        self.assertNotIn("free_internal", reply)
        diag = firmware.handle({"id": 8, "op": "ble_diag"})
        self.assertEqual(diag["error"], "unauthenticated")
        self.assertNotIn("ble", diag)

    async def test_ble_diag_allowed_only_when_unbound(self):
        firmware = FakeDotiiFirmware(token=TOKEN, bound=False)
        reply = firmware.handle({"id": 1, "op": "ble_diag"})
        self.assertTrue(reply["ok"])
        self.assertIn("ble", reply)

    async def test_desired_exception_does_not_kill_worker(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        harness = Harness(self.folder / "flaky", firmware=firmware)
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] <= 2:
                raise RuntimeError("transient")
            return False, "mode_disabled"

        harness.worker.desired = flaky  # type: ignore[method-assign]
        with mock.patch.object(bluetooth_bridge, "SYNC_BACKOFF_SECONDS", (0.05, 0.05, 0.05)):
            await self.start(harness)
            await wait_until(lambda: calls["n"] >= 3, timeout=5)
        self.assertEqual(harness.worker.status()["state"], "idle")


if __name__ == "__main__":
    unittest.main()
