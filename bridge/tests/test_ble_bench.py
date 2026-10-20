"""scripts/ble_bench.py auth helper against the in-memory firmware model."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from ble_link import BleLink  # noqa: E402
from bluetooth_bridge import AsyncDtuClient, verify_device_mac, ble_auth_mac  # noqa: E402
from dotii_ble_fakes import FakeDotiiFirmware  # noqa: E402
from dotii_test_support import temporary_directory  # noqa: E402
from dtu_protocol import DtuSession  # noqa: E402

TOKEN = "synthetic-test-token-0001"


def load_bench():
    spec = importlib.util.spec_from_file_location("ble_bench_under_test", ROOT / "scripts" / "ble_bench.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bench = load_bench()


async def session(firmware: FakeDotiiFirmware):
    link = BleLink(firmware.write, chunk=242)
    firmware.attach(link.on_notify)
    rpc = AsyncDtuClient(link, DtuSession(), timeout=2)
    await link.reset()
    return rpc


class BenchAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_bound_with_token_authenticates_mutually(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        rpc = await session(firmware)
        summary = await bench.authenticate(rpc, TOKEN)
        self.assertTrue(summary["authenticated"])
        self.assertTrue(summary["diag_allowed"])
        auth = [r for r in firmware.requests if r.get("op") == "auth"][0]
        self.assertRegex(auth["host_nonce"], r"^[0-9a-f]{32}$")
        self.assertNotIn("token", auth)
        self.assertNotIn(TOKEN, json.dumps(summary))
        diag = await rpc.call("ble_diag")
        self.assertIn("ble", diag)

    async def test_bound_without_token_explains_and_skips_diag(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        rpc = await session(firmware)
        summary = await bench.authenticate(rpc, "")
        self.assertFalse(summary["diag_allowed"])
        self.assertIn("--token-file", summary["note"])
        self.assertFalse(any(r.get("op") == "auth" for r in firmware.requests))

    async def test_unbound_allows_diag_without_auth(self):
        firmware = FakeDotiiFirmware(token=TOKEN, bound=False)
        rpc = await session(firmware)
        summary = await bench.authenticate(rpc, "")
        self.assertTrue(summary["diag_allowed"])
        self.assertFalse(summary["authenticated"])
        self.assertTrue((await rpc.call("ble_diag"))["ok"])

    async def test_wrong_token_reports_binding_mismatch(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        rpc = await session(firmware)
        summary = await bench.authenticate(rpc, "another-synthetic-token")
        self.assertEqual(summary["error"], "binding_mismatch")
        self.assertFalse(summary["diag_allowed"])

    async def test_impostor_without_device_proof_is_rejected(self):
        firmware = FakeDotiiFirmware(token=TOKEN)
        original = firmware.handle

        def no_proof(request):
            reply = original(request)
            reply.pop("device_mac", None)
            return reply

        firmware.handle = no_proof  # type: ignore[method-assign]
        rpc = await session(firmware)
        summary = await bench.authenticate(rpc, TOKEN)
        self.assertEqual(summary["error"], "device_impersonation")
        self.assertFalse(summary["authenticated"])


class BenchHelperTests(unittest.TestCase):
    def test_verify_device_mac(self):
        nonce = "ab" * 16
        good = ble_auth_mac(TOKEN, "AABBCCDDEEFF", nonce)
        self.assertTrue(verify_device_mac(TOKEN, "AABBCCDDEEFF", nonce, good))
        self.assertFalse(verify_device_mac(TOKEN, "AABBCCDDEEFF", nonce, "00" * 32))
        self.assertFalse(verify_device_mac(TOKEN, "AABBCCDDEEFF", nonce, None))
        self.assertFalse(verify_device_mac(TOKEN, "112233445566", nonce, good))

    def test_encryption_error_detection(self):
        error = Exception('Failed to update the notification status for characteristic 24: Error '
                          'Domain=CBATTErrorDomain Code=15 "Encryption is insufficient."')
        self.assertTrue(bench.is_encryption_error(error))
        self.assertFalse(bench.is_encryption_error(Exception("Device disconnected")))
        self.assertIn("System Settings > Bluetooth", bench.ENCRYPTION_HINT)

    def test_token_file_is_validated_without_echoing(self):
        with temporary_directory() as folder:
            path = Path(folder) / "token"
            path.write_text(TOKEN + "\n", encoding="utf-8")
            self.assertEqual(bench.read_token(str(path)), TOKEN)
            path.write_text("short", encoding="utf-8")
            with self.assertRaises(SystemExit) as raised:
                bench.read_token(str(path))
            self.assertNotIn("short", str(raised.exception))
            with self.assertRaises(SystemExit):
                bench.read_token(str(Path(folder) / "missing"))
        self.assertEqual(bench.read_token(None), "")

    def test_nonzero_return_codes(self):
        self.assertEqual(bench.nonzero_return_codes({"dle_request_rc": 0, "mtu_request_rc": 8, "security_rc": 0}),
                         {"mtu_request_rc": 8})


if __name__ == "__main__":
    unittest.main()
