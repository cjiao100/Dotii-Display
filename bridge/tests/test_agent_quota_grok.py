"""Grok Build provider: billing parser and ACP stdio client against a fake agent."""

from __future__ import annotations

import json
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock

from dotii_test_support import temporary_directory

BRIDGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE))

from agent_quota import base  # noqa: E402
from agent_quota.base import QuotaError  # noqa: E402
from agent_quota.grok import GrokProvider, parse_billing_response  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agent_quota"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class GrokParserTests(unittest.TestCase):
    def test_weekly_credit_usage(self):
        result = parse_billing_response(fixture("grok_billing.json"))
        entry = base.normalize_result("grok", "Grok", result)
        self.assertEqual(entry["plan"], "SuperGrok Example")
        self.assertEqual(entry["windows"][0]["id"], "weekly")
        self.assertEqual(entry["used_percent"], 63.5)
        self.assertEqual(entry["reset_at_epoch"], 1792627200)
        on_demand = entry["windows"][1]
        self.assertEqual((on_demand["used"], on_demand["limit"], on_demand["unit"]), (12.5, 50.0, "USD"))
        self.assertEqual(result.extra["prepaid_balance_usd"], 20.0)
        self.assertTrue(result.extra["unified_billing"])

    def test_deprecated_fields_fallback(self):
        entry = base.normalize_result("grok", "Grok", parse_billing_response(fixture("grok_billing_legacy.json")))
        self.assertEqual(entry["used_percent"], 25.0)
        self.assertEqual(entry["windows"][0]["id"], "period")

    def test_empty_payload_raises(self):
        with self.assertRaises(QuotaError):
            parse_billing_response({"config": {}})


@unittest.skipIf(os.name != "posix", "fake CLI uses a shebang script")
class GrokAcpTests(unittest.TestCase):
    def setUp(self):
        self.folder = temporary_directory()
        self.cli = Path(self.folder.name) / "grok"
        self.cli.write_text(
            f"#!{sys.executable}\nimport runpy, sys\nrunpy.run_path({str(FIXTURES / 'fake_acp_agent.py')!r}, run_name='__main__')\n",
            encoding="utf-8")
        self.cli.chmod(self.cli.stat().st_mode | stat.S_IXUSR)

    def tearDown(self):
        self.folder.cleanup()

    def provider(self, mode, timeout=10.0):
        provider = GrokProvider()
        provider.timeout = timeout
        grok_home = Path(self.folder.name) / "grok-home"
        grok_home.mkdir(exist_ok=True)
        (grok_home / "auth.json").write_text("{}", encoding="utf-8")  # mock login marker, no token
        patcher = mock.patch.dict("os.environ", {"DOTII_GROK_COMMAND": str(self.cli), "FAKE_ACP_MODE": mode,
                                                 "GROK_HOME": str(grok_home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return provider

    def test_billing_over_acp_uses_underscore_method(self):
        provider = self.provider("ok")
        self.assertTrue(provider.detect().configured)
        entry = provider.fetch_quota()
        self.assertEqual(entry["used_percent"], 63.5)

    def test_not_logged_in_maps_to_auth_error(self):
        with self.assertRaises(QuotaError) as caught:
            self.provider("auth").fetch()
        self.assertEqual(caught.exception.status, "auth_error")

    def test_method_not_found_is_reported(self):
        with self.assertRaises(QuotaError) as caught:
            self.provider("old").fetch()
        self.assertIn("-32601", str(caught.exception))

    def test_hang_times_out(self):
        with self.assertRaises(QuotaError) as caught:
            self.provider("hang", timeout=1.5).fetch()
        self.assertEqual(caught.exception.status, "unavailable")

    def test_login_detection_checks_only_auth_file_presence(self):
        with temporary_directory() as folder:
            grok_home = Path(folder) / ".grok"
            grok_home.mkdir()
            env = {"DOTII_GROK_COMMAND": str(self.cli), "GROK_HOME": str(grok_home)}
            with mock.patch.dict("os.environ", env):
                detection = GrokProvider().detect()
                self.assertEqual((detection.available, detection.configured), (True, False))
                self.assertIn("grok login", detection.detail)
                auth = grok_home / "auth.json"
                auth.write_text("{}", encoding="utf-8")
                auth.chmod(0)  # unreadable: detection must not open it
                try:
                    detection = GrokProvider().detect()
                finally:
                    auth.chmod(0o600)
                self.assertEqual((detection.available, detection.configured), (True, True))
            with mock.patch.dict("os.environ", {"DOTII_GROK_COMMAND": str(Path(folder) / "missing"),
                                                "GROK_HOME": str(grok_home), "PATH": ""}), \
                    mock.patch("agent_quota.grok.find_executable", return_value=None):
                detection = GrokProvider().detect()
                self.assertEqual((detection.available, detection.configured, detection.detail),
                                 (False, False, "未检测到 grok CLI"))

    def test_missing_cli_is_unavailable(self):
        provider = GrokProvider()
        with mock.patch.object(GrokProvider, "executable", return_value=None):
            self.assertFalse(provider.detect().available)
            with self.assertRaises(QuotaError) as caught:
                provider.fetch()
        self.assertEqual(caught.exception.status, "unavailable")


class ProcessTreeTests(unittest.TestCase):
    @unittest.skipIf(os.name != "posix", "process groups are posix-only")
    def test_helpers_are_killed_even_after_parent_exited(self):
        import subprocess
        from agent_quota.stdio_rpc import terminate_process_tree
        from test_agent_quota_p2 import assert_process_gone
        script = ("import subprocess, sys; "
                  "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
                  "stdout=subprocess.DEVNULL); print(p.pid, flush=True)")
        process = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True,
                                   start_new_session=True)
        helper_pid = int(process.stdout.readline())
        process.wait(5)  # the parent is gone (and reaped) before cleanup runs
        terminate_process_tree(process, grace=1.0)
        assert_process_gone(self, helper_pid)

    @unittest.skipIf(os.name != "posix", "fake CLI uses a shebang script")
    def test_grok_child_does_not_inherit_dotii_keys(self):
        from agent_quota.grok import GrokProvider as Provider
        captured = {}
        real = __import__("agent_quota.stdio_rpc", fromlist=["StdioJsonRpc"]).StdioJsonRpc

        class Spy(real):
            def __init__(self, command, cwd=None, env=None):
                captured["env"] = env
                super().__init__(command, cwd=cwd, env=env)

            def start(self):
                raise QuotaError("stop here", "unavailable")

        with mock.patch.dict("os.environ", {"DOTII_KIMI_API_KEY": "dummy", "DOTII_GROK_COMMAND": sys.executable}), \
                mock.patch("agent_quota.grok.StdioJsonRpc", Spy):
            with self.assertRaises(QuotaError):
                Provider().fetch()
        self.assertIsNotNone(captured["env"])
        self.assertNotIn("DOTII_KIMI_API_KEY", captured["env"])


if __name__ == "__main__":
    unittest.main()
