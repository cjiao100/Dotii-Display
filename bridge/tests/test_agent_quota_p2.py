"""Antigravity and Qoder providers (P2): parsers and fake CLIs with synthetic data."""

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
from agent_quota.antigravity import AntigravityProvider, extract_json_document, parse_usage_report  # noqa: E402
from agent_quota.base import QuotaError  # noqa: E402
from agent_quota.qoder import QoderProvider, control_response_payload, parse_usage_info  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agent_quota"


def fake_cli(folder: Path, name: str, body: str) -> Path:
    path = folder / name
    path.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def assert_process_gone(test: unittest.TestCase, pid: int, timeout: float = 5.0) -> None:
    """The pid must disappear (or be a zombie awaiting its new parent's reap)."""
    import subprocess
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        if not state or state.startswith("Z"):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    test.fail(f"helper process {pid} was left running")


class AntigravityParserTests(unittest.TestCase):
    def test_remaining_fraction_is_converted_to_used_percent(self):
        payload = json.loads((FIXTURES / "antigravity_usage.json").read_text(encoding="utf-8"))
        result = parse_usage_report(payload)
        entry = base.normalize_result("antigravity", "Antigravity", result)
        windows = {window["id"]: window for window in entry["windows"]}
        self.assertEqual(set(windows), {"gemini_models_weekly", "gemini_models_5h", "claude_and_gpt_models_weekly"})
        self.assertEqual(windows["gemini_models_weekly"]["used_percent"], 14.0)
        self.assertEqual(windows["gemini_models_5h"]["reset_at_epoch"], 1792483200)
        self.assertEqual(entry["used_percent"], 60.0)  # most constraining enabled bucket

    def test_json_lines_output_and_failures(self):
        document = extract_json_document('{"type":"init"}\n{"status":"SUCCESS","command":{"name":"usage","data":{}}}\n')
        self.assertIn("command", document)
        with self.assertRaises(QuotaError):
            parse_usage_report(document)
        with self.assertRaises(QuotaError) as caught:
            parse_usage_report({"status": "ERROR", "response": "Please sign in to continue"})
        self.assertEqual(caught.exception.status, "auth_error")
        with self.assertRaises(QuotaError):
            extract_json_document("plain text")

    @unittest.skipIf(os.name != "posix", "fake CLI uses a shebang script")
    def test_fetch_runs_print_mode(self):
        with temporary_directory() as folder:
            fixture = FIXTURES / "antigravity_usage.json"
            cli = fake_cli(Path(folder), "agy",
                           "import os, sys\n"
                           "if sys.argv[1:] == ['--version']:\n    print('agy 1.1.12'); sys.exit(0)\n"
                           "assert sys.argv[1:5] == ['-p', '/usage', '--output-format', 'json']\n"
                           "assert 'DOTII_ZCODE_API_KEY' not in os.environ\n"
                           f"print(open({str(fixture)!r}).read())")
            with mock.patch.dict("os.environ", {"DOTII_AGY_COMMAND": str(cli), "DOTII_ZCODE_API_KEY": "dummy"}):
                provider = AntigravityProvider()
                self.assertTrue(provider.detect().configured)
                entry = provider.fetch_quota()
        self.assertEqual(entry["used_percent"], 60.0)


    @unittest.skipIf(os.name != "posix", "fake CLI uses a shebang script")
    def test_old_or_unknown_version_never_runs_usage(self):
        for version_output in ("agy 1.1.10", "agy (build unknown)"):
            with self.subTest(version_output=version_output), temporary_directory() as folder:
                marker = Path(folder) / "usage-called"
                cli = fake_cli(Path(folder), "agy",
                               "import sys\n"
                               f"if sys.argv[1:] == ['--version']:\n    print({version_output!r}); sys.exit(0)\n"
                               f"open({str(marker)!r}, 'w').write('x')\nprint('{{}}')")
                with mock.patch.dict("os.environ", {"DOTII_AGY_COMMAND": str(cli)}):
                    with self.assertRaises(QuotaError) as caught:
                        AntigravityProvider().fetch()
                self.assertEqual(caught.exception.status, "unavailable")
                self.assertIn("未执行 /usage", str(caught.exception))
                self.assertFalse(marker.exists())

    @unittest.skipIf(os.name != "posix", "process groups are posix-only")
    def test_fetch_reaps_helpers_left_after_agy_exits(self):
        with temporary_directory() as folder:
            fixture = FIXTURES / "antigravity_usage.json"
            pid_file = Path(folder) / "helper.pid"
            # The helper inherits stdout (like an MCP server would) and outlives agy.
            cli = fake_cli(Path(folder), "agy",
                           "import subprocess, sys\n"
                           "if sys.argv[1:] == ['--version']:\n    print('1.1.11'); sys.exit(0)\n"
                           "helper = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                           f"open({str(pid_file)!r}, 'w').write(str(helper.pid))\n"
                           f"print(open({str(fixture)!r}).read(), flush=True)")
            with mock.patch.dict("os.environ", {"DOTII_AGY_COMMAND": str(cli)}):
                entry = AntigravityProvider().fetch_quota()
            self.assertEqual(entry["used_percent"], 60.0)
            assert_process_gone(self, int(pid_file.read_text()))

class QoderParserTests(unittest.TestCase):
    def setUp(self):
        self.lines = (FIXTURES / "qoder_usage_info.jsonl").read_text(encoding="utf-8").splitlines()

    def test_usage_info_from_control_response(self):
        message = json.loads(self.lines[1].replace("REQUEST_ID", "r1"))
        self.assertIsNone(control_response_payload(json.loads(self.lines[0]), "r1"))
        self.assertIsNone(control_response_payload(message, "other"))
        result = parse_usage_info(control_response_payload(message, "r1"))
        entry = base.normalize_result("qoder", "Qoder", result)
        self.assertEqual(entry["plan"], "pro")
        self.assertEqual(entry["used_percent"], 35.0)
        self.assertEqual((entry["used"], entry["limit"]), (700.0, 2000.0))
        self.assertEqual(entry["windows"][1]["id"], "addon")
        self.assertFalse(result.extra["quota_exceeded"])

    def test_error_and_unknown_payloads(self):
        with self.assertRaises(QuotaError) as caught:
            control_response_payload({"type": "control_response", "response": {
                "subtype": "error", "request_id": "r1", "error": "Not logged in"}}, "r1")
        self.assertEqual(caught.exception.status, "auth_error")
        with self.assertRaises(QuotaError):
            parse_usage_info({"foo": 1})

    @unittest.skipIf(os.name != "posix", "fake CLI uses a shebang script")
    def test_fetch_over_stream_json(self):
        with temporary_directory() as folder:
            cli = fake_cli(Path(folder), "qodercli",
                           f"import runpy\nrunpy.run_path({str(FIXTURES / 'fake_qodercli.py')!r}, run_name='__main__')")
            with mock.patch.dict("os.environ", {"DOTII_QODER_COMMAND": str(cli), "FAKE_QODER_MODE": "ok"}):
                entry = QoderProvider().fetch_quota()
            self.assertEqual(entry["used_percent"], 35.0)
            with mock.patch.dict("os.environ", {"DOTII_QODER_COMMAND": str(cli), "FAKE_QODER_MODE": "error"}):
                with self.assertRaises(QuotaError) as caught:
                    QoderProvider().fetch()
            self.assertEqual(caught.exception.status, "auth_error")


class RegistryTests(unittest.TestCase):
    def test_unverified_cli_providers_default_off(self):
        from agent_quota import default_providers
        flags = {provider.id: provider.auto_enable for provider in default_providers()}
        self.assertEqual(flags, {"zcode": True, "kimi": True, "grok": True, "antigravity": False, "qoder": False})

    @unittest.skipIf(os.name != "posix", "fake CLI uses a shebang script")
    def test_detected_antigravity_and_qoder_stay_disabled(self):
        from agent_quota.manager import OPT_IN_DETAIL, AgentQuotaConfigStore, AgentQuotaManager
        with temporary_directory() as folder:
            agy = fake_cli(Path(folder), "agy", "raise SystemExit('must not run')")
            qoder = fake_cli(Path(folder), "qodercli", "raise SystemExit('must not run')")
            spawned = []
            with mock.patch.dict("os.environ", {"DOTII_AGY_COMMAND": str(agy), "DOTII_QODER_COMMAND": str(qoder)}):
                manager = AgentQuotaManager([AntigravityProvider(), QoderProvider()],
                                            AgentQuotaConfigStore(Path(folder) / "agent-quota.json"),
                                            spawn=lambda target, name: spawned.append(name))
                manager.tick()
            entries = {entry["id"]: entry for entry in manager.snapshot()["providers"]}
            self.assertEqual(spawned, [])
            for provider_id in ("antigravity", "qoder"):
                self.assertEqual(entries[provider_id]["status"], "disabled")
                self.assertEqual(entries[provider_id]["detail"], OPT_IN_DETAIL)
                self.assertFalse(entries[provider_id]["enabled"])

    def test_default_registry_order_and_unique_ids(self):
        from agent_quota import default_providers
        ids = [provider.id for provider in default_providers()]
        self.assertEqual(ids, ["zcode", "kimi", "grok", "antigravity", "qoder"])
        for provider in default_providers():
            self.assertGreaterEqual(provider.default_interval, 60)
            self.assertGreater(provider.timeout, 0)


if __name__ == "__main__":
    unittest.main()
