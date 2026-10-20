"""Agent quota providers: parsers use sanitized, synthetic fixtures only."""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

from dotii_test_support import temporary_directory

BRIDGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE))

from agent_quota import base, credentials  # noqa: E402
from agent_quota.base import (  # noqa: E402
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow, parse_epoch,
)
from agent_quota.kimi import KimiProvider, parse_usages_response, token_from_credentials  # noqa: E402
from agent_quota.manager import AgentQuotaConfigStore, AgentQuotaManager  # noqa: E402
from agent_quota.zcode import ZCodeProvider, parse_quota_response  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agent_quota"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class BaseHelpersTests(unittest.TestCase):
    def test_parse_epoch_accepts_seconds_millis_and_rfc3339(self):
        self.assertEqual(parse_epoch(1792483200), 1792483200)
        self.assertEqual(parse_epoch(1792483200000), 1792483200)
        self.assertEqual(parse_epoch("2026-10-20T08:00:00Z"), 1792483200)
        self.assertEqual(parse_epoch("2026-10-20T08:00:00.123456789Z"), 1792483200)
        self.assertEqual(parse_epoch("not a date"), 0)
        self.assertEqual(parse_epoch(None), 0)

    def test_redact_and_scrub_never_echo_full_secret(self):
        self.assertEqual(credentials.redact("abcdefghijkl"), "abcd…")
        self.assertEqual(credentials.scrub("bad key abcdefghijkl here", ["abcdefghijkl"]), "bad key abcd… here")

    def test_normalize_uses_most_constraining_window(self):
        result = QuotaResult(plan="pro", windows=[
            QuotaWindow("a", "A", used_percent=10), QuotaWindow("b", "B", used=90, limit=100),
        ])
        entry = base.normalize_result("x", "X", result, fetched_at=5)
        self.assertEqual(entry["used_percent"], 90.0)
        self.assertEqual(entry["remaining_percent"], 10.0)
        self.assertEqual(entry["windows"][1]["used_percent"], 90.0)
        self.assertEqual(entry["status"], "ok")


class ZCodeParserTests(unittest.TestCase):
    def test_personal_plan_windows(self):
        result = parse_quota_response(fixture("zcode_quota_limit.json"))
        self.assertEqual(result.plan, "PRO")
        ids = [window.id for window in result.windows]
        self.assertEqual(ids, ["5h", "weekly", "mcp_monthly"])
        self.assertEqual(result.primary_window_id, "5h")
        entry = base.normalize_result("zcode", "ZCode", result)
        self.assertEqual(entry["used_percent"], 37.0)
        self.assertEqual(entry["reset_at_epoch"], 1792483200)
        mcp = entry["windows"][2]
        self.assertEqual((mcp["used"], mcp["limit"], mcp["used_percent"]), (250.0, 1000.0, 25.0))

    def test_credit_limit_is_treated_as_tokens_limit_and_weekly_may_be_missing(self):
        result = parse_quota_response(fixture("zcode_quota_limit_team.json"))
        self.assertEqual([window.id for window in result.windows], ["5h", "mcp_monthly"])
        self.assertEqual(result.primary_window_id, "5h")
        self.assertEqual(result.windows[0].reset_at_epoch, 0)
        self.assertEqual(result.windows[1].used, 100.0)

    def test_error_payload_raises_auth_error(self):
        with self.assertRaises(QuotaError) as caught:
            parse_quota_response(fixture("zcode_error.json"))
        self.assertEqual(caught.exception.status, "auth_error")

    def test_fetch_sends_raw_key_without_bearer(self):
        provider = ZCodeProvider({"region": "global"})
        fake_key = "fakeid.fakesecretvalue"
        with mock.patch.dict("os.environ", {"DOTII_ZCODE_API_KEY": fake_key}, clear=False), \
                mock.patch("agent_quota.zcode.http_get_json", return_value=fixture("zcode_quota_limit.json")) as get:
            entry = provider.fetch_quota()
        url, headers = get.call_args.args[0], get.call_args.args[1]
        self.assertEqual(url, "https://api.z.ai/api/monitor/usage/quota/limit")
        self.assertEqual(headers, {"authorization": fake_key})
        self.assertNotIn(fake_key, json.dumps(entry))

    def test_missing_key_is_not_configured(self):
        provider = ZCodeProvider()
        with mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("agent_quota.zcode.keychain_secret", return_value=None):
            self.assertFalse(provider.detect().configured)
            with self.assertRaises(QuotaError) as caught:
                provider.fetch()
        self.assertEqual(caught.exception.status, "not_configured")

    def test_anthropic_token_only_used_for_zai_endpoints(self):
        provider = ZCodeProvider()
        with mock.patch("agent_quota.zcode.keychain_secret", return_value=None):
            with mock.patch.dict("os.environ", {"ANTHROPIC_BASE_URL": "https://api.anthropic.com",
                                                "ANTHROPIC_AUTH_TOKEN": "fake-token-1"}, clear=True):
                self.assertFalse(provider.detect().configured)
            with mock.patch.dict("os.environ", {"ANTHROPIC_BASE_URL": "https://open.bigmodel.cn/api/anthropic",
                                                "ANTHROPIC_AUTH_TOKEN": "fake-token-1"}, clear=True):
                self.assertTrue(provider.detect().configured)
                self.assertEqual(provider.resolved_region(), "cn")


class KimiParserTests(unittest.TestCase):
    def test_new_schema(self):
        result = parse_usages_response(fixture("kimi_usages_new.json"))
        self.assertEqual([window.id for window in result.windows], ["5h", "monthly_total", "monthly_code"])
        entry = base.normalize_result("kimi", "Kimi", result)
        self.assertEqual(entry["windows"][0]["used_percent"], 42.0)
        self.assertEqual(entry["windows"][0]["reset_at_epoch"], 1792483200)
        self.assertEqual(entry["used_percent"], 42.0)
        self.assertEqual(result.extra["extra_usage_balance"], 25.0)
        self.assertEqual(result.extra["extra_usage_monthly_cap"], 100.0)

    def test_legacy_schema(self):
        result = parse_usages_response(fixture("kimi_usages_legacy.json"))
        windows = {window.id: window for window in result.windows}
        self.assertEqual(set(windows), {"total", "5h"})
        self.assertEqual(windows["total"].used, 360.0)
        self.assertEqual(windows["5h"].used, 55.0)
        entry = base.normalize_result("kimi", "Kimi", result)
        self.assertEqual(entry["used_percent"], 55.0)

    def test_unrecognized_payload_raises(self):
        with self.assertRaises(QuotaError):
            parse_usages_response({"something": "else"})

    def test_credentials_file_token_and_expiry(self):
        token, expired = token_from_credentials({"access_token": "fake-value", "expires_at": 100}, now=200)
        self.assertEqual((token, expired), ("fake-value", True))
        token, expired = token_from_credentials({"accessToken": "fake-value", "expiresAt": 300_000}, now=200)
        self.assertEqual((token, expired), ("fake-value", False))
        self.assertEqual(token_from_credentials({"refresh_token": "x"}), (None, False))

    def test_fetch_uses_bearer_and_region_and_never_refreshes_expired_token(self):
        with temporary_directory() as folder:
            home = Path(folder)
            creds = home / ".kimi-code" / "credentials"
            creds.mkdir(parents=True)
            (creds / "kimi-code.json").write_text(json.dumps(
                {"access_token": "fake-oauth-value", "refresh_token": "fake-refresh", "expires_at": 4102444800}
            ), encoding="utf-8")
            provider = KimiProvider({"region": "global"})
            with mock.patch.dict("os.environ", {"KIMI_CODE_HOME": str(home / ".kimi-code")}, clear=True), \
                    mock.patch("agent_quota.kimi.keychain_secret", return_value=None), \
                    mock.patch("agent_quota.kimi.http_get_json", return_value=fixture("kimi_usages_new.json")) as get:
                self.assertTrue(provider.detect().configured)
                entry = provider.fetch_quota()
            self.assertEqual(get.call_args.args[0], "https://api.kimi.ai/coding/v1/usages")
            self.assertEqual(get.call_args.args[1], {"Authorization": "Bearer fake-oauth-value"})
            self.assertNotIn("fake-oauth-value", json.dumps(entry))
            self.assertEqual(entry["extra"]["credential_source"], "file")

            (creds / "kimi-code.json").write_text(json.dumps(
                {"access_token": "fake-oauth-value", "expires_at": 1}
            ), encoding="utf-8")
            with mock.patch.dict("os.environ", {"KIMI_CODE_HOME": str(home / ".kimi-code")}, clear=True), \
                    mock.patch("agent_quota.kimi.keychain_secret", return_value=None), \
                    mock.patch("agent_quota.kimi.http_get_json") as get:
                with self.assertRaises(QuotaError) as caught:
                    provider.fetch()
                get.assert_not_called()
            self.assertEqual(caught.exception.status, "auth_error")


class _FakeProvider(QuotaProvider):
    id = "fake"
    name = "Fake"
    default_interval = 60
    regions = ("a", "b")
    default_region = "a"

    def __init__(self, detection=None, outcome=None):
        super().__init__()
        self.detection = detection or Detection(True, True, "ok")
        self.outcome = outcome
        self.calls = 0

    def detect(self):
        return self.detection

    def fetch(self):
        self.calls += 1
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome or QuotaResult(plan="p", windows=[QuotaWindow("w", "W", used_percent=20)])


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.folder = temporary_directory()
        self.store = AgentQuotaConfigStore(Path(self.folder.name) / "agent-quota.json")
        self.now = [1000.0]

    def tearDown(self):
        self.folder.cleanup()

    def manager(self, *providers):
        return AgentQuotaManager(providers, self.store, clock=lambda: self.now[0],
                                 spawn=lambda target, name: target())

    def entry(self, manager, provider_id="fake"):
        return next(item for item in manager.snapshot()["providers"] if item["id"] == provider_id)

    def test_detected_provider_defaults_on_and_polls_on_interval(self):
        provider = _FakeProvider()
        manager = self.manager(provider)
        manager.tick()
        self.assertEqual(self.entry(manager)["status"], "ok")
        self.assertTrue(self.entry(manager)["enabled"])
        manager.tick()
        self.assertEqual(provider.calls, 1)
        self.now[0] += 61
        manager.tick()
        self.assertEqual(provider.calls, 2)

    def test_undetected_provider_defaults_off(self):
        provider = _FakeProvider(Detection(False, False, "missing"))
        manager = self.manager(provider)
        manager.tick()
        entry = self.entry(manager)
        self.assertEqual(entry["status"], "disabled")
        self.assertFalse(entry["enabled"])
        self.assertEqual(provider.calls, 0)

    def test_enabled_but_unconfigured_api_provider_reports_not_configured(self):
        provider = _FakeProvider(Detection(False, False, "need key"))
        manager = self.manager(provider)
        manager.update_provider("fake", {"enabled": True})
        manager.tick()
        self.assertEqual(self.entry(manager)["status"], "not_configured")
        provider.kind = "cli"
        manager.tick()
        self.assertEqual(self.entry(manager)["status"], "unavailable")

    def test_failures_are_isolated_and_keep_last_value_as_stale(self):
        good = _FakeProvider()
        bad = _FakeProvider(outcome=RuntimeError("boom"))
        bad.id = "bad"
        manager = self.manager(good, bad)
        manager.tick()
        self.assertEqual(self.entry(manager)["status"], "ok")
        self.assertEqual(self.entry(manager, "bad")["status"], "error")
        self.assertIn("RuntimeError", self.entry(manager, "bad")["error"])
        good.outcome = QuotaError("网络不可用", "unavailable")
        self.now[0] += 61
        manager.tick()
        entry = self.entry(manager)
        self.assertEqual(entry["status"], "unavailable")
        self.assertTrue(entry["stale"])
        self.assertEqual(entry["used_percent"], 20.0)

    def test_detection_exception_does_not_crash(self):
        provider = _FakeProvider()
        provider.detect = mock.Mock(side_effect=OSError("disk"))
        manager = self.manager(provider)
        manager.tick()
        self.assertEqual(self.entry(manager)["status"], "disabled")

    def test_settings_persist_without_secrets_and_reject_unknown_keys(self):
        provider = _FakeProvider()
        manager = self.manager(provider)
        manager.update_provider("fake", {"enabled": False, "region": "b", "interval_seconds": 300})
        saved = json.loads(self.store.path.read_text(encoding="utf-8"))
        self.assertEqual(saved["providers"]["fake"], {"enabled": False, "region": "b", "interval_seconds": 300})
        for bad in ({"api_key": "x"}, {"enabled": "yes"}, {"region": "zz"}, {"interval_seconds": 5}):
            with self.assertRaises(ValueError):
                manager.update_provider("fake", bad)
        with self.assertRaises(ValueError):
            manager.update_provider("nope", {"enabled": True})
        reloaded = self.manager(_FakeProvider())
        self.assertEqual(self.entry(reloaded)["region"], "b")
        self.assertFalse(self.entry(reloaded)["enabled"])

    def test_hung_worker_is_abandoned_by_watchdog(self):
        provider = _FakeProvider()
        started = []
        manager = AgentQuotaManager([provider], self.store, clock=lambda: self.now[0],
                                    spawn=lambda target, name: started.append(target))
        manager.tick()
        self.assertTrue(self.entry(manager)["refreshing"])
        self.now[0] += provider.timeout + 31
        manager.tick()
        self.assertEqual(self.entry(manager)["error"], "读取超时")
        started[0]()  # late result from the abandoned worker is discarded
        self.assertEqual(self.entry(manager)["status"], "error")

    def test_settings_change_mid_fetch_clears_running_and_drops_result(self):
        provider = _FakeProvider()
        started = []
        manager = AgentQuotaManager([provider], self.store, clock=lambda: self.now[0],
                                    spawn=lambda target, name: started.append(target))
        manager.tick()
        self.assertTrue(self.entry(manager)["refreshing"])
        manager.update_provider("fake", {"region": "b"})
        started[0]()  # the old worker finishes after the settings change
        entry = self.entry(manager)
        self.assertFalse(entry["refreshing"])
        self.assertNotEqual(entry["status"], "ok")  # stale-settings result dropped
        manager.tick()  # immediately re-reads with the new settings
        self.assertEqual(len(started), 2)
        started[1]()
        self.assertEqual(self.entry(manager)["status"], "ok")
        self.now[0] += provider.timeout + 60
        manager.tick()
        self.assertNotEqual(self.entry(manager)["error"], "读取超时")

    def test_disable_mid_fetch_never_reports_false_timeout(self):
        provider = _FakeProvider()
        started = []
        manager = AgentQuotaManager([provider], self.store, clock=lambda: self.now[0],
                                    spawn=lambda target, name: started.append(target))
        manager.tick()
        manager.update_provider("fake", {"enabled": False})
        manager.tick()
        self.assertEqual(self.entry(manager)["status"], "disabled")
        started[0]()
        self.assertFalse(self.entry(manager)["refreshing"])
        self.now[0] += provider.timeout + 60
        manager.tick()
        entry = self.entry(manager)
        self.assertEqual((entry["status"], entry["error"]), ("disabled", ""))
        self.assertEqual(len(started), 1)

    def test_manual_refresh_has_floor(self):
        provider = _FakeProvider()
        manager = self.manager(provider)
        manager.tick()
        self.assertEqual(provider.calls, 1)
        self.now[0] += 5
        self.assertEqual(manager.request_refresh("fake"), [])
        manager.tick()
        self.assertEqual(provider.calls, 1)
        self.now[0] += 26  # 31 s after the last fetch started
        manager.tick()
        self.assertEqual(provider.calls, 2)  # the deferred refresh ran at the floor
        self.now[0] += 31
        self.assertEqual(manager.request_refresh(), ["fake"])
        manager.tick()
        self.assertEqual(provider.calls, 3)

    def test_unverified_provider_stays_off_when_detected(self):
        provider = _FakeProvider()
        provider.auto_enable = False
        manager = self.manager(provider)
        manager.tick()
        self.assertEqual(self.entry(manager)["status"], "disabled")
        self.assertEqual(provider.calls, 0)
        manager.update_provider("fake", {"enabled": True})
        manager.tick()
        self.assertEqual(self.entry(manager)["status"], "ok")

    def test_overview_is_not_blocked_by_slow_detection(self):
        release = threading.Event()
        entered = threading.Event()
        provider = _FakeProvider()

        def slow_detect():
            entered.set()
            release.wait(5)
            return Detection(True, True, "slow")
        provider.detect = slow_detect
        manager = self.manager(provider)
        worker = threading.Thread(target=manager.tick)
        worker.start()
        self.assertTrue(entered.wait(2))
        done = threading.Event()
        threading.Thread(target=lambda: (manager.snapshot(), done.set())).start()
        self.assertTrue(done.wait(1), "snapshot blocked while detect() was running")
        release.set()
        worker.join(3)
        self.assertEqual(self.entry(manager)["status"], "ok")

    def test_run_loop_survives_and_stops(self):
        provider = _FakeProvider()
        manager = AgentQuotaManager([provider], self.store)
        stop = threading.Event()
        thread = manager.start(stop)
        for _ in range(50):
            if self.entry(manager)["status"] == "ok":
                break
            threading.Event().wait(0.05)
        stop.set()
        manager.request_refresh()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.entry(manager)["status"], "ok")


if __name__ == "__main__":
    unittest.main()
