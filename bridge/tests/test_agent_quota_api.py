"""Admin endpoints and firmware-snapshot isolation for agent quotas."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

from dotii_test_support import temporary_directory

BRIDGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE))

import codex_bridge  # noqa: E402
from agent_quota import AgentQuotaConfigStore, AgentQuotaManager  # noqa: E402
from agent_quota.base import Detection, QuotaProvider, QuotaResult, QuotaWindow  # noqa: E402


class _Provider(QuotaProvider):
    id = "fake"
    name = "Fake"
    regions = ("cn", "global")
    default_region = "cn"

    def detect(self):
        return Detection(True, True, "fake detected")

    def fetch(self):
        return QuotaResult(plan="pro", windows=[QuotaWindow("5h", "5 小时", used_percent=40)])


class _Connections:
    def read(self):
        return {"language": "zh-CN"}


def _handler(manager, path, payload, client="127.0.0.1"):
    handler = codex_bridge.BridgeHandler.__new__(codex_bridge.BridgeHandler)
    handler.server = mock.Mock(agent_quota=manager, connections=_Connections())
    handler.client_address = (client, 5000)
    body = json.dumps(payload).encode("utf-8")
    handler.headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler.path = path
    sent = {}
    handler._send_json = lambda status, data: sent.update(status=int(status), data=data)
    return handler, sent


class AgentQuotaApiTests(unittest.TestCase):
    def setUp(self):
        self.folder = temporary_directory()
        self.manager = AgentQuotaManager(
            [_Provider()], AgentQuotaConfigStore(Path(self.folder.name) / "agent-quota.json"),
            spawn=lambda target, name: target(),
        )
        self.manager.tick()

    def tearDown(self):
        self.folder.cleanup()

    def test_provider_update_and_refresh(self):
        handler, sent = _handler(self.manager, "/api/v1/admin/agent-quota/provider",
                                 {"id": "fake", "enabled": False, "region": "global"})
        handler.do_POST()
        self.assertEqual(sent["status"], 200)
        entry = sent["data"]["agent_quota"]["providers"][0]
        self.assertFalse(entry["enabled"])
        self.assertEqual(entry["region"], "global")

        handler, sent = _handler(self.manager, "/api/v1/admin/agent-quota/refresh", {"id": "fake"})
        handler.do_POST()
        self.assertEqual(sent["status"], 200)

    def test_rejects_secret_like_or_unknown_settings(self):
        for payload in ({"id": "fake", "api_key": "x"}, {"id": "nope", "enabled": True}, {"enabled": True}):
            handler, sent = _handler(self.manager, "/api/v1/admin/agent-quota/provider", payload)
            handler.do_POST()
            self.assertEqual(sent["status"], 400, payload)

    def test_endpoints_are_local_only(self):
        handler, sent = _handler(self.manager, "/api/v1/admin/agent-quota/refresh", {}, client="192.168.1.20")
        handler.do_POST()
        self.assertEqual(sent["status"], 403)

    def test_firmware_snapshot_schema_does_not_carry_agent_quota(self):
        sample = json.loads((BRIDGE / "state.json").read_text(encoding="utf-8"))
        validated = codex_bridge.validate_snapshot(sample)
        self.assertNotIn("agent_quota", validated)
        self.assertNotIn("agent_quota", validated["codex"])
        self.assertEqual(validated["schema_version"], 1)
        source = (BRIDGE / "codex_bridge.py").read_text(encoding="utf-8")
        server_class = source.split("class BridgeServer(", 1)[1]
        snapshot_body = server_class.split("    def snapshot(self) -> dict[str, Any]:", 1)[1].split("\ndef main", 1)[0]
        self.assertNotIn("agent_quota", snapshot_body)

    def test_frontend_renders_agent_quota_from_overview(self):
        script = (BRIDGE / "web" / "app.js").read_text(encoding="utf-8")
        page = (BRIDGE / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn("overview.agent_quota", script)
        self.assertIn('id="panel-agents"', page)
        self.assertIn('id="agent-quota-grid"', page)


if __name__ == "__main__":
    unittest.main()
