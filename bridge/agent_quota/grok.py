"""Grok Build (``grok`` CLI, The X Subscription) quota via ACP.

Source: xai-org/grok-build extensions/billing.rs and acp_agent.rs. The CLI is
started as ``grok agent stdio`` and asked for the ACP extension method
``_x.ai/billing`` (the leading underscore is mandatory on the wire; without it
ACP 0.10.4 returns -32601). The CLI keeps its own token; Dotii never reads it.
The REST fallback (cli-chat-proxy) is intentionally not implemented because it
would require Dotii to read and send the CLI's token.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from .base import (
    STATUS_AUTH_ERROR, STATUS_ERROR, STATUS_UNAVAILABLE,
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow,
    as_number, clamp_percent, parse_epoch, safe_text,
)
from .credentials import child_env, find_executable
from .stdio_rpc import RpcError, StdioJsonRpc


BILLING_METHOD = "_x.ai/billing"
PERIOD_LABELS = {
    "USAGE_PERIOD_TYPE_WEEKLY": ("weekly", "每周"),
    "USAGE_PERIOD_TYPE_MONTHLY": ("monthly", "每月"),
    "USAGE_PERIOD_TYPE_DAILY": ("daily", "每日"),
}


def _cents(value: Any) -> float | None:
    if isinstance(value, dict):
        value = value.get("val", value.get("value"))
    return as_number(value)


def parse_billing_response(payload: Any) -> QuotaResult:
    if not isinstance(payload, dict):
        raise QuotaError("Grok billing 返回格式无效")
    config = payload.get("config") if isinstance(payload.get("config"), dict) else {}
    period = config.get("currentPeriod") if isinstance(config.get("currentPeriod"), dict) else {}
    period_type = str(period.get("type") or "")
    window_id, label = PERIOD_LABELS.get(period_type, ("period", "当前周期"))
    used_percent = clamp_percent(config.get("creditUsagePercent"))
    used = limit = None
    if used_percent is None:
        # Deprecated fields, kept as a fallback for older CLI builds.
        limit = _cents(config.get("monthlyLimit"))
        used = _cents(config.get("used"))
    reset = parse_epoch(period.get("end")) or parse_epoch(config.get("billingPeriodEnd"))
    windows: list[QuotaWindow] = []
    if used_percent is not None or (used is not None and limit):
        windows.append(QuotaWindow(
            id=window_id, label=label, used_percent=used_percent,
            used=None if used is None else used / 100, limit=None if limit is None else limit / 100,
            unit="USD" if used_percent is None else "", reset_at_epoch=reset,
        ))
    cap = _cents(config.get("onDemandCap"))
    on_demand_used = _cents(config.get("onDemandUsed"))
    if payload.get("on_demand_enabled") and cap:
        windows.append(QuotaWindow(
            id="on_demand", label="按需用量", used=(on_demand_used or 0) / 100, limit=cap / 100, unit="USD",
            reset_at_epoch=reset,
        ))
    extra: dict[str, Any] = {}
    prepaid = _cents(config.get("prepaidBalance"))
    if prepaid is not None:
        extra["prepaid_balance_usd"] = round(prepaid / 100, 2)
    if isinstance(config.get("isUnifiedBillingUser"), bool):
        extra["unified_billing"] = config["isUnifiedBillingUser"]
    if not windows:
        raise QuotaError("Grok billing 未返回额度字段")
    return QuotaResult(
        plan=safe_text(payload.get("subscription_tier") or payload.get("subscriptionTier") or "", 30),
        windows=windows,
        primary_window_id=window_id if windows[0].id == window_id else "",
        extra=extra,
    )


def classify_rpc_error(error: RpcError) -> QuotaError:
    message = str(error)
    lowered = message.lower()
    if error.code == -32601:
        return QuotaError("grok CLI 不支持 _x.ai/billing（-32601），请升级 grok", STATUS_ERROR)
    if "grok login" in lowered or "auth" in lowered or "unauthenticated" in lowered:
        return QuotaError("grok CLI 未登录 grok.com，请先运行 grok login", STATUS_AUTH_ERROR)
    return QuotaError(f"grok billing 失败：{safe_text(message, 120)}", STATUS_ERROR)


class GrokProvider(QuotaProvider):
    id = "grok"
    name = "Grok Build"
    kind = "cli"
    default_interval = 300
    min_interval = 120
    timeout = 30.0

    def executable(self) -> str | None:
        grok_home = Path(os.environ.get("GROK_HOME", "").strip() or Path.home() / ".grok").expanduser()
        return find_executable(["grok"], extra=[grok_home / "bin" / "grok"], env_name="DOTII_GROK_COMMAND")

    def detect(self) -> Detection:
        path = self.executable()
        if not path:
            return Detection(False, False, "未找到 grok CLI")
        return Detection(True, True, f"grok CLI：{path}", "cli")

    def fetch(self) -> QuotaResult:
        path = self.executable()
        if not path:
            raise QuotaError("未找到 grok CLI", STATUS_UNAVAILABLE)
        deadline = time.monotonic() + self.timeout
        with StdioJsonRpc([path, "agent", "stdio"], cwd=Path.home(), env=child_env()) as client:
            try:
                client.request("initialize", {
                    "protocolVersion": 1,
                    "clientCapabilities": {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False},
                    "clientInfo": {"name": "dotii-bridge", "title": "Dotii", "version": "1"},
                }, deadline)
                payload = client.request(BILLING_METHOD, {}, deadline)
            except RpcError as error:
                raise classify_rpc_error(error) from None
        return parse_billing_response(payload)
