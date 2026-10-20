"""ZCode / GLM Coding Plan (Zhipu bigmodel.cn, Z.ai) quota.

Source: zai-org/ZCode docs/bigmodel-coding-plan-usage-quota.md and the official
zai-coding-plugins usage-query script. ``GET <host>/api/monitor/usage/quota/limit``
is a read-only quota query. The raw API key is sent in ``authorization``
*without* a ``Bearer`` prefix. The key is never used for inference.

Credentials: Dotii no longer asks for a key. The ZCode desktop app keeps
provider keys in ``~/.zcode/v2/credentials.json`` encrypted (``enc:v1:``,
AES-256-GCM); Dotii does not decrypt them, so a ZCode install alone is shown
as detected but not readable. The only automatic source is the environment
the official Z.ai usage plugin reads (``ANTHROPIC_AUTH_TOKEN`` while
``ANTHROPIC_BASE_URL`` points at Z.ai / BigModel).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .base import (
    STATUS_AUTH_ERROR, STATUS_ERROR, STATUS_NOT_CONFIGURED,
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow,
    as_number, parse_epoch, safe_text,
)
from .credentials import env_secret, http_get_json


QUOTA_PATH = "/api/monitor/usage/quota/limit"
HOSTS = {"cn": "https://open.bigmodel.cn", "global": "https://api.z.ai"}
UNIT_LABELS = {3: "小时", 5: "月", 6: "周"}
TOKEN_TYPES = {"TOKENS_LIMIT", "CREDIT_LIMIT"}


def _host_matches(host: str, domain: str) -> bool:
    """Exact host or a real subdomain; ``evilz.ai`` must not match ``z.ai``."""
    return host == domain or host.endswith("." + domain)


def _region_from_base_url(value: str) -> str:
    host = (urlparse(value).hostname or "").lower()
    if _host_matches(host, "z.ai"):
        return "global"
    if _host_matches(host, "bigmodel.cn"):
        return "cn"
    return ""


def _window_identity(item: dict[str, Any]) -> tuple[str, str]:
    kind = str(item.get("type") or "").upper()
    unit = int(as_number(item.get("unit")) or 0)
    number = int(as_number(item.get("number")) or 0)
    if kind in TOKEN_TYPES and unit == 3:
        return (f"{number or 5}h", f"{number or 5} 小时")
    if kind in TOKEN_TYPES and unit == 6:
        return ("weekly" if number <= 1 else f"{number}w", "每周" if number <= 1 else f"{number} 周")
    if kind in TOKEN_TYPES and unit == 5:
        return ("monthly", "每月")
    if kind == "TIME_LIMIT":
        return ("mcp_monthly" if unit == 5 else f"mcp_{unit}_{number}", "MCP 工具（月）" if unit == 5 else "MCP 工具")
    label = f"{number} {UNIT_LABELS.get(unit, '')}".strip() or kind.lower() or "limit"
    return (f"{kind.lower() or 'limit'}_{unit}_{number}", label)


def parse_quota_response(payload: Any) -> QuotaResult:
    """Translate the documented quota/limit JSON into normalized windows."""
    if not isinstance(payload, dict):
        raise QuotaError("ZCode 额度接口返回格式无效")
    code = payload.get("code")
    success = payload.get("success")
    if success is False or (code is not None and as_number(code) not in (None, 0.0, 200.0)):
        message = safe_text(payload.get("msg") or payload.get("message") or "", 80)
        status = STATUS_AUTH_ERROR if as_number(code) in (401.0, 1001.0, 1002.0) else STATUS_ERROR
        raise QuotaError(f"ZCode 额度接口返回错误 {safe_text(code, 12)} {message}".strip(), status)
    data = payload.get("data")
    if not isinstance(data, dict):
        raise QuotaError("ZCode 额度接口缺少 data")
    windows: list[QuotaWindow] = []
    seen: set[str] = set()
    limits = data.get("limits") if isinstance(data.get("limits"), list) else []
    for item in limits:
        if not isinstance(item, dict):
            continue
        window_id, label = _window_identity(item)
        if window_id in seen:
            continue
        seen.add(window_id)
        kind = str(item.get("type") or "").upper()
        used = limit = None
        unit = "credits" if kind in TOKEN_TYPES else ""
        if kind == "TIME_LIMIT":
            limit = as_number(item.get("usage"))
            used = as_number(item.get("currentValue"))
            remaining = as_number(item.get("remaining"))
            if used is None and limit is not None and remaining is not None:
                used = max(0.0, limit - remaining)
            unit = "次"
        windows.append(QuotaWindow(
            id=window_id,
            label=label,
            used_percent=as_number(item.get("percentage")),
            used=used,
            limit=limit,
            unit=unit,
            reset_at_epoch=parse_epoch(item.get("nextResetTime")),
        ))
    token_windows = [window for window in windows if not window.id.startswith("mcp")]
    primary = ""
    if token_windows:
        ranked = [window for window in token_windows if window.used_percent is not None]
        if ranked:
            primary = max(ranked, key=lambda window: window.used_percent or 0).id
    level = safe_text(data.get("level") or data.get("planName") or "", 20)
    return QuotaResult(
        plan=level.upper() if level.islower() else level,
        windows=windows,
        primary_window_id=primary,
        detail="" if windows else "ZCode 未返回任何额度窗口",
    )


class ZCodeProvider(QuotaProvider):
    id = "zcode"
    name = "ZCode（GLM Coding Plan）"
    default_interval = 120
    min_interval = 60
    timeout = 10.0
    regions = ("auto", "cn", "global")
    default_region = "auto"

    def _credential(self) -> tuple[str | None, str]:
        # The official Z.ai usage plugin reads ANTHROPIC_AUTH_TOKEN, but only
        # when Claude Code is pointed at a Z.ai / bigmodel endpoint.
        base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
        if _region_from_base_url(base_url):
            value, source = env_secret("ANTHROPIC_AUTH_TOKEN")
            if value:
                return value, source
        return None, ""

    def resolved_region(self) -> str:
        region = self.region
        if region in HOSTS:
            return region
        return _region_from_base_url(os.environ.get("ANTHROPIC_BASE_URL", "")) or "cn"

    def detect(self) -> Detection:
        key, source = self._credential()
        app_present = (Path.home() / ".zcode").exists()
        if key:
            return Detection(True, True, f"凭据来源：{source}", source)
        if app_present:
            return Detection(True, False, "已检测到 ZCode，但它的 API Key 加密保存，暂不支持自动读取")
        return Detection(False, False, "未检测到 ZCode")

    def fetch(self) -> QuotaResult:
        key, _source = self._credential()
        if not key:
            raise QuotaError("未读取到 GLM Coding Plan 登录信息", STATUS_NOT_CONFIGURED)
        header_value = key.strip()
        if header_value.lower().startswith("bearer "):
            header_value = header_value[7:].strip()
        url = HOSTS[self.resolved_region()] + QUOTA_PATH
        payload = http_get_json(url, {"authorization": header_value}, self.timeout, secrets=[key])
        result = parse_quota_response(payload)
        result.extra["region"] = self.resolved_region()
        return result
