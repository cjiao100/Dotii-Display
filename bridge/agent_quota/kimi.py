"""Kimi Code (Moonshot) membership quota.

Source: MoonshotAI/kimi-code packages/oauth/src/managed-usage.ts (the official
CLI ``/usage`` implementation): ``GET {base}/usages`` with
``Authorization: Bearer <api key | OAuth access token>``. Read-only.

Dotii never refreshes OAuth tokens: the official CLI rotates refresh tokens
under a cross-process lock, so refreshing here could log the user out.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from .base import (
    STATUS_AUTH_ERROR, STATUS_NOT_CONFIGURED,
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow,
    as_number, parse_epoch, safe_text,
)
from .credentials import env_secret, http_get_json, keychain_secret, read_json_file


BASE_URLS = {"cn": "https://api.kimi.com/coding/v1", "global": "https://api.kimi.ai/coding/v1"}
KEYCHAIN_ACCOUNT = "kimi"
ENV_KEY = "DOTII_KIMI_API_KEY"
NEW_WINDOWS = (
    ("limit_5h", "5h", "5 小时"),
    ("limit_7d", "weekly", "7 天"),
    ("limit_month_total", "monthly_total", "月度总额度"),
    ("limit_month_code", "monthly_code", "月度 Code 额度"),
)
TIME_UNITS = {
    "TIME_UNIT_MINUTE": ("m", 1 / 60), "MINUTE": ("m", 1 / 60), "MINUTES": ("m", 1 / 60),
    "TIME_UNIT_HOUR": ("h", 1), "HOUR": ("h", 1), "HOURS": ("h", 1),
    "TIME_UNIT_DAY": ("d", 24), "DAY": ("d", 24), "DAYS": ("d", 24),
    "TIME_UNIT_WEEK": ("w", 168), "WEEK": ("w", 168),
    "TIME_UNIT_MONTH": ("mo", 720), "MONTH": ("mo", 720),
}


def credential_files() -> list[Path]:
    files: list[Path] = []
    code_home = os.environ.get("KIMI_CODE_HOME", "").strip()
    files.append((Path(code_home).expanduser() if code_home else Path.home() / ".kimi-code") / "credentials" / "kimi-code.json")
    share_dir = os.environ.get("KIMI_SHARE_DIR", "").strip()
    files.append((Path(share_dir).expanduser() if share_dir else Path.home() / ".kimi") / "credentials" / "kimi-code.json")
    return files


def token_from_credentials(payload: Any, now: float | None = None) -> tuple[str | None, bool]:
    """Return (access_token, expired). Field names are matched leniently."""
    if not isinstance(payload, dict):
        return None, False
    container = payload
    for key in ("token", "tokens", "oauth", "credentials"):
        if isinstance(payload.get(key), dict):
            container = payload[key]
            break
    token = None
    for key in ("access_token", "accessToken", "api_key", "apiKey"):
        value = container.get(key)
        if isinstance(value, str) and value.strip():
            token = value.strip()
            break
    if not token:
        return None, False
    expires = 0
    for key in ("expires_at", "expiresAt", "expiry", "expires"):
        if key in container:
            expires = parse_epoch(container.get(key))
            break
    now = time.time() if now is None else now
    return token, bool(expires and expires <= now)


def _ratio_percent(value: Any) -> float | None:
    number = as_number(value)
    if number is None:
        return None
    # used_ratio is documented as 0-1; tolerate servers that already send 0-100.
    return number * 100 if number <= 1.0 else number


def _legacy_window_label(window: Any) -> tuple[str, str]:
    if not isinstance(window, dict):
        return "limit", "额度"
    duration = int(as_number(window.get("duration")) or 0)
    unit = str(window.get("timeUnit") or window.get("time_unit") or "").upper()
    suffix, hours = TIME_UNITS.get(unit, ("", 0))
    if duration and suffix:
        total_hours = duration * hours
        if total_hours == 5:
            return "5h", "5 小时"
        if total_hours == 168:
            return "weekly", "7 天"
        return f"{duration}{suffix}", f"{duration}{suffix}"
    return "limit", "额度"


def _legacy_detail(detail: Any, window_id: str, label: str) -> QuotaWindow | None:
    if not isinstance(detail, dict):
        return None
    limit = as_number(detail.get("limit"))
    used = as_number(detail.get("used"))
    remaining = as_number(detail.get("remaining"))
    if used is None and limit is not None and remaining is not None:
        used = max(0.0, limit - remaining)
    reset = 0
    for key in ("resetTime", "reset_time", "resetAt", "reset_at"):
        if detail.get(key):
            reset = parse_epoch(detail.get(key))
            break
    if limit is None and used is None:
        return None
    return QuotaWindow(id=window_id, label=label, used=used, limit=limit, reset_at_epoch=reset)


def parse_usages_response(payload: Any) -> QuotaResult:
    if not isinstance(payload, dict):
        raise QuotaError("Kimi 额度接口返回格式无效")
    windows: list[QuotaWindow] = []
    usages = payload.get("usages") if isinstance(payload.get("usages"), dict) else None
    if usages is not None:
        for key, window_id, label in NEW_WINDOWS:
            item = usages.get(key)
            if not isinstance(item, dict):
                continue
            windows.append(QuotaWindow(
                id=window_id, label=label,
                used_percent=_ratio_percent(item.get("used_ratio", item.get("usedRatio"))),
                reset_at_epoch=parse_epoch(item.get("reset_time", item.get("resetTime"))),
            ))
    seen = {window.id for window in windows}
    legacy_total = _legacy_detail(payload.get("usage"), "total", "总额度")
    if legacy_total is not None and "total" not in seen:
        windows.append(legacy_total)
        seen.add("total")
    for entry in payload.get("limits") if isinstance(payload.get("limits"), list) else []:
        if not isinstance(entry, dict):
            continue
        window_id, label = _legacy_window_label(entry.get("window"))
        window = _legacy_detail(entry.get("detail", entry), window_id, label)
        if window is not None and window.id not in seen:
            windows.append(window)
            seen.add(window.id)
    extra: dict[str, Any] = {}
    wallet = payload.get("boosterWallet") or payload.get("booster_wallet")
    if isinstance(wallet, dict):
        balance = wallet.get("balance") if isinstance(wallet.get("balance"), dict) else {}
        amount_left = as_number(balance.get("amountLeft", balance.get("amount_left")))
        if amount_left is not None:
            # Fixed-point: amount / 1_000_000 = cents.
            extra["extra_usage_balance"] = round(amount_left / 1_000_000 / 100, 2)
        cap = wallet.get("monthlyChargeLimit") if isinstance(wallet.get("monthlyChargeLimit"), dict) else {}
        if as_number(cap.get("priceInCents")) is not None:
            extra["extra_usage_monthly_cap"] = round((as_number(cap.get("priceInCents")) or 0) / 100, 2)
            extra["extra_usage_currency"] = safe_text(cap.get("currency"), 8)
    if not windows:
        raise QuotaError("Kimi 额度接口未返回可识别的额度字段")
    plan = ""
    for key in ("plan", "planName", "membership", "level"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            plan = value
            break
        if isinstance(value, dict) and isinstance(value.get("name"), str):
            plan = value["name"]
            break
    return QuotaResult(plan=safe_text(plan, 30), windows=windows, extra=extra)


class KimiProvider(QuotaProvider):
    id = "kimi"
    name = "Kimi Code"
    default_interval = 120
    min_interval = 60
    timeout = 8.0
    regions = ("cn", "global")
    default_region = "cn"

    def _credential(self) -> tuple[str | None, str, bool]:
        value, source = env_secret(ENV_KEY)
        if value:
            return value, source, False
        value = keychain_secret(KEYCHAIN_ACCOUNT)
        if value:
            return value, "keychain", False
        for path in credential_files():
            if path.is_file():
                token, expired = token_from_credentials(read_json_file(path))
                if token:
                    label = "~/" + str(path.relative_to(Path.home())) if str(path).startswith(str(Path.home())) else str(path)
                    return token, f"file:{label}", expired
        return None, "", False

    def base_url(self) -> str:
        override = os.environ.get("KIMI_CODE_BASE_URL", "").strip().rstrip("/")
        if override.startswith("https://"):
            return override
        return BASE_URLS[self.region]

    def detect(self) -> Detection:
        token, source, expired = self._credential()
        if token:
            detail = f"凭据来源：{source}" + ("（OAuth 已过期，请在 Kimi Code CLI 中重新登录）" if expired else "")
            return Detection(True, True, detail, source)
        return Detection(False, False, "未找到 Kimi Code 凭据（Keychain 账户 kimi，或 ~/.kimi-code/credentials）")

    def fetch(self) -> QuotaResult:
        token, source, expired = self._credential()
        if not token:
            raise QuotaError("未配置 Kimi Code API Key 或 CLI 登录", STATUS_NOT_CONFIGURED)
        if expired:
            raise QuotaError("Kimi Code 登录已过期，请运行 Kimi Code CLI 重新登录（Dotii 不会刷新令牌）", STATUS_AUTH_ERROR)
        payload = http_get_json(
            self.base_url() + "/usages", {"Authorization": f"Bearer {token}"}, self.timeout, secrets=[token],
        )
        result = parse_usages_response(payload)
        result.extra["region"] = self.region
        result.extra["credential_source"] = source.split(":", 1)[0]
        return result
