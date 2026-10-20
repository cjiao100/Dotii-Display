"""Kimi Code (Moonshot) membership quota.

Source: MoonshotAI/kimi-code packages/oauth/src/managed-usage.ts (the official
CLI ``/usage`` implementation): ``GET {base}/usages`` with
``Authorization: Bearer <api key | OAuth access token>``. Read-only.

Credentials are only read, at runtime, from the official Kimi Code CLI's own
login files (``packages/oauth/src/storage.ts``, ``managed-kimi-code.ts``):

- ``<KIMI_CODE_HOME or ~/.kimi-code>/credentials/kimi-code.json``: the default
  slot, mainland-China login (auth.kimi.com / api.kimi.com).
- ``<...>/credentials/kimi-code-env-<sha256[:16]>.json``: the scoped slot of a
  global login (auth.kimi.ai / api.kimi.ai), named from
  ``sha256(JSON.stringify({oauthHost, baseUrl}))``.
- ``<KIMI_SHARE_DIR or ~/.kimi>/credentials/kimi-code.json``: archived Python CLI.

Only ``access_token`` and ``expires_at`` are used. Nothing is written, logged or
cached. Dotii never refreshes OAuth tokens: the official CLI rotates refresh
tokens under a cross-process lock, so refreshing here could log the user out.
An expired access token is reported as "not logged in" until the CLI renews it.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from .base import (
    STATUS_NOT_CONFIGURED,
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow,
    as_number, parse_epoch, safe_text,
)
from .credentials import find_executable, http_get_json, read_json_file


BASE_URLS = {"cn": "https://api.kimi.com/coding/v1", "global": "https://api.kimi.ai/coding/v1"}
OAUTH_HOSTS = {"cn": "https://auth.kimi.com", "global": "https://auth.kimi.ai"}
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


def kimi_code_home() -> Path:
    value = os.environ.get("KIMI_CODE_HOME", "").strip()
    return Path(value).expanduser() if value else Path.home() / ".kimi-code"


def legacy_share_dir() -> Path:
    value = os.environ.get("KIMI_SHARE_DIR", "").strip()
    return Path(value).expanduser() if value else Path.home() / ".kimi"


def scoped_slot_name(oauth_host: str, base_url: str) -> str:
    """Mirror of resolveKimiCodeOAuthKey() for a non-default (oauthHost, baseUrl)."""
    material = json.dumps({"oauthHost": oauth_host, "baseUrl": base_url}, separators=(",", ":"))
    return "kimi-code-env-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def credential_slots() -> list[tuple[str, Path]]:
    """(region, file) candidates in lookup order. Paths only; nothing is read here."""
    folder = kimi_code_home() / "credentials"
    return [
        ("cn", folder / "kimi-code.json"),
        ("global", folder / (scoped_slot_name(OAUTH_HOSTS["global"], BASE_URLS["global"]) + ".json")),
        ("cn", legacy_share_dir() / "credentials" / "kimi-code.json"),
    ]


def _display_path(path: Path) -> str:
    try:
        return "~/" + str(path.relative_to(Path.home()))
    except ValueError:
        return str(path)


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
    regions = ("auto", "cn", "global")
    default_region = "auto"

    def _credential(self) -> tuple[str | None, str, bool, str]:
        """Return (token, source label, expired, region) from the CLI login files."""
        wanted = self.region
        expired_hit: tuple[str | None, str, bool, str] | None = None
        for region, path in credential_slots():
            if wanted in BASE_URLS and region != wanted:
                continue
            if not path.is_file():
                continue
            token, expired = token_from_credentials(read_json_file(path))
            if not token:
                continue
            hit = (token, f"file:{_display_path(path)}", expired, region)
            if not expired:
                return hit
            expired_hit = expired_hit or hit
        return expired_hit or (None, "", False, wanted if wanted in BASE_URLS else "cn")

    def cli_present(self) -> bool:
        if kimi_code_home().is_dir() or (legacy_share_dir() / "credentials").is_dir():
            return True
        return bool(find_executable(["kimi"], extra=[kimi_code_home() / "bin" / "kimi"]))

    @staticmethod
    def base_url(region: str) -> str:
        override = os.environ.get("KIMI_CODE_BASE_URL", "").strip().rstrip("/")
        if override.startswith("https://"):
            return override
        return BASE_URLS[region]

    def detect(self) -> Detection:
        token, source, expired, _region = self._credential()
        if token and not expired:
            return Detection(True, True, f"已读取 Kimi Code CLI 登录：{source}", source)
        if token:
            return Detection(True, False, "Kimi Code CLI 登录令牌已过期；打开 Kimi Code CLI 后会自动续期（Dotii 不会刷新令牌）", source)
        if self.cli_present():
            return Detection(True, False, "未登录：在 Kimi Code CLI 中运行 /login 后自动读取")
        return Detection(False, False, "未检测到 Kimi Code CLI")

    def fetch(self) -> QuotaResult:
        token, source, expired, region = self._credential()
        if not token or expired:
            raise QuotaError("未登录 Kimi Code CLI（或登录令牌已过期）", STATUS_NOT_CONFIGURED)
        payload = http_get_json(
            self.base_url(region) + "/usages", {"Authorization": f"Bearer {token}"}, self.timeout, secrets=[token],
        )
        result = parse_usages_response(payload)
        result.extra["region"] = region
        result.extra["credential_source"] = source.split(":", 1)[0]
        return result
