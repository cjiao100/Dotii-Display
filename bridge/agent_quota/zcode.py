"""ZCode / GLM Coding Plan (Zhipu bigmodel.cn, Z.ai) quota.

Source: zai-org/ZCode docs/bigmodel-coding-plan-usage-quota.md and the official
zai-coding-plugins usage-query script. ``GET <host>/api/monitor/usage/quota/limit``
is a read-only quota query. The raw API key is sent in ``authorization``
*without* a ``Bearer`` prefix. The key is never used for inference.

Credentials: Dotii does not ask for a key. It reads, read-only, the provider
API key the ZCode desktop app stored in ``<data base dir>/.zcode/v2/
credentials.json``. Each value is ``enc:v1:<iv>.<tag>.<ciphertext>`` (all
base64url), AES-256-GCM. The 32-byte key is ``sha256(secret)`` where ``secret``
is ``$ZCODE_CREDENTIAL_SECRET`` or, by default,
``zcode-credential-fallback:<os.platform>:<homedir>:<username>`` — derivable
from the local machine, with no Keychain, password or elevation involved. See
ZCode ``packages/services/src/credential/providers/credentialCipherProvider.ts``
and ``apps/zcode-cli/packages/adapters/src/auth/credential-cipher.ts``. The
decrypted key lives only in memory: it is never written, cached, logged, or
returned to the web UI. The documented ``ANTHROPIC_AUTH_TOKEN`` environment
(while ``ANTHROPIC_BASE_URL`` points at Z.ai / BigModel) is also honoured.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:  # pragma: no cover - import guard
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - reported at runtime, never crashes import
    AESGCM = None

from .base import (
    STATUS_AUTH_ERROR, STATUS_ERROR, STATUS_NOT_CONFIGURED,
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow,
    as_number, parse_epoch, safe_text,
)
from .credentials import env_secret, http_get_json


QUOTA_PATH = "/api/monitor/usage/quota/limit"
HOSTS = {"cn": "https://open.bigmodel.cn", "global": "https://api.z.ai"}
ENC_PREFIX = "enc:v1:"
GCM_IV_BYTES = 12
GCM_TAG_BYTES = 16
CREDENTIAL_SECRET_ENV = "ZCODE_CREDENTIAL_SECRET"
# The on-disk key format is <base64url iv>.<base64url tag>.<base64url ciphertext>;
# the api-key entries are account-provider:...:api-key (provider-provisioning.ts).
API_KEY_SUFFIX = ":api-key"
ACCOUNT_PROVIDER_PREFIX = "account-provider:"
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


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def _machine_username() -> str:
    try:
        import pwd  # type: ignore
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:  # noqa: BLE001 - matches the CLI's try/catch fallback
        return "unknown"


def _node_platform() -> str:
    # Mirror node's os.platform() for the three desktop targets ZCode ships.
    return {"darwin": "darwin", "win32": "win32"}.get(sys.platform, "linux")


def credential_secret() -> str:
    configured = os.environ.get(CREDENTIAL_SECRET_ENV, "").strip()
    if configured:
        return configured
    return f"zcode-credential-fallback:{_node_platform()}:{Path.home()}:{_machine_username()}"


def _cipher_key() -> bytes:
    return hashlib.sha256(credential_secret().encode("utf-8")).digest()


def decrypt_credential_value(value: str, key: bytes | None = None) -> str | None:
    """Decrypt one enc:v1: value. Returns None for a plaintext or malformed value.

    Raises QuotaError only when cryptography is unavailable; a wrong key or a bad
    auth tag surfaces as None so one corrupt entry never breaks detection.
    """
    if not isinstance(value, str) or not value.startswith(ENC_PREFIX):
        return None
    if AESGCM is None:
        raise QuotaError("缺少 cryptography 库，无法解密 ZCode 凭据", STATUS_ERROR)
    parts = value[len(ENC_PREFIX):].split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None
    try:
        iv, tag, ciphertext = (_b64url_decode(part) for part in parts)
    except Exception:  # noqa: BLE001 - malformed base64url
        return None
    if len(iv) != GCM_IV_BYTES or len(tag) != GCM_TAG_BYTES:
        return None
    try:
        # cryptography expects ciphertext||tag for AES-GCM.
        plaintext = AESGCM(key or _cipher_key()).decrypt(iv, ciphertext + tag, None)
    except Exception:  # noqa: BLE001 - InvalidTag / key mismatch -> treat as unreadable
        return None
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _zcode_data_root() -> Path:
    env_base = os.environ.get("ZCODE_DATA_BASE_DIR", "").strip()
    if env_base:
        return Path(env_base).expanduser() / ".zcode"
    setting = Path.home() / ".zcode" / "v2" / "setting.json"
    try:
        data = json.loads(setting.read_text(encoding="utf-8"))
        base = data.get("dataBaseDir")
        if isinstance(base, str) and base.strip():
            return Path(base).expanduser() / ".zcode"
    except (OSError, ValueError):
        pass
    return Path.home() / ".zcode"


def credentials_file() -> Path:
    return _zcode_data_root() / "v2" / "credentials.json"


def _region_for_credential_key(key: str) -> str:
    lowered = key.lower()
    if "bigmodel" in lowered:
        return "cn"
    if "zai" in lowered or "z.ai" in lowered:
        return "global"
    return ""


def read_stored_api_keys() -> list[tuple[str, str]]:
    """Return (region, api_key) pairs decrypted from the ZCode credential store.

    Only ``account-provider:...:api-key`` entries are considered; JWTs and other
    secrets are ignored. Nothing is written and no value is logged.
    """
    path = credentials_file()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(raw, dict):
        return []
    if AESGCM is None:
        return []  # detect() reports the missing library; never raise from here
    key_material = _cipher_key()
    results: list[tuple[str, str]] = []
    for store_key, value in raw.items():
        if not (isinstance(store_key, str) and store_key.startswith(ACCOUNT_PROVIDER_PREFIX)
                and store_key.endswith(API_KEY_SUFFIX)):
            continue
        try:
            plaintext = decrypt_credential_value(value, key_material)
        except QuotaError:
            return []
        if plaintext and plaintext.strip():
            results.append((_region_for_credential_key(store_key), plaintext.strip()))
    return results


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

    def _credential(self) -> tuple[str | None, str, str]:
        """Return (api_key, source, region). Order: ZCode store, then ANTHROPIC env."""
        wanted = self.region if self.region in HOSTS else ""
        stored = read_stored_api_keys()
        # Prefer a key whose provider matches the requested region, else Z.ai
        # (global) ahead of BigModel (cn), matching ZCode's own resolution order.
        def rank(entry: tuple[str, str]) -> tuple[int, int]:
            region, _ = entry
            matches_wanted = 0 if (wanted and region == wanted) else 1
            global_first = 0 if region == "global" else 1
            return (matches_wanted, global_first)

        for region, api_key in sorted(stored, key=rank):
            if wanted and region and region != wanted:
                continue
            return api_key, "zcode", region or wanted or "cn"
        # The official Z.ai usage plugin reads ANTHROPIC_AUTH_TOKEN, but only
        # when Claude Code is pointed at a Z.ai / bigmodel endpoint.
        base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
        env_region = _region_from_base_url(base_url)
        if env_region:
            value, source = env_secret("ANTHROPIC_AUTH_TOKEN")
            if value:
                return value, source, (wanted or env_region)
        return None, "", ""

    def resolved_region(self) -> str:
        region = self.region
        if region in HOSTS:
            return region
        _key, _source, detected = self._credential()
        return detected if detected in HOSTS else "cn"

    def _store_error(self) -> str | None:
        """None if the store is readable; a short reason if it exists but cannot be read."""
        path = credentials_file()
        if not path.is_file():
            return None
        try:
            path.read_text(encoding="utf-8")
        except OSError:
            return "无法读取 ZCode 凭据文件"
        if AESGCM is None:
            return "缺少 cryptography 库，无法解密 ZCode 凭据"
        return None

    def detect(self) -> Detection:
        key, source, region = self._credential()
        if key:
            label = {"global": "Z.ai", "cn": "BigModel"}.get(region, region or "")
            where = "ZCode 本地凭据" if source == "zcode" else source
            detail = f"已读取 {where}（{label}）" if label else f"已读取 {where}"
            return Detection(True, True, detail, source)
        app_present = (Path.home() / ".zcode").exists()
        if app_present:
            reason = self._store_error()
            if reason:
                return Detection(True, False, f"已检测到 ZCode，但{reason}")
            return Detection(True, False, "已检测到 ZCode，但未登录或无法读取 Key")
        return Detection(False, False, "未检测到 ZCode")

    def fetch(self) -> QuotaResult:
        key, _source, region = self._credential()
        if not key:
            raise QuotaError("未读取到 GLM Coding Plan 登录信息", STATUS_NOT_CONFIGURED)
        header_value = key.strip()
        if header_value.lower().startswith("bearer "):
            header_value = header_value[7:].strip()
        region = region if region in HOSTS else self.resolved_region()
        url = HOSTS[region] + QUOTA_PATH
        payload = http_get_json(url, {"authorization": header_value}, self.timeout, secrets=[key])
        result = parse_quota_response(payload)
        result.extra["region"] = region
        return result
