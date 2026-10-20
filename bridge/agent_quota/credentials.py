"""Read-only credential helpers.

Secrets are only ever read at runtime from the user's own sources (environment
variables, the macOS Keychain, or files written by the official CLIs). They are
never written, logged, or returned to the web UI. Use :func:`redact` when a
value has to be mentioned at all.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

from .base import STATUS_AUTH_ERROR, STATUS_ERROR, STATUS_UNAVAILABLE, QuotaError


KEYCHAIN_SERVICE = "Dotii Agent Quota"
USER_AGENT = "DotiiBridge-AgentQuota/1"


def redact(value: str | None) -> str:
    if not value:
        return ""
    return value[:4] + "…"


def scrub(text: str, secrets: Iterable[str | None]) -> str:
    """Remove any secret that might have been echoed into an error message."""
    for secret in secrets:
        if secret and len(secret) >= 6:
            text = text.replace(secret, redact(secret))
    return text


def keychain_secret(account: str, service: str = KEYCHAIN_SERVICE) -> str | None:
    """Read a generic password from the login Keychain (macOS only, read-only)."""
    if sys.platform != "darwin":
        return None
    security = shutil.which("security") or "/usr/bin/security"
    if not Path(security).exists():
        return None
    try:
        completed = subprocess.run(
            [security, "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def env_secret(*names: str) -> tuple[str | None, str]:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value, f"env:{name}"
    return None, ""


def read_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def find_executable(names: Iterable[str], extra: Iterable[Path] = (), env_name: str = "") -> str | None:
    if env_name:
        explicit = os.environ.get(env_name, "").strip()
        if explicit and Path(explicit).expanduser().is_file():
            return str(Path(explicit).expanduser())
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    home = Path.home()
    candidates = [*extra]
    for name in names:
        candidates.extend([
            home / ".local" / "bin" / name,
            Path("/opt/homebrew/bin") / name,
            Path("/usr/local/bin") / name,
            home / ".npm-global" / "bin" / name,
            home / ".bun" / "bin" / name,
        ])
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def http_get_json(url: str, headers: dict[str, str], timeout: float,
                  secrets: Iterable[str | None] = ()) -> Any:
    """GET a JSON document. Error messages never include request headers."""
    secret_list = list(secrets)
    request = urllib.request.Request(url, method="GET", headers={
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        **headers,
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https hosts
            body = response.read(1024 * 1024)
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise QuotaError(f"鉴权失败（HTTP {error.code}），请检查凭据", STATUS_AUTH_ERROR) from None
        if error.code == 404:
            raise QuotaError("额度接口不存在（HTTP 404）", STATUS_ERROR) from None
        if error.code == 429:
            raise QuotaError("请求过于频繁（HTTP 429），稍后重试", STATUS_ERROR) from None
        raise QuotaError(f"额度接口返回 HTTP {error.code}", STATUS_ERROR) from None
    except urllib.error.URLError as error:
        reason = scrub(str(getattr(error, "reason", error)), secret_list)
        raise QuotaError(f"网络不可用：{reason}"[:160], STATUS_UNAVAILABLE) from None
    except (TimeoutError, OSError) as error:
        raise QuotaError(f"网络请求失败：{scrub(str(error), secret_list)}"[:160], STATUS_UNAVAILABLE) from None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise QuotaError("额度接口返回的不是 JSON", STATUS_ERROR) from None
