"""Antigravity (Google, ``agy`` CLI) quota via the official print mode.

Source: antigravity-cli 1.1.11 release notes: ``agy -p "/usage" --output-format
json`` answers read-only slash commands "without starting an agent turn,
spending quota, or leaving a conversation behind". The structure of
``command.data`` is not documented; the parser follows the only known shape
(CodexBar's synthetic fixture: groups[].buckets[] with ``remaining_fraction``)
and must be confirmed against real output. Cold starts are slow, so the
default interval is 15 minutes. Local RPC / v1internal endpoints are not used.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Any

from .base import (
    STATUS_AUTH_ERROR, STATUS_ERROR, STATUS_UNAVAILABLE,
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow,
    as_number, parse_epoch, safe_text,
)
from .credentials import child_env, find_executable
from .stdio_rpc import terminate_process_tree


# `-p /usage` answers without an agent turn only since 1.1.11; older builds
# would treat "/usage" as a prompt and spend quota, so they are never run.
MIN_VERSION = (1, 1, 11)
VERSION_TIMEOUT = 10.0
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(text or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


WINDOW_LABELS = {"5h": "5 小时", "weekly": "每周", "daily": "每日", "monthly": "每月"}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "group"


def extract_json_document(output: str) -> Any:
    """Accept a single JSON document or JSON lines (stream-json); prefer the command record."""
    text = output.strip()
    if not text:
        raise QuotaError("agy 没有输出")
    try:
        return json.loads(text)
    except ValueError:
        pass
    candidates = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                candidates.append(json.loads(line))
            except ValueError:
                continue
    for item in reversed(candidates):
        if isinstance(item, dict) and isinstance(item.get("command"), dict):
            return item
    if candidates:
        return candidates[-1]
    raise QuotaError("agy 输出不是 JSON")


def parse_usage_report(payload: Any) -> QuotaResult:
    if not isinstance(payload, dict):
        raise QuotaError("agy /usage 返回格式无效")
    status = str(payload.get("status") or "").upper()
    if status and status != "SUCCESS":
        message = safe_text(payload.get("response") or payload.get("error") or status, 120)
        lowered = message.lower()
        auth_words = ("login", "logged in", "sign in", "auth")
        kind = STATUS_AUTH_ERROR if any(word in lowered for word in auth_words) else STATUS_ERROR
        raise QuotaError(f"agy /usage 失败：{message}", kind)
    command = payload.get("command") if isinstance(payload.get("command"), dict) else {}
    data = command.get("data") if isinstance(command.get("data"), dict) else {}
    groups = data.get("groups") if isinstance(data.get("groups"), list) else []
    windows: list[QuotaWindow] = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        group_name = safe_text(group.get("name") or "", 40)
        for bucket in group.get("buckets") if isinstance(group.get("buckets"), list) else []:
            if not isinstance(bucket, dict) or bucket.get("disabled") is True:
                continue
            remaining = as_number(bucket.get("remaining_fraction", bucket.get("remainingFraction")))
            if remaining is None:
                continue
            remaining = max(0.0, min(1.0, remaining))
            window = str(bucket.get("window") or bucket.get("id") or "")
            label = WINDOW_LABELS.get(window, window or "额度")
            windows.append(QuotaWindow(
                id=f"{_slug(group_name)}_{_slug(window)}",
                label=f"{group_name} · {label}" if group_name else label,
                used_percent=(1.0 - remaining) * 100,  # remaining fraction -> used percent
                reset_at_epoch=parse_epoch(bucket.get("reset_time", bucket.get("resetTime"))),
            ))
    if not windows:
        raise QuotaError("agy /usage 未返回可识别的额度分组（结构未公开，需要实测确认）")
    plan = safe_text(data.get("plan") or data.get("tier") or "", 30)
    return QuotaResult(plan=plan, windows=windows)


class AntigravityProvider(QuotaProvider):
    id = "antigravity"
    name = "Antigravity"
    kind = "cli"
    default_interval = 900
    min_interval = 600
    timeout = 120.0
    # Output shape of /usage is unconfirmed: only runs after the user opts in.
    auto_enable = False

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        super().__init__(settings)
        self._version_cache: tuple[str, float, tuple[int, int, int] | None] | None = None

    def executable(self) -> str | None:
        return find_executable(["agy"], env_name="DOTII_AGY_COMMAND")

    def detect(self) -> Detection:
        path = self.executable()
        if not path:
            return Detection(False, False, "未找到 agy CLI")
        return Detection(True, True, f"agy CLI：{path}", "cli")

    def fetch(self) -> QuotaResult:
        path = self.executable()
        if not path:
            raise QuotaError("未找到 agy CLI", STATUS_UNAVAILABLE)
        env = self._env()
        self._require_supported_version(path, env)
        try:
            process = subprocess.Popen(
                [path, "-p", "/usage", "--output-format", "json", "--print-timeout", "90s"],
                cwd=str(Path.home()), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
                start_new_session=os.name == "posix",
            )
        except OSError as error:
            raise QuotaError(f"无法启动 agy：{error.strerror or type(error).__name__}", STATUS_UNAVAILABLE) from None
        chunks: list[str] = []

        def read_stdout() -> None:
            try:
                for chunk in iter(lambda: process.stdout.read(65536), ""):
                    chunks.append(chunk)
            except (OSError, ValueError):
                pass  # pipe closed by terminate_process_tree

        reader = threading.Thread(target=read_stdout, name="agy-stdout", daemon=True)
        reader.start()
        try:
            try:
                process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                raise QuotaError("agy /usage 超时", STATUS_UNAVAILABLE) from None
            # A helper that inherited stdout can hold the pipe open after agy exits;
            # do not wait for EOF beyond a short grace period.
            reader.join(2.0)
        finally:
            # Reap MCP helpers that agy may leave in its process group.
            terminate_process_tree(process)
            reader.join(2.0)
        output = "".join(chunks)
        if process.returncode not in (0, None) and not output.strip():
            raise QuotaError(f"agy 退出码 {process.returncode}", STATUS_ERROR)
        return parse_usage_report(extract_json_document(output))

    @staticmethod
    def _env() -> dict[str, str]:
        env = child_env()
        # Best effort: discourage an interactive browser OAuth pop-up from a background poll.
        env["BROWSER"] = "/usr/bin/true"
        env.setdefault("NO_COLOR", "1")
        return env

    def _require_supported_version(self, path: str, env: dict[str, str]) -> None:
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            mtime = 0.0
        cached = self._version_cache
        if cached and cached[0] == path and cached[1] == mtime:
            version = cached[2]
        else:
            version = self._read_version(path, env)
            self._version_cache = (path, mtime, version)
        wanted = ".".join(map(str, MIN_VERSION))
        if version is None:
            raise QuotaError(f"无法确认 agy 版本（需要 ≥ {wanted}），为避免消耗额度未执行 /usage", STATUS_UNAVAILABLE)
        if version < MIN_VERSION:
            found = ".".join(map(str, version))
            raise QuotaError(f"agy {found} 过旧（需要 ≥ {wanted}），为避免消耗额度未执行 /usage", STATUS_UNAVAILABLE)

    @staticmethod
    def _read_version(path: str, env: dict[str, str]) -> tuple[int, int, int] | None:
        try:
            process = subprocess.Popen(
                [path, "--version"], cwd=str(Path.home()), env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                errors="replace", start_new_session=os.name == "posix",
            )
        except OSError:
            return None
        try:
            output, _ = process.communicate(timeout=VERSION_TIMEOUT)
        except subprocess.TimeoutExpired:
            return None
        finally:
            terminate_process_tree(process, grace=1.0)
        return parse_version(output[:2000])
