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
from pathlib import Path
from typing import Any

from .base import (
    STATUS_AUTH_ERROR, STATUS_ERROR, STATUS_UNAVAILABLE,
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow,
    as_number, parse_epoch, safe_text,
)
from .credentials import find_executable
from .stdio_rpc import terminate_process_tree


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
        env = dict(os.environ)
        # Best effort: discourage an interactive browser OAuth pop-up from a background poll.
        env["BROWSER"] = "/usr/bin/true"
        env.setdefault("NO_COLOR", "1")
        try:
            process = subprocess.Popen(
                [path, "-p", "/usage", "--output-format", "json", "--print-timeout", "90s"],
                cwd=str(Path.home()), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
                start_new_session=os.name == "posix",
            )
        except OSError as error:
            raise QuotaError(f"无法启动 agy：{error.strerror or type(error).__name__}", STATUS_UNAVAILABLE) from None
        try:
            output, _ = process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            terminate_process_tree(process)
            raise QuotaError("agy /usage 超时", STATUS_UNAVAILABLE) from None
        finally:
            # Reap MCP helpers that agy may leave in its session.
            terminate_process_tree(process)
        if process.returncode not in (0, None) and not output.strip():
            raise QuotaError(f"agy 退出码 {process.returncode}", STATUS_ERROR)
        return parse_usage_report(extract_json_document(output))
