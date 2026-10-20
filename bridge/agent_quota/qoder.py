"""Qoder (``qodercli``) quota via the CLI's stream-json control request.

Source: the official Agent SDK exposes ``get_usage_info()`` (documented name,
undocumented fields); under the hood it sends the control request
``get_usage_info`` to ``qodercli`` (found in the official npm bundle 1.1.74).
No prompt is sent, so no credits are spent. Field names below come from a
third-party sample (spacering-net/codeg PR #869) and must be confirmed on a
real account. The CLI keeps its own login; Dotii never reads it.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .base import (
    STATUS_AUTH_ERROR, STATUS_ERROR, STATUS_UNAVAILABLE,
    Detection, QuotaError, QuotaProvider, QuotaResult, QuotaWindow,
    as_number, parse_epoch, safe_text,
)
from .credentials import find_executable
from .stdio_rpc import terminate_process_tree


QUOTA_BLOCKS = (
    ("userQuota", "plan", "套餐 Credits"),
    ("addOnQuota", "addon", "加油包 Credits"),
    ("sharedQuota", "shared", "共享额度"),
    ("orgResourcePackage", "org", "组织资源包"),
)


def _find_usage(value: Any, depth: int = 0) -> dict[str, Any] | None:
    if not isinstance(value, dict) or depth > 4:
        return None
    if any(key in value for key in ("userQuota", "totalUsagePercentage", "isQuotaExceeded")):
        return value
    if isinstance(value.get("usage"), dict):
        found = _find_usage(value["usage"], depth + 1)
        if found:
            return found
    for key in ("response", "result", "data"):
        found = _find_usage(value.get(key), depth + 1)
        if found:
            return found
    return None


def _quota_window(block: Any, window_id: str, label: str) -> QuotaWindow | None:
    if not isinstance(block, dict):
        return None
    total = as_number(block.get("total", block.get("limitValue")))
    used = as_number(block.get("used", block.get("usedValue")))
    remaining = as_number(block.get("remaining", block.get("remainingValue")))
    if used is None and total is not None and remaining is not None:
        used = max(0.0, total - remaining)
    percent = None
    if used is None or not total:
        # Only trust "percentage" when used/total are missing (its direction is undocumented).
        percent = as_number(block.get("percentage"))
    if used is None and percent is None:
        return None
    return QuotaWindow(
        id=window_id, label=label, used_percent=percent, used=used, limit=total,
        unit=safe_text(block.get("unit") or "credits", 12),
        reset_at_epoch=parse_epoch(block.get("nextResetAt") or block.get("resetAt") or block.get("expiresAt")),
    )


def parse_usage_info(payload: Any) -> QuotaResult:
    usage = _find_usage(payload)
    if usage is None:
        raise QuotaError("Qoder get_usage_info 未返回可识别字段（字段未公开，需要实测确认）")
    windows = []
    for key, window_id, label in QUOTA_BLOCKS:
        window = _quota_window(usage.get(key), window_id, label)
        if window is not None:
            windows.append(window)
    total_percent = as_number(usage.get("totalUsagePercentage"))
    if not windows and total_percent is not None:
        windows.append(QuotaWindow(id="total", label="总用量", used_percent=total_percent))
    if not windows:
        raise QuotaError("Qoder get_usage_info 未返回额度数据")
    extra: dict[str, Any] = {}
    if isinstance(usage.get("isQuotaExceeded"), bool):
        extra["quota_exceeded"] = usage["isQuotaExceeded"]
    return QuotaResult(
        plan=safe_text(usage.get("userType") or usage.get("plan") or "", 30),
        windows=windows,
        primary_window_id="plan" if any(window.id == "plan" for window in windows) else "",
        extra=extra,
    )


def control_response_payload(message: Any, request_id: str) -> Any | None:
    """Return the payload for our request id, or None if this line is unrelated."""
    if not isinstance(message, dict) or message.get("type") != "control_response":
        return None
    response = message.get("response") if isinstance(message.get("response"), dict) else {}
    found_id = message.get("request_id") or response.get("request_id")
    if found_id != request_id:
        return None
    if response.get("subtype") == "error" or message.get("subtype") == "error":
        detail = safe_text(response.get("error") or message.get("error") or "unknown", 120)
        lowered = detail.lower()
        auth_words = ("login", "logged in", "sign in", "auth", "token")
        kind = STATUS_AUTH_ERROR if any(word in lowered for word in auth_words) else STATUS_ERROR
        raise QuotaError(f"Qoder get_usage_info 失败：{detail}", kind)
    return response.get("response", response)


class QoderProvider(QuotaProvider):
    id = "qoder"
    name = "Qoder"
    kind = "cli"
    default_interval = 900
    min_interval = 300
    timeout = 60.0

    def executable(self) -> str | None:
        return find_executable(["qodercli"], env_name="DOTII_QODER_COMMAND")

    def detect(self) -> Detection:
        path = self.executable()
        if not path:
            return Detection(False, False, "未找到 qodercli")
        return Detection(True, True, f"qodercli：{path}", "cli")

    def fetch(self) -> QuotaResult:
        path = self.executable()
        if not path:
            raise QuotaError("未找到 qodercli", STATUS_UNAVAILABLE)
        request_id = f"dotii-{uuid.uuid4().hex[:12]}"
        command = [path, "--print", "--output-format", "stream-json", "--input-format", "stream-json",
                   "--no-session-persistence", "--strict-mcp-config"]
        try:
            process = subprocess.Popen(
                command, cwd=str(Path.home()), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", bufsize=1,
                start_new_session=os.name == "posix",
            )
        except OSError as error:
            raise QuotaError(f"无法启动 qodercli：{error.strerror or type(error).__name__}", STATUS_UNAVAILABLE) from None
        lines: "queue.Queue[str | None]" = queue.Queue()

        def reader() -> None:
            assert process.stdout is not None
            try:
                for line in process.stdout:
                    lines.put(line)
            except (OSError, ValueError):
                pass  # pipe closed during shutdown
            lines.put(None)

        threading.Thread(target=reader, name="agent-quota-qoder", daemon=True).start()
        try:
            assert process.stdin is not None
            process.stdin.write(json.dumps({
                "type": "control_request", "request_id": request_id,
                "request": {"type": "get_usage_info", "subtype": "get_usage_info"},
            }) + "\n")
            process.stdin.flush()
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise QuotaError("Qoder get_usage_info 超时", STATUS_UNAVAILABLE)
                try:
                    line = lines.get(timeout=min(0.25, remaining))
                except queue.Empty:
                    continue
                if line is None:
                    raise QuotaError("qodercli 提前退出", STATUS_UNAVAILABLE)
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    continue
                payload = control_response_payload(message, request_id)
                if payload is not None:
                    return parse_usage_info(payload)
        except (BrokenPipeError, OSError) as error:
            raise QuotaError(f"qodercli 通信失败：{type(error).__name__}", STATUS_UNAVAILABLE) from None
        finally:
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except OSError:
                pass
            terminate_process_tree(process)
