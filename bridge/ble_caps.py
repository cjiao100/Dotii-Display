"""Size caps for snapshots sent over the BLE data channel.

Wi-Fi and USB carry the full snapshot; BLE is a low-bandwidth fallback, so
unbounded text (last_user_message, codex_messages, task history) is trimmed
at UTF-8 boundaries and images are never advertised.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from dtu_protocol import MAX_INFLATED, encode_compressed_frame, json_body

ELLIPSIS = "…"
# Byte caps per text field at scale 1.0 (firmware snapshot buffers in
# app_state.h: last_user_message 1536, last_assistant_message 256,
# conversation_text 3073; task details are PSRAM-backed).
TEXT_CAPS = {
    "title": 95,
    "last_user_message": 1200,
    "last_assistant_message": 1200,
    "reasoning_summary": 383,
    "current_action": 127,
}
MESSAGE_CAP = 900
MESSAGE_COUNT = 6
MAX_TASKS = 6                       # CODEX_TASK_DETAIL_MAX
COMPRESSED_BUDGET = 12 * 1024       # whole DTZ1 request on the wire
RAW_BUDGET = 64 * 1024              # well under the firmware 96 KB inflate cap
SCALES = (1.0, 0.5, 0.25, 0.1)
VOLATILE_KEYS = ("generated_at_epoch",)


def truncate_utf8(text: Any, limit: int) -> Any:
    """Trim text to at most ``limit`` UTF-8 bytes without splitting a character."""
    if not isinstance(text, str):
        return text
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    marker = ELLIPSIS.encode("utf-8")
    if limit <= len(marker):
        return encoded[:max(0, limit)].decode("utf-8", "ignore")
    return encoded[:limit - len(marker)].decode("utf-8", "ignore") + ELLIPSIS


def _cap_task(task: Any, scale: float) -> Any:
    if not isinstance(task, dict):
        return task
    for key, limit in TEXT_CAPS.items():
        if key in task:
            fixed = key in ("title", "current_action")
            task[key] = truncate_utf8(task[key], limit if fixed else max(48, int(limit * scale)))
    messages = task.get("codex_messages")
    if isinstance(messages, list):
        count = max(1, int(round(MESSAGE_COUNT * scale)))
        task["codex_messages"] = [truncate_utf8(item, max(48, int(MESSAGE_CAP * scale)))
                                  for item in messages[-count:]]
    return task


def _shape(snapshot: dict[str, Any], scale: float, drop_history: bool) -> dict[str, Any]:
    capped = copy.deepcopy(snapshot)
    custom = capped.get("custom")
    if isinstance(custom, dict):
        custom["image_available"] = False
    bambu = capped.get("bambu")
    if isinstance(bambu, dict):
        bambu["camera_available"] = False
    codex = capped.get("codex")
    if isinstance(codex, dict):
        _cap_task(codex.get("task"), scale)
        tasks = codex.get("tasks")
        if isinstance(tasks, list):
            tasks = tasks[:1 if drop_history else MAX_TASKS]
            codex["tasks"] = [_cap_task(item, scale) for item in tasks]
            if drop_history:
                for item in codex["tasks"]:
                    if isinstance(item, dict):
                        item["codex_messages"] = item.get("codex_messages", [])[-1:]
    return capped


def cap_snapshot_for_ble(snapshot: dict[str, Any], envelope: dict[str, Any] | None = None,
                         budget: int = COMPRESSED_BUDGET) -> tuple[dict[str, Any], int]:
    """Return (capped snapshot, DTZ1 request size) that fits ``budget``.

    ``envelope`` is the rest of the request (id/op/epoch/...) so the measured
    size is the size actually written to the radio.
    """
    envelope = dict(envelope or {"id": 0, "op": "snapshot"})
    attempts = [(scale, False) for scale in SCALES] + [(SCALES[-1], True)]
    capped: dict[str, Any] = snapshot
    size = 0
    for scale, drop_history in attempts:
        capped = _shape(snapshot, scale, drop_history)
        request = {**envelope, "snapshot": capped}
        raw = len(json_body(request))
        if raw > min(RAW_BUDGET, MAX_INFLATED):
            continue
        size = len(encode_compressed_frame(request))
        if size <= budget:
            return capped, size
    raise ValueError("snapshot_too_large_for_ble")


def snapshot_digest(snapshot: dict[str, Any], device: dict[str, Any] | None = None) -> str:
    """Content hash used for send-on-change (ignores generation timestamps)."""
    stable = {key: value for key, value in snapshot.items() if key not in VOLATILE_KEYS}
    payload = json.dumps({"snapshot": stable, "device": device or {}}, sort_keys=True,
                         ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
