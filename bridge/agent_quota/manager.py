"""Background polling and settings for agent quota providers.

Each provider runs in its own short-lived worker thread so a slow or failing
provider can never block the others or the HTTP bridge. All exceptions are
caught and turned into a per-provider error state.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from .base import (
    STATUS_DISABLED, STATUS_ERROR, STATUS_NOT_CONFIGURED, STATUS_OK, STATUS_PENDING,
    STATUS_UNAVAILABLE, Detection, QuotaError, QuotaProvider, empty_entry, safe_text,
)


DETECT_TTL_SECONDS = 300
MANUAL_REFRESH_FLOOR_SECONDS = 30
OPT_IN_DETAIL = "已检测到；该数据源尚未充分验证，默认关闭，可手动开启"
MAX_INTERVAL_SECONDS = 6 * 60 * 60
WATCHDOG_GRACE_SECONDS = 30
ALLOWED_SETTING_KEYS = {"enabled", "region", "interval_seconds"}


def validate_provider_settings(provider: QuotaProvider, payload: Any) -> dict[str, Any]:
    """Only non-secret settings are accepted; credentials never go to disk here."""
    if not isinstance(payload, dict):
        raise ValueError("provider settings must be an object")
    unknown = set(payload) - ALLOWED_SETTING_KEYS
    if unknown:
        raise ValueError(f"unsupported provider setting: {sorted(unknown)[0]}")
    result: dict[str, Any] = {}
    if "enabled" in payload:
        if not isinstance(payload["enabled"], bool):
            raise ValueError("enabled must be boolean")
        result["enabled"] = payload["enabled"]
    if "region" in payload:
        if payload["region"] not in provider.regions:
            raise ValueError("unsupported region")
        result["region"] = payload["region"]
    if "interval_seconds" in payload:
        value = payload["interval_seconds"]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("interval_seconds must be an integer")
        if value < provider.min_interval or value > MAX_INTERVAL_SECONDS:
            raise ValueError(f"interval_seconds must be between {provider.min_interval} and {MAX_INTERVAL_SECONDS}")
        result["interval_seconds"] = value
    return result


class AgentQuotaConfigStore:
    """Local, untracked settings file in the bridge data folder (no secrets)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.RLock()

    def read(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            if not self.path.is_file():
                return {}
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                logging.warning("Agent 额度配置文件无法读取，使用默认设置")
                return {}
            providers = payload.get("providers") if isinstance(payload, dict) else None
            if not isinstance(providers, dict):
                return {}
            return {
                str(key): {k: v for k, v in value.items() if k in ALLOWED_SETTING_KEYS}
                for key, value in providers.items() if isinstance(value, dict)
            }

    def write(self, providers: dict[str, dict[str, Any]]) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary_name = tempfile.mkstemp(prefix="agent-quota-", suffix=".json", dir=self.path.parent)
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    json.dump({"version": 1, "providers": providers}, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
                os.replace(temporary_name, self.path)
            finally:
                if os.path.exists(temporary_name):
                    os.unlink(temporary_name)


class _ProviderState:
    def __init__(self, provider: QuotaProvider) -> None:
        self.provider = provider
        self.entry = empty_entry(provider.id, provider.name, STATUS_PENDING)
        self.detection = Detection(False, False, "尚未检测")
        self.detected_at = 0.0
        self.next_due = 0.0
        # A fetch in flight is identified by run_id (0 = idle). settings_generation
        # changes when the user edits settings; a run started under an older
        # generation still clears its own run_id on exit but its result is dropped.
        self.run_id = 0
        self.running_since = 0.0
        self.last_started = 0.0
        self.settings_generation = 0
        self.detect_token = 0
        self.last_success_epoch = 0


class AgentQuotaManager:
    def __init__(self, providers: Iterable[QuotaProvider], config: AgentQuotaConfigStore,
                 clock: Callable[[], float] = time.time,
                 spawn: Callable[[Callable[[], None], str], None] | None = None) -> None:
        self.config = config
        self.clock = clock
        self.lock = threading.RLock()
        self.states: dict[str, _ProviderState] = {}
        for provider in providers:
            self.states[provider.id] = _ProviderState(provider)
        self._spawn = spawn or self._spawn_thread
        self._wake = threading.Event()
        self._run_counter = 0
        self._apply_settings(self.config.read())

    # ----- settings -----------------------------------------------------
    def _apply_settings(self, settings: dict[str, dict[str, Any]]) -> None:
        for provider_id, state in self.states.items():
            state.provider.configure(settings.get(provider_id, {}))

    def settings_for(self, provider_id: str) -> dict[str, Any]:
        return dict(self.config.read().get(provider_id, {}))

    def update_provider(self, provider_id: str, changes: Any) -> dict[str, Any]:
        with self.lock:
            state = self.states.get(provider_id)
            if state is None:
                raise ValueError("unknown provider")
            validated = validate_provider_settings(state.provider, changes)
            settings = self.config.read()
            merged = {**settings.get(provider_id, {}), **validated}
            settings[provider_id] = merged
            self.config.write(settings)
            state.provider.configure(merged)
            state.detected_at = 0.0
            state.detect_token += 1
            state.next_due = 0.0
            state.settings_generation += 1
        self._wake.set()
        return merged

    def request_refresh(self, provider_id: str | None = None) -> list[str]:
        """Ask for an early re-read. A floor protects providers from click spam.

        Returns the ids whose refresh was accepted immediately; the others are
        deferred until MANUAL_REFRESH_FLOOR_SECONDS after their last fetch.
        """
        accepted: list[str] = []
        with self.lock:
            if provider_id is not None and provider_id not in self.states:
                raise ValueError("unknown provider")
            now = self.clock()
            for state in self.states.values():
                if provider_id is not None and state.provider.id != provider_id:
                    continue
                earliest = state.last_started + MANUAL_REFRESH_FLOOR_SECONDS if state.last_started else 0.0
                if state.next_due > earliest:
                    state.next_due = earliest
                if earliest <= now:
                    state.detected_at = 0.0
                    state.detect_token += 1
                    accepted.append(state.provider.id)
        self._wake.set()
        return accepted

    # ----- polling --------------------------------------------------------
    def _interval(self, provider: QuotaProvider) -> int:
        value = provider.settings.get("interval_seconds")
        if isinstance(value, int) and not isinstance(value, bool):
            return max(provider.min_interval, min(MAX_INTERVAL_SECONDS, value))
        return max(provider.min_interval, provider.default_interval)

    def _enabled(self, state: _ProviderState) -> bool:
        explicit = state.provider.settings.get("enabled")
        if isinstance(explicit, bool):
            return explicit
        if not state.provider.auto_enable:
            return False
        return state.detection.available or state.detection.configured

    @staticmethod
    def _safe_detect(provider: QuotaProvider) -> Detection:
        try:
            return provider.detect()
        except Exception as error:  # noqa: BLE001 - detection must never crash the bridge
            logging.warning("Agent 额度检测失败 %s：%s", provider.id, type(error).__name__)
            return Detection(False, False, f"检测失败：{type(error).__name__}")

    def tick(self) -> None:
        now = self.clock()
        # Detection may spawn subprocesses (e.g. the macOS `security` tool), so it
        # runs without holding the lock; the overview never waits on it.
        with self.lock:
            pending = [
                (state, state.detect_token) for state in self.states.values()
                if not state.detected_at or now - state.detected_at >= DETECT_TTL_SECONDS
            ]
        results = [(state, token, self._safe_detect(state.provider)) for state, token in pending]
        with self.lock:
            for state, token, detection in results:
                state.detection = detection
                # A settings change during detection forces another detection next tick.
                state.detected_at = now if token == state.detect_token else 0.0
            self._schedule(now)

    def _schedule(self, now: float) -> None:
        for state in self.states.values():
            provider = state.provider
            enabled = self._enabled(state)
            if state.run_id and now - state.running_since > provider.timeout + WATCHDOG_GRACE_SECONDS:
                # Abandon a hung worker; its late result is discarded by run id.
                state.run_id = 0
                state.running_since = 0.0
                state.next_due = now + self._interval(provider)
                if enabled:
                    self._set_failure(state, QuotaError("读取超时", STATUS_ERROR), now)
            if not enabled:
                detail = state.detection.detail
                if (not provider.auto_enable and "enabled" not in provider.settings
                        and (state.detection.available or state.detection.configured)):
                    detail = OPT_IN_DETAIL
                state.entry = empty_entry(provider.id, provider.name, STATUS_DISABLED, detail)
                continue
            if state.run_id:
                continue
            if not state.detection.configured:
                # Installed but not logged in -> "未登录"; nothing found locally -> "未检测到".
                status = STATUS_NOT_CONFIGURED if state.detection.available else STATUS_UNAVAILABLE
                state.entry = empty_entry(provider.id, provider.name, status, state.detection.detail)
                state.next_due = 0.0
                continue
            if now < state.next_due:
                continue
            self._run_counter += 1
            run_id = self._run_counter
            state.run_id = run_id
            state.running_since = now
            state.last_started = now
            if state.entry["status"] in {STATUS_DISABLED, STATUS_NOT_CONFIGURED, STATUS_UNAVAILABLE}:
                state.entry = empty_entry(provider.id, provider.name, STATUS_PENDING, "正在读取")
            generation = state.settings_generation
            self._spawn(lambda s=state, r=run_id, g=generation: self._run(s, r, g), f"agent-quota-{provider.id}")

    def _run(self, state: _ProviderState, run_id: int, generation: int) -> None:
        provider = state.provider
        try:
            entry = provider.fetch_quota()
            error: QuotaError | None = None
        except QuotaError as failure:
            entry, error = None, failure
        except Exception as failure:  # noqa: BLE001 - isolate provider bugs
            # No traceback: unexpected messages could echo request details.
            logging.warning("Agent 额度读取异常 %s：%s", provider.id, type(failure).__name__)
            entry, error = None, QuotaError(f"内部错误：{type(failure).__name__}", STATUS_ERROR)
        now = self.clock()
        with self.lock:
            if run_id != state.run_id:
                return  # abandoned by the watchdog; a newer run may be in flight
            state.run_id = 0
            state.running_since = 0.0
            if generation != state.settings_generation or not self._enabled(state):
                # Settings changed mid-fetch: drop the result; next tick re-reads if enabled.
                state.next_due = 0.0
                return
            state.next_due = now + self._interval(provider)
            if entry is not None:
                entry["detail"] = entry.get("detail") or state.detection.detail
                state.entry = entry
                state.last_success_epoch = int(now)
            elif error is not None:
                self._set_failure(state, error, now)

    def _set_failure(self, state: _ProviderState, error: QuotaError, now: float) -> None:
        provider = state.provider
        message = safe_text(str(error), 200)
        previous = state.entry
        if previous.get("status") == STATUS_OK or (previous.get("stale") and previous.get("windows")):
            # Keep the last good numbers, flagged stale, so the card shows "last value".
            state.entry = {**previous, "status": error.status, "error": message, "stale": True}
        else:
            entry = empty_entry(provider.id, provider.name, error.status, state.detection.detail)
            entry["error"] = message
            entry["fetched_at_epoch"] = int(now)
            state.entry = entry
        logging.info("Agent 额度暂不可用 %s：%s", provider.id, message)

    @staticmethod
    def _spawn_thread(target: Callable[[], None], name: str) -> None:
        threading.Thread(target=target, name=name, daemon=True).start()

    def run(self, stop: threading.Event, step: float = 1.0) -> None:
        while not stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - the poller itself must survive
                logging.exception("Agent 额度轮询异常")
            self._wake.wait(step)
            self._wake.clear()

    def start(self, stop: threading.Event) -> threading.Thread:
        thread = threading.Thread(target=self.run, args=(stop,), name="agent-quota", daemon=True)
        thread.start()
        return thread

    # ----- reporting ------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            providers = []
            for state in self.states.values():
                provider = state.provider
                entry = json.loads(json.dumps(state.entry))
                entry.update({
                    "kind": provider.kind,
                    "enabled": self._enabled(state),
                    "enabled_explicit": isinstance(provider.settings.get("enabled"), bool),
                    "detected": bool(state.detection.available or state.detection.configured),
                    "configured": bool(state.detection.configured),
                    "detection_detail": state.detection.detail,
                    "interval_seconds": self._interval(provider),
                    "region": provider.region,
                    "regions": list(provider.regions),
                    "refreshing": bool(state.run_id),
                    "auto_enable": provider.auto_enable,
                    "last_success_epoch": state.last_success_epoch,
                })
                providers.append(entry)
            return {"providers": providers, "generated_at_epoch": int(self.clock())}
