"""Provider interface and normalized result shape for AI coding agent quotas.

Every provider returns the same structure so the management UI can render any
agent without provider-specific code. Percentages are always expressed as
*used* percent (0-100); providers that report remaining fractions convert them.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


STATUS_OK = "ok"
STATUS_PENDING = "pending"
STATUS_DISABLED = "disabled"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_UNAVAILABLE = "unavailable"
STATUS_AUTH_ERROR = "auth_error"
STATUS_ERROR = "error"
STATUSES = {
    STATUS_OK, STATUS_PENDING, STATUS_DISABLED, STATUS_NOT_CONFIGURED,
    STATUS_UNAVAILABLE, STATUS_AUTH_ERROR, STATUS_ERROR,
}


class QuotaError(RuntimeError):
    """A provider failure that is safe to show to the user (never contains secrets)."""

    def __init__(self, message: str, status: str = STATUS_ERROR) -> None:
        super().__init__(message)
        self.status = status if status in STATUSES else STATUS_ERROR


@dataclass
class Detection:
    """Local, offline detection result. Must never perform network calls."""

    available: bool
    configured: bool
    detail: str = ""
    source: str = ""


@dataclass
class QuotaWindow:
    id: str
    label: str
    used_percent: float | None = None
    used: float | None = None
    limit: float | None = None
    unit: str = ""
    reset_at_epoch: int = 0

    def as_dict(self) -> dict[str, Any]:
        used_percent = clamp_percent(self.used_percent)
        if used_percent is None and self.used is not None and self.limit:
            used_percent = clamp_percent(self.used / self.limit * 100)
        return {
            "id": self.id,
            "label": self.label,
            "used_percent": rounded(used_percent),
            "remaining_percent": rounded(None if used_percent is None else 100 - used_percent),
            "used": rounded(self.used),
            "limit": rounded(self.limit),
            "unit": self.unit,
            "reset_at_epoch": int(self.reset_at_epoch or 0),
        }


@dataclass
class QuotaResult:
    plan: str = ""
    windows: list[QuotaWindow] = field(default_factory=list)
    primary_window_id: str = ""
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, str) and value.strip():
        try:
            number = float(value.strip())
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    return None


def clamp_percent(value: Any) -> float | None:
    number = as_number(value)
    if number is None:
        return None
    return max(0.0, min(100.0, number))


def rounded(value: float | None) -> float | None:
    if value is None:
        return None
    return round(float(value), 1)


def parse_epoch(value: Any) -> int:
    """Accept epoch seconds, epoch milliseconds or ISO-8601/RFC3339 strings."""
    number = as_number(value)
    if number is not None:
        if number > 10_000_000_000:
            number /= 1000
        return max(0, int(number))
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        # Python < 3.11 rejects more than 6 fractional digits (RFC3339 nanos).
        if "." in text:
            head, _, tail = text.partition(".")
            digits = "".join(ch for ch in tail if ch.isdigit())
            suffix = tail[len(digits):]
            text = f"{head}.{digits[:6]}{suffix}" if digits else head + suffix
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return 0
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, int(parsed.timestamp()))
    return 0


def safe_text(value: Any, maximum: int = 80) -> str:
    if value is None:
        return ""
    text = " ".join(str(value).replace("\x00", "").split())
    return text[:maximum]


def empty_entry(provider_id: str, name: str, status: str, detail: str = "") -> dict[str, Any]:
    return {
        "id": provider_id,
        "name": name,
        "status": status,
        "plan": "",
        "used_percent": None,
        "remaining_percent": None,
        "used": None,
        "limit": None,
        "unit": "",
        "reset_at_epoch": 0,
        "windows": [],
        "detail": detail,
        "error": "",
        "fetched_at_epoch": 0,
        "stale": False,
        "extra": {},
    }


def normalize_result(provider_id: str, name: str, result: QuotaResult,
                     fetched_at: int | None = None) -> dict[str, Any]:
    windows = [window.as_dict() for window in result.windows]
    primary = None
    if result.primary_window_id:
        primary = next((item for item in windows if item["id"] == result.primary_window_id), None)
    if primary is None:
        # Most constraining window drives the headline number.
        ranked = [item for item in windows if item["used_percent"] is not None]
        primary = max(ranked, key=lambda item: item["used_percent"]) if ranked else None
    entry = empty_entry(provider_id, name, STATUS_OK, result.detail)
    entry.update({
        "plan": safe_text(result.plan, 40),
        "windows": windows,
        "fetched_at_epoch": int(fetched_at or time.time()),
        "extra": result.extra,
    })
    if primary is not None:
        entry.update({
            "used_percent": primary["used_percent"],
            "remaining_percent": primary["remaining_percent"],
            "used": primary["used"],
            "limit": primary["limit"],
            "unit": primary["unit"],
            "reset_at_epoch": primary["reset_at_epoch"],
        })
    return entry


class QuotaProvider:
    """Base class. Subclasses override ``detect`` and ``fetch``.

    ``detect`` must be cheap and offline. ``fetch`` may block up to ``timeout``
    seconds and raises :class:`QuotaError` for expected failures. The manager
    catches every other exception so one provider can never crash the bridge.
    """

    id = "base"
    name = "Base"
    kind = "api"  # "api": needs a credential; "cli": needs a local executable
    default_interval = 60
    min_interval = 60
    timeout = 10.0
    regions: tuple[str, ...] = ()
    default_region = ""

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        self.settings = dict(settings or {})

    def configure(self, settings: dict[str, Any]) -> None:
        self.settings = dict(settings or {})

    @property
    def region(self) -> str:
        value = str(self.settings.get("region") or self.default_region)
        return value if value in self.regions else self.default_region

    def detect(self) -> Detection:  # pragma: no cover - interface
        raise NotImplementedError

    def fetch(self) -> QuotaResult:  # pragma: no cover - interface
        raise NotImplementedError

    def fetch_quota(self) -> dict[str, Any]:
        """Fetch and normalize. Raises QuotaError on failure."""
        return normalize_result(self.id, self.name, self.fetch())

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "default_interval": self.default_interval,
            "min_interval": self.min_interval,
            "timeout": self.timeout,
            "regions": list(self.regions),
            "default_region": self.default_region,
        }
