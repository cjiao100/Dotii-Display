"""Pluggable quota collection for AI coding agents shown in the management UI.

This data is only exposed through the loopback-only admin overview. It is not
part of the schema v1 snapshot sent to the Dotii firmware.
"""

from __future__ import annotations

from .base import QuotaError, QuotaProvider, QuotaResult, QuotaWindow, normalize_result
from .grok import GrokProvider
from .kimi import KimiProvider
from .manager import AgentQuotaConfigStore, AgentQuotaManager
from .zcode import ZCodeProvider


def default_providers() -> list[QuotaProvider]:
    return [ZCodeProvider(), KimiProvider(), GrokProvider()]


__all__ = [
    "AgentQuotaConfigStore", "AgentQuotaManager", "GrokProvider", "KimiProvider", "QuotaError",
    "QuotaProvider", "QuotaResult", "QuotaWindow", "ZCodeProvider", "default_providers", "normalize_result",
]
