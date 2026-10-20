"""Pluggable quota collection for AI coding agents shown in the management UI.

This data is only exposed through the loopback-only admin overview. It is not
part of the schema v1 snapshot sent to the Dotii firmware.
"""

from __future__ import annotations

from .antigravity import AntigravityProvider
from .base import QuotaError, QuotaProvider, QuotaResult, QuotaWindow, normalize_result
from .grok import GrokProvider
from .kimi import KimiProvider
from .manager import AgentQuotaConfigStore, AgentQuotaManager
from .qoder import QoderProvider
from .zcode import ZCodeProvider


def default_providers() -> list[QuotaProvider]:
    """P0 ZCode/Kimi, P1 Grok, P2 Antigravity/Qoder. Each defaults on only when detected."""
    return [ZCodeProvider(), KimiProvider(), GrokProvider(), AntigravityProvider(), QoderProvider()]


__all__ = [
    "AgentQuotaConfigStore", "AgentQuotaManager", "AntigravityProvider", "GrokProvider", "KimiProvider",
    "QoderProvider", "QuotaError", "QuotaProvider", "QuotaResult", "QuotaWindow", "ZCodeProvider",
    "default_providers", "normalize_result",
]
