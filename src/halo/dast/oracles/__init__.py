"""Dual-Layer Verification Oracles (Wire-Level & Semantic LLM Differ)."""

from halo.dast.oracles.semantic import SemanticDifferOracle, SemanticDifferResult
from halo.dast.oracles.wire import (
    DEFAULT_PUBLIC_FIELDS,
    DEFAULT_SENSITIVE_PATTERNS,
    StateMutationResult,
    WireOracle,
)

__all__ = [
    "DEFAULT_PUBLIC_FIELDS",
    "DEFAULT_SENSITIVE_PATTERNS",
    "SemanticDifferOracle",
    "SemanticDifferResult",
    "StateMutationResult",
    "WireOracle",
]
