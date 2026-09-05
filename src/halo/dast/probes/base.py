"""Base models and abstract foundations for DAST dynamic probing engines."""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field


class ProbeResult(BaseModel):
    """Encapsulates the dynamic active verification outcome, wire evidence, and reproduction steps."""

    model_config = ConfigDict(extra="allow")

    flaw_type: str = Field(
        default="UNKNOWN",
        description="Vulnerability flaw class (e.g. BOLA_IDOR, BFLA, RACE_CONDITION, WORKFLOW_BYPASS)",
    )
    endpoint: str = Field(default="", description="Target route or endpoint verified")
    vulnerable: bool = Field(default=False, description="Whether the dynamic probe proved the vulnerability")
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score in the dynamic verification outcome (0.0 to 1.0)",
    )
    request_evidence: list[dict[str, Any]] | dict[str, Any] = Field(
        default_factory=list,
        description="Recorded wire requests sent during probe execution",
    )
    response_evidence: list[dict[str, Any]] | dict[str, Any] = Field(
        default_factory=list,
        description="Recorded wire responses received during probe execution",
    )
    observed_side_effects: list[str] = Field(
        default_factory=list,
        description="Empirical side effects observed during probing (e.g. state mutation, token leakage)",
    )
    reproduction_steps: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Step-by-step reproduction sequence for exploit verification",
    )
    details: str = Field(default="", description="Explanatory details of the probe outcome")


class BaseProbe:
    """Base class providing shared wire recording and evidence collection utilities."""

    def record_request_evidence(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: Any = None,
        actor: str = "",
    ) -> dict[str, Any]:
        """Format request metadata for evidence collection."""
        sanitized_headers = {
            k: ("Bearer [REDACTED]" if k.lower() == "authorization" and "bearer" in v.lower() else v)
            for k, v in (headers or {}).items()
        }
        entry: dict[str, Any] = {
            "actor": actor,
            "method": method.upper(),
            "url": str(url),
            "headers": sanitized_headers,
        }
        if body is not None:
            entry["body"] = body
        return entry

    def record_response_evidence(
        self,
        response: httpx.Response,
        actor: str = "",
        step: str = "",
    ) -> dict[str, Any]:
        """Format HTTP response metadata for evidence collection."""
        body_data: Any = None
        try:
            body_data = response.json()
        except Exception:  # noqa: BLE001
            body_data = response.text[:2000] if response.text else ""

        return {
            "step": step,
            "actor": actor,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body_data,
        }
