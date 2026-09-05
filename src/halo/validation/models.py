"""Validation data models for Project HALO findings, PoCs, and remediations."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FindingData(BaseModel):
    """Encapsulates a verified business logic vulnerability finding."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str = Field(description="Unique finding identifier (e.g. HALO-BOLA-01)")
    flaw_type: str = Field(
        default="UNKNOWN",
        description="Vulnerability flaw category (e.g. BOLA_IDOR, BFLA, RACE_CONDITION, WORKFLOW_BYPASS)",
    )
    endpoint: str = Field(default="", description="Vulnerable route or endpoint path")
    target_url: str = Field(default="", description="Base target URL where finding was verified")
    method: str = Field(default="GET", description="HTTP method used for the vulnerable action")
    severity: str = Field(
        default="HIGH", description="Severity rating (CRITICAL, HIGH, MEDIUM, LOW, INFO)"
    )
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Verification confidence score"
    )
    reproduction_steps: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Chronological steps for exploit reproduction",
    )
    file_path: str = Field(default="", description="Source code file path where flaw originates")
    line_start: int = Field(default=1, description="Starting source line number")
    line_end: int = Field(default=1, description="Ending source line number")
    details: str = Field(
        default="", description="Detailed narrative and empirical evidence of the finding"
    )

    # Optional compatibility / alias fields
    rule_id: str = Field(default="", description="Compatibility alias for flaw_type")
    description: str = Field(default="", description="Compatibility alias for details")
    line_number: int = Field(default=1, description="Compatibility alias for line_start")

    @model_validator(mode="before")
    @classmethod
    def _map_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            data_dict = dict(data)
            # Sync flaw_type <-> rule_id
            if data_dict.get("rule_id") and not data_dict.get("flaw_type"):
                data_dict["flaw_type"] = data_dict["rule_id"]
            elif data_dict.get("flaw_type") and not data_dict.get("rule_id"):
                data_dict["rule_id"] = data_dict["flaw_type"]

            # Sync details <-> description
            if data_dict.get("description") and not data_dict.get("details"):
                data_dict["details"] = data_dict["description"]
            elif data_dict.get("details") and not data_dict.get("description"):
                data_dict["description"] = data_dict["details"]

            # Sync line_start <-> line_number <-> line_end
            if "line_number" in data_dict:
                if "line_start" not in data_dict:
                    data_dict["line_start"] = data_dict["line_number"]
                if "line_end" not in data_dict:
                    data_dict["line_end"] = data_dict["line_number"]
            elif "line_start" in data_dict and "line_number" not in data_dict:
                data_dict["line_number"] = data_dict["line_start"]

            return data_dict
        return data


FindingRecord = FindingData
