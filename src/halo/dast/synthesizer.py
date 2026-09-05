"""Semantic payload synthesizer bypassing 400/422 validation barriers."""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any

from halo.llm.provider import LLMProvider
from halo.static.graph import ValidationSchemaNode

logger = logging.getLogger(__name__)


class PayloadSynthesizer:
    """Synthesizes schema-compliant payloads from validation schemas or AST nodes."""

    def __init__(self, llm_provider: LLMProvider | None = None) -> None:
        self.llm_provider = llm_provider

    def generate_payload(
        self,
        schema_info: dict[str, Any] | ValidationSchemaNode | None = None,
        context: str = "",
    ) -> dict[str, Any]:
        """Synthesize a valid payload adhering to schema constraints using LLM or deterministic fallback."""
        schema_dict, field_list = self._normalize_schema(schema_info)

        # 1. Attempt LLM generation if provider is available
        if self.llm_provider is not None:
            try:
                payload = self._generate_with_llm(schema_dict, field_list, context)
                if isinstance(payload, dict) and payload:
                    # Fill any missing requested fields with deterministic fallbacks
                    for field_name in field_list:
                        if field_name not in payload:
                            payload[field_name] = self.generate_field_value(field_name)
                    return payload
            except Exception as err:  # noqa: BLE001
                logger.warning("LLM payload synthesis failed, falling back to deterministic: %s", err)

        # 2. Deterministic fallback generation
        return self._generate_deterministic(schema_dict, field_list)

    def synthesize_payload(
        self,
        schema_node: ValidationSchemaNode | dict[str, Any],
        llm_provider: LLMProvider | None = None,
    ) -> dict[str, Any]:
        """Convenience interface for synthesizing payload from schema node."""
        provider = llm_provider or self.llm_provider
        synth = PayloadSynthesizer(provider)
        return synth.generate_payload(schema_node)

    def _normalize_schema(
        self,
        schema_info: dict[str, Any] | ValidationSchemaNode | None,
    ) -> tuple[dict[str, Any], list[str]]:
        """Normalize various schema representation inputs into a dictionary and field list."""
        if schema_info is None:
            return {}, []

        if isinstance(schema_info, ValidationSchemaNode):
            fields = list(schema_info.allowed_fields)
            return {
                "name": schema_info.name,
                "schema_type": schema_info.schema_type,
                "fields": fields,
                "strict": schema_info.strict,
                "strictness_flags": schema_info.strictness_flags,
            }, fields

        if isinstance(schema_info, dict):
            # Extract fields from common schema keys
            if "fields" in schema_info and isinstance(schema_info["fields"], list):
                fields = [str(f) for f in schema_info["fields"]]
            elif "allowed_fields" in schema_info and isinstance(schema_info["allowed_fields"], list):
                fields = [str(f) for f in schema_info["allowed_fields"]]
            elif "properties" in schema_info and isinstance(schema_info["properties"], dict):
                fields = list(schema_info["properties"].keys())
            else:
                fields = list(schema_info.keys())
            return schema_info, fields

        return {}, []

    def _generate_with_llm(
        self,
        schema_dict: dict[str, Any],
        field_list: list[str],
        context: str = "",
    ) -> dict[str, Any]:
        """Prompt the LLM provider to synthesize a JSON object matching schema requirements."""
        system_prompt = (
            "You are an API testing payload generator. Your task is to output a single, strictly valid "
            "JSON object containing realistic, schema-compliant dummy values for the requested fields "
            "so the payload bypasses schema validation (e.g. Zod, Pydantic) and reaches business logic. "
            "Output ONLY raw JSON. No code fences, no markdown formatting, no explanations."
        )

        prompt_lines = [
            "Generate a valid JSON object matching the following schema specifications:",
            f"Schema Fields: {json.dumps(field_list if field_list else schema_dict)}",
        ]
        if "schema_type" in schema_dict:
            prompt_lines.append(f"Schema Framework: {schema_dict['schema_type']}")
        if context:
            prompt_lines.append(f"Context / Endpoint details: {context}")
        prompt_lines.append("Return valid JSON:")

        prompt = "\n".join(prompt_lines)
        response_text = self.llm_provider.generate(prompt=prompt, system_prompt=system_prompt)

        return self._parse_json_response(response_text)

    def _parse_json_response(self, text: str) -> dict[str, Any]:
        """Parse and sanitize JSON from LLM response text."""
        cleaned = text.strip()

        # Strip markdown code blocks ```json ... ```
        if "```" in cleaned:
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
            if match:
                cleaned = match.group(1).strip()

        # Find outer braces if surrounded by other characters
        if not (cleaned.startswith("{") and cleaned.endswith("}")):
            match = re.search(r"(\{[\s\S]*\})", cleaned)
            if match:
                cleaned = match.group(1).strip()

        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
        raise ValueError(f"Expected JSON dict, got {type(parsed)}")

    def _generate_deterministic(
        self,
        schema_dict: dict[str, Any],
        field_list: list[str],
    ) -> dict[str, Any]:
        """Generate deterministic values based on field names and common data types."""
        result: dict[str, Any] = {}
        for field in field_list:
            result[field] = self.generate_field_value(field, schema_dict)

        # If field_list was empty but schema_dict had keys
        if not result and schema_dict:
            for k in schema_dict:
                if k not in ("name", "schema_type", "strict", "strictness_flags"):
                    result[k] = self.generate_field_value(k, schema_dict)

        if not result:
            result = {"status": "active"}

        return result

    def generate_field_value(self, field_name: str, schema_dict: dict[str, Any] | None = None) -> Any:
        """Infer a suitable value for a field name using security testing heuristics."""
        name_lower = field_name.lower()

        # UUID / ID fields
        if name_lower == "id" or name_lower.endswith("_id") or "uuid" in name_lower:
            return str(uuid.uuid4())

        # Email
        if "email" in name_lower:
            return "test_user@example.com"

        # Currency
        if "currency" in name_lower:
            return "USD"

        # Financial / Numeric Amounts
        if any(term in name_lower for term in ("amount", "price", "cost", "balance", "total", "fee")):
            return 100

        # Quantities and integer counts
        if any(term in name_lower for term in ("count", "quantity", "qty", "limit", "offset", "age")):
            return 10

        # Booleans
        if name_lower.startswith(("is_", "has_")) or name_lower in ("enabled", "active"):
            return True

        # Status / Enum
        if "status" in name_lower or "state" in name_lower:
            return "active"

        # Role
        if "role" in name_lower:
            return "user"

        # Usernames
        if "username" in name_lower or "user" in name_lower:
            return "testuser"

        # Full names / Titles
        if "name" in name_lower or "title" in name_lower:
            return "Test Name"

        # Phone numbers
        if "phone" in name_lower or "mobile" in name_lower:
            return "+15551234567"

        # URLs
        if "url" in name_lower or "website" in name_lower or "link" in name_lower:
            return "https://example.com"

        # Timestamps / Dates
        if any(term in name_lower for term in ("date", "time", "created_at", "updated_at", "timestamp")):
            return "2026-09-05T12:00:00Z"

        # Passwords / Tokens
        if "password" in name_lower or "secret" in name_lower:
            return "SuperSecretP@ssw0rd123!"

        if "token" in name_lower:
            return f"test_token_{uuid.uuid4().hex[:12]}"

        # Default string
        return f"val_{field_name}"
