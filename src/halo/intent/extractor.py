"""Business intent mining subsystem: OpenAPI distillation and policy matrix extraction."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from halo.llm.provider import LLMProvider

logger = logging.getLogger(__name__)


class BusinessPolicyMatrix(BaseModel):
    """Synthesized business policies and security invariants mined from docs and specs."""

    model_config = ConfigDict(extra="allow")

    ownership_rules: list[str] = Field(
        default_factory=list,
        description="List of entity ownership and multi-tenancy invariants",
    )
    role_hierarchy: list[str] = Field(
        default_factory=list,
        description="List of roles ordered from highest privilege to lowest privilege",
    )
    state_invariants: list[str] = Field(
        default_factory=list,
        description="List of state machine transition rules and prerequisite invariants",
    )


class IntentExtractor:
    """Extracts business intent and policy matrices from repo docs, OpenAPI specs, and docstrings."""

    KNOWN_ROLES_PRIORITY: ClassVar[list[str]] = [
        "superadmin",
        "root",
        "owner",
        "admin",
        "administrator",
        "manager",
        "staff",
        "moderator",
        "editor",
        "merchant",
        "seller",
        "vendor",
        "user",
        "member",
        "customer",
        "client",
        "guest",
        "anonymous",
        "public",
    ]

    def __init__(self, llm_provider: LLMProvider | None = None) -> None:
        self.llm_provider = llm_provider

    def distill_openapi(self, spec: dict[str, Any] | str) -> dict[str, Any]:
        """Deterministically distill an OpenAPI/Swagger specification.

        Strips verbose UI/markdown descriptions and retains essential paths,
        HTTP methods, security requirements, response status codes, and schema summaries.
        """
        if isinstance(spec, str):
            try:
                raw_dict: dict[str, Any] = json.loads(spec)
            except json.JSONDecodeError:
                raw_dict = {}
        elif isinstance(spec, dict):
            raw_dict = spec
        else:
            raw_dict = {}

        distilled: dict[str, Any] = {}

        # 1. Distill paths
        paths = raw_dict.get("paths", {})
        if isinstance(paths, dict):
            distilled_paths: dict[str, Any] = {}
            for path_str, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                distilled_item: dict[str, Any] = {}
                for method, op_data in path_item.items():
                    method_lower = method.lower()
                    if method_lower not in {
                        "get",
                        "post",
                        "put",
                        "delete",
                        "patch",
                        "options",
                        "head",
                    }:
                        continue
                    if not isinstance(op_data, dict):
                        continue

                    distilled_op: dict[str, Any] = {}

                    # Retain security
                    if "security" in op_data and isinstance(op_data["security"], list):
                        distilled_op["security"] = op_data["security"]

                    # Retain tags (for role/module hints)
                    if "tags" in op_data and isinstance(op_data["tags"], list):
                        distilled_op["tags"] = op_data["tags"]

                    # Retain status codes from responses
                    responses = op_data.get("responses", {})
                    if isinstance(responses, dict):
                        distilled_responses: dict[str, Any] = {}
                        for code, resp_obj in responses.items():
                            code_str = str(code)
                            schema_info: dict[str, Any] = {}
                            if isinstance(resp_obj, dict):
                                content = resp_obj.get("content", {})
                                if isinstance(content, dict):
                                    json_content = content.get("application/json", {})
                                    schema = json_content.get("schema", {})
                                    if isinstance(schema, dict) and "type" in schema:
                                        schema_info["type"] = schema["type"]
                            distilled_responses[code_str] = schema_info
                        distilled_op["responses"] = distilled_responses

                    # Retain parameters (name, in, required, schema type)
                    params = op_data.get("parameters", [])
                    if isinstance(params, list):
                        distilled_params: list[dict[str, Any]] = []
                        for param in params:
                            if isinstance(param, dict) and "name" in param:
                                p_summary: dict[str, Any] = {
                                    "name": param["name"],
                                    "in": param.get("in", "query"),
                                }
                                if "required" in param:
                                    p_summary["required"] = bool(param["required"])
                                if "schema" in param and isinstance(param["schema"], dict):
                                    schema_type = param["schema"].get("type")
                                    if schema_type:
                                        p_summary["type"] = schema_type
                                distilled_params.append(p_summary)
                        if distilled_params:
                            distilled_op["parameters"] = distilled_params

                    # Retain requestBody properties summary
                    req_body = op_data.get("requestBody", {})
                    if isinstance(req_body, dict):
                        content = req_body.get("content", {})
                        if isinstance(content, dict):
                            json_body = content.get("application/json", {})
                            schema = json_body.get("schema", {})
                            if isinstance(schema, dict):
                                body_summary: dict[str, Any] = {}
                                if "required" in schema and isinstance(schema["required"], list):
                                    body_summary["required"] = schema["required"]
                                properties = schema.get("properties", {})
                                if isinstance(properties, dict):
                                    body_summary["properties"] = {
                                        k: v.get("type", "unknown")
                                        for k, v in properties.items()
                                        if isinstance(v, dict)
                                    }
                                if body_summary:
                                    distilled_op["requestBody"] = body_summary

                    distilled_item[method_lower] = distilled_op

                if distilled_item:
                    distilled_paths[path_str] = distilled_item

            distilled["paths"] = distilled_paths

        # 2. Retain top-level security schemes
        components = raw_dict.get("components", {})
        sec_schemes = {}
        if isinstance(components, dict) and "securitySchemes" in components:
            sec_schemes = components["securitySchemes"]
        elif "securityDefinitions" in raw_dict:
            sec_schemes = raw_dict["securityDefinitions"]

        if isinstance(sec_schemes, dict):
            distilled_sec: dict[str, Any] = {}
            for k, v in sec_schemes.items():
                if isinstance(v, dict):
                    scheme_summary: dict[str, Any] = {}
                    for field_name in ("type", "scheme", "in", "name"):
                        if field_name in v:
                            scheme_summary[field_name] = v[field_name]
                    distilled_sec[k] = scheme_summary
            if distilled_sec:
                distilled["securitySchemes"] = distilled_sec

        return distilled

    def distill_readme(self, readme_text: str, max_chars: int = 4000) -> str:
        """Distill repository README text to retain relevant security and architecture context."""
        if not readme_text:
            return ""

        # Remove image links, badges, and HTML comments
        cleaned = re.sub(r"\[!\[.*?\]\(.*?\)\]\(.*?\)", "", readme_text)
        cleaned = re.sub(r"!\[.*?\]\(.*?\)", "", cleaned)
        cleaned = re.sub(r"<!--.*?-->", "", cleaned, flags=re.DOTALL)

        lines = cleaned.splitlines()
        relevant_lines: list[str] = []

        keywords = {
            "role",
            "permission",
            "auth",
            "tenant",
            "owner",
            "order",
            "invoice",
            "state",
            "status",
            "workflow",
            "security",
            "admin",
            "access",
            "user",
        }

        in_relevant_section = True
        for line in lines:
            line_str = line.strip()
            if line_str.startswith("#"):
                heading_lower = line_str.lower()
                in_relevant_section = any(k in heading_lower for k in keywords) or len(line_str.split()) <= 4
            if in_relevant_section or any(k in line_str.lower() for k in keywords):
                relevant_lines.append(line)

        result = "\n".join(relevant_lines).strip()
        if len(result) > max_chars:
            result = result[:max_chars] + "\n...[truncated]"
        return result

    def ingest_documentation(self, repo_path: str) -> dict[str, Any]:
        """Collect README, OpenAPI specifications, and relevant inline docstrings from repo."""
        repo = Path(repo_path)
        docs: dict[str, Any] = {
            "readme": "",
            "openapi": [],
            "docstrings": [],
        }

        if not repo.exists():
            return docs

        # 1. Look for README
        for readme_name in ("README.md", "readme.md", "README.MD", "README.txt", "readme.txt"):
            readme_path = repo / readme_name
            if readme_path.is_file():
                try:
                    raw_text = readme_path.read_text(encoding="utf-8", errors="ignore")
                    docs["readme"] = self.distill_readme(raw_text)
                    break
                except (OSError, UnicodeDecodeError) as e:
                    logger.debug("Could not read %s: %s", readme_path, e)

        # 2. Look for OpenAPI/Swagger files
        openapi_candidates = [
            repo / "openapi.json",
            repo / "swagger.json",
            repo / "api.json",
            repo / "docs" / "openapi.json",
            repo / "docs" / "swagger.json",
            repo / "api" / "openapi.json",
            repo / "specs" / "openapi.json",
        ]
        try:
            for p in repo.glob("*.json"):
                if p not in openapi_candidates:
                    openapi_candidates.append(p)
            for p in repo.glob("*/*.json"):
                if p not in openapi_candidates:
                    openapi_candidates.append(p)
        except OSError as e:
            logger.debug("Error globbing openapi json candidates: %s", e)

        for candidate in openapi_candidates:
            if candidate.is_file():
                try:
                    content = candidate.read_text(encoding="utf-8", errors="ignore")
                    data = json.loads(content)
                    if isinstance(data, dict) and ("openapi" in data or "swagger" in data or "paths" in data):
                        distilled = self.distill_openapi(data)
                        docs["openapi"].append({"file": candidate.name, "spec": distilled})
                except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
                    logger.debug("Failed parsing openapi candidate %s: %s", candidate, e)
                    continue

        return docs

    def extract_policies(
        self,
        repo_path: str,
        llm_provider: LLMProvider | None = None,
    ) -> BusinessPolicyMatrix:
        """Synthesize BusinessPolicyMatrix using LLM or deterministic fallback."""
        provider = llm_provider if llm_provider is not None else self.llm_provider
        docs = self.ingest_documentation(repo_path)

        if provider is not None:
            try:
                system_prompt = (
                    "You are HALO's Business Intent Analyzer. Extract the application's core business "
                    "policy invariants, entity ownership rules, role hierarchy, and state transition requirements. "
                    "Return ONLY a JSON object matching this schema:\n"
                    "{\n"
                    '  "ownership_rules": ["<entity ownership invariant>", ...],\n'
                    '  "role_hierarchy": ["<highest_role>", "<next_role>", ..., "<lowest_role>"],\n'
                    '  "state_invariants": ["<state transition requirement>", ...]\n'
                    "}"
                )

                prompt = (
                    "Synthesize the Business Policy Matrix from the following project documentation.\n\n"
                    f"### README Context:\n{docs.get('readme', 'None')}\n\n"
                    f"### OpenAPI Distillation:\n{json.dumps(docs.get('openapi', []), indent=2)}\n\n"
                    "Respond with strict JSON adhering to the specified schema."
                )

                response_text = provider.generate(prompt=prompt, system_prompt=system_prompt)
                parsed_json = self._parse_json_response(response_text)
                if parsed_json and isinstance(parsed_json, dict):
                    return BusinessPolicyMatrix(
                        ownership_rules=list(parsed_json.get("ownership_rules", [])),
                        role_hierarchy=list(parsed_json.get("role_hierarchy", [])),
                        state_invariants=list(parsed_json.get("state_invariants", [])),
                    )
            except Exception as e:  # noqa: BLE001
                logger.warning("LLM policy matrix generation failed, falling back to deterministic: %s", e)

        # Deterministic rule-based fallback
        return self._extract_deterministic_fallback(docs)

    def _parse_json_response(self, text: str) -> dict[str, Any] | None:
        """Extract and parse JSON object from LLM response string."""
        if not text:
            return None
        # 1. Try markdown code block
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                logger.debug("Markdown code block did not parse as JSON")

        # 2. Try outermost braces
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                logger.debug("Substring between outermost braces did not parse as JSON")

        # 3. Direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _extract_deterministic_fallback(self, docs: dict[str, Any]) -> BusinessPolicyMatrix:
        """Deterministic rule-based policy extraction from docs and OpenAPI paths when offline."""
        readme = docs.get("readme", "")
        openapi_specs = docs.get("openapi", [])

        # 1. Extract Role Hierarchy
        discovered_roles: list[str] = []

        # Check for explicit hierarchy: e.g. "admin > merchant > customer"
        hierarchy_match = re.search(
            r"([a-zA-Z0-9_\-]+(?:\s*>\s*[a-zA-Z0-9_\-]+)+)",
            readme,
            re.IGNORECASE,
        )
        if hierarchy_match:
            parts = [p.strip().lower() for p in hierarchy_match.group(1).split(">")]
            for part in parts:
                if part and part not in discovered_roles:
                    discovered_roles.append(part)
        else:
            readme_lower = readme.lower()
            for role in self.KNOWN_ROLES_PRIORITY:
                if re.search(r"\b" + re.escape(role) + r"\b", readme_lower) and role not in discovered_roles:
                    discovered_roles.append(role)

        if not discovered_roles:
            discovered_roles = ["admin", "user"]

        # 2. Extract Ownership Rules
        ownership_rules: list[str] = []
        for sentence in re.split(r"[.\n]+", readme):
            s_clean = sentence.strip()
            s_lower = s_clean.lower()
            if (
                any(k in s_lower for k in ("belong", "tenant", "cross-tenant", "owner", "private to"))
                and len(s_clean) > 10
                and s_clean not in ownership_rules
            ):
                ownership_rules.append(s_clean)

        # Infer from OpenAPI paths with parameters (e.g. /invoices/{id})
        entity_names: set[str] = set()
        for spec_entry in openapi_specs:
            spec_paths = spec_entry.get("spec", {}).get("paths", {})
            for p in spec_paths:
                segments = [seg for seg in p.split("/") if seg]
                for i, seg in enumerate(segments):
                    if ("{" in seg or ":" in seg) and i > 0:
                        prev_seg = segments[i - 1]
                        if prev_seg not in ("api", "v1", "v2", "v3"):
                            entity_names.add(prev_seg)

        for ent in sorted(entity_names):
            rule = f"All {ent} belong to the creating tenant/user; cross-user viewing and mutation is prohibited"
            if not any(ent in r.lower() for r in ownership_rules):
                ownership_rules.append(rule)

        if not ownership_rules:
            ownership_rules = ["Resources belong to their creator or tenant and must not be accessed cross-tenant"]

        # 3. Extract State Invariants
        state_invariants: list[str] = []
        for sentence in re.split(r"[.\n]+", readme):
            s_clean = sentence.strip()
            s_lower = s_clean.lower()
            if (
                any(k in s_lower for k in ("before", "transition", "status", "prerequisite", "state"))
                and any(v in s_lower for v in ("ship", "pay", "paid", "refund", "checkout", "approve", "permit"))
                and len(s_clean) > 10
                and s_clean not in state_invariants
            ):
                state_invariants.append(s_clean)

        for spec_entry in openapi_specs:
            spec_paths = spec_entry.get("spec", {}).get("paths", {})
            for p in spec_paths:
                p_lower = p.lower()
                if "ship" in p_lower:
                    inv = "Order must be PAID and confirmed before SHIP can be invoked"
                    if inv not in state_invariants:
                        state_invariants.append(inv)
                elif "refund" in p_lower:
                    inv = "Transaction must be COMPLETED before REFUND can be processed"
                    if inv not in state_invariants:
                        state_invariants.append(inv)

        if not state_invariants:
            state_invariants = ["State transitions must satisfy precondition checks before execution"]

        return BusinessPolicyMatrix(
            ownership_rules=ownership_rules,
            role_hierarchy=discovered_roles,
            state_invariants=state_invariants,
        )
