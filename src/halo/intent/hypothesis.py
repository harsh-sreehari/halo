"""Contextual LLM Hypothesis Generator: Builds AST context slices and synthesizes dynamic probing recipes."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from halo.intent.pruner import SuspectCandidate
from halo.llm.governor import estimate_tokens
from halo.llm.provider import LLMProvider
from halo.static.graph import (
    CodeKnowledgeGraph,
    HandlerNode,
    RouteNode,
    SinkNode,
    ValidationSchemaNode,
)

logger = logging.getLogger(__name__)

# Normalization mapping for standard security flaw classes
FLAW_CLASS_NORMALIZATION: dict[str, str] = {
    "BOLA": "BOLA_IDOR",
    "BOLA_IDOR": "BOLA_IDOR",
    "IDOR": "BOLA_IDOR",
    "BFLA": "BFLA",
    "RACE": "RACE_CONDITION",
    "RACE_CONDITION": "RACE_CONDITION",
    "CONCURRENCY": "RACE_CONDITION",
    "WORKFLOW": "WORKFLOW_BYPASS",
    "WORKFLOW_BYPASS": "WORKFLOW_BYPASS",
    "MASS_ASSIGNMENT": "MASS_ASSIGNMENT",
}

# Strategy defaults mapped by normalized flaw class
FLAW_DEFAULT_STRATEGIES: dict[str, str] = {
    "BOLA_IDOR": "multi_actor_handshake",
    "BFLA": "role_escalation",
    "RACE_CONDITION": "race_condition",
    "WORKFLOW_BYPASS": "workflow_permutation",
    "MASS_ASSIGNMENT": "mass_assignment_tamper",
}


class ProbingRecipe(BaseModel):
    """Actionable dynamic probing recipe guiding autonomous DAST verification."""

    model_config = ConfigDict(extra="allow")

    strategy: str = Field(
        description="Probing strategy (e.g. multi_actor_handshake, role_escalation, race_condition, workflow_permutation)"
    )
    primary_param: str = Field(default="", description="Primary parameter under dynamic testing")
    expected_safe_status: int = Field(
        default=403, description="Expected HTTP status code when behavior is secure"
    )
    expected_vuln_status: int = Field(
        default=200, description="Expected HTTP status code indicating vulnerability"
    )
    extra_params: dict[str, Any] = Field(
        default_factory=dict, description="Additional dynamic probing parameters"
    )


class HypothesisResult(BaseModel):
    """Contextual security flaw hypothesis and dynamic verification recipe."""

    model_config = ConfigDict(extra="allow")

    candidate_id: str = Field(default="", description="Identifier of the source suspect candidate")
    route_id: str = Field(default="", description="Identifier of the target route")
    flaw_class: str = Field(
        description="Vulnerability flaw class (BOLA_IDOR, BFLA, RACE_CONDITION, WORKFLOW_BYPASS, MASS_ASSIGNMENT)"
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0",
    )
    hypothesis: str = Field(
        default="", description="Explanatory security reasoning for the suspected flaw"
    )
    probing_recipe: ProbingRecipe = Field(description="Actionable dynamic probing recipe")

    @field_validator("flaw_class", mode="before")
    @classmethod
    def normalize_flaw_class(cls, v: Any) -> str:
        if not isinstance(v, str):
            return "BOLA_IDOR"
        cleaned = v.strip().upper()
        return FLAW_CLASS_NORMALIZATION.get(cleaned, cleaned)

    @field_validator("confidence", mode="before")
    @classmethod
    def parse_and_clamp_confidence(cls, v: Any) -> float:
        try:
            val = float(v)
        except (TypeError, ValueError):
            val = 0.5
        return max(0.0, min(1.0, val))

    @field_validator("probing_recipe", mode="before")
    @classmethod
    def parse_probing_recipe(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return ProbingRecipe(**v)
        return v


def extract_primary_parameter(route: RouteNode, sink: SinkNode | None = None) -> str:
    """Extract primary path or query parameter name from route or sink."""
    # 1. Path parameters matching {param}, {param:type}, :param, <param>, <type:param>
    path_matches = re.findall(
        r"\{([a-zA-Z0-9_]+)(?::[a-zA-Z0-9_]+)?\}|:([a-zA-Z0-9_]+)|<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>",
        route.path,
    )
    for m in path_matches:
        param = m[0] or m[1] or m[2]
        if param:
            return param

    # 2. param_constraints on RouteNode
    if route.param_constraints:
        return next(iter(route.param_constraints.keys()))

    # 3. Sink query parameters
    if sink and sink.query_params:
        return sink.query_params[0]

    return ""


class HypothesisGenerator:
    """Single-pass contextual LLM hypothesis generator for pruned suspect candidates."""

    def __init__(self, llm_provider: LLMProvider | None = None) -> None:
        self.llm_provider = llm_provider

    def build_ast_context(
        self,
        candidate: SuspectCandidate,
        ckg: CodeKnowledgeGraph | None = None,
        max_tokens: int = 2400,
    ) -> str:
        """Build an AST context slice (<2,500 tokens) distilling route, handler, schema, and sink nodes."""
        route = candidate.route
        sink = candidate.sink
        sections: list[str] = []

        # 1. Route endpoint metadata
        sections.append(
            f"### Route\n"
            f"Method: {route.method.upper()}\n"
            f"Path: {route.path}\n"
            f"File: {route.file_path}:{route.line_number}\n"
            f"Param Constraints: {json.dumps(route.param_constraints)}"
        )

        # 2. Traversed CKG context nodes (Handlers, Validation Schemas, Sinks)
        handlers: list[HandlerNode] = []
        schemas: list[ValidationSchemaNode] = []
        sinks: list[SinkNode] = []

        if sink is not None:
            sinks.append(sink)

        if ckg is not None and route.id in ckg:
            trace = ckg.get_route_trace(route.id)
            trace_nodes = trace.get("nodes", [])

            # Also check direct successors
            for succ_id in ckg.graph.successors(route.id):
                succ_node = ckg.get_node(succ_id)
                if succ_node is not None and succ_node not in trace_nodes:
                    trace_nodes.append(succ_node)

            for node in trace_nodes:
                if isinstance(node, HandlerNode) and node not in handlers:
                    handlers.append(node)
                elif isinstance(node, ValidationSchemaNode) and node not in schemas:
                    schemas.append(node)
                elif isinstance(node, SinkNode) and node not in sinks:
                    sinks.append(node)

        # Format Handler details
        if handlers:
            handler_texts: list[str] = []
            for h in handlers:
                info = (
                    f"- Name: {h.name}\n"
                    f"  Signature: {h.signature or h.name + '()'}\n"
                    f"  Arguments: {', '.join(h.arguments) if h.arguments else 'none'}\n"
                    f"  File: {h.file_path}:{h.line_number}"
                )
                # Attempt to load source code body if file exists
                code_snippet = self._extract_handler_code(h)
                if code_snippet:
                    info += f"\n  Body:\n```python\n{code_snippet}\n```"
                handler_texts.append(info)
            sections.append("### Handler Function(s)\n" + "\n".join(handler_texts))

        # Format Validation Schemas (DTOs)
        if schemas:
            schema_texts: list[str] = []
            for s in schemas:
                schema_texts.append(
                    f"- Schema: {s.name}\n"
                    f"  Type: {s.schema_type or 'DTO'}\n"
                    f"  Strict: {s.strict}\n"
                    f"  Allowed Fields: {', '.join(s.allowed_fields) if s.allowed_fields else 'all'}\n"
                    f"  Stripped Fields: {', '.join(s.stripped_fields) if s.stripped_fields else 'none'}"
                )
            sections.append("### Validation Schema / DTO\n" + "\n".join(schema_texts))

        # Format Data Sinks (ORM queries, DB writes/reads)
        if sinks:
            sink_texts: list[str] = []
            for sk in sinks:
                sink_texts.append(
                    f"- Operation: {sk.operation} on Entity: '{sk.entity}'\n"
                    f"  Query Params: {', '.join(sk.query_params) if sk.query_params else 'none'}\n"
                    f"  Filters / Clauses: {', '.join(sk.filters) if sk.filters else 'none'}\n"
                    f"  Location: {sk.file_path}:{sk.line_number}"
                )
            sections.append("### Database Sinks / ORM Queries\n" + "\n".join(sink_texts))

        # 3. Static candidate analysis flags & reasoning
        sections.append(
            f"### Static Analysis Observations\n"
            f"Candidate Flaws: {', '.join(candidate.candidate_flaws) if candidate.candidate_flaws else 'UNSPECIFIED'}\n"
            f"Reasoning: {candidate.reasoning or 'Flagged by deterministic pruner.'}"
        )

        full_context = "\n\n".join(sections)

        # 4. Enforce strict token budget (< 2500 tokens)
        if estimate_tokens(full_context) > max_tokens:
            char_budget = max_tokens * 4
            full_context = (
                full_context[:char_budget]
                + "\n\n...[AST slice truncated to enforce token budget <2500 tokens]"
            )

        return full_context

    def _extract_handler_code(self, handler: HandlerNode, max_lines: int = 60) -> str:
        """Extract handler source code lines from disk if file is available."""
        if not handler.file_path:
            return ""

        fpath = Path(handler.file_path)
        if not fpath.is_file():
            return ""

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            start_line, end_line = handler.line_span
            if start_line <= 0:
                start_line = max(1, handler.line_number)
            if end_line <= 0 or end_line < start_line:
                end_line = min(len(lines), start_line + max_lines)

            # Cap lines to max_lines
            if end_line - start_line > max_lines:
                end_line = start_line + max_lines

            snippet = "\n".join(lines[start_line - 1 : end_line])
            return snippet.strip()
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("Could not read handler source code from %s: %s", fpath, exc)
            return ""

    def _parse_llm_response(self, text: str) -> dict[str, Any] | None:
        """Extract and parse structured JSON recipe from LLM response text."""
        if not text or not text.strip():
            return None

        clean_text = text.strip()

        # 1. Look for markdown code fence (```json ... ``` or ``` ... ```)
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean_text)
        if fence_match:
            try:
                parsed = json.loads(fence_match.group(1).strip())
                if isinstance(parsed, dict):
                    return parsed
                if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                    return parsed[0]
            except json.JSONDecodeError:
                logger.debug("Markdown code block did not decode as JSON")

        # 2. Substring between outermost curly braces
        start = clean_text.find("{")
        end = clean_text.rfind("}")
        if start != -1 and end > start:
            try:
                parsed = json.loads(clean_text[start : end + 1])
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                logger.debug("Substring between outermost braces did not decode as JSON")

        # 3. Substring between outermost square brackets (if LLM returned an array)
        arr_start = clean_text.find("[")
        arr_end = clean_text.rfind("]")
        if arr_start != -1 and arr_end > arr_start:
            try:
                parsed = json.loads(clean_text[arr_start : arr_end + 1])
                if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                    return parsed[0]
            except json.JSONDecodeError:
                logger.debug("Substring between square brackets did not decode as JSON")

        # 4. Direct parse attempt
        try:
            parsed = json.loads(clean_text)
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                return parsed[0]
        except json.JSONDecodeError:
            logger.debug("Direct JSON parse failed on LLM output")

        return None

    def _build_fallback_hypothesis(self, candidate: SuspectCandidate) -> HypothesisResult:
        """Deterministic fallback heuristics when LLM is unavailable, offline, or malformed."""
        route = candidate.route
        sink = candidate.sink

        # Determine primary flaw
        primary_flaw_raw = (
            candidate.candidate_flaws[0]
            if candidate.candidate_flaws
            else ("BOLA" if "{" in route.path or ":" in route.path or "<" in route.path else "BFLA")
        )
        flaw_class = FLAW_CLASS_NORMALIZATION.get(primary_flaw_raw.strip().upper(), "BOLA_IDOR")

        primary_param = extract_primary_parameter(route, sink)
        entity_name = sink.entity if (sink and sink.entity) else "resource"
        cand_id = getattr(candidate, "id", None) or (f"{route.id}_{sink.id}" if sink else route.id)

        if flaw_class == "BOLA_IDOR":
            recipe = ProbingRecipe(
                strategy="multi_actor_handshake",
                primary_param=primary_param or "id",
                expected_safe_status=403,
                expected_vuln_status=200,
                extra_params={"method": route.method.upper(), "entity": entity_name},
            )
            hypothesis = (
                f"Parameterized route '{route.path}' accesses '{entity_name}' by ID without "
                "verified tenant or ownership boundary enforcement."
            )
            confidence = 0.85

        elif flaw_class == "BFLA":
            recipe = ProbingRecipe(
                strategy="role_escalation",
                primary_param=primary_param,
                expected_safe_status=403,
                expected_vuln_status=200,
                extra_params={"method": route.method.upper()},
            )
            hypothesis = (
                f"Privileged route '{route.path}' lacks verified role-based authorization guards, "
                "allowing unauthorized vertical privilege escalation."
            )
            confidence = 0.80

        elif flaw_class == "RACE_CONDITION":
            recipe = ProbingRecipe(
                strategy="race_condition",
                primary_param=primary_param,
                expected_safe_status=409,
                expected_vuln_status=200,
                extra_params={"concurrency_burst": 16, "method": route.method.upper()},
            )
            hypothesis = (
                f"Mutation endpoint '{route.path}' modifies '{entity_name}' state without atomic "
                "locking or concurrency synchronization controls."
            )
            confidence = 0.75

        elif flaw_class == "WORKFLOW_BYPASS":
            recipe = ProbingRecipe(
                strategy="workflow_permutation",
                primary_param=primary_param,
                expected_safe_status=400,
                expected_vuln_status=200,
                extra_params={"method": route.method.upper()},
            )
            hypothesis = (
                f"State transition route '{route.path}' allows out-of-order execution, "
                "bypassing mandatory business state invariants."
            )
            confidence = 0.75

        elif flaw_class == "MASS_ASSIGNMENT":
            recipe = ProbingRecipe(
                strategy="mass_assignment_tamper",
                primary_param=primary_param or "role",
                expected_safe_status=400,
                expected_vuln_status=200,
                extra_params={"injected_field": "role", "injected_value": "admin"},
            )
            hypothesis = (
                f"Mutation endpoint '{route.path}' binds payload fields without strict filtering, "
                "permitting unauthorized attribute tampering."
            )
            confidence = 0.70

        else:
            recipe = ProbingRecipe(
                strategy="multi_actor_handshake",
                primary_param=primary_param,
                expected_safe_status=403,
                expected_vuln_status=200,
                extra_params={"method": route.method.upper()},
            )
            hypothesis = f"Suspect route '{route.path}' requires active dynamic verification."
            confidence = 0.60

        return HypothesisResult(
            candidate_id=cand_id,
            route_id=route.id,
            flaw_class=flaw_class,
            confidence=confidence,
            hypothesis=hypothesis,
            probing_recipe=recipe,
        )

    def generate_hypothesis(
        self,
        candidate: SuspectCandidate,
        ckg: CodeKnowledgeGraph | None = None,
        llm_provider: LLMProvider | None = None,
    ) -> HypothesisResult:
        """Generate hypothesis and dynamic probing recipe for a single suspect candidate."""
        provider = llm_provider if llm_provider is not None else self.llm_provider
        cand_id = getattr(candidate, "id", None) or (
            f"{candidate.route.id}_{candidate.sink.id}" if candidate.sink else candidate.route.id
        )

        if provider is None:
            return self._build_fallback_hypothesis(candidate)

        ast_context = self.build_ast_context(candidate, ckg=ckg)

        system_prompt = (
            "You are HALO's Contextual Hypothesis Generator, an expert application security auditor.\n"
            "Analyze the provided AST context slice (route, handler, validation schema, and data sink) "
            "for business logic vulnerabilities.\n"
            "Target Flaw Classes:\n"
            "- BOLA_IDOR: Broken Object Level Authorization / Insecure Direct Object References\n"
            "- BFLA: Broken Function Level Authorization / Role Escalation\n"
            "- RACE_CONDITION: Concurrency anomalies, double spending, limit bypasses\n"
            "- WORKFLOW_BYPASS: State machine invariant violations, skipping workflow steps\n"
            "- MASS_ASSIGNMENT: Unauthorized modification of sensitive object attributes\n\n"
            "Formulate a concrete, actionable hypothesis and an exact dynamic probing recipe.\n"
            "Respond ONLY with a JSON object adhering to this schema:\n"
            "{\n"
            '  "flaw_class": "BOLA_IDOR" | "BFLA" | "RACE_CONDITION" | "WORKFLOW_BYPASS" | "MASS_ASSIGNMENT",\n'
            '  "confidence": <float between 0.0 and 1.0>,\n'
            '  "hypothesis": "<clear, concise explanation of the flaw and why it exists>",\n'
            '  "probing_recipe": {\n'
            '    "strategy": "multi_actor_handshake" | "role_escalation" | "race_condition" | "workflow_permutation" | "mass_assignment_tamper",\n'
            '    "primary_param": "<primary parameter name to test, or empty string>",\n'
            '    "expected_safe_status": <HTTP status code when secure, e.g. 403 or 400>,\n'
            '    "expected_vuln_status": <HTTP status code when vulnerable, e.g. 200>,\n'
            '    "extra_params": { ... }\n'
            "  }\n"
            "}"
        )

        user_prompt = (
            f"Analyze the following suspect route AST context slice:\n\n"
            f"=== AST Context Slice ===\n"
            f"{ast_context}\n\n"
            f"Provide your security hypothesis and dynamic probing recipe in strict JSON format."
        )

        try:
            response_text = provider.generate(prompt=user_prompt, system_prompt=system_prompt)
            parsed = self._parse_llm_response(response_text)
            if not parsed or not isinstance(parsed, dict):
                logger.warning(
                    "LLM response for route %s could not be parsed as JSON; using fallback",
                    candidate.route.id,
                )
                return self._build_fallback_hypothesis(candidate)

            # If probing_recipe is absent or invalid, supply fallback recipe
            recipe_raw = parsed.get("probing_recipe")
            if not isinstance(recipe_raw, dict):
                fallback = self._build_fallback_hypothesis(candidate)
                recipe_obj = fallback.probing_recipe
            else:
                recipe_obj = ProbingRecipe(**recipe_raw)

            flaw_class = parsed.get(
                "flaw_class",
                candidate.candidate_flaws[0] if candidate.candidate_flaws else "BOLA_IDOR",
            )
            confidence = parsed.get("confidence", 0.75)
            hypothesis_text = parsed.get("hypothesis", "")

            return HypothesisResult(
                candidate_id=parsed.get("candidate_id", cand_id),
                route_id=parsed.get("route_id", candidate.route.id),
                flaw_class=flaw_class,
                confidence=confidence,
                hypothesis=hypothesis_text,
                probing_recipe=recipe_obj,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Hypothesis generation failed for candidate %s: %s; using deterministic fallback",
                cand_id,
                exc,
            )
            return self._build_fallback_hypothesis(candidate)

    def generate_hypotheses(
        self,
        suspects: list[SuspectCandidate],
        ckg: CodeKnowledgeGraph | None = None,
        llm_provider: LLMProvider | None = None,
    ) -> list[HypothesisResult]:
        """Generate hypotheses for a collection of pruned suspect candidates."""
        results: list[HypothesisResult] = []
        for candidate in suspects:
            hypo = self.generate_hypothesis(candidate=candidate, ckg=ckg, llm_provider=llm_provider)
            results.append(hypo)
        return results
