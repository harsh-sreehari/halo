"""AST-Anchored Role-Aware Remediation Patcher."""

from __future__ import annotations

import logging
import re
from typing import Any

from halo.static.graph import HandlerNode
from halo.validation.models import FindingData, FindingRecord

logger = logging.getLogger(__name__)


class RemediationPatcher:
    """Emits AST-anchored, role-aware code replacement blocks rather than fragile unified diffs."""

    def format_patch_block(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
        original_code: str,
        replacement_code: str,
        language: str = "",
    ) -> str:
        """Format an AST replacement block with clear markdown headers and syntax fences."""
        lang = language or self._detect_language(file_path)
        lines_desc = (
            f"Lines {start_line}–{end_line}" if end_line > start_line else f"Line {start_line}"
        )

        return (
            f"### Remediation for `{file_path}` ({lines_desc})\n\n"
            f"**Original Code:**\n"
            f"```{lang}\n"
            f"{original_code.strip()}\n"
            f"```\n\n"
            f"**Replacement Code:**\n"
            f"```{lang}\n"
            f"{replacement_code.strip()}\n"
            f"```\n"
        )

    def generate_role_aware_patch(
        self,
        finding: FindingData | FindingRecord,
        handler_node: HandlerNode | None,
        original_code: str,
        llm_provider: Any | None = None,
    ) -> str:
        """Generate role-aware remediation code using LLM reasoning with deterministic fallback."""
        file_path = (
            (handler_node.file_path if handler_node and handler_node.file_path else "")
            or finding.file_path
            or "handler.py"
        )

        if handler_node and handler_node.line_span and handler_node.line_span != (0, 0):
            start_line, end_line = handler_node.line_span
        else:
            start_line = finding.line_start or 1
            end_line = finding.line_end or start_line

        lang = self._detect_language(file_path)
        code_snippet = self._extract_snippet(original_code, start_line, end_line)

        replacement_code: str | None = None

        if llm_provider is not None:
            try:
                replacement_code = self._llm_generate_patch(
                    finding=finding,
                    handler_node=handler_node,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    original_code=code_snippet,
                    lang=lang,
                    llm_provider=llm_provider,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"LLM remediation generation failed, falling back: {exc}")
                replacement_code = None

        if not replacement_code:
            replacement_code = self._deterministic_patch(
                flaw_type=finding.flaw_type,
                original_code=code_snippet,
                lang=lang,
            )

        return self.format_patch_block(
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            original_code=code_snippet,
            replacement_code=replacement_code,
            language=lang,
        )

    def _llm_generate_patch(
        self,
        finding: FindingData | FindingRecord,
        handler_node: HandlerNode | None,
        file_path: str,
        start_line: int,
        end_line: int,
        original_code: str,
        lang: str,
        llm_provider: Any,
    ) -> str:
        """Prompt LLMProvider to generate role-aware remediation code."""
        handler_info = (
            f"Handler Function: {handler_node.name} (args: {handler_node.arguments})"
            if handler_node
            else "Target Function/Route Handler"
        )

        prompt = f"""You are an expert secure coding engineer for Project HALO.
Generate a secure, role-aware remediation replacement for the following verified business logic vulnerability.

Vulnerability Type: {finding.flaw_type}
Endpoint: {finding.endpoint}
Target File: {file_path} (Lines {start_line}–{end_line})
Context: {handler_info}
Details: {finding.details}

Original Vulnerable Code:
```{lang}
{original_code}
```

Requirements:
1. Enforce strict role-aware authorization and tenant scoping.
2. For BOLA/IDOR: scope queries/updates to authenticated user context (e.g. `ownerId: req.user.id` or `user_id=current_user.id`), permitting authorized administrative bypass if applicable.
3. For BFLA: enforce role authorization checks before executing privileged operations.
4. For Race Conditions: wrap critical state operations in atomic transactions or row-level locks.
5. For Workflow Bypass: validate prerequisite state-machine invariants before mutations.
6. Provide ONLY the replacement code snippet inside a ```{lang} ... ``` markdown fence. Do not include conversational commentary.
"""
        system_prompt = (
            "You are an automated secure code remediation engine. "
            "Output only the replacement code snippet within a single markdown code block."
        )

        response = llm_provider.generate(prompt, system_prompt=system_prompt)
        return self._extract_code(response)

    def _extract_code(self, response: str) -> str:
        """Extract code snippet from markdown code blocks or plain text."""
        # Check if response already has a replacement code block
        if "**Replacement Code:**" in response:
            parts = response.split("**Replacement Code:**", 1)
            code_match = re.search(r"```(?:\w+)?\s*(.*?)\s*```", parts[1], flags=re.DOTALL)
            if code_match:
                return code_match.group(1).strip()

        code_match = re.search(r"```(?:\w+)?\s*(.*?)\s*```", response, flags=re.DOTALL)
        if code_match:
            return code_match.group(1).strip()

        return response.strip()

    def _deterministic_patch(
        self,
        flaw_type: str,
        original_code: str,
        lang: str,
    ) -> str:
        """Deterministic rule-based template fallback when LLM is unavailable or offline."""
        orig = original_code.strip()
        upper_flaw = flaw_type.upper()

        if "BOLA" in upper_flaw or "IDOR" in upper_flaw:
            if "findUnique" in orig:
                replaced = orig.replace("findUnique", "findFirst")
                if "where: { id }" in replaced:
                    return replaced.replace(
                        "where: { id }",
                        "where: { id, ownerId: req.user.id }",
                    )
                if "where: { id: req.params.id }" in replaced:
                    return replaced.replace(
                        "where: { id: req.params.id }",
                        "where: { id: req.params.id, ...(req.user.role !== 'admin' && { ownerId: req.user.id }) }",
                    )
                return replaced.replace(
                    "where: {",
                    "where: { ...(req.user.role !== 'admin' && { ownerId: req.user.id }),",
                )
            if lang == "python":
                return (
                    f"{orig}\n"
                    f"# Enforce tenant boundary authorization\n"
                    f"if resource.owner_id != current_user.id and not getattr(current_user, 'is_admin', False):\n"
                    f"    raise HTTPException(status_code=403, detail='Forbidden: Tenant boundary violation')"
                )
            if lang in ("typescript", "javascript"):
                return (
                    f"{orig}\n"
                    f"// Enforce tenant boundary and role override\n"
                    f"if (resource.ownerId !== req.user.id && req.user.role !== 'admin') {{\n"
                    f"  return res.status(403).json({{ error: 'Forbidden: Tenant access violation' }});\n"
                    f"}}"
                )
            return (
                f"{orig}\n"
                f"// Enforce tenant scoping check\n"
                f"if ($resource->owner_id !== $user->id && !$user->isAdmin()) {{\n"
                f"    abort(403, 'Tenant access forbidden');\n"
                f"}}"
            )

        if "BFLA" in upper_flaw:
            if lang in ("typescript", "javascript"):
                return (
                    f"// Enforce role-based function access guard\n"
                    f"if (!req.user || req.user.role !== 'admin') {{\n"
                    f"  return res.status(403).json({{ error: 'Forbidden: Administrator privileges required' }});\n"
                    f"}}\n"
                    f"{orig}"
                )
            if lang == "python":
                return (
                    f"# Enforce role-based function access guard\n"
                    f"if not getattr(current_user, 'is_admin', False):\n"
                    f"    raise HTTPException(status_code=403, detail='Forbidden: Admin role required')\n"
                    f"{orig}"
                )
            return f"if (!$user->isAdmin()) {{\n    abort(403, 'Unauthorized access');\n}}\n{orig}"

        if "RACE" in upper_flaw:
            if lang == "python":
                return f"# Enforce concurrency transaction lock\nwith db.transaction():\n    {orig}"
            return f"await prisma.$transaction(async (tx) => {{\n  {orig}\n}});"

        if "WORKFLOW" in upper_flaw:
            if lang in ("typescript", "javascript"):
                return (
                    f"// Validate workflow state machine transition\n"
                    f"if (order.status !== 'APPROVED') {{\n"
                    f"  return res.status(400).json({{ error: 'Invalid workflow state transition' }});\n"
                    f"}}\n"
                    f"{orig}"
                )
            return (
                f"# Validate workflow state machine transition\n"
                f"if not entity.is_valid_transition():\n"
                f"    raise ValueError('Invalid state transition')\n"
                f"{orig}"
            )

        return f"{orig}\n// Verify actor permissions and tenant boundary before proceeding"

    def _extract_snippet(self, code: str, start_line: int, end_line: int) -> str:
        """Extract target lines if full file is provided, else return code as snippet."""
        lines = code.splitlines()
        if len(lines) > (end_line - start_line + 5) and start_line > 0:
            sliced = lines[start_line - 1 : end_line]
            return "\n".join(sliced)
        return code.strip()

    def _detect_language(self, file_path: str) -> str:
        """Infer markdown syntax highlighting language from file extension."""
        lower = file_path.lower()
        if lower.endswith((".js", ".mjs", ".cjs")):
            return "javascript"
        if lower.endswith((".ts", ".tsx")):
            return "typescript"
        if lower.endswith(".py"):
            return "python"
        if lower.endswith((".php", ".phtml")):
            return "php"
        if lower.endswith(".go"):
            return "go"
        if lower.endswith(".java"):
            return "java"
        if lower.endswith(".rb"):
            return "ruby"
        return "javascript"
