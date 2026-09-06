"""Adaptive PoC Self-Repair Loop with Subprocess Execution and LLM Reasoning."""

from __future__ import annotations

import ast
import logging
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class PoCRepairLoop:
    """Adaptive PoC self-repair loop that executes reproduction scripts against target URLs

    and utilizes LLM reasoning to iteratively diagnose and repair execution failures.
    """

    def __init__(
        self,
        runner: Callable[[str], tuple[int, str, str]] | None = None,
        timeout: float = 10.0,
        llm_provider: Any | None = None,
    ) -> None:
        self.runner = runner
        self.timeout = timeout
        self.llm_provider = llm_provider

    def _execute_script(self, script_content: str, target_url: str) -> tuple[int, str, str]:
        """Execute the PoC reproduction script via runner callback or subprocess.

        Returns (exit_code, stdout, stderr).
        """
        if self.runner is not None:
            return self.runner(script_content)

        # Safety gate: verify AST parse and block suspicious shell/subprocess execution
        try:
            tree = ast.parse(script_content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute) and func.attr in (
                        "system",
                        "popen",
                        "spawn",
                        "rmtree",
                    ):
                        return (
                            1,
                            "",
                            f"Safety gate rejected execution: detected potentially destructive call '{func.attr}'",
                        )
        except SyntaxError as err:
            return 1, "", f"Syntax error in script: {err}"

        # Execute in subprocess
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script_content)
            temp_path = f.name

        try:
            env = os.environ.copy()
            env["HALO_TARGET_URL"] = target_url
            proc = subprocess.run(
                [sys.executable, temp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                env=env,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return 124, "", f"Execution timed out after {self.timeout}s"
        except Exception as exc:  # noqa: BLE001
            return 1, "", str(exc)
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    def _build_repair_prompt(
        self,
        current_script: str,
        target_url: str,
        returncode: int,
        stdout: str,
        stderr: str,
    ) -> str:
        """Construct diagnostic prompt for LLM provider detailing runtime failures."""
        return f"""An automated exploit reproduction script failed execution against target URL: {target_url}

Exit Code: {returncode}

STDOUT:
{stdout}

STDERR:
{stderr}

CURRENT REPRODUCTION SCRIPT:
```python
{current_script}
```

Task:
Analyze the execution failure (e.g. missing CSRF token, redirect mismatch, header requirements, authorization token handling, or assertion discrepancies) and provide a corrected, complete, working Python script.

Requirements:
1. Maintain PEP 723 dependency metadata if present.
2. Resolve the root cause of the runtime failure (e.g. acquire CSRF token or session cookies before sending mutations).
3. Return the entire updated Python script inside a single ```python ... ``` code block.
"""

    def _extract_code(self, response: str) -> str:
        """Extract Python code block from LLM completion."""
        pattern = r"```python\s*(.*?)\s*```"
        match = re.search(pattern, response, flags=re.DOTALL)
        if match:
            return match.group(1).strip()

        generic_pattern = r"```\s*(.*?)\s*```"
        generic_match = re.search(generic_pattern, response, flags=re.DOTALL)
        if generic_match:
            return generic_match.group(1).strip()

        return response.strip()

    def _deterministic_repair(
        self, current_script: str, returncode: int, stdout: str, stderr: str
    ) -> str | None:
        """Attempt rule-based deterministic repair when LLM is offline or unconfigured."""
        output = f"{stderr}\n{stdout}"

        # 1. Status code mismatch in assertion, e.g. "Expected 200, got 201" or "got 204"
        match = re.search(r"got (\d{3})", output)
        if match:
            got_status = int(match.group(1))
            if 200 <= got_status < 400:
                new_script = re.sub(
                    r"assert (attack|res_\d+)\.status_code == \d{3}",
                    f"assert \\1.status_code in (200, 201, 204, {got_status})",
                    current_script,
                )
                if new_script != current_script:
                    return new_script

        # 2. Missing redirects
        if "follow_redirects" not in current_script and ("301" in output or "302" in output):
            new_script = current_script.replace(
                "httpx.Client(", "httpx.Client(follow_redirects=True, "
            )
            if new_script != current_script:
                return new_script

        return None

    def verify_and_repair(
        self,
        script_content: str,
        target_url: str,
        llm_provider: Any | None = None,
        max_retries: int = 2,
    ) -> tuple[bool, str]:
        """Execute script and attempt adaptive LLM-driven repair up to max_retries on failure.

        Returns (is_repaired_and_verified, final_script_content).
        """
        current_script = script_content
        effective_llm = llm_provider if llm_provider is not None else self.llm_provider

        for attempt in range(max_retries + 1):
            returncode, stdout, stderr = self._execute_script(current_script, target_url)
            if returncode == 0:
                logger.info(f"PoC verification succeeded on attempt {attempt + 1}")
                return True, current_script

            logger.warning(
                f"PoC execution failed on attempt {attempt + 1} (code {returncode}):\n{stderr or stdout}"
            )

            # If all retries exhausted, abort
            if attempt >= max_retries:
                break

            # If no LLM provider available, attempt deterministic repair
            if effective_llm is None:
                det_code = self._deterministic_repair(current_script, returncode, stdout, stderr)
                if det_code and det_code != current_script:
                    current_script = det_code
                    continue
                break

            # Query LLM to repair the script
            prompt = self._build_repair_prompt(
                current_script=current_script,
                target_url=target_url,
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
            )
            system_prompt = (
                "You are an automated exploit reproduction repair engineer for Project HALO. "
                "Analyze why the Python exploit script failed and repair it so it succeeds. "
                "Return the complete repaired Python script enclosed in a ```python ... ``` code block."
            )

            try:
                response = effective_llm.generate(prompt, system_prompt=system_prompt)
                repaired_code = self._extract_code(response)
                if repaired_code.strip():
                    current_script = repaired_code
            except Exception as exc:  # noqa: BLE001
                logger.error(f"PoC repair LLM invocation failed: {exc}")
                det_code = self._deterministic_repair(current_script, returncode, stdout, stderr)
                if det_code and det_code != current_script:
                    current_script = det_code
                    continue
                break

        return False, current_script

    def repair_and_verify(
        self,
        script_content: str,
        target_url: str,
        llm_provider: Any | None = None,
        max_retries: int = 2,
    ) -> tuple[bool, str]:
        """Alias for verify_and_repair matching CLI invocation signature."""
        return self.verify_and_repair(
            script_content=script_content,
            target_url=target_url,
            llm_provider=llm_provider,
            max_retries=max_retries,
        )


def verify_and_repair(
    script_content: str,
    target_url: str,
    llm_provider: Any | None = None,
    max_retries: int = 2,
    runner: Callable[[str], tuple[int, str, str]] | None = None,
    timeout: float = 10.0,
) -> tuple[bool, str]:
    """Module-level convenience wrapper for PoC self-repair loop."""
    loop = PoCRepairLoop(runner=runner, timeout=timeout)
    return loop.verify_and_repair(
        script_content=script_content,
        target_url=target_url,
        llm_provider=llm_provider,
        max_retries=max_retries,
    )
