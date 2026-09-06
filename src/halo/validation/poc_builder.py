"""PEP 723 Standalone PoC Reproduction Script Builder."""

from __future__ import annotations

import json
from typing import Any

from halo.validation.models import FindingData, FindingRecord


class PoCBuilder:
    """Generates self-authenticating, standalone reproduction scripts conforming to PEP 723."""

    def build_script(
        self,
        finding_id: str,
        flaw_type: str,
        endpoint: str,
        target_url: str,
        steps: list[dict[str, Any]] | None = None,
        method: str = "GET",
        details: str = "",
        tokens: dict[str, str] | None = None,
        auth_endpoints: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> str:
        """Construct a standalone PEP 723 Python script that reproduces the finding."""
        safe_target = target_url or "http://localhost:3000"
        steps_list = steps or []

        # Generate test body lines
        body_lines = self._generate_test_body(
            finding_id=finding_id,
            flaw_type=flaw_type,
            endpoint=endpoint,
            method=method,
            steps=steps_list,
            tokens=tokens,
        )

        doc_details = details.strip() if details else f"Automated PoC for {flaw_type} on {endpoint}"
        script = f'''# /// script
# dependencies = ["httpx"]
# ///
"""Project HALO Automated Exploit Reproduction
Finding ID: {finding_id}
Vulnerability: {flaw_type} on {endpoint}
Target: {safe_target}

Details:
{doc_details}
"""
import os
import sys
import httpx

BASE_URL = os.environ.get("HALO_TARGET_URL", {json.dumps(safe_target)})



def test_reproduction():
    """Execute multi-actor reproduction sequence and verify vulnerability."""
    with httpx.Client(base_url=BASE_URL, follow_redirects=True) as client:
{body_lines}


if __name__ == "__main__":
    try:
        test_reproduction()
        sys.exit(0)
    except AssertionError as exc:
        print(f"FAILED: {{exc}}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: {{exc}}")
        sys.exit(1)
'''
        return script

    def generate_pep723_script(self, finding: FindingData | FindingRecord) -> str:
        """Generate PEP 723 script directly from a FindingData or FindingRecord instance."""
        return self.build_script(
            finding_id=finding.id,
            flaw_type=finding.flaw_type,
            endpoint=finding.endpoint,
            target_url=finding.target_url,
            steps=finding.reproduction_steps,
            method=finding.method,
            details=finding.details,
        )

    def _generate_test_body(
        self,
        finding_id: str,
        flaw_type: str,
        endpoint: str,
        method: str,
        steps: list[dict[str, Any]],
        tokens: dict[str, str] | None = None,
    ) -> str:
        lines: list[str] = []
        indent = "        "

        # Persona tokens
        tok_a = (tokens or {}).get("USER_A", "halo_token_user_a")
        tok_b = (tokens or {}).get("USER_B", "halo_token_user_b")
        tok_admin = (tokens or {}).get("ADMIN", "halo_token_admin")
        lines.append(f"{indent}# 1. Setup Test Persona Headers")
        lines.append(f'{indent}headers_user_a = {{"Authorization": "Bearer {tok_a}"}}')
        lines.append(f'{indent}headers_user_b = {{"Authorization": "Bearer {tok_b}"}}')
        lines.append(f'{indent}headers_admin = {{"Authorization": "Bearer {tok_admin}"}}')
        lines.append(f'{indent}victim_id = "1"')
        lines.append("")

        if not steps:
            # Synthesize single default step
            lines.append(f"{indent}# Reproduction Step: Direct Probe")
            http_m = method.lower()
            lines.append(f'{indent}attack = client.{http_m}("{endpoint}", headers=headers_user_a)')
            lines.append(
                f'{indent}assert attack.status_code == 200, f"Expected 200, got {{attack.status_code}}"'
            )
            lines.append(f'{indent}print("CONFIRMED: {flaw_type} verified successfully.")')
            return "\n".join(lines)

        for i, step in enumerate(steps, start=1):
            actor_raw = step.get("as") or step.get("actor") or "user_a"
            actor = str(actor_raw).lower()
            if "admin" in actor:
                headers_var = "headers_admin"
            elif "b" in actor:
                headers_var = "headers_user_b"
            else:
                headers_var = "headers_user_a"
            action_raw = step.get("action", "")
            step_path = step.get("path", "")
            body = step.get("body") if "body" in step else step.get("payload")
            assert_status = step.get("assert_status") or step.get("status")
            captured_id = step.get("captured_id")

            # Parse action string if it includes method and path, e.g. "POST /api/orders"
            parsed_method = ""
            if " " in action_raw:
                parts = action_raw.split(None, 1)
                first_word = parts[0].upper()
                if first_word in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    parsed_method = first_word
                    if not step_path and len(parts) > 1 and parts[1].startswith("/"):
                        step_path = parts[1]
                elif first_word == "BURST" or "burst" in action_raw.lower():
                    parsed_method = "BURST"

            if not parsed_method:
                if action_raw.lower() in ("create", "post"):
                    parsed_method = "POST"
                elif action_raw.lower() in ("read", "get"):
                    parsed_method = "GET"
                elif action_raw.lower() == "patch":
                    parsed_method = "PATCH"
                elif action_raw.lower() in ("update", "put"):
                    parsed_method = "PUT"
                elif action_raw.lower() in ("delete",):
                    parsed_method = "DELETE"
                elif "burst" in action_raw.lower():
                    parsed_method = "BURST"
                else:
                    parsed_method = method.upper()

            if not step_path or " " in step_path:
                step_path = step.get("path") or step.get("endpoint") or endpoint

            lines.append(f"{indent}# Step {i}: {actor_raw} executes {action_raw or parsed_method}")

            if parsed_method == "BURST":
                burst_target = step.get("path") or step.get("endpoint") or endpoint
                if " " in burst_target:
                    burst_target = endpoint
                count = step.get("count", 10)
                lines.append(f"{indent}import concurrent.futures")
                lines.append(f"{indent}def _send():")
                if body is not None:
                    lines.append(
                        f'{indent}    return client.post("{burst_target}", headers={headers_var}, json={json.dumps(body)})'
                    )
                else:
                    lines.append(
                        f'{indent}    return client.post("{burst_target}", headers={headers_var})'
                    )
                lines.append(
                    f"{indent}with concurrent.futures.ThreadPoolExecutor(max_workers={count}) as executor:"
                )
                lines.append(
                    f"{indent}    futures = [executor.submit(_send) for _ in range({count})]"
                )
                lines.append(f"{indent}    statuses = [f.result().status_code for f in futures]")
                lines.append(
                    f'{indent}assert sum(1 for s in statuses if 200 <= s < 300) > 1, f"Race condition not observed: {{statuses}}"'
                )
                lines.append("")
                continue

            # Check if step path contains parameter substitution
            path_repr: str
            if i > 1 and captured_id and str(captured_id) in step_path:
                formatted_path = step_path.replace(str(captured_id), "{victim_id}")
                path_repr = f'f"{formatted_path}"'
            elif "{victim_id}" in step_path or "{id}" in step_path:
                formatted_path = step_path.replace("{id}", "{victim_id}")
                path_repr = f'f"{formatted_path}"'
            else:
                path_repr = f'"{step_path}"'

            m_lower = parsed_method.lower()
            req_args = [path_repr, f"headers={headers_var}"]
            if body is not None:
                req_args.append(f"json={json.dumps(body)}")

            call_str = f"client.{m_lower}({', '.join(req_args)})"

            # If create step or step with captured_id
            if parsed_method == "POST" and (i == 1 or "create" in action_raw.lower()):
                lines.append(f"{indent}res_{i} = {call_str}")
                if captured_id:
                    lines.append(f'{indent}victim_id = "{captured_id}"')
                else:
                    lines.append(f"{indent}try:")
                    lines.append(f"{indent}    _data = res_{i}.json()")
                    lines.append(f"{indent}    if isinstance(_data, dict):")
                    lines.append(
                        f"{indent}        victim_id = str(_data.get('id') or _data.get('uuid') or _data.get('_id') or '1')"
                    )
                    lines.append(f"{indent}except Exception:")
                    lines.append(f"{indent}    victim_id = '1'")
                if assert_status:
                    lines.append(
                        f'{indent}assert res_{i}.status_code == {assert_status}, f"Step {i} setup failed: {{res_{i}.status_code}}"'
                    )
            else:
                # Attack or inspection step
                lines.append(f"{indent}attack = {call_str}")
                if assert_status:
                    lines.append(
                        f'{indent}assert attack.status_code == {assert_status}, f"Expected status {assert_status}, got {{attack.status_code}}"'
                    )
                else:
                    lines.append(
                        f'{indent}assert attack.status_code == 200, f"Expected 200, got {{attack.status_code}}"'
                    )

                # Check if victim data leaked (e.g. for BOLA)
                if flaw_type == "BOLA_IDOR" and i == len(steps):
                    lines.append(f"{indent}# Verify response contains substantive payload")
                    lines.append(
                        f'{indent}assert len(attack.text) > 2, "Empty response received for unauthorized access"'
                    )

            lines.append("")

        lines.append(f'{indent}print("CONFIRMED: {flaw_type} verified successfully.")')
        return "\n".join(lines)
