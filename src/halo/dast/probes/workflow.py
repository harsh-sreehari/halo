"""Dynamic Stateful Workflow Permutation Probing Engine."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from halo.dast.probes.base import BaseProbe, ProbeResult
from halo.dast.vault import PersonaType, SessionVault
from halo.intent.hypothesis import HypothesisResult, ProbingRecipe

logger = logging.getLogger(__name__)


class WorkflowStep(BaseModel):
    """Represents a single step in a multi-stage business workflow."""

    model_config = ConfigDict(extra="allow")

    name: str = Field(description="Logical identifier for the step (e.g. cart, payment, ship)")
    endpoint: str = Field(description="Route path or URL for this step")
    method: str = Field(default="POST", description="HTTP method (POST, PUT, GET, PATCH)")
    payload: dict[str, Any] | None = Field(default=None, description="Request JSON payload")
    params: dict[str, Any] | None = Field(default=None, description="Query parameters")
    headers: dict[str, str] = Field(default_factory=dict, description="Custom headers for this step")
    expected_status: int | list[int] = Field(
        default=200, description="Expected safe status code(s) for successful execution"
    )
    extract: dict[str, str] = Field(
        default_factory=dict,
        description="Mappings of variable name to response JSON key path for state propagation",
    )


class WorkflowProbe(BaseProbe):
    """Dynamic active verification probe for state machine workflow bypasses.

    Tests:
    1. Step-Skipping Permutations: Skips required intermediate state transitions (e.g. Cart -> Ship, skipping Payment).
    2. Step-Reordering Permutations: Executes terminal actions out-of-order or before prerequisites.
    """

    def execute(
        self,
        client: httpx.Client | None = None,
        target_url: str = "",
        vault: SessionVault | None = None,
        workflow_steps: list[WorkflowStep | dict[str, Any]] | None = None,
        recipe: ProbingRecipe | HypothesisResult | dict[str, Any] | None = None,
        actor: PersonaType | str = PersonaType.USER_A,
    ) -> ProbeResult:
        """Execute stateful workflow permutations and detect invariant bypasses."""
        # Unpack recipe if provided
        if isinstance(recipe, HypothesisResult):
            recipe = recipe.probing_recipe

        raw_steps = workflow_steps
        if raw_steps is None and isinstance(recipe, ProbingRecipe):
            raw_steps = recipe.extra_params.get("workflow_steps", recipe.extra_params.get("steps", []))
        elif raw_steps is None and isinstance(recipe, dict):
            extra = recipe.get("extra_params", recipe)
            raw_steps = extra.get("workflow_steps", extra.get("steps", []))

        if not raw_steps or len(raw_steps) < 2:
            ep = ""
            if raw_steps:
                first = raw_steps[0]
                ep = first.endpoint if isinstance(first, WorkflowStep) else first.get("endpoint", "")
            return ProbeResult(
                flaw_type="WORKFLOW_BYPASS",
                endpoint=ep,
                vulnerable=False,
                confidence=0.0,
                details="Workflow probing requires at least 2 steps with prerequisite state to permute.",
            )

        # Normalize into WorkflowStep models
        steps: list[WorkflowStep] = []
        for s in raw_steps:
            if isinstance(s, WorkflowStep):
                steps.append(s)
            elif isinstance(s, dict):
                steps.append(WorkflowStep(**s))

        actor_type = PersonaType.from_str(actor) if isinstance(actor, (PersonaType, str)) else PersonaType.USER_A
        actor_headers = dict(vault.get_headers(actor_type) if vault else {})

        http_client = client or httpx.Client(base_url=target_url, timeout=10.0)

        req_evidence: list[dict[str, Any]] = []
        resp_evidence: list[dict[str, Any]] = []
        observed_side_effects: list[str] = []
        reproduction_steps: list[dict[str, Any]] = []

        terminal_endpoint = steps[-1].endpoint if steps else ""

        # -------------------------------------------------------------------
        # 1. Permutation Strategy: Step Skipping
        # -------------------------------------------------------------------
        # For multi-step workflows (>= 3 steps), dynamically generate permutations:
        # 1. For each intermediate step k in [1, N-2], test sequence skipping k.
        # 2. Also test skipping all intermediate steps directly from initial step[0] to terminal step[N-1].
        if len(steps) >= 3:
            n_steps = len(steps)
            skip_sequences: list[tuple[list[WorkflowStep], list[str], str]] = []

            # Permutation 1a: Skip each individual intermediate step k
            for k in range(1, n_steps - 1):
                seq = [steps[i] for i in range(n_steps) if i != k]
                skipped_names = [steps[k].name]
                desc = (
                    f"Skipping intermediate step '{steps[k].name}' "
                    f"(executed '{' -> '.join(s.name for s in seq)}')"
                )
                skip_sequences.append((seq, skipped_names, desc))

            # Permutation 1b: Skip all intermediate steps directly from initial to terminal
            if n_steps > 3:
                seq = [steps[0], steps[-1]]
                skipped_names = [s.name for s in steps[1:-1]]
                desc = (
                    f"Skipping all intermediate steps ({', '.join(skipped_names)}) "
                    f"directly from '{steps[0].name}' to '{steps[-1].name}'"
                )
                skip_sequences.append((seq, skipped_names, desc))

            for seq, skipped_names, desc in skip_sequences:
                is_vuln, last_resp, seq_req_ev, seq_resp_ev = self._run_step_sequence(
                    http_client, seq, actor_headers, actor_type.value, target_url, vault
                )
                req_evidence.extend(seq_req_ev)
                resp_evidence.extend(seq_resp_ev)

                if is_vuln and last_resp is not None:
                    skipped_str = ", ".join(skipped_names)
                    observed_side_effects.append(
                        f"Workflow step '{skipped_str}' was bypassed; step '{seq[-1].name}' completed without prerequisite (status {last_resp.status_code})"
                    )
                    reproduction_steps.append({
                        "step": 1,
                        "actor": actor_type.value,
                        "action": f"Executed sequence skipping [{skipped_str}]",
                        "status": last_resp.status_code,
                        "description": desc,
                    })
                    return ProbeResult(
                        flaw_type="WORKFLOW_BYPASS",
                        endpoint=seq[-1].endpoint,
                        vulnerable=True,
                        confidence=0.90,
                        request_evidence=req_evidence,
                        response_evidence=resp_evidence,
                        observed_side_effects=observed_side_effects,
                        reproduction_steps=reproduction_steps,
                        details=(
                            f"State machine invariant violation detected: workflow step(s) '{skipped_str}' "
                            f"were successfully bypassed. Terminal endpoint '{seq[-1].endpoint}' accepted the transaction."
                        ),
                    )

        # -------------------------------------------------------------------
        # 2. Permutation Strategy: Direct Out-of-Order Terminal Execution
        # -------------------------------------------------------------------
        # Test directly calling the terminal step without prior workflow setup
        if len(steps) >= 2:
            terminal_step = steps[-1]
            is_vuln, last_resp, seq_req_ev, seq_resp_ev = self._run_step_sequence(
                http_client, [terminal_step], actor_headers, actor_type.value, target_url, vault
            )
            req_evidence.extend(seq_req_ev)
            resp_evidence.extend(seq_resp_ev)

            resolved_ep = self._interpolate_template(terminal_step.endpoint, {})

            if is_vuln and last_resp is not None:
                observed_side_effects.append(
                    f"Terminal workflow step '{terminal_step.name}' accepted execution out of order without prerequisite steps (status {last_resp.status_code})"
                )
                reproduction_steps.append({
                    "step": 1,
                    "actor": actor_type.value,
                    "action": f"{terminal_step.method.upper()} {resolved_ep}",
                    "path": resolved_ep,
                    "status": last_resp.status_code,
                    "description": f"Directly invoked {terminal_step.method} {resolved_ep} without prior workflow initialization",
                })
                return ProbeResult(
                    flaw_type="WORKFLOW_BYPASS",
                    endpoint=terminal_step.endpoint,
                    vulnerable=True,
                    confidence=0.95,
                    request_evidence=req_evidence,
                    response_evidence=resp_evidence,
                    observed_side_effects=observed_side_effects,
                    reproduction_steps=reproduction_steps,
                    details=(
                        f"Workflow Reordering Flaw detected on {terminal_step.endpoint}: "
                        f"Terminal step '{terminal_step.name}' executed successfully (status {last_resp.status_code}) "
                        f"without required prerequisite state."
                    ),
                )

        # If all permutations were rejected (e.g. 400 Bad Request, 403 Forbidden, 422 Unprocessable Entity)
        return ProbeResult(
            flaw_type="WORKFLOW_BYPASS",
            endpoint=terminal_endpoint,
            vulnerable=False,
            confidence=0.0,
            request_evidence=req_evidence,
            response_evidence=resp_evidence,
            reproduction_steps=reproduction_steps,
            details="Workflow state invariants enforced: all step-skipping and reordering permutations were rejected with client errors.",
        )

    def _run_step_sequence(
        self,
        client: httpx.Client,
        sequence: list[WorkflowStep],
        base_headers: dict[str, str],
        actor: str,
        target_url: str,
        vault: SessionVault | None,
    ) -> tuple[bool, httpx.Response | None, list[dict[str, Any]], list[dict[str, Any]]]:
        """Execute a concrete sequence of workflow steps, propagating state."""
        state_vars: dict[str, Any] = {}
        req_evs: list[dict[str, Any]] = []
        resp_evs: list[dict[str, Any]] = []
        last_resp: httpx.Response | None = None

        for idx, step in enumerate(sequence):
            step_headers = dict(base_headers)
            step_headers.update(step.headers)

            # Substitute state variables into endpoint and payload
            endpoint = self._interpolate_template(step.endpoint, state_vars)
            payload = self._interpolate_payload(step.payload, state_vars) if step.payload is not None else None

            req_ev = self.record_request_evidence(
                step.method, endpoint, step_headers, payload, actor=actor
            )
            req_evs.append(req_ev)

            try:
                resp = client.request(
                    step.method,
                    endpoint,
                    headers=step_headers,
                    json=payload,
                    params=step.params,
                )
                if vault:
                    vault.record_request(actor, client=client, target_url=target_url)
                resp_ev = self.record_response_evidence(
                    resp, actor=actor, step=f"workflow_perm_{step.name}_{idx + 1}"
                )
                resp_evs.append(resp_ev)
                last_resp = resp

                # Extract variables for next steps (supports 200, 201, 204 No Content, etc.)
                if 200 <= resp.status_code < 300:
                    self._extract_step_variables(resp, step.extract, state_vars)
                elif idx < len(sequence) - 1:
                    # An intermediate step in the sequence failed, sequence broken
                    return False, resp, req_evs, resp_evs

            except Exception as exc:  # noqa: BLE001
                logger.debug("Sequence execution error on step %s: %s", step.name, exc)
                return False, last_resp, req_evs, resp_evs

        if last_resp is None:
            return False, None, req_evs, resp_evs

        # Terminal step succeeded (status 200..299)
        succeeded = 200 <= last_resp.status_code < 300
        return succeeded, last_resp, req_evs, resp_evs

    def _interpolate_template(self, text: str, state_vars: dict[str, Any]) -> str:
        """Replace {key} in URL with state variables if available."""
        result = text
        for k, v in state_vars.items():
            result = result.replace(f"{{{k}}}", str(v))
            result = result.replace(f":{k}", str(v))
        # Fallback replacement for any unresolved path parameters
        result = re.sub(r"\{[a-zA-Z0-9_]+\}|:[a-zA-Z0-9_]+", "1", result)
        return result

    def _interpolate_payload(self, payload: Any, state_vars: dict[str, Any]) -> Any:
        """Deeply substitute state variables into dictionary or list payload."""
        if isinstance(payload, dict):
            new_dict = {}
            for k, v in payload.items():
                new_dict[k] = self._interpolate_payload(v, state_vars)
            return new_dict
        elif isinstance(payload, list):
            return [self._interpolate_payload(item, state_vars) for item in payload]
        elif isinstance(payload, str):
            for k, v in state_vars.items():
                if payload == f"{{{k}}}":
                    return v
                payload = payload.replace(f"{{{k}}}", str(v))
            return payload
        return payload

    def _extract_step_variables(
        self,
        resp: httpx.Response,
        extract_rules: dict[str, str],
        state_vars: dict[str, Any],
    ) -> None:
        """Extract output fields from JSON response into shared state variables."""
        try:
            data = resp.json()
            if not isinstance(data, dict):
                return

            # Default heuristic extractions
            for default_key in ("id", "order_id", "cart_id", "token", "session_id"):
                if default_key in data and default_key not in state_vars:
                    state_vars[default_key] = data[default_key]

            # Explicit rule extractions
            for var_name, field_path in extract_rules.items():
                parts = field_path.split(".")
                curr = data
                for p in parts:
                    if isinstance(curr, dict) and p in curr:
                        curr = curr[p]
                    else:
                        curr = None
                        break
                if curr is not None:
                    state_vars[var_name] = curr
        except Exception:  # noqa: BLE001, S110
            pass
