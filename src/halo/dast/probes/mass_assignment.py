"""Dynamic Mass Assignment and Price Tampering Probing Engine."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from halo.dast.probes.base import BaseProbe, ProbeResult
from halo.dast.vault import PersonaType, SessionVault
from halo.intent.hypothesis import HypothesisResult, ProbingRecipe

logger = logging.getLogger(__name__)


class MassAssignmentProbe(BaseProbe):
    """Dynamic active verification probe for Mass Assignment and Price Tampering flaws."""

    def execute(
        self,
        client: httpx.Client | None = None,
        target_url: str = "",
        vault: SessionVault | None = None,
        recipe: ProbingRecipe | HypothesisResult | dict[str, Any] | None = None,
        endpoint: str = "",
        method: str = "POST",
        payload: dict[str, Any] | None = None,
        actor: PersonaType | str = PersonaType.USER_A,
        expected_safe_status: int = 400,
        expected_vuln_status: int = 200,
    ) -> ProbeResult:
        """Execute dynamic mass assignment / price tamper probe."""
        if isinstance(recipe, HypothesisResult):
            endpoint = endpoint or recipe.route_id or ""
            recipe = recipe.probing_recipe

        if isinstance(recipe, ProbingRecipe):
            expected_safe_status = recipe.expected_safe_status or expected_safe_status
            expected_vuln_status = recipe.expected_vuln_status or expected_vuln_status
            extra = recipe.extra_params
            method = extra.get("method", method)
            endpoint = endpoint or extra.get("endpoint", extra.get("path", ""))
            payload = payload if payload is not None else extra.get("payload")
        elif isinstance(recipe, dict):
            extra = recipe.get("extra_params", recipe)
            expected_safe_status = recipe.get("expected_safe_status", expected_safe_status)
            expected_vuln_status = recipe.get("expected_vuln_status", expected_vuln_status)
            method = extra.get("method", method)
            endpoint = endpoint or extra.get("endpoint", extra.get("path", ""))
            payload = payload if payload is not None else extra.get("payload")
        else:
            extra = {}

        http_client = client or httpx.Client(base_url=target_url, timeout=10.0)
        actor_type = (
            PersonaType.from_str(actor)
            if isinstance(actor, (PersonaType, str))
            else PersonaType.USER_A
        )
        headers = dict(vault.get_headers(actor_type) if vault else {})

        # Construct tamper payload
        tamper_payload: dict[str, Any]
        if payload is not None:
            tamper_payload = payload
        else:
            ep_lower = endpoint.lower()
            if any(k in ep_lower for k in ("cart", "checkout", "price", "order", "pay")):
                tamper_payload = {
                    "items": [{"id": "item_1", "price": 100.0, "quantity": 1}],
                    "total": 0.01,
                    "price": 0.01,
                }
            else:
                injected_field = extra.get("injected_field", "role")
                injected_val = extra.get("injected_value", "admin")
                tamper_payload = {injected_field: injected_val}

        req_evidence: list[dict[str, Any]] = []
        resp_evidence: list[dict[str, Any]] = []
        observed_side_effects: list[str] = []
        reproduction_steps: list[dict[str, Any]] = []

        req_evidence.append(
            self.record_request_evidence(
                method, endpoint, headers, tamper_payload, actor=actor_type.value
            )
        )

        try:
            resp = http_client.request(
                method,
                endpoint,
                headers=headers,
                json=tamper_payload,
            )
            if vault:
                vault.record_request(actor_type, client=http_client, target_url=target_url)
            resp_evidence.append(
                self.record_response_evidence(resp, actor=actor_type.value, step="tamper_mutation")
            )
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                flaw_type="MASS_ASSIGNMENT",
                endpoint=endpoint,
                vulnerable=False,
                confidence=0.0,
                details=f"Network error during mass assignment probe: {exc}",
            )

        is_vuln = False
        if resp.status_code == expected_vuln_status or (
            200 <= resp.status_code < 300 and resp.status_code != expected_safe_status
        ):
            # Semantic Oracle: Verify that injected attributes are actually reflected or bound in response
            try:
                resp_json = resp.json()

                priv_keys = {
                    "role",
                    "roles",
                    "is_admin",
                    "isadmin",
                    "admin",
                    "total",
                    "price",
                    "discount",
                    "amount",
                    "balance",
                    "credit",
                    "credits",
                    "status",
                    "verified",
                    "vip",
                    "tier",
                    "permissions",
                    "access_level",
                }
                injected_field = extra.get("injected_field")
                target_keys: dict[str, Any] = {}
                if injected_field and injected_field in tamper_payload:
                    target_keys = {injected_field: tamper_payload[injected_field]}
                else:
                    target_keys = {
                        k: v for k, v in tamper_payload.items() if k.lower() in priv_keys
                    }
                if not target_keys:
                    benign = {"username", "email", "password", "name", "items", "description"}
                    target_keys = {
                        k: v for k, v in tamper_payload.items() if k.lower() not in benign
                    }
                if not target_keys:
                    target_keys = tamper_payload

                def check_reflected(data: Any) -> bool:
                    if isinstance(data, dict):
                        for k, v in target_keys.items():
                            if k in ("items",):
                                continue
                            if k in data:
                                if data[k] == v or str(data[k]) == str(v):
                                    return True
                                if (
                                    isinstance(v, (int, float))
                                    and isinstance(data[k], (int, float))
                                    and abs(float(data[k]) - float(v)) < 1e-5
                                ):
                                    return True
                        return any(
                            check_reflected(sub)
                            for sub in data.values()
                            if isinstance(sub, (dict, list))
                        )
                    elif isinstance(data, list):
                        return any(check_reflected(item) for item in data)
                    return False

                reflected = check_reflected(resp_json)
                if not reflected and isinstance(resp_json, str):
                    for k, v in target_keys.items():
                        if k in ("items",):
                            continue
                        pattern = rf'"{re.escape(k)}"\s*:\s*(?:"{re.escape(str(v))}"|{re.escape(str(v))})'
                        if re.search(pattern, resp.text):
                            reflected = True
                            break
                is_vuln = reflected
            except Exception:  # noqa: BLE001
                is_vuln = False

        reproduction_steps.append(
            {
                "step": 1,
                "actor": actor_type.value,
                "action": f"{method.upper()} {endpoint}",
                "path": endpoint,
                "body": tamper_payload,
                "status": resp.status_code,
                "description": f"Attacker submits tampered payload ({tamper_payload}) to {endpoint}",
            }
        )

        if is_vuln:
            observed_side_effects.append(
                f"Tampered attributes accepted by {endpoint} with status {resp.status_code}"
            )
            return ProbeResult(
                flaw_type="MASS_ASSIGNMENT",
                endpoint=endpoint,
                vulnerable=True,
                confidence=0.90,
                request_evidence=req_evidence,
                response_evidence=resp_evidence,
                observed_side_effects=observed_side_effects,
                reproduction_steps=reproduction_steps,
                details=(
                    f"Mass Assignment / Attribute Tampering confirmed on {endpoint}: "
                    f"Server accepted client-supplied untrusted parameters (status {resp.status_code})."
                ),
            )

        return ProbeResult(
            flaw_type="MASS_ASSIGNMENT",
            endpoint=endpoint,
            vulnerable=False,
            confidence=0.0,
            request_evidence=req_evidence,
            response_evidence=resp_evidence,
            reproduction_steps=reproduction_steps,
            details=f"Server rejected tampered payload with status {resp.status_code}.",
        )
