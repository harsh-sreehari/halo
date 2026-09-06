"""Dynamic BFLA / Function Level Authorization Probing Engine."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from halo.dast.probes.base import BaseProbe, ProbeResult
from halo.dast.vault import PersonaType, SessionVault
from halo.intent.hypothesis import HypothesisResult, ProbingRecipe

logger = logging.getLogger(__name__)


class BFLAProbe(BaseProbe):
    """Dynamic active verification probe for Broken Function Level Authorization (BFLA).

    Executes a 3-Stage Role Escalation Handshake:
    1. Admin baseline: Confirms route is accessible and operational with administrative privileges (200 OK).
    2. Vertical escalation: Evaluates whether standard user (User_A) can access privileged functionality (200 instead of 403).
    3. Missing authentication: Evaluates whether unauthenticated access is permitted (200 instead of 401).
    """

    def execute(
        self,
        client: httpx.Client | None = None,
        target_url: str = "",
        vault: SessionVault | None = None,
        recipe: ProbingRecipe | HypothesisResult | dict[str, Any] | None = None,
        endpoint: str = "",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        expected_safe_status: int = 403,
        expected_vuln_status: int = 200,
        actor_admin: PersonaType | str = PersonaType.ADMIN,
        actor_user: PersonaType | str = PersonaType.USER_A,
    ) -> ProbeResult:
        """Execute dynamic BFLA active verification probe."""
        # Unpack recipe parameters if provided
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

        req_evidence: list[dict[str, Any]] = []
        resp_evidence: list[dict[str, Any]] = []
        observed_side_effects: list[str] = []
        reproduction_steps: list[dict[str, Any]] = []

        http_client = client or httpx.Client(base_url=target_url, timeout=10.0)

        admin_type = PersonaType.from_str(actor_admin) if isinstance(actor_admin, (PersonaType, str)) else PersonaType.ADMIN
        user_type = PersonaType.from_str(actor_user) if isinstance(actor_user, (PersonaType, str)) else PersonaType.USER_A

        admin_headers = dict(vault.get_headers(admin_type) if vault else {})
        if headers:
            admin_headers.update(headers)

        user_headers = dict(vault.get_headers(user_type) if vault else {})
        if headers:
            for k, v in headers.items():
                if k.lower() not in ("authorization", "cookie"):
                    user_headers[k] = v

        unauth_headers = {
            k: v
            for k, v in (headers or {}).items()
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        }

        # -------------------------------------------------------------------
        # Step 1: Positive Baseline Check (Admin)
        # -------------------------------------------------------------------
        req_admin_ev = self.record_request_evidence(
            method, endpoint, admin_headers, payload, actor=admin_type.value
        )
        req_evidence.append(req_admin_ev)

        try:
            admin_resp = http_client.request(
                method,
                endpoint,
                headers=admin_headers,
                json=payload,
                params=params,
            )
            if vault:
                vault.record_request(admin_type, client=http_client, target_url=target_url)
            resp_evidence.append(
                self.record_response_evidence(admin_resp, actor=admin_type.value, step="admin_baseline")
            )
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                flaw_type="BFLA",
                endpoint=endpoint,
                vulnerable=False,
                confidence=0.0,
                details=f"Admin baseline request failed with network error: {exc}",
            )

        reproduction_steps.append({
            "step": 1,
            "actor": admin_type.value,
            "action": f"{method.upper()} {endpoint}",
            "path": endpoint,
            "status": admin_resp.status_code,
            "description": "Admin requests privileged endpoint to verify availability baseline",
        })

        # Baseline must be 200..299 or matching expected_vuln_status
        admin_succeeded = (200 <= admin_resp.status_code < 300) or (admin_resp.status_code == expected_vuln_status)
        if not admin_succeeded:
            return ProbeResult(
                flaw_type="BFLA",
                endpoint=endpoint,
                vulnerable=False,
                confidence=0.0,
                request_evidence=req_evidence,
                response_evidence=resp_evidence,
                reproduction_steps=reproduction_steps,
                details=f"Admin baseline check failed: Expected successful status (200 OK), received {admin_resp.status_code}.",
            )

        # -------------------------------------------------------------------
        # Step 2: Vertical Privilege Escalation Check (Standard User)
        # -------------------------------------------------------------------
        req_user_ev = self.record_request_evidence(
            method, endpoint, user_headers, payload, actor=user_type.value
        )
        req_evidence.append(req_user_ev)

        try:
            user_resp = http_client.request(
                method,
                endpoint,
                headers=user_headers,
                json=payload,
                params=params,
            )
            if vault:
                vault.record_request(user_type, client=http_client, target_url=target_url)
            resp_evidence.append(
                self.record_response_evidence(user_resp, actor=user_type.value, step="user_escalation")
            )
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                flaw_type="BFLA",
                endpoint=endpoint,
                vulnerable=False,
                confidence=0.0,
                request_evidence=req_evidence,
                response_evidence=resp_evidence,
                details=f"Standard user request failed: {exc}",
            )

        reproduction_steps.append({
            "step": 2,
            "actor": user_type.value,
            "action": f"{method.upper()} {endpoint}",
            "path": endpoint,
            "status": user_resp.status_code,
            "description": f"Standard user ({user_type.value}) sends identical request to privileged route",
        })

        user_succeeded = (200 <= user_resp.status_code < 300) or (user_resp.status_code == expected_vuln_status)
        if user_succeeded:
            observed_side_effects.append(
                f"Standard user ({user_type.value}) accessed admin endpoint {endpoint} (status {user_resp.status_code})"
            )

        # -------------------------------------------------------------------
        # Step 3: Missing Authentication Check (Unauthenticated)
        # -------------------------------------------------------------------
        req_unauth_ev = self.record_request_evidence(
            method, endpoint, unauth_headers, payload, actor="UNAUTHENTICATED"
        )
        req_evidence.append(req_unauth_ev)

        try:
            unauth_resp = http_client.request(
                method,
                endpoint,
                headers=unauth_headers,
                json=payload,
                params=params,
            )
            resp_evidence.append(
                self.record_response_evidence(unauth_resp, actor="UNAUTHENTICATED", step="unauthenticated_access")
            )
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                flaw_type="BFLA",
                endpoint=endpoint,
                vulnerable=False,
                confidence=0.0,
                request_evidence=req_evidence,
                response_evidence=resp_evidence,
                details=f"Unauthenticated request failed: {exc}",
            )

        reproduction_steps.append({
            "step": 3,
            "actor": "UNAUTHENTICATED",
            "action": f"{method.upper()} {endpoint}",
            "path": endpoint,
            "status": unauth_resp.status_code,
            "description": "Unauthenticated client sends identical request without credentials",
        })

        unauth_succeeded = (200 <= unauth_resp.status_code < 300) or (unauth_resp.status_code == expected_vuln_status)
        if unauth_succeeded:
            observed_side_effects.append(
                f"Unauthenticated request accessed admin endpoint {endpoint} (status {unauth_resp.status_code})"
            )

        # -------------------------------------------------------------------
        # Synthesize Verification Findings
        # -------------------------------------------------------------------
        # Check if the endpoint is a benign public metadata endpoint
        is_read_only = method.upper() in {"GET", "HEAD"}
        if is_read_only and user_succeeded and unauth_succeeded:
            ep_lower = endpoint.lower()
            public_tokens = (
                "version",
                "application-version",
                "app-version",
                "application-configuration",
                "health",
                "info",
                "public",
                "ping",
                "status",
            )
            admin_sensitive_tokens = (
                "export",
                "settings",
                "users",
                "roles",
                "secrets",
                "keys",
                "backup",
                "logs",
                "delete",
                "modify",
            )
            is_metadata = any(pt in ep_lower for pt in public_tokens) and not any(
                st in ep_lower for st in admin_sensitive_tokens
            )
            if is_metadata:
                return ProbeResult(
                    flaw_type="BFLA",
                    endpoint=endpoint,
                    vulnerable=False,
                    confidence=0.0,
                    request_evidence=req_evidence,
                    response_evidence=resp_evidence,
                    reproduction_steps=reproduction_steps,
                    details=f"Endpoint {endpoint} is a public metadata endpoint and does not expose administrative functions.",
                )

        is_vuln = user_succeeded or unauth_succeeded
        if is_vuln:
            if user_succeeded and unauth_succeeded:
                confidence = 0.95
                summary = (
                    f"BFLA / Missing Authorization confirmed on {endpoint}: "
                    f"both standard user ({user_resp.status_code}) and unauthenticated actor ({unauth_resp.status_code}) gained access."
                )
            elif user_succeeded:
                confidence = 0.90
                summary = (
                    f"BFLA / Vertical Privilege Escalation confirmed on {endpoint}: "
                    f"standard user ({user_type.value}) received status {user_resp.status_code} (expected 403 Forbidden)."
                )
            else:
                confidence = 0.85
                summary = (
                    f"Missing Authentication confirmed on {endpoint}: "
                    f"unauthenticated request received status {unauth_resp.status_code} (expected 401 Unauthorized)."
                )

            return ProbeResult(
                flaw_type="BFLA",
                endpoint=endpoint,
                vulnerable=True,
                confidence=confidence,
                request_evidence=req_evidence,
                response_evidence=resp_evidence,
                observed_side_effects=observed_side_effects,
                reproduction_steps=reproduction_steps,
                details=summary,
            )

        return ProbeResult(
            flaw_type="BFLA",
            endpoint=endpoint,
            vulnerable=False,
            confidence=0.0,
            request_evidence=req_evidence,
            response_evidence=resp_evidence,
            reproduction_steps=reproduction_steps,
            details=(
                f"Access control enforced on {endpoint}: Admin received {admin_resp.status_code}, "
                f"User_A received {user_resp.status_code} (safe: {expected_safe_status}), "
                f"unauthenticated received {unauth_resp.status_code}."
            ),
        )
