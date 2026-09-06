"""Dynamic BOLA / IDOR Probing Engine with Multi-Actor Handshake and Read-Your-Own-Writes Gate."""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx

from halo.dast.probes.base import BaseProbe, ProbeResult
from halo.dast.vault import PersonaType, SessionVault
from halo.intent.hypothesis import HypothesisResult, ProbingRecipe

logger = logging.getLogger(__name__)


class BOLAProbe(BaseProbe):
    """Dynamic active verification probe for Broken Object Level Authorization (BOLA/IDOR).

    Executes a Multi-Actor Handshake:
    1. User_B (victim) creates a resource -> captures returned ID.
    2. Read-Your-Own-Writes Gate: User_B polls read endpoint until 200 OK confirms replica sync.
    3. User_A (attacker) attempts unauthorized read or mutation of User_B's resource.
    """

    def execute(
        self,
        client: httpx.Client | None = None,
        target_url: str = "",
        vault: SessionVault | None = None,
        recipe: ProbingRecipe | HypothesisResult | dict[str, Any] | None = None,
        create_endpoint: str | None = None,
        create_payload: dict[str, Any] | None = None,
        create_method: str = "POST",
        read_endpoint_template: str | None = None,
        read_endpoint: str | None = None,
        read_method: str = "GET",
        write_endpoint_template: str | None = None,
        write_endpoint: str | None = None,
        write_method: str = "PUT",
        write_payload: dict[str, Any] | None = None,
        test_write: bool = False,
        id_field: str = "id",
        primary_param: str = "id",
        expected_safe_status: int = 403,
        expected_vuln_status: int = 200,
        max_sync_attempts: int = 5,
        sync_delay: float = 0.05,
        actor_victim: PersonaType | str = PersonaType.USER_B,
        actor_attacker: PersonaType | str = PersonaType.USER_A,
    ) -> ProbeResult:
        """Execute dynamic BOLA active verification handshake."""
        # 1. Unpack recipe parameters if provided
        if isinstance(recipe, HypothesisResult):
            recipe = recipe.probing_recipe

        if isinstance(recipe, ProbingRecipe):
            expected_safe_status = recipe.expected_safe_status or expected_safe_status
            expected_vuln_status = recipe.expected_vuln_status or expected_vuln_status
            primary_param = recipe.primary_param or primary_param
            extra = recipe.extra_params
        elif isinstance(recipe, dict):
            extra = recipe.get("extra_params", recipe)
            expected_safe_status = recipe.get("expected_safe_status", expected_safe_status)
            expected_vuln_status = recipe.get("expected_vuln_status", expected_vuln_status)
            primary_param = recipe.get("primary_param", primary_param)
        else:
            extra = {}

        create_endpoint = create_endpoint or extra.get("create_endpoint")
        create_payload = (
            create_payload
            if create_payload is not None
            else extra.get("create_payload", {"name": "halo_probe_resource", "amount": 100})
        )
        read_endpoint_template = read_endpoint_template or extra.get("read_endpoint_template")
        read_endpoint = read_endpoint or extra.get("read_endpoint")
        write_endpoint_template = write_endpoint_template or extra.get("write_endpoint_template")
        write_endpoint = write_endpoint or extra.get("write_endpoint")
        write_payload = write_payload if write_payload is not None else extra.get("write_payload")
        test_write = test_write or extra.get("test_write", write_payload is not None)

        # Fallback template extraction from endpoint path
        if not read_endpoint_template and not read_endpoint:
            candidate_path = extra.get("endpoint") or extra.get("path") or ""
            if candidate_path:
                read_endpoint_template = candidate_path

        # If create_endpoint is missing, deduce from read template
        if not create_endpoint and read_endpoint_template:
            # Strip trailing placeholder e.g. /invoices/{id} -> /invoices
            create_endpoint = re.sub(r"/\{[^{}]+\}$|/:[a-zA-Z0-9_]+$|/<[^<>]+>$", "", read_endpoint_template)

        req_evidence: list[dict[str, Any]] = []
        resp_evidence: list[dict[str, Any]] = []
        observed_side_effects: list[str] = []
        reproduction_steps: list[dict[str, Any]] = []

        http_client = client or httpx.Client(base_url=target_url, timeout=10.0)

        # Persona credentials
        victim_type = PersonaType.from_str(actor_victim) if isinstance(actor_victim, (PersonaType, str)) else PersonaType.USER_B
        attacker_type = PersonaType.from_str(actor_attacker) if isinstance(actor_attacker, (PersonaType, str)) else PersonaType.USER_A

        victim_headers = vault.get_headers(victim_type) if vault else {}
        attacker_headers = vault.get_headers(attacker_type) if vault else {}

        target_test_endpoint = read_endpoint_template or read_endpoint or create_endpoint or ""

        # Step 1: User_B creates resource
        resource_id: str | None = None
        if create_endpoint:
            req_ev = self.record_request_evidence(
                create_method, create_endpoint, victim_headers, create_payload, actor=victim_type.value
            )
            req_evidence.append(req_ev)
            try:
                create_resp = http_client.request(
                    create_method,
                    create_endpoint,
                    headers=victim_headers,
                    json=create_payload,
                )
                if vault:
                    vault.record_request(victim_type, client=http_client, target_url=target_url)
                resp_ev = self.record_response_evidence(create_resp, actor=victim_type.value, step="create_resource")
                resp_evidence.append(resp_ev)

                if create_resp.status_code not in (200, 201, 202):
                    return ProbeResult(
                        flaw_type="BOLA_IDOR",
                        endpoint=target_test_endpoint,
                        vulnerable=False,
                        confidence=0.0,
                        request_evidence=req_evidence,
                        response_evidence=resp_evidence,
                        details=f"Victim failed to create resource on {create_endpoint} (status {create_resp.status_code})",
                    )

                resource_id = self._extract_resource_id(create_resp, id_field=id_field, primary_param=primary_param)
                reproduction_steps.append({
                    "step": 1,
                    "actor": victim_type.value,
                    "action": f"{create_method} {create_endpoint}",
                    "path": create_endpoint,
                    "body": create_payload,
                    "status": create_resp.status_code,
                    "captured_id": resource_id,
                    "description": f"Victim creates resource, resulting in ID '{resource_id}'",
                })
            except Exception as exc:  # noqa: BLE001
                return ProbeResult(
                    flaw_type="BOLA_IDOR",
                    endpoint=target_test_endpoint,
                    vulnerable=False,
                    confidence=0.0,
                    details=f"Network error during victim resource creation: {exc}",
                )

        if not resource_id:
            # Check if read_endpoint already had hardcoded ID
            if read_endpoint:
                resource_id = read_endpoint.rstrip("/").split("/")[-1]
            else:
                return ProbeResult(
                    flaw_type="BOLA_IDOR",
                    endpoint=target_test_endpoint,
                    vulnerable=False,
                    confidence=0.0,
                    request_evidence=req_evidence,
                    response_evidence=resp_evidence,
                    details="Could not extract newly created resource ID from victim creation response",
                )

        # Resolve read endpoint path
        resolved_read_endpoint = self._resolve_path(read_endpoint_template, read_endpoint, resource_id, primary_param)

        # Step 2: Read-Your-Own-Writes Gate
        # Poll GET resolved_read_endpoint until 200 OK is returned to guarantee replica sync
        sync_confirmed = False
        last_sync_resp: httpx.Response | None = None
        for attempt in range(max_sync_attempts):
            try:
                last_sync_resp = http_client.request(
                    read_method,
                    resolved_read_endpoint,
                    headers=victim_headers,
                )
                if vault:
                    vault.record_request(victim_type, client=http_client, target_url=target_url)
                if last_sync_resp.status_code == 200:
                    sync_confirmed = True
                    resp_evidence.append(
                        self.record_response_evidence(last_sync_resp, actor=victim_type.value, step="read_own_writes_gate")
                    )
                    break
            except Exception as exc:  # noqa: BLE001
                logger.debug("Read-your-own-writes attempt %d failed: %s", attempt + 1, exc)

            if attempt < max_sync_attempts - 1 and sync_delay > 0:
                time.sleep(sync_delay)

        if not sync_confirmed:
            status_desc = last_sync_resp.status_code if last_sync_resp else "N/A"
            return ProbeResult(
                flaw_type="BOLA_IDOR",
                endpoint=resolved_read_endpoint,
                vulnerable=False,
                confidence=0.0,
                request_evidence=req_evidence,
                response_evidence=resp_evidence,
                details=f"Read-Your-Own-Writes Gate failed: Victim could not read newly created resource '{resource_id}' (status {status_desc})",
            )

        reproduction_steps.append({
            "step": 2,
            "actor": victim_type.value,
            "action": f"{read_method} {resolved_read_endpoint}",
            "path": resolved_read_endpoint,
            "status": 200,
            "description": "Victim verifies resource exists (Read-Your-Own-Writes Gate passes)",
        })

        # Step 3: User_A attempts unauthorized access
        if test_write:
            # BOLA State Mutation Probe
            resolved_write_endpoint = self._resolve_path(
                write_endpoint_template or read_endpoint_template,
                write_endpoint or resolved_read_endpoint,
                resource_id,
                primary_param,
            )
            mutation_body = write_payload or {"name": "halo_tampered_value"}
            req_ev_a = self.record_request_evidence(
                write_method, resolved_write_endpoint, attacker_headers, mutation_body, actor=attacker_type.value
            )
            req_evidence.append(req_ev_a)
            attack_resp = http_client.request(
                write_method,
                resolved_write_endpoint,
                headers=attacker_headers,
                json=mutation_body,
            )
            if vault:
                vault.record_request(attacker_type, client=http_client, target_url=target_url)
            resp_evidence.append(
                self.record_response_evidence(attack_resp, actor=attacker_type.value, step="unauthorized_mutation")
            )

            is_vuln = (
                attack_resp.status_code in (200, 201, 204)
                or attack_resp.status_code == expected_vuln_status
            )
            if is_vuln:
                observed_side_effects.append(
                    f"State mutation confirmed: User_A successfully tampered with User_B's resource '{resource_id}' via {write_method} {resolved_write_endpoint} (status {attack_resp.status_code})"
                )
                reproduction_steps.append({
                    "step": 3,
                    "actor": attacker_type.value,
                    "action": f"{write_method} {resolved_write_endpoint}",
                    "path": resolved_write_endpoint,
                    "body": mutation_body,
                    "status": attack_resp.status_code,
                    "description": f"Attacker tampers with victim resource '{resource_id}'",
                })
                return ProbeResult(
                    flaw_type="BOLA_IDOR",
                    endpoint=resolved_write_endpoint,
                    vulnerable=True,
                    confidence=0.95,
                    request_evidence=req_evidence,
                    response_evidence=resp_evidence,
                    observed_side_effects=observed_side_effects,
                    reproduction_steps=reproduction_steps,
                    details=f"BOLA Mutation detected: Attacker ({attacker_type.value}) mutated resource of {victim_type.value}.",
                )
            else:
                return ProbeResult(
                    flaw_type="BOLA_IDOR",
                    endpoint=resolved_write_endpoint,
                    vulnerable=False,
                    confidence=0.0,
                    request_evidence=req_evidence,
                    response_evidence=resp_evidence,
                    details=f"BOLA write mutation denied: Status {attack_resp.status_code} received (expected safe {expected_safe_status}).",
                )

        # Standard BOLA Read Probe
        req_ev_a = self.record_request_evidence(
            read_method, resolved_read_endpoint, attacker_headers, actor=attacker_type.value
        )
        req_evidence.append(req_ev_a)
        attack_resp = http_client.request(
            read_method,
            resolved_read_endpoint,
            headers=attacker_headers,
        )
        if vault:
            vault.record_request(attacker_type, client=http_client, target_url=target_url)
        resp_evidence.append(
            self.record_response_evidence(attack_resp, actor=attacker_type.value, step="unauthorized_read")
        )

        reproduction_steps.append({
            "step": 3,
            "actor": attacker_type.value,
            "action": f"{read_method} {resolved_read_endpoint}",
            "path": resolved_read_endpoint,
            "status": attack_resp.status_code,
            "description": f"Attacker requests victim resource '{resource_id}' across tenant boundary",
        })

        if attack_resp.status_code == expected_vuln_status or (200 <= attack_resp.status_code < 300):
            observed_side_effects.append(
                f"Unauthorized read of User_B resource '{resource_id}' by User_A at {resolved_read_endpoint} (status {attack_resp.status_code})"
            )
            return ProbeResult(
                flaw_type="BOLA_IDOR",
                endpoint=read_endpoint_template or resolved_read_endpoint,
                vulnerable=True,
                confidence=0.95,
                request_evidence=req_evidence,
                response_evidence=resp_evidence,
                observed_side_effects=observed_side_effects,
                reproduction_steps=reproduction_steps,
                details=f"BOLA / IDOR vulnerability confirmed: {attacker_type.value} accessed {victim_type.value}'s resource '{resource_id}' with status {attack_resp.status_code}.",
            )

        return ProbeResult(
            flaw_type="BOLA_IDOR",
            endpoint=read_endpoint_template or resolved_read_endpoint,
            vulnerable=False,
            confidence=0.0,
            request_evidence=req_evidence,
            response_evidence=resp_evidence,
            reproduction_steps=reproduction_steps,
            details=f"Access correctly denied: {attacker_type.value} received status {attack_resp.status_code} (expected safe: {expected_safe_status}).",
        )

    def _extract_resource_id(
        self,
        response: httpx.Response,
        id_field: str = "id",
        primary_param: str = "id",
    ) -> str | None:
        """Extract resource identifier from creation response body or Location header."""
        try:
            data = response.json()
            # 1. Direct key match
            for key in (id_field, primary_param, "id", "uuid", "_id", "ID"):
                if isinstance(data, dict) and key in data and data[key] is not None:
                    return str(data[key])

            # 2. Nested data / item / result dict
            if isinstance(data, dict):
                for container_key in ("data", "item", "result", "payload", "entity"):
                    container = data.get(container_key)
                    if isinstance(container, dict):
                        for key in (id_field, primary_param, "id", "uuid", "_id"):
                            if key in container and container[key] is not None:
                                return str(container[key])

            # 3. List of items
            if isinstance(data, list) and data and isinstance(data[0], dict):
                for key in (id_field, primary_param, "id", "uuid"):
                    if key in data[0] and data[0][key] is not None:
                        return str(data[0][key])

            # 4. Any key ending in _id or Id
            if isinstance(data, dict):
                for k, v in data.items():
                    if k.endswith(("_id", "Id")) and v is not None:
                        return str(v)
        except Exception:  # noqa: BLE001, S110
            pass

        # 5. Location header
        loc = response.headers.get("Location") or response.headers.get("location")
        if loc:
            parts = loc.rstrip("/").split("/")
            if parts:
                return parts[-1]

        return None

    def _resolve_path(
        self,
        template: str | None,
        concrete: str | None,
        resource_id: str,
        primary_param: str = "id",
    ) -> str:
        """Substitute resource_id into route template or append to path."""
        if concrete and not template:
            return concrete

        path = template or concrete or f"/{resource_id}"

        # 1. High priority: exact match on primary_param (e.g. {invoice_id} or :invoice_id)
        if primary_param:
            exact_patterns = [
                r"\{" + re.escape(primary_param) + r"(?::[^{}]+)?\}",
                r":" + re.escape(primary_param) + r"\b",
                r"<(?:\w+:)?" + re.escape(primary_param) + r">",
            ]
            for pat in exact_patterns:
                if re.search(pat, path):
                    return re.sub(pat, resource_id, path, count=1)

        # 2. Standard ID patterns: {id}, :id, <id>
        id_patterns = [
            r"\{id(?::[^{}]+)?\}",
            r":id\b",
            r"<(?:\w+:)?id>",
        ]
        for pat in id_patterns:
            if re.search(pat, path):
                return re.sub(pat, resource_id, path, count=1)

        # 3. Entity-specific ID patterns ending in _id or Id (e.g. {invoice_id}, :order_id)
        entity_id_patterns = [
            r"\{[a-zA-Z0-9_]*(?:_id|Id)(?::[^{}]+)?\}",
            r":[a-zA-Z0-9_]*(?:_id|Id)\b",
            r"<(?:\w+:)?[a-zA-Z0-9_]*(?:_id|Id)>",
        ]
        for pat in entity_id_patterns:
            matches = list(re.finditer(pat, path))
            if matches:
                # Replace the innermost / last matching entity ID parameter
                last_m = matches[-1]
                return path[: last_m.start()] + resource_id + path[last_m.end() :]

        # 4. Fallback: match the last generic path parameter {...}, :..., <...>
        generic_patterns = [
            r"\{[^{}]+\}",
            r":[a-zA-Z0-9_]+",
            r"<[^<>]+>",
        ]
        for pat in generic_patterns:
            matches = list(re.finditer(pat, path))
            if matches:
                last_m = matches[-1]
                return path[: last_m.start()] + resource_id + path[last_m.end() :]

        # 5. Append if not already ending in resource_id
        if not path.endswith(f"/{resource_id}"):
            if path.endswith("/"):
                path = f"{path}{resource_id}"
            else:
                path = f"{path}/{resource_id}"

        return path
