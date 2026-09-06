"""Unit tests for DAST dynamic probing engines: BOLA, BFLA, Race Condition, and Workflow probes."""

from __future__ import annotations

import json
import threading
from typing import Any

import httpx

from halo.dast.probes import ProbeResult
from halo.dast.probes.bfla import BFLAProbe
from halo.dast.probes.bola import BOLAProbe
from halo.dast.probes.mass_assignment import MassAssignmentProbe
from halo.dast.probes.race import RaceConditionProbe
from halo.dast.probes.workflow import WorkflowProbe, WorkflowStep
from halo.dast.vault import PersonaType, SessionVault
from halo.intent.hypothesis import ProbingRecipe

# ---------------------------------------------------------------------------
# 1. BOLA / IDOR Probing Tests
# ---------------------------------------------------------------------------


def test_bola_probe_detects_unauthorized_access():
    """Verify BOLAProbe detects when User_A accesses User_B's private resource."""
    invoices: dict[str, dict[str, Any]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/invoices":
            inv_id = "inv_123"
            invoices[inv_id] = {"id": inv_id, "owner": "user_b", "amount": 500}
            return httpx.Response(201, json={"id": inv_id})
        elif request.method == "GET" and request.url.path == "/invoices/inv_123":
            # Vulnerable: does not verify owner matching auth token
            return httpx.Response(200, json=invoices["inv_123"])
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")
    vault.set_token(PersonaType.USER_B, "token_b")

    probe = BOLAProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        create_endpoint="/invoices",
        create_payload={"amount": 500},
        read_endpoint_template="/invoices/{id}",
    )
    assert isinstance(result, ProbeResult)
    assert result.vulnerable is True
    assert result.flaw_type == "BOLA_IDOR"
    assert result.endpoint == "/invoices/{id}"
    assert result.confidence >= 0.85
    assert len(result.request_evidence) > 0
    assert len(result.response_evidence) > 0
    assert len(result.observed_side_effects) > 0
    assert any("inv_123" in se for se in result.observed_side_effects)


def test_bola_probe_enforced_access_control():
    """Verify BOLAProbe reports secure when server enforces tenant boundary (403 Forbidden)."""
    invoices: dict[str, dict[str, Any]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if request.method == "POST" and request.url.path == "/invoices":
            inv_id = "inv_456"
            invoices[inv_id] = {"id": inv_id, "owner": "token_b", "amount": 250}
            return httpx.Response(201, json={"id": inv_id})
        elif request.method == "GET" and request.url.path == "/invoices/inv_456":
            # Secure: validates owner token
            if auth == "Bearer token_b":
                return httpx.Response(200, json=invoices["inv_456"])
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")
    vault.set_token(PersonaType.USER_B, "token_b")

    probe = BOLAProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        create_endpoint="/invoices",
        create_payload={"amount": 250},
        read_endpoint_template="/invoices/{id}",
    )
    assert result.vulnerable is False
    assert result.flaw_type == "BOLA_IDOR"
    assert "403" in result.details or "denied" in result.details.lower()


def test_bola_probe_write_mutation():
    """Verify BOLAProbe detects unauthorized state mutation (PUT/PATCH/DELETE)."""
    items: dict[str, dict[str, Any]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/items":
            items["item_99"] = {"id": "item_99", "name": "victim_item", "owner": "user_b"}
            return httpx.Response(201, json={"id": "item_99"})
        elif request.method == "GET" and request.url.path == "/items/item_99":
            return httpx.Response(200, json=items["item_99"])
        elif request.method == "PUT" and request.url.path == "/items/item_99":
            # Vulnerable: allows User_A to mutate User_B's item
            body = json.loads(request.content)
            items["item_99"].update(body)
            return httpx.Response(200, json=items["item_99"])
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")
    vault.set_token(PersonaType.USER_B, "token_b")

    probe = BOLAProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        create_endpoint="/items",
        create_payload={"name": "victim_item"},
        read_endpoint_template="/items/{id}",
        write_endpoint_template="/items/{id}",
        write_method="PUT",
        write_payload={"name": "tampered_by_user_a"},
        test_write=True,
    )
    assert result.vulnerable is True
    assert result.flaw_type == "BOLA_IDOR"
    assert any(
        "mutation" in se.lower() or "tamper" in se.lower() for se in result.observed_side_effects
    )
    assert items["item_99"]["name"] == "tampered_by_user_a"


def test_bola_probe_read_your_own_writes_gate_retry():
    """Verify Read-Your-Own-Writes Gate retries until replica synchronization is confirmed."""
    attempts = [0]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/documents":
            return httpx.Response(201, json={"data": {"id": "doc_sync_1"}})
        elif request.method == "GET" and request.url.path == "/documents/doc_sync_1":
            attempts[0] += 1
            # First attempt returns 404 (replica lag), second returns 200
            if attempts[0] < 2:
                return httpx.Response(404, json={"error": "syncing"})
            return httpx.Response(200, json={"id": "doc_sync_1", "content": "secret"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")
    vault.set_token(PersonaType.USER_B, "token_b")

    probe = BOLAProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        create_endpoint="/documents",
        create_payload={"content": "secret"},
        read_endpoint_template="/documents/{id}",
        max_sync_attempts=3,
        sync_delay=0.01,
    )
    assert result.vulnerable is True
    assert attempts[0] >= 2


def test_bola_probe_with_recipe_object():
    """Verify BOLAProbe accepts ProbingRecipe from hypothesis generator."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json={"id": "obj_001"})
        return httpx.Response(200, json={"id": "obj_001", "secret": "data"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")
    vault.set_token(PersonaType.USER_B, "token_b")

    recipe = ProbingRecipe(
        strategy="multi_actor_handshake",
        primary_param="id",
        expected_safe_status=403,
        expected_vuln_status=200,
        extra_params={
            "create_endpoint": "/api/v1/objects",
            "read_endpoint_template": "/api/v1/objects/{id}",
        },
    )

    probe = BOLAProbe()
    result = probe.execute(client=client, target_url="http://test", vault=vault, recipe=recipe)
    assert result.vulnerable is True
    assert result.flaw_type == "BOLA_IDOR"


# ---------------------------------------------------------------------------
# 2. BFLA / Role Escalation Probing Tests
# ---------------------------------------------------------------------------


def test_bfla_probe_detects_role_escalation():
    """Verify BFLAProbe detects standard user accessing admin route."""

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if request.url.path == "/api/admin/users":
            if auth == "Bearer admin_token":
                return httpx.Response(200, json={"users": ["u1", "u2"]})
            elif auth == "Bearer user_token":
                # Vulnerable: standard user receives 200 instead of 403 Forbidden
                return httpx.Response(200, json={"users": ["u1", "u2"]})
            else:
                return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.ADMIN, "admin_token")
    vault.set_token(PersonaType.USER_A, "user_token")

    probe = BFLAProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        endpoint="/api/admin/users",
        method="GET",
    )
    assert isinstance(result, ProbeResult)
    assert result.vulnerable is True
    assert result.flaw_type == "BFLA"
    assert result.endpoint == "/api/admin/users"
    assert result.confidence >= 0.85
    assert any(
        "Standard user" in se or "escalation" in se.lower() for se in result.observed_side_effects
    )


def test_bfla_probe_detects_missing_authentication():
    """Verify BFLAProbe detects completely unauthenticated access to administrative route."""

    def handler(request: httpx.Request) -> httpx.Response:
        # Route has zero authentication checks!
        if request.url.path == "/api/admin/export":
            return httpx.Response(200, json={"exported": True})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.ADMIN, "admin_token")
    vault.set_token(PersonaType.USER_A, "user_token")

    probe = BFLAProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        endpoint="/api/admin/export",
        method="GET",
    )
    assert result.vulnerable is True
    assert result.flaw_type == "BFLA"
    assert any(
        "Unauthenticated" in se or "missing" in se.lower() for se in result.observed_side_effects
    )


def test_bfla_probe_enforced_access_control():
    """Verify BFLAProbe reports secure when standard and unauthenticated actors are rejected."""

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if request.url.path == "/api/admin/settings":
            if auth == "Bearer admin_tok":
                return httpx.Response(200, json={"status": "ok"})
            elif auth == "Bearer user_tok":
                return httpx.Response(403, json={"error": "forbidden"})
            else:
                return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.ADMIN, "admin_tok")
    vault.set_token(PersonaType.USER_A, "user_tok")

    probe = BFLAProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        endpoint="/api/admin/settings",
        method="GET",
    )
    assert result.vulnerable is False
    assert result.flaw_type == "BFLA"
    assert (
        "restricted" in result.details.lower()
        or "enforced" in result.details.lower()
        or "403" in result.details
    )


def test_bfla_probe_admin_baseline_failure():
    """Verify BFLAProbe aborts and flags false if admin baseline route check fails (404/500)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "not found"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.ADMIN, "admin_tok")

    probe = BFLAProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        endpoint="/api/admin/nonexistent",
    )
    assert result.vulnerable is False
    assert "baseline" in result.details.lower()


# ---------------------------------------------------------------------------
# 3. Race Condition / Concurrency Probing Tests
# ---------------------------------------------------------------------------


def test_race_condition_probe_detects_multiplication():
    """Verify RaceConditionProbe detects state multiplication in a race-prone endpoint."""
    state = {"redemptions": 0, "balance": 100}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/coupons/redeem":
            # Intentionally vulnerable to race conditions (check-then-act without lock)
            current = state["redemptions"]
            if current < 1:
                # Simulate small processing delay allowing race window
                threading.Event().wait(0.005)
                with lock:
                    state["redemptions"] += 1
                    state["balance"] += 50
                return httpx.Response(200, json={"redeemed": True, "balance": state["balance"]})
            return httpx.Response(409, json={"error": "already_redeemed"})
        elif request.url.path == "/api/coupons/state":
            return httpx.Response(200, json=state)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")

    probe = RaceConditionProbe()
    result = probe.execute(
        target_url="http://test",
        endpoint="/api/coupons/redeem",
        method="POST",
        payload={"coupon_code": "SUMMER50"},
        vault=vault,
        client=client,
        burst_size=10,
        verify_endpoint="/api/coupons/state",
        force_h2=False,
    )
    assert isinstance(result, ProbeResult)
    assert result.vulnerable is True
    assert result.flaw_type == "RACE_CONDITION"
    assert result.endpoint == "/api/coupons/redeem"
    assert len(result.observed_side_effects) > 0
    assert any(
        "multiplication" in se.lower() or "concurrent" in se.lower()
        for se in result.observed_side_effects
    )


def test_race_condition_probe_enforces_atomicity():
    """Verify RaceConditionProbe reports secure when atomic locks prevent double spending."""
    state = {"redeemed": 0}
    mutex = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/claim":
            with mutex:
                if state["redeemed"] >= 1:
                    return httpx.Response(409, json={"error": "already claimed"})
                state["redeemed"] += 1
                return httpx.Response(200, json={"success": True})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")

    probe = RaceConditionProbe()
    result = probe.execute(
        target_url="http://test",
        endpoint="/api/claim",
        method="POST",
        payload={"item": "reward"},
        vault=vault,
        client=client,
        burst_size=8,
        force_h2=False,
    )
    assert result.vulnerable is False
    assert result.flaw_type == "RACE_CONDITION"
    assert (
        "atomic" in result.details.lower()
        or "prevented" in result.details.lower()
        or "secure" in result.details.lower()
    )


def test_race_condition_alpn_negotiation_fallback():
    """Verify RaceConditionProbe ALPN detection gracefully handles plain HTTP or failures."""
    probe = RaceConditionProbe()
    # Plain http url -> ALPN not used, returns False
    is_h2 = probe.check_alpn_support("http://localhost:8080")
    assert is_h2 is False

    # Unreachable host -> returns False without raising unhandled exception
    is_h2_unreach = probe.check_alpn_support("https://127.0.0.1:65530")
    assert is_h2_unreach is False


# ---------------------------------------------------------------------------
# 4. Workflow Permutator Probing Tests
# ---------------------------------------------------------------------------


def test_workflow_probe_detects_step_skipping():
    """Verify WorkflowProbe detects state machine bypass by skipping checkout payment step."""
    order_state: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/api/cart":
            order_state["status"] = "in_cart"
            return httpx.Response(201, json={"order_id": "ord_100", "status": "in_cart"})
        elif request.method == "POST" and request.url.path == "/api/payment":
            order_state["status"] = "paid"
            return httpx.Response(200, json={"order_id": "ord_100", "status": "paid"})
        elif request.method == "POST" and request.url.path == "/api/ship":
            # Vulnerable: does not verify if order is 'paid', ships directly from 'in_cart'!
            if order_state.get("status") in ("in_cart", "paid"):
                order_state["status"] = "shipped"
                return httpx.Response(200, json={"status": "shipped", "tracking": "TRK999"})
            return httpx.Response(400, json={"error": "no active cart"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")

    steps = [
        WorkflowStep(name="cart", endpoint="/api/cart", method="POST", payload={"item": "laptop"}),
        WorkflowStep(
            name="payment", endpoint="/api/payment", method="POST", payload={"amount": 1000}
        ),
        WorkflowStep(
            name="ship", endpoint="/api/ship", method="POST", payload={"address": "Main St"}
        ),
    ]

    probe = WorkflowProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        workflow_steps=steps,
    )
    assert isinstance(result, ProbeResult)
    assert result.vulnerable is True
    assert result.flaw_type == "WORKFLOW_BYPASS"
    assert any(
        "payment" in se.lower() or "skip" in se.lower() for se in result.observed_side_effects
    )
    assert len(result.reproduction_steps) > 0


def test_workflow_probe_detects_step_reordering():
    """Verify WorkflowProbe detects executing a terminal step before prerequisite setup."""

    def handler(request: httpx.Request) -> httpx.Response:
        # Vulnerable: permits instant finalization even without prior steps
        if request.url.path == "/api/account/upgrade/finalize":
            return httpx.Response(200, json={"upgraded": True, "tier": "enterprise"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")

    steps = [
        {"name": "request_quote", "endpoint": "/api/account/upgrade/quote", "method": "POST"},
        {"name": "verify_eligibility", "endpoint": "/api/account/upgrade/verify", "method": "POST"},
        {"name": "finalize", "endpoint": "/api/account/upgrade/finalize", "method": "POST"},
    ]

    probe = WorkflowProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        workflow_steps=steps,
    )
    assert result.vulnerable is True
    assert result.flaw_type == "WORKFLOW_BYPASS"


def test_workflow_probe_enforced_invariants():
    """Verify WorkflowProbe reports secure when strict state transitions are enforced."""
    current_state = ["empty"]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/step1":
            current_state[0] = "step1_done"
            return httpx.Response(200, json={"state": "step1_done"})
        elif request.url.path == "/api/step2":
            if current_state[0] != "step1_done":
                return httpx.Response(400, json={"error": "step 1 required"})
            current_state[0] = "step2_done"
            return httpx.Response(200, json={"state": "step2_done"})
        elif request.url.path == "/api/step3":
            if current_state[0] != "step2_done":
                return httpx.Response(400, json={"error": "step 2 required"})
            current_state[0] = "completed"
            return httpx.Response(200, json={"state": "completed"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")

    steps = [
        {"name": "s1", "endpoint": "/api/step1", "method": "POST"},
        {"name": "s2", "endpoint": "/api/step2", "method": "POST"},
        {"name": "s3", "endpoint": "/api/step3", "method": "POST"},
    ]

    probe = WorkflowProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        workflow_steps=steps,
    )
    assert result.vulnerable is False
    assert result.flaw_type == "WORKFLOW_BYPASS"
    assert "enforced" in result.details.lower() or "rejected" in result.details.lower()


# ---------------------------------------------------------------------------
# 5. ProbeResult Model Tests
# ---------------------------------------------------------------------------


def test_probe_result_serialization_and_fields():
    """Verify ProbeResult serialization, validation, and field completeness."""
    res = ProbeResult(
        flaw_type="BOLA_IDOR",
        endpoint="/api/v1/users/{id}",
        vulnerable=True,
        confidence=0.92,
        request_evidence=[{"method": "GET", "path": "/api/v1/users/42"}],
        response_evidence=[{"status_code": 200, "data": {"id": 42}}],
        observed_side_effects=["Leaked personal profile across tenant boundary"],
        reproduction_steps=[
            {"step": 1, "description": "Create user B profile"},
            {"step": 2, "description": "Access profile as User A"},
        ],
        details="BOLA detected: User A was able to read User B's record directly.",
    )
    data = res.model_dump()
    assert data["flaw_type"] == "BOLA_IDOR"
    assert data["vulnerable"] is True
    assert data["confidence"] == 0.92
    assert len(data["observed_side_effects"]) == 1
    assert len(data["reproduction_steps"]) == 2

    # Round trip JSON serialization
    serialized = res.model_dump_json()
    loaded = ProbeResult.model_validate_json(serialized)
    assert loaded.flaw_type == res.flaw_type
    assert loaded.confidence == res.confidence
    assert loaded.vulnerable == res.vulnerable


# ---------------------------------------------------------------------------
# 6. Review Round 1 Specific Regression & Edge-Case Tests
# ---------------------------------------------------------------------------


def test_race_condition_h2_transmitted_no_destructive_fallback(monkeypatch):
    """Verify that if HTTP/2 burst streams were transmitted, H1.1 fallback is not triggered."""
    probe = RaceConditionProbe()
    h1_called = [False]

    def mock_h2_burst(*args, **kwargs):
        # Packets were transmitted to the server, but timeout occurred on receive
        return True, False, [httpx.Response(504)]

    def mock_h1_burst(*args, **kwargs):
        h1_called[0] = True
        return []

    monkeypatch.setattr(probe, "_attempt_h2_burst", mock_h2_burst)
    monkeypatch.setattr(probe, "_execute_h1_barrier_burst", mock_h1_burst)

    result = probe.execute(
        target_url="https://api.test",
        endpoint="/api/redeem",
        method="POST",
        force_h2=True,
    )
    assert h1_called[0] is False, (
        "H1.1 fallback should NOT be called if H2 packets were transmitted"
    )
    assert result.vulnerable is False


def test_race_condition_vault_heartbeat_tracking():
    """Verify request counts are recorded in SessionVault during concurrency race bursts."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")
    initial_count = vault.request_counts[PersonaType.USER_A]

    probe = RaceConditionProbe()
    probe.execute(
        target_url="http://test",
        endpoint="/api/vote",
        method="POST",
        vault=vault,
        client=client,
        burst_size=12,
        force_h2=False,
    )
    assert vault.request_counts[PersonaType.USER_A] == initial_count + 12


def test_workflow_probe_dynamic_n_step_skipping():
    """Verify WorkflowProbe dynamically skips intermediate steps for N >= 3 workflows."""
    called_endpoints = []

    def handler(request: httpx.Request) -> httpx.Response:
        called_endpoints.append(request.url.path)
        # Vulnerable: accepts step 4 if step 0 occurred, regardless of intermediate steps
        return httpx.Response(200, json={"status": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")

    steps = [
        {"name": "step_0", "endpoint": "/api/step0", "method": "POST"},
        {"name": "step_1", "endpoint": "/api/step1", "method": "POST"},
        {"name": "step_2", "endpoint": "/api/step2", "method": "POST"},
        {"name": "step_3", "endpoint": "/api/step3", "method": "POST"},
        {"name": "step_4", "endpoint": "/api/step4", "method": "POST"},
    ]

    probe = WorkflowProbe()
    result = probe.execute(
        client=client,
        target_url="http://test",
        vault=vault,
        workflow_steps=steps,
    )
    assert result.vulnerable is True
    assert result.flaw_type == "WORKFLOW_BYPASS"
    assert any("step_" in se for se in result.observed_side_effects)


def test_workflow_probe_204_no_content_support():
    """Verify that intermediate steps returning 204 No Content succeed without failing sequence."""
    order_status = ["created"]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/cart":
            return httpx.Response(200, json={"cart_id": "c123"})
        elif request.url.path == "/api/coupon":
            # 204 No Content for coupon application
            order_status[0] = "discounted"
            return httpx.Response(204)
        elif request.url.path == "/api/checkout":
            return httpx.Response(200, json={"order_status": order_status[0]})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_a")

    steps = [
        {"name": "cart", "endpoint": "/api/cart", "method": "POST"},
        {"name": "coupon", "endpoint": "/api/coupon", "method": "POST"},
        {"name": "checkout", "endpoint": "/api/checkout", "method": "POST"},
    ]

    probe = WorkflowProbe()
    # Execute a sequence that includes the 204 step
    is_vuln, last_resp, _, _ = probe._run_step_sequence(
        client,
        [WorkflowStep(**s) for s in steps],
        vault.get_headers(PersonaType.USER_A),
        "USER_A",
        "http://test",
        vault,
    )
    assert is_vuln is True
    assert last_resp is not None
    assert last_resp.status_code == 200


def test_bola_probe_multi_param_path_replacement():
    """Verify _resolve_path replaces primary_param rather than parent route parameters."""
    probe = BOLAProbe()

    # Route with parent org_id and target invoice id
    path_1 = probe._resolve_path(
        template="/api/v1/organizations/{org_id}/invoices/{id}",
        concrete=None,
        resource_id="inv_999",
        primary_param="id",
    )
    assert path_1 == "/api/v1/organizations/{org_id}/invoices/inv_999"

    # Route with parent tenant_id and explicit invoice_id parameter
    path_2 = probe._resolve_path(
        template="/api/v1/tenants/{tenant_id}/orders/{order_id}",
        concrete=None,
        resource_id="ord_777",
        primary_param="order_id",
    )
    assert path_2 == "/api/v1/tenants/{tenant_id}/orders/ord_777"


def test_mass_assignment_probe_detects_reflected_tampering():
    """Verify MassAssignmentProbe flags vulnerability when injected parameter is reflected in response."""

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"orderId": "123", "total": data.get("total", 100.0)})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    probe = MassAssignmentProbe()
    res = probe.execute(
        client=client, endpoint="/api/cart/checkout", method="POST", payload={"total": 0.01}
    )
    assert res.vulnerable is True
    assert res.flaw_type == "MASS_ASSIGNMENT"


def test_mass_assignment_probe_rejects_ignored_attributes():
    """Verify MassAssignmentProbe does not falsely flag 200 responses that ignore the injected attribute."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "message": "Updated without extra fields"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    probe = MassAssignmentProbe()
    res = probe.execute(
        client=client, endpoint="/api/user/profile", method="PUT", payload={"role": "admin"}
    )
    assert res.vulnerable is False


def test_race_condition_generic_promo_payload():
    """Verify RaceConditionProbe falls back to generic PROMO payload without hardcoded testbed seed."""
    captured_payload = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_payload
        captured_payload = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"redeemed": True})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    probe = RaceConditionProbe()
    # Force single request to inspect payload
    probe._h1_burst = lambda client, ep, m, p, h, bs, to: [
        httpx.Response(200, json={"redeemed": True}),
        httpx.Response(200, json={"redeemed": True}),
    ]
    res = probe.execute(
        client=client, endpoint="/api/v1/coupons/apply", method="POST", force_h2=False
    )
    assert res.vulnerable is True
    assert "DISCOUNT50" not in str(res.request_evidence)
    assert any("PROMO" in str(req) for req in res.request_evidence)
