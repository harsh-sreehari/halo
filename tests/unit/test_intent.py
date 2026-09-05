from __future__ import annotations

import json
from pathlib import Path

from halo.intent.extractor import BusinessPolicyMatrix, IntentExtractor
from halo.intent.pruner import CandidatePruner, SuspectCandidate
from halo.llm.provider import MockLLMProvider
from halo.static.graph import (
    CodeKnowledgeGraph,
    EdgeType,
    HandlerNode,
    MiddlewareNode,
    RouteNode,
    SinkNode,
    ValidationSchemaNode,
)


def test_candidate_pruner_filters_static_reads():
    """Verify CandidatePruner discards static read-only routes without parameters."""
    ckg = CodeKnowledgeGraph()
    # Route without parameters
    r1 = RouteNode(
        id="r1",
        method="GET",
        path="/api/v1/health",
        file_path="app.py",
        line_number=1,
    )
    # Route with ID parameter accessing entity
    r2 = RouteNode(
        id="r2",
        method="GET",
        path="/api/v1/invoices/{id}",
        file_path="app.py",
        line_number=10,
    )
    s2 = SinkNode(
        id="s2",
        operation="READ",
        entity="Invoice",
        query_params=["id"],
        file_path="db.py",
        line_number=20,
    )

    ckg.add_node(r1)
    ckg.add_node(r2)
    ckg.add_node(s2)
    ckg.add_edge(r2.id, s2.id, EdgeType.CALLS)

    pruner = CandidatePruner()
    suspects = pruner.prune_candidates(ckg)
    suspect_routes = [s.route.id for s in suspects]
    assert "r1" not in suspect_routes
    assert "r2" in suspect_routes

    # Check that r2 is flagged with BOLA
    r2_candidate = next(s for s in suspects if s.route.id == "r2")
    assert "BOLA" in r2_candidate.candidate_flaws


def test_candidate_pruner_authorization_guard_pruning():
    """Verify routes guarded by verified authorization middleware are marked safe or skipped."""
    ckg = CodeKnowledgeGraph()

    # Route 1: Guarded by verified authorization middleware
    r_guarded = RouteNode(
        id="r_guarded",
        method="GET",
        path="/api/v1/documents/{id}",
        file_path="routes.py",
        line_number=10,
    )
    guard = MiddlewareNode(
        id="guard_authz",
        name="isOwnerGuard",
        type="AUTHZ",
        is_auth_guard=True,
    )
    sink_guarded = SinkNode(
        id="sink_guarded",
        operation="READ",
        entity="Document",
        query_params=["id"],
    )

    ckg.add_node(r_guarded)
    ckg.add_node(guard)
    ckg.add_node(sink_guarded)
    ckg.add_edge(r_guarded.id, guard.id, EdgeType.PROTECTED_BY)
    ckg.add_edge(r_guarded.id, sink_guarded.id, EdgeType.CALLS)

    # Route 2: Unguarded route accessing sensitive entity
    r_unguarded = RouteNode(
        id="r_unguarded",
        method="GET",
        path="/api/v1/users/{id}/profile",
        file_path="routes.py",
        line_number=30,
    )
    sink_unguarded = SinkNode(
        id="sink_unguarded",
        operation="READ",
        entity="UserProfile",
        query_params=["id"],
    )

    ckg.add_node(r_unguarded)
    ckg.add_node(sink_unguarded)
    ckg.add_edge(r_unguarded.id, sink_unguarded.id, EdgeType.CALLS)

    pruner = CandidatePruner()
    suspects = pruner.prune_candidates(ckg)
    suspect_route_ids = [s.route.id for s in suspects]

    assert "r_guarded" not in suspect_route_ids
    assert "r_unguarded" in suspect_route_ids


def test_candidate_pruner_mass_assignment_filtering():
    """Verify strict validation schemas discard routes from Mass Assignment analysis."""
    ckg = CodeKnowledgeGraph()

    # Route 1: Mutation route wrapped by strict validation schema without sensitive fields
    r_strict = RouteNode(
        id="r_strict",
        method="POST",
        path="/api/v1/profile",
        file_path="profile.py",
        line_number=5,
    )
    schema_strict = ValidationSchemaNode(
        id="schema_strict",
        name="ProfileUpdateDTO",
        strict=True,
        allowed_fields=["first_name", "last_name", "bio"],
        stripped_fields=["role", "is_admin"],
    )
    sink_strict = SinkNode(
        id="sink_strict",
        operation="UPDATE",
        entity="UserProfile",
        query_params=[],
    )

    ckg.add_node(r_strict)
    ckg.add_node(schema_strict)
    ckg.add_node(sink_strict)
    ckg.add_edge(r_strict.id, schema_strict.id, EdgeType.FILTERED_BY)
    ckg.add_edge(r_strict.id, sink_strict.id, EdgeType.CALLS)

    # Route 2: Mutation route with non-strict schema (allows unvalidated extra fields)
    r_loose = RouteNode(
        id="r_loose",
        method="POST",
        path="/api/v1/tenants",
        file_path="tenant.py",
        line_number=15,
    )
    schema_loose = ValidationSchemaNode(
        id="schema_loose",
        name="TenantCreateDTO",
        strict=False,
        allowed_fields=["name"],
    )
    sink_loose = SinkNode(
        id="sink_loose",
        operation="CREATE",
        entity="Tenant",
        query_params=[],
    )

    ckg.add_node(r_loose)
    ckg.add_node(schema_loose)
    ckg.add_node(sink_loose)
    ckg.add_edge(r_loose.id, schema_loose.id, EdgeType.FILTERED_BY)
    ckg.add_edge(r_loose.id, sink_loose.id, EdgeType.CALLS)

    # Route 3: Mutation route with strict schema but containing sensitive privilege fields in allowed_fields
    r_sensitive = RouteNode(
        id="r_sensitive",
        method="PUT",
        path="/api/v1/users/{id}",
        file_path="users.py",
        line_number=25,
    )
    schema_sensitive = ValidationSchemaNode(
        id="schema_sensitive",
        name="UserUpdateDTO",
        strict=True,
        allowed_fields=["name", "email", "role", "is_admin"],
    )
    sink_sensitive = SinkNode(
        id="sink_sensitive",
        operation="UPDATE",
        entity="User",
        query_params=["id"],
    )

    ckg.add_node(r_sensitive)
    ckg.add_node(schema_sensitive)
    ckg.add_node(sink_sensitive)
    ckg.add_edge(r_sensitive.id, schema_sensitive.id, EdgeType.FILTERED_BY)
    ckg.add_edge(r_sensitive.id, sink_sensitive.id, EdgeType.CALLS)

    pruner = CandidatePruner()
    suspects = pruner.prune_candidates(ckg)

    suspect_map = {s.route.id: s for s in suspects}
    # r_strict has strict schema with safe fields -> Mass Assignment pruned
    assert "r_strict" not in suspect_map or "MASS_ASSIGNMENT" not in suspect_map["r_strict"].candidate_flaws

    # r_loose has loose schema -> MASS_ASSIGNMENT candidate
    assert "r_loose" in suspect_map
    assert "MASS_ASSIGNMENT" in suspect_map["r_loose"].candidate_flaws

    # r_sensitive exposes role/is_admin in allowed_fields -> MASS_ASSIGNMENT candidate
    assert "r_sensitive" in suspect_map
    assert "MASS_ASSIGNMENT" in suspect_map["r_sensitive"].candidate_flaws


def test_candidate_pruner_race_condition_filtering():
    """Verify simple updates are discarded from Race Condition analysis, keeping threshold/counter mutations."""
    ckg = CodeKnowledgeGraph()

    # Route 1: Simple profile update (no counter or threshold)
    r_simple = RouteNode(
        id="r_simple",
        method="POST",
        path="/api/v1/user/bio",
        file_path="user.py",
        line_number=10,
    )
    h_simple = HandlerNode(id="h_simple", name="update_bio", file_path="user.py")
    s_simple = SinkNode(
        id="s_simple",
        operation="UPDATE",
        entity="UserProfile",
        query_params=[],
    )

    ckg.add_node(r_simple)
    ckg.add_node(h_simple)
    ckg.add_node(s_simple)
    ckg.add_edge(r_simple.id, h_simple.id, EdgeType.ROUTES_TO)
    ckg.add_edge(h_simple.id, s_simple.id, EdgeType.CALLS)

    # Route 2: Coupon redemption / balance transfer with threshold comparison
    r_race = RouteNode(
        id="r_race",
        method="POST",
        path="/api/v1/coupons/redeem",
        file_path="coupon.py",
        line_number=30,
    )
    h_race = HandlerNode(id="h_race", name="redeem_coupon_code", file_path="coupon.py")
    s_race = SinkNode(
        id="s_race",
        operation="UPDATE",
        entity="CouponBalance",
        query_params=["code", "amount"],
    )

    ckg.add_node(r_race)
    ckg.add_node(h_race)
    ckg.add_node(s_race)
    ckg.add_edge(r_race.id, h_race.id, EdgeType.ROUTES_TO)
    ckg.add_edge(h_race.id, s_race.id, EdgeType.CALLS)

    pruner = CandidatePruner()
    suspects = pruner.prune_candidates(ckg)
    suspect_map = {s.route.id: s for s in suspects}

    # r_simple should not be flagged with RACE
    if "r_simple" in suspect_map:
        assert "RACE" not in suspect_map["r_simple"].candidate_flaws

    # r_race should be flagged with RACE
    assert "r_race" in suspect_map
    assert "RACE" in suspect_map["r_race"].candidate_flaws


def test_candidate_pruner_bfla_and_workflow_detection():
    """Verify BFLA and WORKFLOW flaw classification using business policy invariants."""
    ckg = CodeKnowledgeGraph()

    # Route 1: Administrative route without authorization guard
    r_admin = RouteNode(
        id="r_admin",
        method="DELETE",
        path="/api/v1/admin/users/{id}",
        file_path="admin.py",
        line_number=20,
    )
    s_admin = SinkNode(id="s_admin", operation="DELETE", entity="User", query_params=["id"])
    ckg.add_node(r_admin)
    ckg.add_node(s_admin)
    ckg.add_edge(r_admin.id, s_admin.id, EdgeType.CALLS)

    # Route 2: State transition route without verified state check
    r_ship = RouteNode(
        id="r_ship",
        method="POST",
        path="/api/v1/orders/{id}/ship",
        file_path="order.py",
        line_number=40,
    )
    s_ship = SinkNode(id="s_ship", operation="UPDATE", entity="Order", query_params=["id"])
    ckg.add_node(r_ship)
    ckg.add_node(s_ship)
    ckg.add_edge(r_ship.id, s_ship.id, EdgeType.CALLS)

    policies = BusinessPolicyMatrix(
        ownership_rules=["Users can only manage their own profile"],
        role_hierarchy=["admin", "merchant", "customer"],
        state_invariants=["Order must be PAID before SHIP can be invoked"],
    )

    pruner = CandidatePruner()
    suspects = pruner.prune_candidates(ckg, policies=policies)
    suspect_map = {s.route.id: s for s in suspects}

    assert "r_admin" in suspect_map
    assert "BFLA" in suspect_map["r_admin"].candidate_flaws

    assert "r_ship" in suspect_map
    assert "WORKFLOW" in suspect_map["r_ship"].candidate_flaws


def test_openapi_distillation():
    """Verify OpenAPI distillation strips redundant UI metadata and retains essential endpoints, auth, and schemas."""
    raw_openapi = {
        "openapi": "3.0.0",
        "info": {
            "title": "Sample Store API",
            "version": "1.0.0",
            "description": "Long redundant description with markdown and UI formatting details.\n\nMore verbose text.",
            "termsOfService": "http://example.com/terms/",
            "contact": {"email": "support@example.com"},
        },
        "paths": {
            "/api/v1/invoices/{id}": {
                "description": "Super long path description",
                "get": {
                    "summary": "Fetch invoice by ID",
                    "description": "Returns full details of an invoice for the current user.",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "description": "Unique identifier of the invoice",
                            "schema": {"type": "string", "example": "inv_123"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful retrieval",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string", "description": "ID field"},
                                            "amount": {"type": "number", "description": "Total amount"},
                                        },
                                    }
                                }
                            },
                        },
                        "403": {"description": "Forbidden error"},
                        "404": {"description": "Not found"},
                    },
                }
            },
            "/api/v1/health": {
                "get": {
                    "summary": "Health check",
                    "description": "Returns system health",
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "description": "JWT token"}
            }
        },
    }

    extractor = IntentExtractor()
    distilled = extractor.distill_openapi(raw_openapi)

    # UI descriptions and redundant text must be stripped
    assert "info" not in distilled or "description" not in distilled.get("info", {})
    assert "/api/v1/invoices/{id}" in distilled["paths"]
    endpoint = distilled["paths"]["/api/v1/invoices/{id}"]["get"]

    # Essential endpoint structure preserved
    assert "security" in endpoint
    assert endpoint["security"] == [{"bearerAuth": []}]
    assert "200" in endpoint["responses"]
    assert "403" in endpoint["responses"]

    # Parameters simplified without verbose description/example
    param = endpoint["parameters"][0]
    assert param["name"] == "id"
    assert param["in"] == "path"
    assert "description" not in param
    assert "example" not in param.get("schema", {})


def test_intent_extractor_with_mock_llm(tmp_path: Path):
    """Verify IntentExtractor synthesizes BusinessPolicyMatrix using LLM."""
    readme = tmp_path / "README.md"
    readme.write_text("# Store API\nRoles: admin > merchant > customer.\nInvoices belong to the creating tenant.")

    openapi_file = tmp_path / "openapi.json"
    openapi_file.write_text(json.dumps({
        "openapi": "3.0.0",
        "paths": {
            "/orders/{id}/ship": {
                "post": {
                    "responses": {"200": {}}
                }
            }
        }
    }))

    mock_response = json.dumps({
        "ownership_rules": ["Invoices belong to the creating tenant; cross-tenant viewing is prohibited"],
        "role_hierarchy": ["admin", "merchant", "customer"],
        "state_invariants": ["Order must be PAID before SHIP can be invoked"],
    })

    mock_llm = MockLLMProvider(default_response=mock_response)
    extractor = IntentExtractor(llm_provider=mock_llm)

    policies = extractor.extract_policies(str(tmp_path))
    assert isinstance(policies, BusinessPolicyMatrix)
    assert len(policies.ownership_rules) == 1
    assert "Invoices belong to the creating tenant" in policies.ownership_rules[0]
    assert policies.role_hierarchy == ["admin", "merchant", "customer"]
    assert len(policies.state_invariants) == 1
    assert "PAID before SHIP" in policies.state_invariants[0]
    assert mock_llm.call_count == 1


def test_intent_extractor_deterministic_fallback_when_offline(tmp_path: Path):
    """Verify IntentExtractor falls back to deterministic rule-based heuristics when offline or LLM fails."""
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Enterprise Billing System\n\n"
        "Roles available: superadmin > admin > staff > customer.\n"
        "All invoices belong to the creator tenant. Cross-tenant access is strictly forbidden.\n"
        "Orders must transition to PAID before SHIP status is permitted.\n"
    )

    openapi_file = tmp_path / "openapi.json"
    openapi_file.write_text(json.dumps({
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/admin/users": {"get": {"responses": {"200": {}}}},
            "/api/v1/invoices/{id}": {"get": {"responses": {"200": {}}}},
            "/api/v1/orders/{id}/ship": {"post": {"responses": {"200": {}}}},
        }
    }))

    extractor = IntentExtractor(llm_provider=None)
    policies = extractor.extract_policies(str(tmp_path))

    assert isinstance(policies, BusinessPolicyMatrix)
    # Role hierarchy should be inferred deterministically
    assert "admin" in policies.role_hierarchy
    assert "customer" in policies.role_hierarchy

    # Ownership rules should identify tenant/creator ownership
    assert any("tenant" in r.lower() or "creator" in r.lower() or "invoice" in r.lower() for r in policies.ownership_rules)

    # State invariants should identify transition requirements
    assert any("ship" in inv.lower() or "paid" in inv.lower() or "order" in inv.lower() for inv in policies.state_invariants)


def test_suspect_candidate_model_defaults():
    """Verify SuspectCandidate default fields and initialization."""
    route = RouteNode(id="r_test", method="GET", path="/test", file_path="t.py")
    candidate = SuspectCandidate(route=route)
    assert candidate.route.id == "r_test"
    assert candidate.sink is None
    assert candidate.candidate_flaws == []
    assert candidate.reasoning == ""
