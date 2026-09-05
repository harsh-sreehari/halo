from __future__ import annotations

import json
from pathlib import Path

from halo.intent.hypothesis import (
    HypothesisGenerator,
    HypothesisResult,
    ProbingRecipe,
)
from halo.intent.pruner import SuspectCandidate
from halo.llm.provider import MockLLMProvider
from halo.static.graph import (
    CodeKnowledgeGraph,
    EdgeType,
    HandlerNode,
    RouteNode,
    SinkNode,
    ValidationSchemaNode,
)


def test_hypothesis_generation_from_recipe():
    """Verify basic hypothesis generation using MockLLMProvider with structured JSON."""
    mock_recipe = {
        "flaw_class": "BOLA_IDOR",
        "confidence": 0.95,
        "hypothesis": "User A can access User B invoices because tenant filter is missing",
        "probing_recipe": {
            "strategy": "multi_actor_handshake",
            "primary_param": "id",
            "expected_safe_status": 403,
            "expected_vuln_status": 200,
        },
    }
    mock_llm = MockLLMProvider(default_response=json.dumps(mock_recipe))
    gen = HypothesisGenerator(mock_llm)

    cand = SuspectCandidate(
        route=RouteNode(
            id="r1",
            method="GET",
            path="/invoices/{id}",
            file_path="routes.py",
            line_number=5,
        ),
        sink=SinkNode(
            id="s1",
            operation="READ",
            entity="Invoice",
            query_params=["id"],
            file_path="db.py",
            line_number=12,
        ),
    )
    results = gen.generate_hypotheses([cand])
    assert len(results) == 1
    assert results[0].flaw_class == "BOLA_IDOR"
    assert results[0].probing_recipe.strategy == "multi_actor_handshake"
    assert results[0].route_id == "r1"
    assert results[0].confidence == 0.95
    assert results[0].probing_recipe.expected_safe_status == 403
    assert results[0].probing_recipe.expected_vuln_status == 200


def test_hypothesis_generation_with_markdown_fences():
    """Verify handling of markdown code blocks ```json ... ``` in LLM responses."""
    mock_payload = """
    Here is your security analysis:
    ```json
    {
      "flaw_class": "BFLA",
      "confidence": 0.9,
      "hypothesis": "Unprivileged user can call admin endpoint directly",
      "probing_recipe": {
        "strategy": "role_escalation",
        "primary_param": "",
        "expected_safe_status": 403,
        "expected_vuln_status": 200
      }
    }
    ```
    Good luck!
    """
    mock_llm = MockLLMProvider(default_response=mock_payload)
    gen = HypothesisGenerator(mock_llm)

    cand = SuspectCandidate(
        route=RouteNode(
            id="r_admin",
            method="DELETE",
            path="/api/admin/users/{id}",
            file_path="admin.py",
            line_number=20,
        ),
        candidate_flaws=["BFLA"],
    )
    results = gen.generate_hypotheses([cand])
    assert len(results) == 1
    assert results[0].flaw_class == "BFLA"
    assert results[0].probing_recipe.strategy == "role_escalation"
    assert results[0].confidence == 0.9


def test_hypothesis_generator_deterministic_fallback_when_offline():
    """Verify deterministic fallback heuristics when LLM is offline or provider is None."""
    gen = HypothesisGenerator(llm_provider=None)

    cand_bola = SuspectCandidate(
        route=RouteNode(
            id="r_bola",
            method="GET",
            path="/documents/{doc_id}",
            file_path="docs.py",
            line_number=10,
        ),
        sink=SinkNode(
            id="s_doc",
            operation="READ",
            entity="Document",
            query_params=["doc_id"],
        ),
        candidate_flaws=["BOLA"],
        reasoning="Parameterized GET route accesses Document without verified ownership guard",
    )
    results = gen.generate_hypotheses([cand_bola])
    assert len(results) == 1
    res = results[0]
    assert res.flaw_class == "BOLA_IDOR"
    assert res.probing_recipe.strategy == "multi_actor_handshake"
    assert res.probing_recipe.primary_param == "doc_id"
    assert res.probing_recipe.expected_safe_status == 403
    assert res.probing_recipe.expected_vuln_status == 200
    assert "Document" in res.hypothesis


def test_deterministic_fallback_for_all_flaw_types():
    """Verify fallback recipes for BFLA, RACE, WORKFLOW, and MASS_ASSIGNMENT."""
    gen = HypothesisGenerator(llm_provider=None)

    # 1. BFLA
    c_bfla = SuspectCandidate(
        route=RouteNode(
            id="r_bfla",
            method="POST",
            path="/api/admin/settings",
            file_path="admin.py",
            line_number=1,
        ),
        candidate_flaws=["BFLA"],
    )
    res_bfla = gen.generate_hypotheses([c_bfla])[0]
    assert res_bfla.flaw_class == "BFLA"
    assert res_bfla.probing_recipe.strategy == "role_escalation"
    assert res_bfla.probing_recipe.expected_safe_status == 403

    # 2. RACE
    c_race = SuspectCandidate(
        route=RouteNode(
            id="r_race",
            method="POST",
            path="/api/v1/wallet/transfer",
            file_path="wallet.py",
            line_number=1,
        ),
        sink=SinkNode(
            id="s_race",
            operation="WRITE",
            entity="Wallet",
            query_params=["amount"],
        ),
        candidate_flaws=["RACE"],
    )
    res_race = gen.generate_hypotheses([c_race])[0]
    assert res_race.flaw_class == "RACE_CONDITION"
    assert res_race.probing_recipe.strategy == "race_condition"

    # 3. WORKFLOW
    c_wf = SuspectCandidate(
        route=RouteNode(
            id="r_wf",
            method="POST",
            path="/orders/{id}/fulfill",
            file_path="orders.py",
            line_number=1,
        ),
        candidate_flaws=["WORKFLOW"],
    )
    res_wf = gen.generate_hypotheses([c_wf])[0]
    assert res_wf.flaw_class == "WORKFLOW_BYPASS"
    assert res_wf.probing_recipe.strategy == "workflow_permutation"

    # 4. MASS_ASSIGNMENT
    c_ma = SuspectCandidate(
        route=RouteNode(
            id="r_ma",
            method="PUT",
            path="/api/users/profile",
            file_path="users.py",
            line_number=1,
        ),
        candidate_flaws=["MASS_ASSIGNMENT"],
    )
    res_ma = gen.generate_hypotheses([c_ma])[0]
    assert res_ma.flaw_class == "MASS_ASSIGNMENT"
    assert res_ma.probing_recipe.expected_safe_status == 400


def test_malformed_llm_response_triggers_graceful_fallback():
    """Verify that corrupt JSON or unparsable LLM response falls back cleanly."""
    mock_llm = MockLLMProvider(
        default_response="Not a JSON response! Internal Server Error occurred."
    )
    gen = HypothesisGenerator(mock_llm)

    cand = SuspectCandidate(
        route=RouteNode(
            id="r1",
            method="GET",
            path="/items/{item_id}",
            file_path="items.py",
            line_number=10,
        ),
        candidate_flaws=["BOLA"],
    )
    results = gen.generate_hypotheses([cand])
    assert len(results) == 1
    assert results[0].flaw_class == "BOLA_IDOR"
    assert results[0].probing_recipe.strategy == "multi_actor_handshake"
    assert results[0].probing_recipe.primary_param == "item_id"


def test_ast_context_slice_building_and_token_cap(tmp_path: Path):
    """Verify that AST context slice extracts handler, schema, and sink info under 2500 tokens."""
    ckg = CodeKnowledgeGraph()
    route = RouteNode(
        id="r_profile",
        method="POST",
        path="/api/v1/profile",
        file_path=str(tmp_path / "app.py"),
        line_number=1,
    )
    handler = HandlerNode(
        id="h_profile",
        name="update_profile",
        signature="async def update_profile(req: Request, dto: ProfileDTO) -> Response",
        arguments=["req", "dto"],
    )
    schema = ValidationSchemaNode(
        id="schema_profile",
        name="ProfileDTO",
        allowed_fields=["name", "bio", "role"],
        strict=False,
    )
    sink = SinkNode(
        id="s_profile",
        operation="WRITE",
        entity="UserProfile",
        query_params=["user_id"],
        filters=["user_id = :current_user"],
    )

    ckg.add_node(route)
    ckg.add_node(handler)
    ckg.add_node(schema)
    ckg.add_node(sink)
    ckg.add_edge(route.id, handler.id, EdgeType.ROUTES_TO)
    ckg.add_edge(handler.id, schema.id, EdgeType.FILTERED_BY)
    ckg.add_edge(handler.id, sink.id, EdgeType.WRITES_TO)

    cand = SuspectCandidate(
        route=route,
        sink=sink,
        candidate_flaws=["MASS_ASSIGNMENT"],
        reasoning="Non-strict DTO allows arbitrary field injection",
    )

    gen = HypothesisGenerator()
    ast_slice = gen.build_ast_context(cand, ckg=ckg)
    assert "update_profile" in ast_slice
    assert "ProfileDTO" in ast_slice
    assert "UserProfile" in ast_slice
    assert "MASS_ASSIGNMENT" in ast_slice

    # Token cap (< 2500 tokens)
    token_count = len(ast_slice) // 4
    assert token_count < 2500


def test_probing_recipe_and_hypothesis_models():
    """Verify validation and normalization of data models."""
    recipe = ProbingRecipe(
        strategy="multi_actor_handshake",
        primary_param="id",
        expected_safe_status=403,
        expected_vuln_status=200,
        extra_params={"extra": "val"},
    )
    assert recipe.strategy == "multi_actor_handshake"

    # Test confidence clamping and flaw normalization
    result = HypothesisResult(
        candidate_id="c1",
        route_id="r1",
        flaw_class="BOLA",  # Should normalize to BOLA_IDOR
        confidence=1.8,  # Should clamp to 1.0
        hypothesis="Potential IDOR flaw",
        probing_recipe=recipe,
    )
    assert result.flaw_class == "BOLA_IDOR"
    assert result.confidence == 1.0

    result2 = HypothesisResult(
        flaw_class="RACE",
        confidence=-0.5,  # Should clamp to 0.0
        hypothesis="Potential race flaw",
        probing_recipe=recipe,
    )
    assert result2.flaw_class == "RACE_CONDITION"
    assert result2.confidence == 0.0
