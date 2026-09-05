"""Unit tests for WireOracle and SemanticDifferOracle verification oracles."""

from __future__ import annotations

from halo.dast.oracles.semantic import SemanticDifferOracle, SemanticDifferResult
from halo.dast.oracles.wire import StateMutationResult, WireOracle
from halo.llm.provider import MockLLMProvider


def test_wire_oracle_sensitive_token_leakage():
    """Verify Layer 1 WireOracle detects private token leaks while excluding public fields."""
    oracle = WireOracle()
    victim_private = {
        "email": "victim@halo.test",
        "ssn": "123-45-6789",
        "api_key": "sec_live_999",
        "username": "victim_user",
    }
    attacker_response = {
        "id": "123",
        "username": "victim_user",  # Public - excluded
        "api_key": "sec_live_999",  # Private - leaked!
    }
    leaked, tokens = oracle.check_token_leakage(victim_private, attacker_response)
    assert leaked is True
    assert "api_key" in tokens
    assert "username" not in tokens  # public field excluded


def test_wire_oracle_clean_response_no_leak():
    """Verify WireOracle returns false when no private victim tokens leak."""
    oracle = WireOracle()
    victim_private = {
        "password_hash": "argon2$secret$hash123",
        "billing_address": "456 Private Way",
        "phone_number": "+1-555-0199",
        "username": "alice",
    }
    attacker_response = {
        "id": "789",
        "username": "alice",
        "status": "active",
        "created_at": "2026-01-01T00:00:00Z",
    }
    leaked, tokens = oracle.check_token_leakage(victim_private, attacker_response)
    assert leaked is False
    assert tokens == []


def test_wire_oracle_raw_string_response_leakage():
    """Verify WireOracle detects token leakage when attacker response is raw text/HTML."""
    oracle = WireOracle()
    victim_private = {
        "api_key": "sec_live_secret_key_888",
        "email": "owner@corp.internal",
        "display_name": "Corp Admin",
    }
    raw_body = "<html><body>Debug Dump: session token sec_live_secret_key_888 for user Corp Admin</body></html>"
    leaked, tokens = oracle.check_token_leakage(victim_private, raw_body)
    assert leaked is True
    assert "api_key" in tokens
    assert "display_name" not in tokens


def test_wire_oracle_nested_data_leakage():
    """Verify WireOracle traverses nested dictionaries and lists."""
    oracle = WireOracle()
    victim_private = {
        "account": {
            "billing": {
                "ssn": "987-65-4321",
                "card_number": "4111222233334444",
            },
            "profile": {
                "avatar": "https://avatar.test/1.png",
            },
        }
    }
    attacker_response = {
        "data": {"results": [{"avatar": "https://avatar.test/1.png", "ssn": "987-65-4321"}]}
    }
    leaked, tokens = oracle.check_token_leakage(victim_private, attacker_response)
    assert leaked is True
    assert any("ssn" in t for t in tokens)
    assert not any("avatar" in t for t in tokens)


def test_wire_oracle_state_mutation_detected():
    """Verify WireOracle confirms unauthorized state mutation verified on victim read."""
    oracle = WireOracle()
    baseline = {
        "id": "item_123",
        "title": "Original Title",
        "amount": 100,
        "status": "pending",
    }
    attacker_mutation_res = {
        "id": "item_123",
        "title": "Hacked Title by User A",
        "amount": 9999,
    }
    victim_verify = {
        "id": "item_123",
        "title": "Hacked Title by User A",
        "amount": 9999,
        "status": "pending",
    }
    res = oracle.check_state_mutation(baseline, attacker_mutation_res, victim_verify)
    assert isinstance(res, StateMutationResult)
    mutated, fields = res
    assert mutated is True
    assert "title" in fields
    assert "amount" in fields
    assert "status" not in fields
    assert bool(res) is True
    assert res == True


def test_wire_oracle_state_mutation_no_change():
    """Verify WireOracle returns false when victim verify read matches baseline."""
    oracle = WireOracle()
    baseline = {
        "id": "item_123",
        "title": "Original Title",
        "amount": 100,
    }
    attacker_mutation_res = {
        "error": "Forbidden",
        "status": 403,
    }
    victim_verify = {
        "id": "item_123",
        "title": "Original Title",
        "amount": 100,
    }
    res = oracle.check_state_mutation(baseline, attacker_mutation_res, victim_verify)
    mutated, fields = res
    assert mutated is False
    assert fields == []
    assert bool(res) is False
    assert res == False


def test_wire_oracle_state_mutation_resource_deleted():
    """Verify WireOracle detects deletion of resource as state mutation."""
    oracle = WireOracle()
    baseline = {
        "id": "doc_456",
        "title": "Secret Strategy",
        "body": "Confidential content",
    }
    attacker_mutation_res = {"deleted": True}
    victim_verify = {}  # Resource deleted / 404 empty body
    res = oracle.check_state_mutation(baseline, attacker_mutation_res, victim_verify)
    mutated, fields = res
    assert mutated is True
    assert len(fields) > 0


def test_semantic_differ_graphql_embedded_error_is_benign():
    """Verify SemanticDifferOracle mediator rules GraphQL 200 with error envelope benign."""
    oracle = SemanticDifferOracle()
    llm = MockLLMProvider()

    victim_view = {
        "data": {
            "invoice": {
                "id": "inv_100",
                "amount": 5000,
                "private_memo": "Tax shelter payout",
            }
        }
    }
    attacker_view = {
        "errors": [
            {
                "message": "Access denied: insufficient permissions to view invoice inv_100",
                "extensions": {"code": "FORBIDDEN"},
            }
        ],
        "data": None,
    }

    res = oracle.evaluate_ambiguous_response(victim_view, attacker_view, llm)
    assert isinstance(res, SemanticDifferResult)
    is_vuln, reasoning, confidence = res
    assert is_vuln is False
    assert confidence >= 0.85
    assert any(term in reasoning.lower() for term in ["error", "denied", "forbidden", "graphql"])

    # Verify 2-tuple unpacking compatibility
    unpacked_vuln, unpacked_reason = res
    assert unpacked_vuln is False
    assert unpacked_reason == reasoning


def test_semantic_differ_masked_json_is_benign():
    """Verify SemanticDifferOracle mediator recognizes masked/null fields as benign."""
    oracle = SemanticDifferOracle()
    llm = MockLLMProvider()

    victim_view = {
        "id": 123,
        "amount": 7500,
        "ssn": "123-45-6789",
        "billing_address": "777 Vault Road",
    }
    attacker_view = {
        "id": 123,
        "amount": None,
        "ssn": None,
        "billing_address": None,
    }

    is_vuln, reasoning, confidence = oracle.evaluate_ambiguous_response(
        victim_view, attacker_view, llm
    )
    assert is_vuln is False
    assert confidence >= 0.85
    assert any(term in reasoning.lower() for term in ["mask", "null", "redact", "benign"])


def test_semantic_differ_empty_collection_is_benign():
    """Verify SemanticDifferOracle mediator rules empty array/collection responses benign."""
    oracle = SemanticDifferOracle()
    llm = MockLLMProvider()

    victim_view = {"orders": [{"id": "ord_1", "total": 1200, "secret_notes": "VIP Client"}]}
    attacker_view = {"orders": []}

    is_vuln, reasoning, confidence = oracle.evaluate_ambiguous_response(
        victim_view, attacker_view, llm
    )
    assert is_vuln is False
    assert confidence >= 0.90
    assert any(term in reasoning.lower() for term in ["empty", "tenant", "filter", "isolate"])


def test_semantic_differ_confirmed_vulnerability():
    """Verify SemanticDifferOracle mediator confirms vulnerability when substantive victim fields leak."""
    oracle = SemanticDifferOracle()
    llm = MockLLMProvider()

    victim_view = {
        "id": "doc_999",
        "title": "Secret Financials",
        "net_revenue": 10000000,
        "auditor_notes": "Offshore subsidiary accounting",
    }
    attacker_view = {
        "id": "doc_999",
        "title": "Secret Financials",
        "net_revenue": 10000000,
        "auditor_notes": "Offshore subsidiary accounting",
    }

    res = oracle.evaluate_ambiguous_response(victim_view, attacker_view, llm)
    assert res.is_vulnerable is True
    assert res.confidence >= 0.90
    assert any(
        term in res.reasoning.lower()
        for term in ["unauthorized", "substantive", "leak", "compromised"]
    )


def test_semantic_differ_duel_prompts_executed():
    """Verify SemanticDifferOracle runs both prosecutor and defender prompts through LLMProvider."""
    oracle = SemanticDifferOracle()
    llm = MockLLMProvider()

    victim_view = {"id": 1, "salary": 200000}
    attacker_view = {"id": 1, "salary": 200000}

    oracle.evaluate_ambiguous_response(victim_view, attacker_view, llm)
    assert llm.call_count >= 2
    system_prompts = [call["system_prompt"] for call in llm.history]
    assert any("prosecutor" in sp.lower() for sp in system_prompts)
    assert any(
        "defender" in sp.lower() or "devil's advocate" in sp.lower() for sp in system_prompts
    )
