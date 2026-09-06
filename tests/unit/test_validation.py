"""Unit tests for Stage 4: PoC Builder, PoC Self-Repair Loop, and Remediation Patcher."""

from __future__ import annotations

import ast

from halo.llm.provider import MockLLMProvider
from halo.static.graph import HandlerNode
from halo.validation.models import FindingData, FindingRecord
from halo.validation.patcher import RemediationPatcher
from halo.validation.poc_builder import PoCBuilder
from halo.validation.repair import PoCRepairLoop, verify_and_repair

# ---------------------------------------------------------------------------
# 1. FindingData & FindingRecord Model Tests
# ---------------------------------------------------------------------------


def test_finding_data_model_defaults_and_aliases():
    """Verify FindingData and FindingRecord instantiate properly with standard and alias fields."""
    finding = FindingData(
        id="HALO-BOLA-01",
        flaw_type="BOLA_IDOR",
        endpoint="/api/v1/invoices/{id}",
        target_url="http://localhost:3000",
        method="GET",
        severity="HIGH",
        confidence=0.95,
        reproduction_steps=[
            {
                "action": "create",
                "as": "USER_B",
                "path": "/api/v1/invoices",
                "body": {"amount": 100},
            },
            {
                "action": "read",
                "as": "USER_A",
                "path": "/api/v1/invoices/{victim_id}",
                "assert_status": 200,
            },
        ],
        file_path="src/controllers/invoice.py",
        line_start=24,
        line_end=28,
        details="Unauthorized access across tenant boundaries.",
    )
    assert finding.id == "HALO-BOLA-01"
    assert finding.flaw_type == "BOLA_IDOR"
    assert finding.rule_id == "BOLA_IDOR"
    assert finding.details == "Unauthorized access across tenant boundaries."
    assert finding.description == "Unauthorized access across tenant boundaries."
    assert finding.line_start == 24
    assert finding.line_number == 24
    assert len(finding.reproduction_steps) == 2

    # Verify FindingRecord alias instantiation with legacy/alternative field names
    record = FindingRecord(
        id="HALO-002",
        rule_id="BFLA",
        description="Missing administrative function level authorization",
        severity="CRITICAL",
        file_path="src/routes/admin.ts",
        line_number=45,
    )
    assert record.id == "HALO-002"
    assert record.flaw_type == "BFLA"
    assert record.rule_id == "BFLA"
    assert record.details == "Missing administrative function level authorization"
    assert record.line_start == 45
    assert record.line_end == 45


# ---------------------------------------------------------------------------
# 2. PoC Builder Tests
# ---------------------------------------------------------------------------


def test_poc_builder_generates_pep723():
    """Verify PoCBuilder generates PEP 723 compliant standalone Python reproduction script."""
    builder = PoCBuilder()
    script = builder.build_script(
        finding_id="BOLA_01",
        flaw_type="BOLA_IDOR",
        endpoint="/api/v1/invoices/{id}",
        target_url="http://localhost:3000",
        steps=[
            {
                "action": "create",
                "as": "USER_B",
                "path": "/api/v1/invoices",
                "body": {"amount": 100},
            },
            {
                "action": "read",
                "as": "USER_A",
                "path": "/api/v1/invoices/{victim_id}",
                "assert_status": 200,
            },
        ],
    )
    assert "# /// script" in script
    assert 'dependencies = ["httpx"]' in script
    assert "# ///" in script
    assert "def test_reproduction():" in script
    assert 'BASE_URL = os.environ.get("HALO_TARGET_URL", "http://localhost:3000")' in script
    assert 'client.post("/api/v1/invoices"' in script
    assert "assert " in script
    assert 'if __name__ == "__main__":' in script

    # Verify generated script is syntactically valid Python code
    parsed_ast = ast.parse(script)
    assert parsed_ast is not None


def test_poc_builder_from_finding_data():
    """Verify PoCBuilder generates PEP 723 script directly from FindingData instance."""
    finding = FindingData(
        id="BOLA_02",
        flaw_type="BOLA_IDOR",
        endpoint="/api/documents/{doc_id}",
        target_url="https://staging.target.test",
        reproduction_steps=[
            {
                "action": "create",
                "as": "USER_B",
                "path": "/api/documents",
                "body": {"title": "Secret"},
            },
            {
                "action": "read",
                "as": "USER_A",
                "path": "/api/documents/{victim_id}",
                "assert_status": 200,
            },
        ],
        details="Document IDOR vulnerability",
    )
    builder = PoCBuilder()
    script = builder.generate_pep723_script(finding)

    assert "# /// script" in script
    assert 'dependencies = ["httpx"]' in script
    assert "https://staging.target.test" in script
    assert "Document IDOR vulnerability" in script
    assert "def test_reproduction():" in script

    parsed_ast = ast.parse(script)
    assert parsed_ast is not None


def test_poc_builder_probe_result_steps_format():
    """Verify PoCBuilder correctly handles DAST ProbeResult step format (actor, action string, status)."""
    builder = PoCBuilder()
    script = builder.build_script(
        finding_id="BOLA_03",
        flaw_type="BOLA_IDOR",
        endpoint="/api/orders/order_456",
        target_url="http://127.0.0.1:8000",
        steps=[
            {
                "step": 1,
                "actor": "user_b",
                "action": "POST /api/orders",
                "status": 201,
                "captured_id": "order_456",
                "description": "Victim creates private order",
            },
            {
                "step": 2,
                "actor": "user_a",
                "action": "GET /api/orders/order_456",
                "status": 200,
                "description": "Attacker accesses victim order",
            },
        ],
    )
    assert "def test_reproduction():" in script
    assert "/api/orders" in script
    assert "order_456" in script
    assert "assert " in script

    parsed = ast.parse(script)
    assert parsed is not None


def test_poc_builder_bfla_and_race_flaws():
    """Verify script generation for BFLA and RACE_CONDITION flaw types."""
    builder = PoCBuilder()

    # BFLA
    bfla_script = builder.build_script(
        finding_id="BFLA_01",
        flaw_type="BFLA",
        endpoint="/api/admin/users",
        target_url="http://localhost:5000",
        method="DELETE",
        steps=[
            {
                "action": "delete",
                "as": "USER_A",
                "path": "/api/admin/users/42",
                "assert_status": 200,
            },
        ],
    )
    assert "BFLA" in bfla_script
    assert "def test_reproduction():" in bfla_script
    ast.parse(bfla_script)

    # Concurrency Race
    race_script = builder.build_script(
        finding_id="RACE_01",
        flaw_type="RACE_CONDITION",
        endpoint="/api/coupons/redeem",
        target_url="http://localhost:5000",
        method="POST",
        steps=[
            {"action": "burst", "as": "USER_A", "path": "/api/coupons/redeem", "count": 10},
        ],
    )
    assert "RACE_CONDITION" in race_script
    assert "def test_reproduction():" in race_script
    assert "assert sum(1 for s in statuses if 200 <= s < 300) > 1" in race_script
    ast.parse(race_script)


def test_poc_builder_explicit_actor_header_mapping():
    """Verify actor headers map explicitly to predefined variables without undefined references."""
    builder = PoCBuilder()
    script = builder.build_script(
        finding_id="ACTOR_01",
        flaw_type="BOLA_IDOR",
        endpoint="/api/v1/items",
        target_url="http://localhost:3000",
        steps=[
            {
                "action": "create",
                "as": "USER_B",
                "path": "/api/v1/items",
                "body": {"name": "Test"},
            },
            {
                "action": "create",
                "as": "bob",
                "path": "/api/v1/items",
                "body": {"name": "BobItem"},
            },
            {"action": "read", "as": "ADMIN", "path": "/api/v1/items/1"},
            {"action": "read", "as": "USER_A", "path": "/api/v1/items/1"},
        ],
    )
    assert "headers_user_b" in script
    assert "headers_admin" in script
    assert "headers_user_a" in script
    assert "headers_bob" not in script
    ast.parse(script)


def test_poc_builder_patch_http_verb():
    """Verify HTTP PATCH verb is preserved rather than coerced to PUT."""
    builder = PoCBuilder()
    script = builder.build_script(
        finding_id="PATCH_01",
        flaw_type="BOLA_IDOR",
        endpoint="/api/v1/users/1",
        target_url="http://localhost:3000",
        steps=[
            {
                "action": "patch",
                "as": "USER_A",
                "path": "/api/v1/users/1",
                "body": {"role": "admin"},
            },
        ],
    )
    assert "client.patch(" in script
    assert "client.put(" not in script
    ast.parse(script)


def test_poc_builder_env_target_url_override():
    """Verify generated script allows overriding target URL via HALO_TARGET_URL environment variable."""
    builder = PoCBuilder()
    script = builder.build_script(
        finding_id="ENV_01",
        flaw_type="BOLA_IDOR",
        endpoint="/api/v1/test",
        target_url="http://original.target",
        steps=[],
    )
    assert 'BASE_URL = os.environ.get("HALO_TARGET_URL", "http://original.target")' in script
    ast.parse(script)


# ---------------------------------------------------------------------------
# 3. Remediation Patcher Tests
# ---------------------------------------------------------------------------


def test_remediation_patcher_block_structure():
    """Verify RemediationPatcher formats AST-anchored role-aware replacement block as specified."""
    patcher = RemediationPatcher()
    patch = patcher.format_patch_block(
        file_path="controllers/invoice.js",
        start_line=24,
        end_line=28,
        original_code="const invoice = await prisma.invoice.findUnique({ where: { id } });",
        replacement_code="const invoice = await prisma.invoice.findFirst({ where: { id, ownerId: req.user.id } });",
    )
    assert "### Remediation for `controllers/invoice.js`" in patch
    assert "(Lines 24–28)" in patch or "(Lines 24-28)" in patch
    assert "**Original Code:**" in patch
    assert "```javascript" in patch
    assert "const invoice = await prisma.invoice.findUnique({ where: { id } });" in patch
    assert "**Replacement Code:**" in patch
    assert (
        "const invoice = await prisma.invoice.findFirst({ where: { id, ownerId: req.user.id } });"
        in patch
    )


def test_remediation_patcher_languages():
    """Verify correct markdown language fences are selected according to file extension."""
    patcher = RemediationPatcher()

    patch_py = patcher.format_patch_block(
        file_path="routes/invoice.py",
        start_line=10,
        end_line=15,
        original_code="item = db.query(Item).get(id)",
        replacement_code="item = db.query(Item).filter_by(id=id, user_id=current_user.id).first()",
    )
    assert "```python" in patch_py

    patch_ts = patcher.format_patch_block(
        file_path="src/invoice.ts",
        start_line=5,
        end_line=8,
        original_code="return this.repo.findOne(id);",
        replacement_code="return this.repo.findOne({ id, tenantId: user.tenantId });",
    )
    assert "```typescript" in patch_ts

    patch_php = patcher.format_patch_block(
        file_path="app/Http/Controllers/InvoiceController.php",
        start_line=30,
        end_line=32,
        original_code="$invoice = Invoice::findOrFail($id);",
        replacement_code="$invoice = Auth::user()->invoices()->findOrFail($id);",
    )
    assert "```php" in patch_php


def test_remediation_patcher_llm_role_aware_generation():
    """Verify generate_role_aware_patch uses LLMProvider to generate role-aware patch."""
    mock_llm = MockLLMProvider(
        default_response="""const invoice = await prisma.invoice.findFirst({
  where: {
    id: req.params.id,
    ...(req.user.role !== 'admin' && { ownerId: req.user.id })
  }
});"""
    )
    patcher = RemediationPatcher()
    finding = FindingData(
        id="BOLA_01",
        flaw_type="BOLA_IDOR",
        endpoint="/api/v1/invoices/:id",
        file_path="controllers/invoice.js",
        line_start=24,
        line_end=28,
        details="Tenant boundary violation in invoice controller",
    )
    handler = HandlerNode(
        id="handler_1",
        name="getInvoice",
        file_path="controllers/invoice.js",
        line_span=(24, 28),
    )

    patch = patcher.generate_role_aware_patch(
        finding=finding,
        handler_node=handler,
        original_code="const invoice = await prisma.invoice.findUnique({ where: { id: req.params.id } });",
        llm_provider=mock_llm,
    )
    assert "### Remediation for `controllers/invoice.js`" in patch
    assert "**Original Code:**" in patch
    assert "**Replacement Code:**" in patch
    assert "req.user.role !== 'admin'" in patch
    assert mock_llm.call_count >= 1


def test_remediation_patcher_deterministic_fallback():
    """Verify generate_role_aware_patch falls back to deterministic rule template when llm_provider is None."""
    patcher = RemediationPatcher()
    finding = FindingData(
        id="BOLA_01",
        flaw_type="BOLA_IDOR",
        endpoint="/api/v1/invoices/:id",
        file_path="controllers/invoice.js",
        line_start=24,
        line_end=28,
        details="BOLA IDOR flaw",
    )

    patch = patcher.generate_role_aware_patch(
        finding=finding,
        handler_node=None,
        original_code="const invoice = await prisma.invoice.findUnique({ where: { id } });",
        llm_provider=None,
    )
    assert "### Remediation for `controllers/invoice.js`" in patch
    assert "**Original Code:**" in patch
    assert "**Replacement Code:**" in patch
    assert "ownerId" in patch or "user" in patch or "tenant" in patch


# ---------------------------------------------------------------------------
# 4. PoC Self-Repair Loop Tests
# ---------------------------------------------------------------------------


def test_poc_repair_loop_success_without_repair():
    """Verify repair loop returns immediately with success when initial execution passes."""
    loop = PoCRepairLoop(
        runner=lambda script: (0, "CONFIRMED: BOLA_IDOR verified successfully.", "")
    )
    mock_llm = MockLLMProvider()

    success, final_script = loop.verify_and_repair(
        script_content="assert True",
        target_url="http://localhost:3000",
        llm_provider=mock_llm,
        max_retries=2,
    )
    assert success is True
    assert final_script == "assert True"
    assert mock_llm.call_count == 0  # No LLM calls needed


def test_poc_repair_loop_self_repairs_via_llm():
    """Verify repair loop invokes LLM on execution failure and retries until passing."""
    # Runner fails on original script (missing CSRF token), passes on repaired script
    original_script = "client.post('/transfer', json={'amount': 100})"
    repaired_script = "token = client.get('/csrf').json()['token']\nclient.post('/transfer', headers={'X-CSRF': token}, json={'amount': 100})"

    def mock_runner(script: str) -> tuple[int, str, str]:
        if "X-CSRF" in script:
            return 0, "CONFIRMED: Exploit verified.", ""
        return 1, "", "HTTP 403 Forbidden: Missing CSRF Token"

    mock_llm = MockLLMProvider(default_response=f"```python\n{repaired_script}\n```")
    loop = PoCRepairLoop(runner=mock_runner)

    success, final_script = loop.verify_and_repair(
        script_content=original_script,
        target_url="http://localhost:3000",
        llm_provider=mock_llm,
        max_retries=2,
    )
    assert success is True
    assert "X-CSRF" in final_script
    assert mock_llm.call_count == 1
    # Verify the LLM was given failure context in prompt
    last_call = mock_llm.last_call
    assert last_call is not None
    assert "HTTP 403 Forbidden" in last_call["prompt"]


def test_poc_repair_loop_exhausts_retries_on_persistent_failure():
    """Verify repair loop respects max_retries and returns False if script cannot be repaired."""
    always_failing_runner = lambda script: (1, "", "AssertionError: Expected 200 got 500")

    mock_llm = MockLLMProvider(default_response="assert 1 == 2")
    loop = PoCRepairLoop(runner=always_failing_runner)

    success, _final_script = loop.verify_and_repair(
        script_content="assert False",
        target_url="http://localhost:3000",
        llm_provider=mock_llm,
        max_retries=2,
    )
    assert success is False
    assert mock_llm.call_count == 2  # Exactly 2 retries attempted


def test_poc_repair_loop_subprocess_execution():
    """Verify real subprocess execution of syntactically valid Python reproduction script."""
    loop = PoCRepairLoop()

    valid_script = """
import sys

def test_reproduction():
    x = 10 + 20
    assert x == 30

if __name__ == "__main__":
    test_reproduction()
    sys.exit(0)
"""
    success, script = loop.verify_and_repair(
        script_content=valid_script,
        target_url="http://localhost:3000",
        llm_provider=None,
        max_retries=0,
    )
    assert success is True
    assert script == valid_script


def test_module_level_verify_and_repair():
    """Verify module-level verify_and_repair helper function works identically."""
    mock_llm = MockLLMProvider()
    valid_script = "import sys; sys.exit(0)"
    success, script = verify_and_repair(
        script_content=valid_script,
        target_url="http://localhost:3000",
        llm_provider=mock_llm,
        max_retries=1,
    )
    assert success is True
    assert script == valid_script
