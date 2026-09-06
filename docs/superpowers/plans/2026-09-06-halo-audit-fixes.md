# HALO Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Patch all 20 testing inaccuracies and 20 codebase flaws in Project HALO discovered during the OWASP Juice Shop audit.

**Architecture:** Strengthen DAST mutation handling, deduplicate Express routes, recognize deny guards in CKG, enforce safe mode guardrails, validate multi-step workflows and mass assignment persistence, decouple vault credentials, wire dead oracles, calculate accurate CVSS, and generate valid PoCs and patches.

**Tech Stack:** Python 3.12, Tree-Sitter, FastAPI, Typer, HTTPX, Pytest, Rich, Pydantic v2.

**Spec:** implementation_plan.md

## Global Constraints
- Target Python 3.12 with strict type annotations and Pydantic v2.
- Preserve backward compatibility with existing CLI commands and flags.
- All existing 219 unit tests and integration tests must pass.
- Ruff line length 100, zero lint errors.

---

### Task 1: DAST Mutation Routing & Route Template Normalization (Flaws 1, 17)

**Files:**
- Modify: `src/halo/cli/main.py:270-290`
- Modify: `src/halo/dast/probes/bola.py:80-150`
- Test: `tests/unit/test_probes.py`

**Interfaces:**
- Consumes: `BOLAProbe.execute(client, target_url, vault, recipe, test_write, write_method, ...)`
- Produces: `ProbeResult(endpoint=template, reproduction_steps=steps, vulnerable=bool)`

- [ ] **Step 1: Write the failing test**

```python
# In tests/unit/test_probes.py
def test_bola_probe_handles_delete_method_and_preserves_template():
    """Verify BOLA probe handles DELETE mutation and retains canonical route template."""
    probe = BOLAProbe()
    client = MagicMock()
    client.request.return_value = MagicMock(status_code=403, json=lambda: {"error": "Denied"})
    vault = SessionVault()
    
    result = probe.execute(
        client=client,
        target_url="http://target",
        vault=vault,
        read_endpoint_template="/api/Users/:id",
        test_write=True,
        write_method="DELETE",
        write_endpoint_template="/api/Users/:id",
    )
    assert result.endpoint == "/api/Users/:id"
    assert not result.vulnerable
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/test_probes.py::test_bola_probe_handles_delete_method_and_preserves_template -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

In `src/halo/cli/main.py`:
```python
is_mutation = method_str.upper() in {"POST", "PUT", "PATCH", "DELETE"}
```
In `src/halo/dast/probes/bola.py`:
Handle `DELETE` method in `execute()`: when `write_method == "DELETE"`, send DELETE request; if response status is 401, 403, or 404, mark not vulnerable; ensure `endpoint=read_endpoint_template` is returned as canonical endpoint.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/test_probes.py::test_bola_probe_handles_delete_method_and_preserves_template -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/halo/cli/main.py src/halo/dast/probes/bola.py tests/unit/test_probes.py
git commit -m "fix(dast): handle DELETE mutations and preserve canonical route template in BOLA probe"
```

---

### Task 2: Express Route Deduplication & Static Deny Guard Detection (Flaws 2, 13)

**Files:**
- Modify: `src/halo/static/parser.py:180-240`
- Modify: `src/halo/static/graph.py:95-135`
- Modify: `src/halo/cli/main.py:195-212`
- Test: `tests/unit/test_parser.py`
- Test: `tests/unit/test_graph.py`

**Interfaces:**
- Consumes: AST route nodes from JavaScript/TypeScript/Python
- Produces: Deduplicated `list[RouteDefinition]` with merged middleware, `is_authorization_guard()` recognizing deny patterns.

- [ ] **Step 1: Write the failing tests**

```python
# In tests/unit/test_parser.py
def test_express_chained_middleware_deduplication():
    code = """
    app.post('/api/Users', security.denyAll(), handleCreateUser);
    """
    parser = CodeParser()
    routes = parser.extract_routes("server.ts", code=code)
    # Should yield exactly 1 route definition, not duplicates
    user_post_routes = [r for r in routes if r.path == "/api/Users" and r.method == "POST"]
    assert len(user_post_routes) == 1
    assert "security.denyAll" in user_post_routes[0].middleware or "denyAll" in str(user_post_routes[0].middleware)

# In tests/unit/test_graph.py
def test_deny_guard_recognition():
    ckg = CodeKnowledgeGraph()
    assert ckg.is_authorization_guard("security.denyAll()")
    assert ckg.is_authorization_guard("denyAll")
    assert ckg.is_authorization_guard("rejectAccess")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_parser.py::test_express_chained_middleware_deduplication tests/unit/test_graph.py::test_deny_guard_recognition -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

In `src/halo/static/parser.py`: Deduplicate routes by `(method, path)` and aggregate middleware chains into `RouteDefinition.middleware`.
In `src/halo/static/graph.py` and `main.py`: Add `deny`, `denyall`, `reject`, `forbidden`, `block` to auth guard tokens.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_parser.py tests/unit/test_graph.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/halo/static/parser.py src/halo/static/graph.py src/halo/cli/main.py tests/unit/test_parser.py tests/unit/test_graph.py
git commit -m "fix(sast): deduplicate Express routes and recognize denyAll authorization guards"
```

---

### Task 3: Multi-Step Workflow Bypass & Mass Assignment Verification (Flaws 3, 7, 8)

**Files:**
- Modify: `src/halo/dast/probes/workflow.py:60-140`
- Modify: `src/halo/dast/probes/mass_assignment.py:70-150`
- Modify: `src/halo/dast/probes/bfla.py:60-120`
- Test: `tests/unit/test_probes.py`

**Interfaces:**
- Consumes: `WorkflowProbe.execute()`, `MassAssignmentProbe.execute()`, `BFLAProbe.execute()`
- Produces: `ProbeResult` reflecting verified privilege escalation or multi-step bypass.

- [ ] **Step 1: Write the failing tests**

```python
# In tests/unit/test_probes.py
def test_workflow_probe_rejects_single_step_bypass():
    probe = WorkflowProbe()
    client = MagicMock()
    vault = SessionVault()
    # 1-step sequence
    steps = [WorkflowStep(name="action", endpoint="/rest/basket/1/checkout", method="POST")]
    res = probe.execute(client=client, target_url="http://target", vault=vault, workflow_steps=steps)
    assert not res.vulnerable, "Single-step workflow cannot be flagged as bypassed out-of-order"

def test_mass_assignment_verifies_field_mutation():
    probe = MassAssignmentProbe()
    client = MagicMock()
    # Server returns 201 Created but silently drops role: admin
    client.post.return_value = MagicMock(status_code=201, json=lambda: {"id": 1, "username": "alice", "role": "customer"})
    vault = SessionVault()
    res = probe.execute(client=client, target_url="http://target", vault=vault, endpoint="/api/Users", method="POST")
    assert not res.vulnerable, "Mass assignment must verify privilege field was accepted"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_probes.py::test_workflow_probe_rejects_single_step_bypass tests/unit/test_probes.py::test_mass_assignment_verifies_field_mutation -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

In `workflow.py`: Guard against `len(workflow_steps) < 2`. Only assert vulnerability when step $N$ succeeds without prerequisite step $N-1$ when prerequisite is required.
In `mass_assignment.py`: Inspect response payload or perform GET to confirm the injected field (`role`) was persisted with the attacker value.
In `bfla.py`: Probe anonymous access first; if accessible anonymously and non-administrative, do not flag as BFLA.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_probes.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/halo/dast/probes/workflow.py src/halo/dast/probes/mass_assignment.py src/halo/dast/probes/bfla.py tests/unit/test_probes.py
git commit -m "fix(dast): require multi-step workflow dependencies and verify mass assignment field mutation"
```

---

### Task 4: Session Vault Decoupling & Dead Subsystems Wiring (Flaws 4, 11, 12)

**Files:**
- Modify: `src/halo/dast/vault.py:250-290`
- Modify: `src/halo/cli/main.py:240-330`
- Modify: `src/halo/dast/oracles/semantic.py`
- Modify: `src/halo/dast/csrf.py`
- Test: `tests/unit/test_dast_core.py`
- Test: `tests/unit/test_oracles.py`

**Interfaces:**
- Consumes: `SessionVault.bootstrap_sessions()`, `check_safe_mode_guardrails()`, `SemanticDifferOracle`
- Produces: Decoupled auth sessions, safe mode guardrail enforcement, differential oracle checks.

- [ ] **Step 1: Write the failing tests**

```python
# In tests/unit/test_dast_core.py
def test_vault_has_no_target_specific_credentials():
    vault = SessionVault()
    # Ensure no hardcoded target credentials like juice-sh.op
    src = inspect.getsource(vault.bootstrap_sessions)
    assert "juice-sh.op" not in src
    assert "admin@juice-sh.op" not in src

def test_safe_mode_blocks_destructive_mutation_on_production():
    from halo.dast.sandbox import check_safe_mode_guardrails
    # Attempt DELETE on production target under safe mode
    allowed = check_safe_mode_guardrails(method="DELETE", path="/api/Users/1", safe_mode=True, is_synthetic=False)
    assert not allowed
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_dast_core.py -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

In `vault.py`: Remove `admin@juice-sh.op`. Read credentials from `HALO_AUTH_CREDS` or config, with generic fallbacks.
In `main.py`: Enforce `check_safe_mode_guardrails` before executing mutating requests. Wire `SemanticDifferOracle` to compare responses between personas. Wire `CSRFHarvester` in `SessionVault`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_dast_core.py tests/unit/test_oracles.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/halo/dast/vault.py src/halo/cli/main.py src/halo/dast/oracles/ tests/unit/test_dast_core.py
git commit -m "fix(dast): decouple vault credentials, enforce safe mode guardrails, and wire oracles"
```

---

### Task 5: LLM Hypotheses Integration & Candidate Merging (Flaw 10)

**Files:**
- Modify: `src/halo/cli/main.py:245-275`
- Test: `tests/unit/test_cli.py`

**Interfaces:**
- Consumes: `hypotheses: list[HypothesisResult]`, `suspects: list[SuspectCandidate]`
- Produces: Integrated flaws queue combining static candidate flaws with LLM hypothesis flaw classes.

- [ ] **Step 1: Write the failing test**

```python
# In tests/unit/test_cli.py
def test_dynamic_probes_incorporates_llm_hypothesis_flaws():
    route = RouteNode(id="r1", method="GET", path="/admin/data")
    cand = SuspectCandidate(candidate_id="c1", route=route, candidate_flaws=[])
    hypo = HypothesisResult(
        route_id="r1", candidate_id="c1", flaw_class="BFLA", confidence=0.9, reasoning="Admin path"
    )
    with patch("halo.cli.main.BFLAProbe.execute") as mock_bfla:
        mock_bfla.return_value = None
        _execute_dynamic_probes(
            suspects=[cand], target_url="http://target", vault=MagicMock(), client=MagicMock(), hypotheses=[hypo]
        )
        assert mock_bfla.called, "Probe must be invoked for LLM hypothesized flaw"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/test_cli.py::test_dynamic_probes_incorporates_llm_hypothesis_flaws -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

In `_execute_dynamic_probes`: Merge `cand.candidate_flaws` with any `h.flaw_class` from matching hypotheses for `cand_route_id`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/test_cli.py::test_dynamic_probes_incorporates_llm_hypothesis_flaws -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/halo/cli/main.py tests/unit/test_cli.py
git commit -m "fix(cli): merge LLM hypothesis flaws into dynamic probe execution loop"
```

---

### Task 6: CVSS Scoring Precision, PoC Realism & Remediation Wiring (Flaws 5, 6, 14, 15, 16, 18)

**Files:**
- Modify: `src/halo/reporting/cvss.py:210-225`
- Modify: `src/halo/validation/poc_builder.py:50-120`
- Modify: `src/halo/validation/repair.py:150-170`
- Modify: `src/halo/validation/patcher.py:80-140`
- Modify: `src/halo/cli/main.py:500-540`
- Test: `tests/unit/test_reporting.py`
- Test: `tests/unit/test_validation.py`

**Interfaces:**
- Consumes: `CVSSCalculator.calculate_for_finding()`, `PoCBuilder.build_script()`, `repair_and_verify(llm_provider)`
- Produces: Accurate CVSS scores, runnable standalone PoC scripts with real auth tokens, and robust patch generation.

- [ ] **Step 1: Write the failing tests**

```python
# In tests/unit/test_reporting.py
def test_cvss_readonly_bfla_integrity_is_none():
    calc = CVSSCalculator()
    score, sev, vec = calc.calculate_for_finding(flaw_type="BFLA", is_write=False)
    assert "I:N" in vec, f"Expected Integrity None for read-only BFLA, got {vec}"
    assert score < 7.0, f"Expected medium/low score for read-only BFLA, got {score}"

# In tests/unit/test_validation.py
def test_poc_builder_uses_real_tokens_and_resolved_ids():
    builder = PoCBuilder()
    finding = FindingRecord(
        id="HALO-BOLA-01", flaw_type="BOLA_IDOR", endpoint="/api/invoices/:id",
        method="GET", severity="HIGH", confidence=0.9, target_url="http://target",
        reproduction_steps=[{"token": "real_token_123", "resolved_id": "42", "path": "/api/invoices/42"}]
    )
    script = builder.build_standalone_script(finding)
    assert "real_token_123" in script
    assert "/api/invoices/42" in script
    assert "halo_token_user_a" not in script
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_reporting.py::test_cvss_readonly_bfla_integrity_is_none tests/unit/test_validation.py::test_poc_builder_uses_real_tokens_and_resolved_ids -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

In `cvss.py`: Set `i = "N"` when `flaw_type == "BFLA"` and not `is_write`.
In `poc_builder.py`: Extract actual auth tokens and resolved resource IDs from finding evidence/reproduction steps.
In `main.py`: Pass `llm_provider` to `repair_and_verify` and `generate_role_aware_patch`.
In `repair.py` & `patcher.py`: Provide deterministic syntax-valid fallbacks when LLM is unavailable.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_reporting.py tests/unit/test_validation.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/halo/reporting/cvss.py src/halo/validation/poc_builder.py src/halo/validation/repair.py src/halo/validation/patcher.py src/halo/cli/main.py tests/unit/test_reporting.py tests/unit/test_validation.py
git commit -m "fix(reporting,validation): refine CVSS read-only BFLA, inject real tokens into PoCs, and wire repair loop"
```

---

### Task 7: Full Integration Verification & End-to-End Suite Gate

- [ ] **Step 1: Run complete unit test suite**
Run: `.venv/bin/pytest tests/unit -v`
Expected: 100% PASS (220+ tests)

- [ ] **Step 2: Run E2E golden pipeline integration test**
Run: `HALO_LLM_PROVIDER=mock .venv/bin/pytest tests/integration/test_pipeline_e2e.py -v`
Expected: 2 passed in < 10s

- [ ] **Step 3: Run linter and formatting checks**
Run: `.venv/bin/ruff check src/ tests/`
Expected: 0 errors
