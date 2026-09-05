"""Unit tests for CVSS v3.1 calculator and multi-format reporting."""

import io
import json
from pathlib import Path
import tempfile

import pytest
from rich.console import Console

from halo.validation.cvss import CVSSCalculator
from halo.validation.models import FindingRecord
from halo.validation.report import ReportGenerator


def test_cvss_calculator_spec_equations():
    """Verify CVSS v3.1 base score computation adheres to FIRST CVSS v3.1 formulas."""
    calc = CVSSCalculator()

    # Zero impact => 0.0 NONE
    score, sev, vec = calc.calculate(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="N",
        integrity="N",
        availability="N",
    )
    assert score == 0.0
    assert sev == "NONE"
    assert vec == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

    # Critical max impact: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H => 9.8 CRITICAL
    score, sev, vec = calc.calculate(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H",
    )
    assert score == 9.8
    assert sev == "CRITICAL"
    assert vec == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    # Scope Changed test: AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H => 9.1 CRITICAL
    score, sev, vec = calc.calculate(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="H",
        user_interaction="N",
        scope="C",
        confidentiality="H",
        integrity="H",
        availability="H",
    )
    assert score == 9.1
    assert sev == "CRITICAL"
    assert "S:C" in vec


def test_cvss_calculator_roundup():
    """Verify FIRST CVSS v3.1 ceiling function to 1 decimal place."""
    calc = CVSSCalculator()
    assert calc.roundup(0.0) == 0.0
    assert calc.roundup(4.0) == 4.0
    assert calc.roundup(4.02) == 4.1
    assert calc.roundup(4.0000001) == 4.0
    assert calc.roundup(10.0) == 10.0
    assert calc.roundup(6.930727) == 7.0


def test_cvss_calculator_severity_scale():
    """Verify qualitative severity scale boundaries."""
    calc = CVSSCalculator()
    assert calc.get_severity(0.0) == "NONE"
    assert calc.get_severity(0.1) == "LOW"
    assert calc.get_severity(3.9) == "LOW"
    assert calc.get_severity(4.0) == "MEDIUM"
    assert calc.get_severity(6.9) == "MEDIUM"
    assert calc.get_severity(7.0) == "HIGH"
    assert calc.get_severity(8.9) == "HIGH"
    assert calc.get_severity(9.0) == "CRITICAL"
    assert calc.get_severity(10.0) == "CRITICAL"


def test_cvss_calculator_alternate_signatures():
    """Verify calculate method flexibly handles positional flaw_type and keyword args."""
    calc = CVSSCalculator()

    # Via calculate with positional flaw_type
    score1, sev1, vec1 = calc.calculate("BOLA_IDOR")
    assert 6.0 <= score1 <= 8.5
    assert sev1 in ["MEDIUM", "HIGH"]

    # Via calculate with keyword flaw_type
    score2, sev2, vec2 = calc.calculate(flaw_type="BFLA", requires_auth=True)
    assert score2 >= 7.0
    assert sev2 in ["HIGH", "CRITICAL"]

    # Positional standard metrics
    score3, sev3, _ = calc.calculate("N", "L", "L", "N", "U", "H", "N", "N")
    assert score3 == 6.5
    assert sev3 == "MEDIUM"


def test_cvss_calculator_bola():
    """Verify BOLA / IDOR flaw mapping and score range."""
    calc = CVSSCalculator()
    score, severity, vector = calc.calculate_for_finding("BOLA_IDOR", requires_auth=True, scope_changed=False)
    assert 6.0 <= score <= 8.5
    assert severity in ["MEDIUM", "HIGH"]
    assert vector.startswith("CVSS:3.1/")
    assert "C:H" in vector

    # Unauthenticated BOLA has PR:N -> higher score
    score_unauth, sev_unauth, vec_unauth = calc.calculate_for_finding(
        "BOLA_IDOR", requires_auth=False, scope_changed=False
    )
    assert score_unauth > score
    assert "PR:N" in vec_unauth

    # Write BOLA has I:H
    score_write, _, vec_write = calc.calculate_for_finding(
        "BOLA_IDOR", requires_auth=True, scope_changed=False, is_write=True
    )
    assert score_write > score
    assert "I:H" in vec_write


def test_cvss_calculator_flaw_mappings():
    """Verify realistic default CVSS metrics for all core business logic flaw types."""
    calc = CVSSCalculator()

    # BFLA (privilege escalation / admin bypass)
    score_bfla, sev_bfla, vec_bfla = calc.calculate_for_finding("BFLA", requires_auth=True)
    assert score_bfla >= 7.0
    assert sev_bfla in ["HIGH", "CRITICAL"]
    assert "C:H" in vec_bfla and "I:H" in vec_bfla

    # RACE_CONDITION (high attack complexity)
    score_race, sev_race, vec_race = calc.calculate_for_finding("RACE_CONDITION", requires_auth=True)
    assert "AC:H" in vec_race
    assert "I:H" in vec_race
    assert sev_race in ["MEDIUM", "HIGH"]

    # WORKFLOW_BYPASS
    score_wf, sev_wf, vec_wf = calc.calculate_for_finding("WORKFLOW_BYPASS", requires_auth=True)
    assert "AC:L" in vec_wf
    assert "I:H" in vec_wf

    # MASS_ASSIGNMENT
    score_ma, sev_ma, vec_ma = calc.calculate_for_finding("MASS_ASSIGNMENT", requires_auth=True)
    assert "C:L" in vec_ma
    assert "I:H" in vec_ma

    # Unknown flaw fallback
    score_unk, sev_unk, vec_unk = calc.calculate_for_finding("CUSTOM_VULN", requires_auth=True)
    assert score_unk > 0.0
    assert vec_unk.startswith("CVSS:3.1/")


def test_sarif_export():
    """Verify SARIF 2.1.0 generation conforming to GitHub Code Scanning schema."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "report.sarif"
        findings = [
            FindingRecord(
                id="HALO-001",
                rule_id="BOLA_IDOR",
                description="Broken Object Level Authorization on /invoices/{id}",
                severity="HIGH",
                file_path="src/routes/invoice.py",
                line_number=25,
            )
        ]
        ReportGenerator.export_sarif(findings, str(out_file))
        sarif_data = json.loads(out_file.read_text())

        assert sarif_data["version"] == "2.1.0"
        assert "$schema" in sarif_data
        assert len(sarif_data["runs"]) == 1

        run = sarif_data["runs"][0]
        assert run["tool"]["driver"]["name"] == "HALO"
        assert run["tool"]["driver"]["semanticVersion"] == "0.1.0"
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert run["tool"]["driver"]["rules"][0]["id"] == "BOLA_IDOR"

        results = run["results"]
        assert len(results) == 1
        result = results[0]
        assert result["ruleId"] == "BOLA_IDOR"
        assert result["level"] == "error"
        assert "Broken Object Level Authorization" in result["message"]["text"]

        # GitHub security location check
        location = result["locations"][0]
        physical = location["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "src/routes/invoice.py"
        assert physical["region"]["startLine"] == 25
        assert physical["region"]["endLine"] == 25


def test_sarif_export_multiple_rules_and_dict_inputs():
    """Verify SARIF export aggregates distinct rules and handles dict representations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "sub" / "report.sarif"
        findings = [
            {
                "id": "HALO-1",
                "flaw_type": "BOLA_IDOR",
                "severity": "CRITICAL",
                "file_path": "app/users.py",
                "line_start": 10,
                "line_end": 12,
            },
            {
                "id": "HALO-2",
                "flaw_type": "RACE_CONDITION",
                "severity": "MEDIUM",
                "file_path": "app/billing.py",
                "line_start": 40,
                "line_end": 45,
            },
            {
                "id": "HALO-3",
                "flaw_type": "WORKFLOW_BYPASS",
                "severity": "LOW",
                "file_path": "app/order.py",
                "line_start": 80,
                "line_end": 85,
            },
        ]

        sarif = ReportGenerator.export_sarif(findings, out_file)
        assert out_file.exists()

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 3
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {"BOLA_IDOR", "RACE_CONDITION", "WORKFLOW_BYPASS"}

        results = sarif["runs"][0]["results"]
        assert len(results) == 3
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "warning"
        assert results[2]["level"] == "note"


def test_json_export():
    """Verify formatted JSON export includes scan metadata and finding details."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "report.json"
        findings = [
            FindingRecord(
                id="HALO-BOLA-01",
                flaw_type="BOLA_IDOR",
                endpoint="/api/v1/orders/{order_id}",
                severity="HIGH",
                file_path="routes/orders.py",
                line_start=42,
                line_end=48,
                details="Attacker can access foreign order documents.",
            ),
            FindingRecord(
                id="HALO-RACE-01",
                flaw_type="RACE_CONDITION",
                endpoint="/api/v1/coupons/apply",
                severity="MEDIUM",
                file_path="routes/coupons.py",
                line_start=15,
                line_end=22,
                details="Concurrent coupon redemption leads to negative balances.",
            ),
        ]

        data = ReportGenerator.export_json(findings, out_file)
        assert out_file.exists()
        saved = json.loads(out_file.read_text())

        assert saved["total_findings"] == 2
        assert "timestamp" in saved or "scan_timestamp" in saved
        assert len(saved["findings"]) == 2

        f0 = saved["findings"][0]
        assert f0["id"] == "HALO-BOLA-01"
        assert f0["flaw_type"] == "BOLA_IDOR"
        assert f0["severity"] == "HIGH"
        assert f0["cvss_score"] >= 6.0
        assert f0["cvss_vector"].startswith("CVSS:3.1/")


def test_markdown_export():
    """Verify markdown executive summary table and detailed findings sections."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "report.md"
        findings = [
            FindingRecord(
                id="HALO-BFLA-01",
                flaw_type="BFLA",
                endpoint="/api/v1/admin/users",
                method="DELETE",
                severity="HIGH",
                file_path="routes/admin.py",
                line_start=30,
                line_end=35,
                details="Unprivileged user can invoke administrative user deletion.",
                reproduction_steps=[
                    {"action": "Authenticate as unprivileged user"},
                    {"action": "Send DELETE to /api/v1/admin/users/123"},
                ],
            )
        ]

        md_text = ReportGenerator.export_markdown(
            findings,
            out_file,
            metadata={"target_url": "http://localhost:3000", "branch": "main"},
        )
        assert out_file.exists()
        saved_md = out_file.read_text()

        assert "# Project HALO" in saved_md
        assert "Executive Summary" in saved_md
        assert "HALO-BFLA-01" in saved_md
        assert "/api/v1/admin/users" in saved_md
        assert "Remediation Recommendation" in saved_md
        assert "Reproduction Steps" in saved_md
        assert "CVSS" in saved_md


def test_markdown_export_empty():
    """Verify markdown export handles empty findings gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "empty.md"
        md_text = ReportGenerator.export_markdown([], out_file)
        assert "Total Findings:** 0" in md_text
        assert out_file.exists()


def test_render_terminal_summary():
    """Verify terminal summary generates a formatted Rich table."""
    findings = [
        FindingRecord(
            id="HALO-001",
            rule_id="BOLA_IDOR",
            endpoint="/invoices/123",
            severity="HIGH",
            file_path="src/invoice.py",
            line_start=10,
            line_end=15,
        ),
        FindingRecord(
            id="HALO-002",
            rule_id="RACE_CONDITION",
            endpoint="/transfers",
            severity="MEDIUM",
            file_path="src/transfers.py",
            line_start=50,
            line_end=60,
        ),
    ]

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, color_system=None)

    table = ReportGenerator.render_terminal_summary(findings, console=console)
    output = buf.getvalue()

    assert table is not None
    assert "HALO-001" in output
    assert "BOLA_IDOR" in output
    assert "HIGH" in output
    assert "/invoices/123" in output
    assert "HALO-002" in output


def test_render_terminal_summary_empty():
    """Verify empty findings list renders clean message without errors."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, color_system=None)
    table = ReportGenerator.render_terminal_summary([], console=console)
    output = buf.getvalue()
    assert "No vulnerabilities" in output or "No findings" in output
