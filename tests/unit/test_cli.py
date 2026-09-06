"""Unit tests for Halo CLI commands and Rich UI terminal components."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typer.testing import CliRunner

from halo.cli.main import app
from halo.cli.ui import (
    print_banner,
    print_scan_summary,
    render_candidates_table,
    render_findings_table,
    render_routes_table,
)
from halo.dast.probes.base import ProbeResult
from halo.intent.pruner import SuspectCandidate
from halo.static.graph import RouteNode, SinkNode
from halo.validation.models import FindingRecord

runner = CliRunner()


def test_cli_help():
    """Verify top-level CLI help command displays branding and description."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AI-Native Hybrid Application Security Testing" in result.output
    assert "scan" in result.output
    assert "sast" in result.output
    assert "dast" in result.output
    assert "daemon" in result.output


def test_cli_subcommand_helps():
    """Verify each CLI subcommand displays appropriate help documentation."""
    for cmd in ["scan", "sast", "dast", "daemon"]:
        res = runner.invoke(app, [cmd, "--help"])
        assert res.exit_code == 0
        assert f"halo {cmd}" in res.output.lower() or cmd in res.output


def test_cli_sast_command():
    """Verify sast command discovers routes, builds CKG, prunes candidates, and exports JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "app.py").write_text(
            "@app.get('/api/v1/invoices/{id}')\ndef get_invoice(id: int):\n    return {'id': id}\n"
        )
        out_ckg = root / "ckg.json"
        res = runner.invoke(app, ["sast", "--repo", str(root), "--out", str(out_ckg)])
        assert res.exit_code == 0
        assert out_ckg.exists()

        data = json.loads(out_ckg.read_text())
        assert "elements" in data
        assert "nodes" in data["elements"]
        assert "edges" in data["elements"]
        # Output should contain route and candidate tables
        assert "/api/v1/invoices/{id}" in res.output


def test_cli_scan_command_mock_repo():
    """Verify scan command runs end-to-end SAST and exports all reports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.py").write_text(
            "@app.get('/api/v1/users/{user_id}')\n"
            "def get_user(user_id: str):\n"
            "    return {'user_id': user_id}\n"
        )
        out_dir = root / "reports"
        res = runner.invoke(app, ["scan", "--repo", str(root), "--output-dir", str(out_dir)])
        assert res.exit_code == 0
        assert (out_dir / "halo_report.json").exists()
        assert (out_dir / "halo_report.sarif").exists()
        assert (out_dir / "halo_report.md").exists()

        # Check JSON report format
        json_data = json.loads((out_dir / "halo_report.json").read_text())
        assert "scanner" in json_data
        assert json_data["scanner"] == "Project HALO"


def test_cli_scan_command_with_url_and_findings():
    """Verify scan command executes dynamic probing when URL is provided and outputs PoC scripts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.py").write_text(
            "@app.get('/api/v1/documents/{doc_id}')\n"
            "def get_doc(doc_id: str):\n"
            "    return {'doc_id': doc_id}\n"
        )
        out_dir = root / "out"

        mock_probe_result = ProbeResult(
            flaw_type="BOLA_IDOR",
            endpoint="/api/v1/documents/{doc_id}",
            vulnerable=True,
            confidence=0.95,
            details="User A accessed User B document without authorization",
            reproduction_steps=[
                {"action": "create", "as": "USER_B", "path": "/api/v1/documents"},
                {"action": "read", "as": "USER_A", "path": "/api/v1/documents/doc_123"},
            ],
            observed_side_effects=["Tenant boundary bypassed"],
        )

        with patch("halo.cli.main.BOLAProbe.execute", return_value=mock_probe_result):
            res = runner.invoke(
                app,
                [
                    "scan",
                    "--repo",
                    str(root),
                    "--url",
                    "http://localhost:8000",
                    "--output-dir",
                    str(out_dir),
                ],
            )
            assert res.exit_code == 0
            assert (out_dir / "halo_report.json").exists()
            assert (out_dir / "halo_report.sarif").exists()
            assert (out_dir / "halo_report.md").exists()

            # Verify PoC script generated
            poc_files = list(out_dir.glob("repro_*.py"))
            assert len(poc_files) >= 1
            poc_content = poc_files[0].read_text()
            assert "# /// script" in poc_content
            assert 'dependencies = ["httpx"]' in poc_content

            # Verify remediation patch file generated
            patch_files = list(out_dir.glob("patch_*.md"))
            assert len(patch_files) >= 1
            patch_content = patch_files[0].read_text()
            assert "### Remediation" in patch_content


def test_cli_dast_command():
    """Verify dast command probes target URL and produces reports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir) / "dast_reports"

        mock_probe_result = ProbeResult(
            flaw_type="BFLA",
            endpoint="/api/v1/admin/settings",
            vulnerable=True,
            confidence=0.9,
            details="Unprivileged user accessed admin settings",
            reproduction_steps=[
                {"action": "get", "as": "USER_A", "path": "/api/v1/admin/settings"},
            ],
        )

        with patch("halo.cli.main.BFLAProbe.execute", return_value=mock_probe_result):
            res = runner.invoke(
                app,
                [
                    "dast",
                    "--url",
                    "http://localhost:8000",
                    "--out",
                    str(out_dir),
                ],
            )
            assert res.exit_code == 0
            assert (out_dir / "halo_report.json").exists()
            assert (out_dir / "halo_report.sarif").exists()
            assert (out_dir / "halo_report.md").exists()
            assert len(list(out_dir.glob("repro_*.py"))) >= 1
            assert len(list(out_dir.glob("patch_*.md"))) >= 1


def test_cli_daemon_command():
    """Verify daemon command starts uvicorn with configured host, port, and database."""
    with patch("uvicorn.run") as mock_uvicorn:
        res = runner.invoke(
            app,
            [
                "daemon",
                "--host",
                "0.0.0.0",
                "--port",
                "8989",
                "--db",
                "/tmp/test_halo.db",
            ],
        )
        assert res.exit_code == 0
        mock_uvicorn.assert_called_once()
        args, kwargs = mock_uvicorn.call_args
        assert kwargs.get("host") == "0.0.0.0"
        assert kwargs.get("port") == 8989
        app_instance = args[0]
        assert app_instance.state.db.db_path == Path("/tmp/test_halo.db").resolve()


def test_ui_banner():
    """Verify print_banner renders styled ASCII art and version branding."""
    console = Console(record=True, width=120)
    print_banner(console=console)
    output = console.export_text()
    assert "HALO" in output
    assert "Hybrid Application Security Testing" in output


def test_ui_render_routes_table():
    """Verify render_routes_table displays method, endpoint, handler, and location."""
    console = Console(record=True, width=120)
    routes = [
        RouteNode(
            id="r1",
            method="GET",
            path="/api/v1/items/{id}",
            file_path="src/routes/items.py",
            line_number=15,
        ),
        {
            "method": "POST",
            "path": "/api/v1/items",
            "handler": "create_item",
            "location": "src/routes/items.py:30",
        },
    ]
    table = render_routes_table(routes, console=console)
    assert isinstance(table, Table)
    output = console.export_text()
    assert "GET" in output
    assert "/api/v1/items/{id}" in output
    assert "POST" in output
    assert "/api/v1/items" in output


def test_ui_render_candidates_table():
    """Verify render_candidates_table displays candidate flaws, endpoint, and reasoning."""
    console = Console(record=True, width=120)
    r = RouteNode(
        id="r1",
        method="GET",
        path="/api/v1/orders/{id}",
        file_path="orders.py",
        line_number=10,
    )
    s = SinkNode(id="s1", operation="READ", entity="Order", query_params=["id"])
    candidate = SuspectCandidate(
        route=r,
        sink=s,
        candidate_flaws=["BOLA"],
        reasoning="Path parameter id without authorization guard",
    )
    dict_candidate = {
        "endpoint": "/api/v1/admin/users",
        "candidate_flaws": ["BFLA"],
        "reasoning": "Admin path accessed without RBAC guard",
    }
    table = render_candidates_table([candidate, dict_candidate], console=console)
    assert isinstance(table, Table)
    output = console.export_text()
    assert "/api/v1/orders/{id}" in output
    assert "BOLA" in output
    assert "/api/v1/admin/users" in output
    assert "BFLA" in output


def test_ui_render_findings_table_with_severity_badges():
    """Verify render_findings_table renders color-coded severity badges."""
    console = Console(record=True, width=140)
    findings = [
        FindingRecord(
            id="HALO-01",
            flaw_type="BOLA_IDOR",
            endpoint="/api/v1/records/{id}",
            severity="CRITICAL",
            file_path="records.py",
            line_start=12,
        ),
        FindingRecord(
            id="HALO-02",
            flaw_type="BFLA",
            endpoint="/api/v1/admin/delete",
            severity="HIGH",
            file_path="admin.py",
            line_start=45,
        ),
        FindingRecord(
            id="HALO-03",
            flaw_type="RACE_CONDITION",
            endpoint="/api/v1/wallet/withdraw",
            severity="MEDIUM",
            file_path="wallet.py",
            line_start=80,
        ),
        {
            "id": "HALO-04",
            "flaw_type": "INFO_DISCLOSURE",
            "endpoint": "/api/v1/status",
            "severity": "LOW",
            "file_path": "status.py",
            "line_start": 5,
        },
    ]
    table = render_findings_table(findings, console=console)
    assert isinstance(table, Table)
    output = console.export_text()
    assert "🔴 CRITICAL" in output
    assert "🟠 HIGH" in output
    assert "🟡 MEDIUM" in output
    assert "🔵 LOW" in output
    assert "BOLA_IDOR" in output
    assert "BFLA" in output


def test_ui_print_scan_summary_panel():
    """Verify print_scan_summary outputs a formatted panel with counts and report paths."""
    console = Console(record=True, width=120)
    reports = {
        "JSON Report": "/tmp/reports/halo_report.json",
        "SARIF Report": "/tmp/reports/halo_report.sarif",
        "Markdown Executive Summary": "/tmp/reports/halo_report.md",
    }
    panel = print_scan_summary(
        total_routes=12,
        total_candidates=4,
        total_findings=2,
        duration_secs=3.45,
        report_paths=reports,
        console=console,
    )
    assert isinstance(panel, Panel)
    output = console.export_text()
    assert "Scan Complete" in output or "Scan Summary" in output
    assert "12" in output
    assert "4" in output
    assert "2" in output
    assert "3.45s" in output
    assert "halo_report.json" in output


def test_cli_dast_command_with_repo():
    """Verify dast command guided by repository context discovers routes and probes target."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "routes.py").write_text(
            "@app.get('/api/v1/admin/audit')\ndef audit_log():\n    return {'audit': 'log'}\n"
        )
        out_dir = root / "dast_out"

        mock_probe = ProbeResult(
            flaw_type="BFLA",
            endpoint="/api/v1/admin/audit",
            vulnerable=False,
            confidence=0.8,
            details="Access properly restricted to administrator",
        )

        with patch("halo.cli.main.BFLAProbe.execute", return_value=mock_probe):
            res = runner.invoke(
                app,
                [
                    "dast",
                    "--url",
                    "http://localhost:8000",
                    "--repo",
                    str(root),
                    "--output-dir",
                    str(out_dir),
                ],
            )
            assert res.exit_code == 0
            assert (out_dir / "halo_report.json").exists()


def test_cli_scan_docker_fallback():
    """Verify scan command handles docker sandbox startup failure gracefully and continues."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.py").write_text("@app.get('/health')\ndef health(): return {}\n")
        out_dir = root / "out"

        with patch(
            "halo.dast.sandbox.SandboxManager.boot_sandbox",
            side_effect=RuntimeError("Docker daemon offline"),
        ):
            res = runner.invoke(
                app,
                [
                    "scan",
                    "--repo",
                    str(root),
                    "--docker",
                    "--output-dir",
                    str(out_dir),
                ],
            )
            assert res.exit_code == 0
            assert (out_dir / "halo_report.json").exists()


def test_ui_empty_collections():
    """Verify rendering helpers handle empty collections gracefully."""
    console = Console(record=True, width=120)
    rt = render_routes_table([], console=console)
    assert isinstance(rt, Table)
    ct = render_candidates_table([], console=console)
    assert isinstance(ct, Table)
    ft = render_findings_table([], console=console)
    assert isinstance(ft, Table)
    p = print_scan_summary(0, 0, 0, 0.5, report_paths=None, console=console)
    assert isinstance(p, Panel)
    out = console.export_text()
    assert "No routes discovered" in out
    assert "All routes verified safe / pruned" in out
    assert "CLEAN" in out


def test_cli_scan_executes_workflow_and_race_probes():
    """Verify workflow and race condition probes are invoked with valid arguments and recipes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "app.py").write_text(
            "@app.post('/api/v1/orders/checkout')\n"
            "def checkout(): pass\n"
            "@app.post('/api/v1/coupons/apply')\n"
            "def apply(): pass\n"
        )
        out_dir = root / "out"

        mock_wf_result = ProbeResult(
            flaw_type="WORKFLOW_BYPASS",
            endpoint="/api/v1/orders/checkout",
            vulnerable=True,
            confidence=0.95,
            details="Checkout succeeded without prior payment step",
        )
        mock_race_result = ProbeResult(
            flaw_type="RACE_CONDITION",
            endpoint="/api/v1/coupons/apply",
            vulnerable=True,
            confidence=0.9,
            details="Coupon applied multiple times concurrently",
        )

        with (
            patch("halo.cli.main.WorkflowProbe.execute", return_value=mock_wf_result) as mock_wf,
            patch(
                "halo.cli.main.RaceConditionProbe.execute", return_value=mock_race_result
            ) as mock_race,
            patch(
                "halo.intent.pruner.CandidatePruner.prune_candidates",
                return_value=[
                    SuspectCandidate(
                        route=RouteNode(
                            id="r_wf",
                            method="POST",
                            path="/api/v1/orders/checkout",
                            file_path="app.py",
                        ),
                        candidate_flaws=["WORKFLOW"],
                        reasoning="Step skipping",
                    ),
                    SuspectCandidate(
                        route=RouteNode(
                            id="r_race",
                            method="POST",
                            path="/api/v1/coupons/apply",
                            file_path="app.py",
                        ),
                        candidate_flaws=["RACE"],
                        reasoning="Concurrency state multiplication",
                    ),
                ],
            ),
        ):
            res = runner.invoke(
                app,
                [
                    "scan",
                    "--repo",
                    str(root),
                    "--url",
                    "http://localhost:8000",
                    "--out",
                    str(out_dir),
                    "--token-budget",
                    "100000",
                ],
            )
            assert res.exit_code == 0
            assert mock_wf.called
            assert mock_race.called

            # Check that workflow steps passed were valid WorkflowStep instances
            wf_kwargs = mock_wf.call_args[1]
            assert "workflow_steps" in wf_kwargs
            assert len(wf_kwargs["workflow_steps"]) >= 1
            assert wf_kwargs["workflow_steps"][0].name == "action_step"

            # Check reports and patches generated
            assert (out_dir / "halo_report.json").exists()
            assert len(list(out_dir.glob("patch_*.md"))) == 2
            assert len(list(out_dir.glob("repro_*.py"))) == 2


def test_cli_scan_with_llm_provider_and_verify_pocs(tmp_path):
    """Verify scan command respects --llm-provider and --verify-pocs flags."""
    root = tmp_path / "app"
    root.mkdir()
    (root / "api.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/test')\ndef t(): pass\n"
    )
    out_dir = tmp_path / "out"

    res = runner.invoke(
        app,
        [
            "scan",
            "--repo",
            str(root),
            "--out",
            str(out_dir),
            "--llm-provider",
            "mock",
            "--verify-pocs",
        ],
    )
    assert res.exit_code == 0
    assert (out_dir / "halo_report.json").exists()


def test_dynamic_probes_incorporates_llm_hypothesis_flaws():
    """Verify _execute_dynamic_probes executes probe for LLM-hypothesized flaw even if not in candidate_flaws."""
    from halo.cli.main import _execute_dynamic_probes
    from halo.dast.vault import SessionVault
    from halo.intent.hypothesis import HypothesisResult, ProbingRecipe
    from halo.intent.pruner import SuspectCandidate
    from halo.static.graph import RouteNode

    route = RouteNode(id="r1", method="GET", path="/admin/data")
    cand = SuspectCandidate(candidate_id="c1", route=route, candidate_flaws=[])
    hypo = HypothesisResult(
        route_id="r1",
        candidate_id="c1",
        flaw_class="BFLA",
        confidence=0.9,
        reasoning="Admin path",
        probing_recipe=ProbingRecipe(strategy="role_escalation"),
    )
    with patch("halo.cli.main.BFLAProbe.execute") as mock_bfla:
        mock_bfla.return_value = None
        _execute_dynamic_probes(
            suspects=[cand],
            target_url="http://test",
            vault=SessionVault(),
            client=MagicMock(),
            hypotheses=[hypo],
        )
        assert mock_bfla.called, "Probe must be invoked for LLM hypothesized flaw"
