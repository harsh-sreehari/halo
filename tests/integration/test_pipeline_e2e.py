"""Project HALO - Golden End-to-End Integration Test Suite.

Validates the full pipeline against the 6 canonical Business Logic Flaws (BLFs):
1. BOLA Read (GET /api/v1/invoices/:id)
2. BOLA Write (PUT /api/v1/invoices/:id)
3. BFLA (GET /api/v1/admin/settings)
4. Workflow Bypass (POST /api/v1/orders/:id/ship)
5. Mass Assignment / Price Tamper (POST /api/v1/cart/checkout)
6. Concurrency Race (POST /api/v1/coupons/apply)
Along with zero false positives on safe endpoints (GET /api/v1/public/info, GET /health).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
from typer.testing import CliRunner

from halo.cli.main import app
from testbed.python_mock_target import MockTargetServer, run_mock_server

runner = CliRunner()


def test_full_pipeline_against_ground_truth(tmp_path: Path) -> None:
    """Full golden E2E test executing HALO scan against the mock target testbed."""
    repo_dir = Path(__file__).parent.parent.parent / "testbed"
    out_dir = tmp_path / "halo_output"
    out_dir.mkdir(parents=True, exist_ok=True)

    with MockTargetServer(host="127.0.0.1", port=0) as (_server, base_url):
        result = runner.invoke(
            app,
            [
                "scan",
                "--repo",
                str(repo_dir),
                "--url",
                base_url,
                "--out",
                str(out_dir),
            ],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Scan CLI failed: {result.stdout}"

        # ---------------------------------------------------------------------
        # 1. Verify Reports Generated
        # ---------------------------------------------------------------------
        report_json = out_dir / "halo_report.json"
        report_sarif = out_dir / "halo_report.sarif"
        report_md = out_dir / "halo_report.md"

        assert report_json.is_file(), f"Missing {report_json}"
        assert report_sarif.is_file(), f"Missing {report_sarif}"
        assert report_md.is_file(), f"Missing {report_md}"

        # Parse JSON report
        report_data = json.loads(report_json.read_text(encoding="utf-8"))
        findings = report_data.get("findings", [])

        # Parse SARIF report
        sarif_data = json.loads(report_sarif.read_text(encoding="utf-8"))
        sarif_results = sarif_data["runs"][0]["results"]

        # Parse Markdown report
        md_content = report_md.read_text(encoding="utf-8")
        assert "# Project HALO - Security Audit Report" in md_content

        # ---------------------------------------------------------------------
        # 2. Verify Findings Recall: All 6 Planted Flaws Detected
        # ---------------------------------------------------------------------
        assert len(findings) == 6, f"Expected 6 findings, got {len(findings)}: {findings}"
        assert len(sarif_results) == 6

        detected_flaws = {f["flaw_type"] for f in findings}
        expected_flaw_types = {
            "BOLA_IDOR",
            "BFLA",
            "WORKFLOW_BYPASS",
            "MASS_ASSIGNMENT",
            "RACE_CONDITION",
        }
        assert expected_flaw_types.issubset(detected_flaws), (
            f"Missing flaw classes: {expected_flaw_types - detected_flaws}"
        )

        # Check endpoints detected
        detected_endpoints = [f["endpoint"] for f in findings]
        assert any("invoices" in ep for ep in detected_endpoints)
        assert any("admin/settings" in ep for ep in detected_endpoints)
        assert any("orders" in ep and "ship" in ep for ep in detected_endpoints)
        assert any("cart/checkout" in ep for ep in detected_endpoints)
        assert any("coupons/apply" in ep for ep in detected_endpoints)

        # ---------------------------------------------------------------------
        # 3. Verify Zero False Positives on Safe Endpoints
        # ---------------------------------------------------------------------
        safe_routes = ["/health", "/api/v1/public/info"]
        for safe_route in safe_routes:
            for f in findings:
                assert f["endpoint"] != safe_route, (
                    f"False positive detected on safe route {safe_route}!"
                )

        # ---------------------------------------------------------------------
        # 4. Verify Emitted PoC Scripts and Remediation Patches
        # ---------------------------------------------------------------------
        repro_scripts = sorted(out_dir.glob("repro_*.py"))
        patch_files = sorted(out_dir.glob("patch_*.md"))

        assert len(repro_scripts) == 6, f"Expected 6 repro scripts, found {len(repro_scripts)}"
        assert len(patch_files) == 6, f"Expected 6 patch files, found {len(patch_files)}"

        # Every patch file must contain remediation content
        for patch in patch_files:
            content = patch.read_text(encoding="utf-8")
            assert len(content) > 50, f"Patch file {patch.name} is too short"
            assert "Remediation" in content or "diff" in content or "```" in content

        # ---------------------------------------------------------------------
        # 5. Execute Emitted PoC Reproduction Scripts Against Live Target
        # ---------------------------------------------------------------------
        for script in repro_scripts:
            proc = subprocess.run(
                [sys.executable, str(script)],
                env={**os.environ, "HALO_TARGET_URL": base_url},
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            assert proc.returncode == 0, (
                f"PoC reproduction script {script.name} failed with code {proc.returncode}!\n"
                f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
            )


def test_mock_target_server_direct_endpoints() -> None:
    """Hermetic verification that MockTargetServer serves all canonical endpoints correctly."""
    server, base_url = run_mock_server(host="127.0.0.1", port=0)
    try:
        with httpx.Client(base_url=base_url, timeout=5.0) as client:
            # 1. Safe routes
            r_health = client.get("/health")
            assert r_health.status_code == 200
            assert r_health.json()["status"] == "ok"

            r_info = client.get("/api/v1/public/info")
            assert r_info.status_code == 200

            # 2. Registration
            r_reg = client.post(
                "/register",
                json={"username": "halo_user_a", "password": "Password123!"},
            )
            assert r_reg.status_code == 201
            assert "token" in r_reg.json()

            # 3. BOLA Read & Write
            r_inv_read = client.get("/api/v1/invoices/inv-b-1")
            assert r_inv_read.status_code == 200
            assert r_inv_read.json()["id"] == "inv-b-1"

            r_inv_write = client.put("/api/v1/invoices/inv-b-1", json={"amount": 999.0})
            assert r_inv_write.status_code == 200
            assert r_inv_write.json()["amount"] == 999.0

            # BOLA write rejects role injection
            r_inv_role = client.put("/api/v1/invoices/inv-b-1", json={"role": "admin"})
            assert r_inv_role.status_code == 400

            # 4. BFLA
            r_admin = client.get("/api/v1/admin/settings")
            assert r_admin.status_code == 200
            assert "settings" in r_admin.json()

            # 5. Workflow Bypass
            r_ship = client.post("/api/v1/orders/1/ship")
            assert r_ship.status_code == 200
            assert r_ship.json()["status"] == "shipped"

            # Workflow ship rejects mass assignment payload
            r_ship_bad = client.post("/api/v1/orders/1/ship", json={"role": "admin"})
            assert r_ship_bad.status_code == 400

            # 6. Mass Assignment / Price Tamper
            r_cart_empty = client.post("/api/v1/cart/checkout", json={})
            assert r_cart_empty.status_code == 400

            r_cart = client.post(
                "/api/v1/cart/checkout",
                json={"items": [{"id": "1", "price": 100}], "total": 0.01},
            )
            assert r_cart.status_code == 200
            assert r_cart.json()["total"] == 0.01

            # 7. Concurrency Race
            r_coupon = client.post("/api/v1/coupons/apply", json={"code": "DISCOUNT50"})
            assert r_coupon.status_code == 200
            assert r_coupon.json()["redeemed"] is True

            r_promo = client.post("/api/v1/coupons/apply", json={"code": "PROMO"})
            assert r_promo.status_code == 200
            assert r_promo.json()["redeemed"] is True
    finally:
        server.shutdown()
        server.server_close()
