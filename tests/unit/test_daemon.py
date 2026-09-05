"""Unit tests for Halo Daemon Service and SQLite Persistence."""

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from halo.daemon.db import Database
from halo.daemon.server import create_app
from halo.daemon.session import ScanSessionManager
from halo.validation.models import FindingData


@pytest.mark.asyncio
async def test_daemon_db_default_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    db = Database()
    expected_path = tmp_path / ".halo" / "halo.db"
    assert db.db_path == expected_path


@pytest.mark.asyncio
async def test_daemon_db_scan_lifecycle(tmp_path: Path):
    db_path = str(tmp_path / "test_halo.db")
    db = Database(db_path)
    await db.initialize()
    # Calling initialize again should be idempotent
    await db.initialize()

    # 1. Create scan
    scan_id = await db.create_scan(
        "/repo/path", "http://localhost:3000", metadata={"framework": "fastapi"}
    )
    assert scan_id is not None

    # 2. Get scan
    scan = await db.get_scan(scan_id)
    assert scan is not None
    assert scan["id"] == scan_id
    assert scan["repo_path"] == "/repo/path"
    assert scan["target_url"] == "http://localhost:3000"
    assert scan["status"] == "PENDING"
    assert scan["total_findings"] == 0
    assert scan["metadata"] == {"framework": "fastapi"}

    # 3. Update status
    await db.update_scan_status(scan_id, "RUNNING")
    scan = await db.get_scan(scan_id)
    assert scan["status"] == "RUNNING"

    await db.update_scan_status(
        scan_id, "COMPLETED", total_findings=3, completed_at="2026-09-06T00:00:00Z"
    )
    scan = await db.get_scan(scan_id)
    assert scan["status"] == "COMPLETED"
    assert scan["total_findings"] == 3
    assert scan["completed_at"] == "2026-09-06T00:00:00Z"

    # 4. List scans
    scans = await db.list_scans(limit=10)
    assert len(scans) == 1
    assert scans[0]["id"] == scan_id

    # 5. Nonexistent scan
    assert await db.get_scan("nonexistent-id") is None

    await db.close()


@pytest.mark.asyncio
async def test_daemon_db_list_scans_pagination(tmp_path: Path):
    db_path = str(tmp_path / "test_pagination.db")
    db = Database(db_path)
    await db.initialize()

    created_ids = []
    for i in range(5):
        sid = await db.create_scan(f"/repo/{i}")
        created_ids.append(sid)

    page1 = await db.list_scans(limit=2, offset=0)
    assert len(page1) == 2

    page2 = await db.list_scans(limit=2, offset=2)
    assert len(page2) == 2
    assert page1[0]["id"] != page2[0]["id"]

    page3 = await db.list_scans(limit=2, offset=4)
    assert len(page3) == 1

    await db.close()


@pytest.mark.asyncio
async def test_daemon_db_findings(tmp_path: Path):
    db_path = str(tmp_path / "test_findings.db")
    db = Database(db_path)
    await db.initialize()

    scan_id = await db.create_scan("/repo/app", "http://localhost:8000")

    # Insert finding from dict
    dict_finding = {
        "id": "HALO-BOLA-01",
        "flaw_type": "BOLA_IDOR",
        "endpoint": "/api/users/{id}",
        "target_url": "http://localhost:8000",
        "method": "GET",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "confidence": 0.95,
        "file_path": "routes/users.py",
        "line_start": 42,
        "line_end": 50,
        "details": "User ID not checked against JWT token subject.",
        "reproduction_steps": [{"step": 1, "action": "GET /api/users/2 with user 1 token"}],
        "poc_script": "import requests\n...",
        "remediation_patch": "--- users.py\n+++ users.py\n",
    }
    fid1 = await db.add_finding(scan_id, dict_finding)
    assert fid1 == "HALO-BOLA-01"

    # Insert finding from FindingData model
    model_finding = FindingData(
        id="HALO-BFLA-02",
        flaw_type="BFLA",
        endpoint="/api/admin/roles",
        method="POST",
        severity="HIGH",
        confidence=0.88,
        file_path="routes/admin.py",
        line_start=15,
        line_end=20,
        details="Admin role modification without RBAC check.",
        reproduction_steps=[{"step": 1, "action": "POST /api/admin/roles"}],
    )
    fid2 = await db.add_finding(scan_id, model_finding)
    assert fid2 == "HALO-BFLA-02"

    # Retrieve findings
    findings = await db.get_findings(scan_id)
    assert len(findings) == 2
    f1 = next(f for f in findings if f["id"] == "HALO-BOLA-01")
    assert f1["severity"] == "CRITICAL"
    assert f1["cvss_score"] == 9.1
    assert isinstance(f1["reproduction_steps"], list)
    assert f1["reproduction_steps"][0]["step"] == 1

    f2 = next(f for f in findings if f["id"] == "HALO-BFLA-02")
    assert f2["flaw_type"] == "BFLA"
    assert f2["endpoint"] == "/api/admin/roles"

    # Verify total_findings counter updated in scan
    scan = await db.get_scan(scan_id)
    assert scan["total_findings"] == 2

    await db.close()


@pytest.mark.asyncio
async def test_daemon_db_ckg_snapshot(tmp_path: Path):
    db_path = str(tmp_path / "test_ckg.db")
    db = Database(db_path)
    await db.initialize()

    scan_id = await db.create_scan("/repo/ckg", "http://localhost:5000")

    # Initially None
    assert await db.get_ckg_snapshot(scan_id) is None

    # Save snapshot
    graph = {"nodes": [{"id": "User", "type": "model"}], "edges": []}
    await db.save_ckg_snapshot(scan_id, graph)

    snapshot = await db.get_ckg_snapshot(scan_id)
    assert snapshot is not None
    assert snapshot["scan_id"] == scan_id
    assert snapshot["graph"] == graph

    # Overwrite snapshot
    updated_graph = {
        "nodes": [{"id": "User", "type": "model"}, {"id": "Admin", "type": "model"}],
        "edges": [],
    }
    await db.save_ckg_snapshot(scan_id, updated_graph)
    snapshot2 = await db.get_ckg_snapshot(scan_id)
    assert len(snapshot2["graph"]["nodes"]) == 2

    await db.close()


@pytest.mark.asyncio
async def test_session_manager_lifecycle_and_cancellation(tmp_path: Path):
    db_path = str(tmp_path / "test_session.db")
    db = Database(db_path)
    await db.initialize()
    manager = ScanSessionManager(db)

    # Custom runner that yields progress and finishes
    async def sample_runner(mgr, s_id, repo, url, config):
        await mgr.publish_progress(s_id, "sast_complete", {"routes_found": 5})
        await asyncio.sleep(0.01)
        await mgr.publish_progress(s_id, "dast_complete", {"flaws_tested": 10})

    scan_id = await manager.start_scan("/test/repo", "http://target", runner_func=sample_runner)
    sub_q = manager.subscribe(scan_id)

    # Collect events from subscription queue
    events = []
    while True:
        try:
            event = await asyncio.wait_for(sub_q.get(), timeout=1.0)
            events.append(event)
            if event["type"] in ("scan_completed", "scan_failed", "scan_cancelled"):
                break
        except TimeoutError:
            break

    manager.unsubscribe(scan_id, sub_q)

    event_types = [e["type"] for e in events]
    assert "scan_started" in event_types
    assert "sast_complete" in event_types
    assert "dast_complete" in event_types
    assert "scan_completed" in event_types

    scan = await db.get_scan(scan_id)
    assert scan["status"] == "COMPLETED"

    # Test cancellation runner
    cancelled_event = asyncio.Event()

    async def hanging_runner(mgr, s_id, repo, url, config):
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled_event.set()
            raise

    cancel_scan_id = await manager.start_scan("/test/repo2", runner_func=hanging_runner)
    assert cancel_scan_id in manager.get_active_scans()

    cancel_sub = manager.subscribe(cancel_scan_id)
    ok = await manager.cancel_scan(cancel_scan_id)
    assert ok is True

    # Wait for cancellation event
    cancel_events = []
    while True:
        try:
            event = await asyncio.wait_for(cancel_sub.get(), timeout=1.0)
            cancel_events.append(event)
            if event["type"] == "scan_cancelled":
                break
        except TimeoutError:
            break

    manager.unsubscribe(cancel_scan_id, cancel_sub)
    assert any(e["type"] == "scan_cancelled" for e in cancel_events)

    scan_c = await db.get_scan(cancel_scan_id)
    assert scan_c["status"] == "CANCELLED"
    assert cancel_scan_id not in manager.get_active_scans()

    await db.close()


@pytest.mark.asyncio
async def test_session_manager_failure_handling(tmp_path: Path):
    db_path = str(tmp_path / "test_session_failure.db")
    db = Database(db_path)
    await db.initialize()
    manager = ScanSessionManager(db)

    async def failing_runner(mgr, s_id, repo, url, config):
        raise RuntimeError("Simulated runner crash")

    scan_id = await manager.start_scan("/fail/repo", runner_func=failing_runner)
    sub = manager.subscribe(scan_id)

    events = []
    while True:
        try:
            event = await asyncio.wait_for(sub.get(), timeout=1.0)
            events.append(event)
            if event["type"] in ("scan_completed", "scan_failed", "scan_cancelled"):
                break
        except TimeoutError:
            break

    assert any(e["type"] == "scan_failed" for e in events)
    scan = await db.get_scan(scan_id)
    assert scan["status"] == "FAILED"
    assert "Simulated runner crash" in scan["error"]

    await db.close()


def test_server_rest_api(tmp_path: Path):
    db_path = str(tmp_path / "test_server.db")
    db = Database(db_path)
    session_manager = ScanSessionManager(db)
    app = create_app(db=db, session_manager=session_manager)

    with TestClient(app) as client:
        # 1. Health check
        res = client.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "version" in data

        # 2. Start a scan
        payload = {
            "repo_path": "/workspace/demo",
            "target_url": "http://127.0.0.1:3000",
            "scan_config": {"safe_mode": True},
        }
        res = client.post("/api/v1/scans", json=payload)
        assert res.status_code in (200, 201)
        scan_data = res.json()
        assert "scan_id" in scan_data
        scan_id = scan_data["scan_id"]

        # 3. List scans
        res = client.get("/api/v1/scans")
        assert res.status_code == 200
        scans = res.json()
        assert any(s["id"] == scan_id for s in scans)

        # 4. Get scan detail
        res = client.get(f"/api/v1/scans/{scan_id}")
        assert res.status_code == 200
        assert res.json()["id"] == scan_id

        # 5. Nonexistent scan 404
        res = client.get("/api/v1/scans/nonexistent-999")
        assert res.status_code == 404

        # 6. Cancel scan
        res = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert res.status_code == 200
        assert res.json()["cancelled"] is True or res.json()["scan_id"] == scan_id

        # 7. Cancel nonexistent scan 404
        res = client.post("/api/v1/scans/nonexistent-999/cancel")
        assert res.status_code == 404

        # 8. Get findings (empty initially)
        res = client.get(f"/api/v1/scans/{scan_id}/findings")
        assert res.status_code == 200
        assert isinstance(res.json(), list)

        # 9. Findings 404 on nonexistent scan
        res = client.get("/api/v1/scans/nonexistent-999/findings")
        assert res.status_code == 404

        # 10. CKG snapshot 404 if not found
        res = client.get(f"/api/v1/scans/{scan_id}/ckg")
        assert res.status_code == 404

        # 11. CKG snapshot 404 on nonexistent scan
        res = client.get("/api/v1/scans/nonexistent-999/ckg")
        assert res.status_code == 404


def test_server_findings_and_ckg_endpoints(tmp_path: Path):
    db_path = str(tmp_path / "test_server_data.db")
    db = Database(db_path)
    session_manager = ScanSessionManager(db)
    app = create_app(db=db, session_manager=session_manager)

    with TestClient(app) as client:
        # Create scan via POST
        res = client.post("/api/v1/scans", json={"repo_path": "/test/repo"})
        scan_id = res.json()["scan_id"]

        # Directly insert a finding and CKG snapshot in DB
        loop = asyncio.new_event_loop()
        loop.run_until_complete(
            db.add_finding(
                scan_id,
                {
                    "id": "HALO-TEST-1",
                    "flaw_type": "BOLA",
                    "endpoint": "/items",
                    "severity": "HIGH",
                },
            )
        )
        loop.run_until_complete(db.save_ckg_snapshot(scan_id, {"nodes": ["a", "b"]}))
        loop.close()

        # Query findings
        res = client.get(f"/api/v1/scans/{scan_id}/findings")
        assert res.status_code == 200
        findings = res.json()
        assert len(findings) == 1
        assert findings[0]["id"] == "HALO-TEST-1"

        # Query CKG
        res = client.get(f"/api/v1/scans/{scan_id}/ckg")
        assert res.status_code == 200
        ckg = res.json()
        assert ckg["scan_id"] == scan_id
        assert ckg["graph"] == {"nodes": ["a", "b"]}


def test_server_websocket_streaming(tmp_path: Path):
    db_path = str(tmp_path / "test_ws.db")
    db = Database(db_path)
    session_manager = ScanSessionManager(db)
    app = create_app(db=db, session_manager=session_manager)

    with TestClient(app) as client:
        # Start scan via REST endpoint
        res = client.post(
            "/api/v1/scans",
            json={"repo_path": "/repo", "target_url": "http://127.0.0.1:3000"},
        )
        assert res.status_code == 201
        scan_id = res.json()["scan_id"]

        # Connect via WebSocket
        with client.websocket_connect(f"/ws/scans/{scan_id}") as ws:
            msg = ws.receive_json()
            assert "type" in msg
            assert msg["scan_id"] == scan_id


def test_server_top_level_findings_endpoint(tmp_path: Path):
    db_path = str(tmp_path / "test_findings_api.db")
    db = Database(db_path)
    session_manager = ScanSessionManager(db)
    app = create_app(db=db, session_manager=session_manager)

    with TestClient(app) as client:
        # Create 2 scans
        s1 = client.post("/api/v1/scans", json={"repo_path": "/repo1"}).json()["scan_id"]
        s2 = client.post("/api/v1/scans", json={"repo_path": "/repo2"}).json()["scan_id"]

        loop = asyncio.new_event_loop()
        loop.run_until_complete(
            db.add_finding(
                s1,
                {"id": "F1", "flaw_type": "BOLA", "endpoint": "/a", "severity": "HIGH"},
            )
        )
        loop.run_until_complete(
            db.add_finding(
                s2,
                {"id": "F2", "flaw_type": "BFLA", "endpoint": "/b", "severity": "CRITICAL"},
            )
        )
        loop.run_until_complete(
            db.add_finding(
                s2,
                {"id": "F3", "flaw_type": "RACE", "endpoint": "/c", "severity": "HIGH"},
            )
        )
        loop.close()

        # Query all findings
        res = client.get("/api/v1/findings")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 3
        assert len(data["findings"]) == 3

        # Filter by scan_id
        res_s1 = client.get(f"/api/v1/findings?scan_id={s1}")
        assert res_s1.status_code == 200
        assert res_s1.json()["total"] == 1
        assert res_s1.json()["findings"][0]["id"] == "F1"

        # Filter by severity
        res_crit = client.get("/api/v1/findings?severity=critical")
        assert res_crit.status_code == 200
        assert res_crit.json()["total"] == 1
        assert res_crit.json()["findings"][0]["id"] == "F2"

        # Pagination
        res_page = client.get("/api/v1/findings?limit=2&offset=1")
        assert res_page.status_code == 200
        assert len(res_page.json()["findings"]) == 2


def test_websocket_invalid_scan_rejected(tmp_path: Path):
    db_path = str(tmp_path / "test_ws_reject.db")
    db = Database(db_path)
    session_manager = ScanSessionManager(db)
    app = create_app(db=db, session_manager=session_manager)

    with (
        TestClient(app) as client,
        pytest.raises(WebSocketDisconnect) as exc_info,
        client.websocket_connect("/ws/scans/nonexistent-scan-id"),
    ):
        pass

    assert exc_info.value.code == 1008


def test_daemon_shutdown_cleanly_awaits_active_tasks(tmp_path: Path):
    db_path = str(tmp_path / "test_shutdown.db")
    db = Database(db_path)
    session_manager = ScanSessionManager(db)
    app = create_app(db=db, session_manager=session_manager)

    with TestClient(app) as client:
        # Start a scan with long running execution
        res = client.post(
            "/api/v1/scans", json={"repo_path": "/repo", "target_url": "http://127.0.0.1:3000"}
        )
        assert res.status_code == 201
        scan_id = res.json()["scan_id"]
        assert scan_id in session_manager.get_active_scans()
    # Exiting TestClient context triggers app lifespan shutdown
    # Active task should be cancelled and awaited cleanly without raising db connection errors
    assert len(session_manager.get_active_scans()) == 0
