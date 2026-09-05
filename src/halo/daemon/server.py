"""Project HALO - FastAPI Daemon Service and WebSocket Real-Time Streaming."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from halo.daemon.db import Database
from halo.daemon.session import ScanSessionManager

logger = logging.getLogger(__name__)


class ScanCreateRequest(BaseModel):
    """Payload to initiate a new security scan."""

    repo_path: str = Field(..., description="Local filesystem path to target repository")
    target_url: str = Field(default="", description="Optional URL of running target instance")
    scan_config: dict[str, Any] = Field(
        default_factory=dict, description="Configuration options for scan modules"
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str = "0.1.0"


def create_app(
    db: Database | None = None,
    session_manager: ScanSessionManager | None = None,
) -> FastAPI:
    """Create and configure the FastAPI Daemon application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        if getattr(app.state, "db", None) is None:
            app.state.db = db if db is not None else Database()
        await app.state.db.initialize()

        if getattr(app.state, "session_manager", None) is None:
            app.state.session_manager = (
                session_manager if session_manager is not None else ScanSessionManager(app.state.db)
            )

        yield

        # Shutdown: cancel active background tasks and close database
        mgr: ScanSessionManager = getattr(app.state, "session_manager", None)
        if mgr is not None:
            for active_scan_id in mgr.get_active_scans():
                await mgr.cancel_scan(active_scan_id)

        database: Database = getattr(app.state, "db", None)
        if database is not None:
            await database.close()

    app = FastAPI(
        title="Project HALO Daemon",
        description="Local background daemon and REST/WebSocket API for Project HALO.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Pre-populate state if instances provided
    app.state.db = db
    app.state.session_manager = session_manager

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- REST API Endpoints ---

    @app.get("/api/v1/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        """Daemon health check endpoint."""
        return HealthResponse(status="ok", version="0.1.0")

    @app.post("/api/v1/scans", status_code=status.HTTP_201_CREATED)
    async def create_scan(payload: ScanCreateRequest) -> dict[str, Any]:
        """Start a new vulnerability scan."""
        mgr: ScanSessionManager = app.state.session_manager
        scan_id = await mgr.start_scan(
            repo_path=payload.repo_path,
            target_url=payload.target_url,
            scan_config=payload.scan_config,
        )
        return {"scan_id": scan_id, "status": "RUNNING"}

    @app.get("/api/v1/scans")
    async def list_scans(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """List past and current scans."""
        database: Database = app.state.db
        return await database.list_scans(limit=limit, offset=offset)

    @app.get("/api/v1/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict[str, Any]:
        """Get scan status and summary details."""
        database: Database = app.state.db
        scan = await database.get_scan(scan_id)
        if scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found",
            )
        return scan

    @app.post("/api/v1/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: str) -> dict[str, Any]:
        """Cancel a running or pending scan."""
        database: Database = app.state.db
        scan = await database.get_scan(scan_id)
        if scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found",
            )

        mgr: ScanSessionManager = app.state.session_manager
        cancelled = await mgr.cancel_scan(scan_id)
        return {"scan_id": scan_id, "cancelled": cancelled}

    @app.get("/api/v1/scans/{scan_id}/findings")
    async def get_findings(scan_id: str) -> list[dict[str, Any]]:
        """Get all verified findings for a given scan."""
        database: Database = app.state.db
        scan = await database.get_scan(scan_id)
        if scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found",
            )
        return await database.get_findings(scan_id)

    @app.get("/api/v1/scans/{scan_id}/ckg")
    async def get_ckg(scan_id: str) -> dict[str, Any]:
        """Get Code Knowledge Graph snapshot for a given scan."""
        database: Database = app.state.db
        scan = await database.get_scan(scan_id)
        if scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found",
            )

        snapshot = await database.get_ckg_snapshot(scan_id)
        if snapshot is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No CKG snapshot found for scan {scan_id}",
            )
        return snapshot

    # --- WebSocket Streaming ---

    @app.websocket("/ws/scans/{scan_id}")
    async def websocket_scan_progress(websocket: WebSocket, scan_id: str) -> None:
        """Stream real-time progress events for a scan over WebSocket."""
        await websocket.accept()

        mgr: ScanSessionManager = app.state.session_manager
        database: Database = app.state.db

        # Send current scan snapshot if available
        scan = await database.get_scan(scan_id)
        if scan is not None:
            await websocket.send_json(
                {
                    "scan_id": scan_id,
                    "type": "scan_status",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "data": scan,
                }
            )

        queue = mgr.subscribe(scan_id)
        try:
            while True:
                event = await queue.get()
                await websocket.send_json(event)
                if event.get("type") in ("scan_completed", "scan_failed", "scan_cancelled"):
                    break
        except WebSocketDisconnect:
            logger.debug(f"Client disconnected from WebSocket for scan {scan_id}")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"WebSocket connection error for scan {scan_id}: {exc}")
        finally:
            mgr.unsubscribe(scan_id, queue)

    return app
