"""Project HALO - SQLite Database Persistence layer for Daemon service."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite

from halo.validation.models import FindingData, FindingRecord


class Database:
    """Asynchronous SQLite database for local scan management and vulnerability records."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            self.db_path = Path.home() / ".halo" / "halo.db"
        else:
            self.db_path = Path(db_path).expanduser().resolve()
        self._conn: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Initialize database connection, enable foreign keys, and ensure tables exist."""
        if self._conn is not None:
            return

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(str(self.db_path))
        self._conn.row_factory = aiosqlite.Row

        await self._conn.execute("PRAGMA foreign_keys = ON;")
        await self._conn.execute("PRAGMA journal_mode = WAL;")

        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                repo_path TEXT NOT NULL,
                target_url TEXT DEFAULT '',
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                total_findings INTEGER DEFAULT 0,
                metadata TEXT,
                error TEXT
            );
            """
        )

        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                flaw_type TEXT DEFAULT '',
                endpoint TEXT DEFAULT '',
                target_url TEXT DEFAULT '',
                method TEXT DEFAULT 'GET',
                severity TEXT DEFAULT 'HIGH',
                cvss_score REAL DEFAULT 0.0,
                cvss_vector TEXT DEFAULT '',
                confidence REAL DEFAULT 1.0,
                file_path TEXT DEFAULT '',
                line_start INTEGER DEFAULT 1,
                line_end INTEGER DEFAULT 1,
                details TEXT DEFAULT '',
                reproduction_steps TEXT DEFAULT '[]',
                poc_script TEXT DEFAULT '',
                remediation_patch TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
            """
        )

        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ckg_snapshots (
                scan_id TEXT PRIMARY KEY,
                graph_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
            """
        )

        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);"
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);"
        )

        await self._conn.commit()

    async def _get_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            await self.initialize()
        assert self._conn is not None
        return self._conn

    async def create_scan(
        self, repo_path: str, target_url: str = "", metadata: dict | None = None
    ) -> str:
        """Create a new scan record with initial PENDING status."""
        conn = await self._get_conn()
        scan_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        metadata_str = json.dumps(metadata) if metadata is not None else "{}"

        await conn.execute(
            """
            INSERT INTO scans (id, repo_path, target_url, status, created_at, total_findings, metadata)
            VALUES (?, ?, ?, 'PENDING', ?, 0, ?)
            """,
            (scan_id, repo_path, target_url, created_at, metadata_str),
        )
        await conn.commit()
        return scan_id

    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        total_findings: int | None = None,
        completed_at: str | None = None,
        error: str | None = None,
    ) -> None:
        """Update scan status and optional summary fields."""
        conn = await self._get_conn()

        if completed_at is None and status in ("COMPLETED", "FAILED", "CANCELLED"):
            completed_at = datetime.now(UTC).isoformat()

        clauses = ["status = ?"]
        params: list[Any] = [status]

        if total_findings is not None:
            clauses.append("total_findings = ?")
            params.append(total_findings)

        if completed_at is not None:
            clauses.append("completed_at = ?")
            params.append(completed_at)

        if error is not None:
            clauses.append("error = ?")
            params.append(error)

        params.append(scan_id)
        sql = f"UPDATE scans SET {', '.join(clauses)} WHERE id = ?"
        await conn.execute(sql, tuple(params))
        await conn.commit()

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Fetch scan record by ID."""
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row is None:
            return None

        data = dict(row)
        if data.get("metadata"):
            try:
                data["metadata"] = json.loads(data["metadata"])
            except (json.JSONDecodeError, TypeError):
                pass
        return data

    async def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """List scan records ordered by created_at descending."""
        conn = await self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            if item.get("metadata"):
                try:
                    item["metadata"] = json.loads(item["metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(item)
        return results

    async def add_finding(
        self, scan_id: str, finding: FindingRecord | FindingData | dict[str, Any]
    ) -> str:
        """Persist a vulnerability finding and update the scan's total_findings counter."""
        conn = await self._get_conn()

        if hasattr(finding, "model_dump"):
            data = finding.model_dump()
        elif hasattr(finding, "dict"):
            data = finding.dict()
        else:
            data = dict(finding)

        finding_id = str(data.get("id") or uuid.uuid4())
        flaw_type = str(data.get("flaw_type") or data.get("rule_id") or "UNKNOWN")
        endpoint = str(data.get("endpoint", ""))
        target_url = str(data.get("target_url", ""))
        method = str(data.get("method", "GET"))
        severity = str(data.get("severity", "HIGH"))
        cvss_score = float(data.get("cvss_score") or 0.0)
        cvss_vector = str(data.get("cvss_vector", ""))
        confidence = float(data.get("confidence") if data.get("confidence") is not None else 1.0)
        file_path = str(data.get("file_path", ""))
        line_start = int(data.get("line_start") or data.get("line_number") or 1)
        line_end = int(data.get("line_end") or line_start)
        details = str(data.get("details") or data.get("description", ""))

        repro_steps = data.get("reproduction_steps", [])
        if isinstance(repro_steps, (list, dict)):
            repro_steps_str = json.dumps(repro_steps)
        else:
            repro_steps_str = str(repro_steps or "[]")

        poc_script = str(data.get("poc_script", ""))
        remediation_patch = str(data.get("remediation_patch", ""))
        created_at = str(data.get("created_at") or datetime.now(UTC).isoformat())

        await conn.execute(
            """
            INSERT INTO findings (
                id, scan_id, flaw_type, endpoint, target_url, method, severity,
                cvss_score, cvss_vector, confidence, file_path, line_start, line_end,
                details, reproduction_steps, poc_script, remediation_patch, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                scan_id,
                flaw_type,
                endpoint,
                target_url,
                method,
                severity,
                cvss_score,
                cvss_vector,
                confidence,
                file_path,
                line_start,
                line_end,
                details,
                repro_steps_str,
                poc_script,
                remediation_patch,
                created_at,
            ),
        )

        # Update total_findings on scan
        await conn.execute(
            "UPDATE scans SET total_findings = (SELECT COUNT(*) FROM findings WHERE scan_id = ?) WHERE id = ?",
            (scan_id, scan_id),
        )
        await conn.commit()
        return finding_id

    async def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """Fetch all findings for a given scan ID."""
        conn = await self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at ASC",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            if item.get("reproduction_steps"):
                try:
                    item["reproduction_steps"] = json.loads(item["reproduction_steps"])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(item)
        return results

    async def list_all_findings(
        self,
        scan_id: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Fetch findings across scans with optional filtering and pagination."""
        conn = await self._get_conn()
        query = "SELECT * FROM findings"
        params: list[Any] = []
        clauses: list[str] = []

        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if severity:
            clauses.append("UPPER(severity) = ?")
            params.append(severity.upper())

        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await conn.execute(query, tuple(params))
        rows = await cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            if item.get("reproduction_steps"):
                try:
                    item["reproduction_steps"] = json.loads(item["reproduction_steps"])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(item)
        return results

    async def save_ckg_snapshot(self, scan_id: str, graph_json: str | dict[str, Any]) -> None:
        """Save or overwrite a Code Knowledge Graph snapshot for a scan."""
        conn = await self._get_conn()
        if isinstance(graph_json, (dict, list)):
            graph_str = json.dumps(graph_json)
        else:
            graph_str = str(graph_json)

        created_at = datetime.now(UTC).isoformat()
        await conn.execute(
            """
            INSERT INTO ckg_snapshots (scan_id, graph_json, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                graph_json = excluded.graph_json,
                created_at = excluded.created_at
            """,
            (scan_id, graph_str, created_at),
        )
        await conn.commit()

    async def get_ckg_snapshot(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve CKG snapshot for a scan."""
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM ckg_snapshots WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row is None:
            return None

        data = dict(row)
        try:
            data["graph"] = json.loads(data["graph_json"])
        except (json.JSONDecodeError, TypeError):
            data["graph"] = data["graph_json"]
        return data

    async def close(self) -> None:
        """Close the SQLite database connection if open."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
