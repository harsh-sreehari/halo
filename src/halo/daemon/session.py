"""Project HALO - Background Scan Session Manager and Pub/Sub Event Orchestration."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from halo.daemon.db import Database

logger = logging.getLogger(__name__)


class ScanSessionManager:
    """Manages background scanning tasks, stage orchestration, and WebSocket pub/sub progress streaming."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._active_tasks: dict[str, asyncio.Task[Any]] = {}
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def subscribe(self, scan_id: str, replay_history: bool = True) -> asyncio.Queue[dict[str, Any]]:
        """Subscribe an event queue to scan progress broadcasts.

        If replay_history is True, previously published events for this scan are immediately
        enqueued so late subscribers do not miss the scan start or early milestones.
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers[scan_id].add(queue)

        if replay_history and scan_id in self._history:
            for past_event in self._history[scan_id]:
                queue.put_nowait(past_event)

        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Unsubscribe an event queue from scan broadcasts."""
        if scan_id in self._subscribers:
            self._subscribers[scan_id].discard(queue)
            if not self._subscribers[scan_id]:
                del self._subscribers[scan_id]

    async def publish_progress(
        self, scan_id: str, event_type: str, data: dict[str, Any] | None = None
    ) -> None:
        """Broadcast an event to all active subscriber queues for a scan and store in history."""
        event = {
            "scan_id": scan_id,
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data or {},
        }
        self._history[scan_id].append(event)
        if len(self._history[scan_id]) > 1000:
            self._history[scan_id].pop(0)

        subscribers = list(self._subscribers.get(scan_id, []))
        for queue in subscribers:
            await queue.put(event)

    async def start_scan(
        self,
        repo_path: str,
        target_url: str = "",
        scan_config: dict[str, Any] | None = None,
        runner_func: Callable[
            [ScanSessionManager, str, str, str, dict[str, Any]], Coroutine[Any, Any, None]
        ]
        | None = None,
    ) -> str:
        """Create a scan in DB, spawn background worker, and return scan_id."""
        scan_id = await self.db.create_scan(repo_path, target_url, metadata=scan_config)
        await self.db.update_scan_status(scan_id, "RUNNING")

        await self.publish_progress(
            scan_id,
            "scan_started",
            {"repo_path": repo_path, "target_url": target_url},
        )

        task = asyncio.create_task(
            self._run_scan(scan_id, repo_path, target_url, scan_config or {}, runner_func)
        )
        self._active_tasks[scan_id] = task

        return scan_id

    async def _run_scan(
        self,
        scan_id: str,
        repo_path: str,
        target_url: str,
        scan_config: dict[str, Any],
        runner_func: Callable[..., Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        """Internal background worker executing scan phases and persisting state."""
        try:
            if runner_func is not None:
                await runner_func(self, scan_id, repo_path, target_url, scan_config)
            else:
                # Default pipeline simulation / phase progression
                await self.publish_progress(scan_id, "phase_sast", {"status": "started"})
                await asyncio.sleep(0.02)
                await self.publish_progress(scan_id, "phase_sast", {"status": "completed"})

                if target_url:
                    await self.publish_progress(scan_id, "phase_dast", {"status": "started"})
                    await asyncio.sleep(0.02)
                    await self.publish_progress(scan_id, "phase_dast", {"status": "completed"})

                await self.publish_progress(scan_id, "phase_validation", {"status": "completed"})

            findings = await self.db.get_findings(scan_id)
            total = len(findings)
            await self.db.update_scan_status(
                scan_id,
                "COMPLETED",
                total_findings=total,
                completed_at=datetime.now(UTC).isoformat(),
            )
            await self.publish_progress(
                scan_id,
                "scan_completed",
                {"total_findings": total},
            )
        except asyncio.CancelledError:
            try:
                if getattr(self.db, "_conn", None) is not None:
                    scan = await self.db.get_scan(scan_id)
                    if scan is not None and scan.get("status") != "CANCELLED":
                        await asyncio.shield(
                            self.db.update_scan_status(
                                scan_id,
                                "CANCELLED",
                                completed_at=datetime.now(UTC).isoformat(),
                            )
                        )
                        await asyncio.shield(self.publish_progress(scan_id, "scan_cancelled", {}))
            except BaseException as e:  # noqa: BLE001
                logger.debug(f"Error handling scan cancellation: {e}")
            raise
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            try:
                await self.db.update_scan_status(
                    scan_id,
                    "FAILED",
                    error=str(exc),
                    completed_at=datetime.now(UTC).isoformat(),
                )
                await self.publish_progress(
                    scan_id,
                    "scan_failed",
                    {"error": str(exc)},
                )
            except Exception as e:  # noqa: BLE001
                logger.error(f"Error recording scan failure: {e}")
        finally:
            self._active_tasks.pop(scan_id, None)

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan task, mark status CANCELLED in DB, and publish cancellation event."""
        task = self._active_tasks.get(scan_id)
        has_task = False
        if task is not None and not task.done():
            has_task = True
            try:
                loop = task.get_loop()
                if not loop.is_closed():
                    task.cancel()
            except RuntimeError:
                pass

        scan = await self.db.get_scan(scan_id)
        if scan is not None:
            if scan.get("status") not in ("COMPLETED", "FAILED", "CANCELLED"):
                await self.db.update_scan_status(
                    scan_id,
                    "CANCELLED",
                    completed_at=datetime.now(UTC).isoformat(),
                )
                await self.publish_progress(scan_id, "scan_cancelled", {})
                return True
            return has_task
        return False

    def get_task(self, scan_id: str) -> asyncio.Task[Any] | None:
        """Return the active background asyncio Task for a scan, if any."""
        return self._active_tasks.get(scan_id)

    def get_active_scans(self) -> list[str]:
        """Return list of active, uncompleted scan IDs."""
        active = []
        for sid, task in self._active_tasks.items():
            try:
                if not task.done():
                    active.append(sid)
            except RuntimeError:
                pass
        return active
