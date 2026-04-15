"""Background task management for long-running MCP operations.

FastMCP tools must return promptly so the MCP client stays responsive. For
analyses that can take many seconds (whole-project scans), we launch the
subprocess in a worker thread and expose start/status/result tools that
MCP clients can poll.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import cli_bridge
from .models import AnalysisResult
from .resources import cache


@dataclass
class Task:
    task_id: str
    kind: str
    status: str = "pending"  # pending | running | completed | failed
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    progress_message: str = ""
    result: Any = None
    error: str | None = None


class TaskManager:
    """In-memory registry of background tasks. Thread-safe."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._lock = threading.Lock()

    def start(self, kind: str, worker, *args, **kwargs) -> str:
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        task = Task(task_id=task_id, kind=kind, status="pending")
        with self._lock:
            self._tasks[task_id] = task

        def runner() -> None:
            with self._lock:
                task.status = "running"
                task.progress_message = f"Running {kind}"
            try:
                result = worker(task, *args, **kwargs)
                with self._lock:
                    task.status = "completed"
                    task.finished_at = time.time()
                    task.result = result
                    task.progress_message = "done"
            except Exception as exc:  # noqa: BLE001 — propagate any failure
                with self._lock:
                    task.status = "failed"
                    task.finished_at = time.time()
                    task.error = str(exc)
                    task.progress_message = f"failed: {exc}"

        thread = threading.Thread(target=runner, daemon=True, name=task_id)
        thread.start()
        return task_id

    def get(self, task_id: str) -> Task | None:
        with self._lock:
            return self._tasks.get(task_id)

    def status_dict(self, task_id: str) -> dict | None:
        task = self.get(task_id)
        if task is None:
            return None
        with self._lock:
            elapsed = (task.finished_at or time.time()) - task.started_at
            return {
                "taskId": task.task_id,
                "kind": task.kind,
                "status": task.status,
                "progress": task.progress_message,
                "elapsedSeconds": round(elapsed, 3),
                "hasResult": task.result is not None,
                "error": task.error,
            }

    def result_json(self, task_id: str) -> str | None:
        task = self.get(task_id)
        if task is None:
            return None
        if task.status != "completed":
            return None
        if isinstance(task.result, str):
            return task.result
        return json.dumps(task.result, indent=2)

    def list_tasks(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "taskId": task.task_id,
                    "kind": task.kind,
                    "status": task.status,
                }
                for task in self._tasks.values()
            ]


# Singleton used by server.py
manager = TaskManager()


# ── Worker implementations ─────────────────────────────────────────────


def analyze_project_worker(task: Task, directory: str, checks: str, jobs: int) -> str:
    """Background worker: runs `astharbor analyze` on a project directory."""
    task.progress_message = f"invoking astharbor analyze on {directory}"
    extra_args_parts: list[str] = []
    if checks:
        extra_args_parts.append(f"--checks={checks}")
    if jobs > 1:
        extra_args_parts.append(f"--jobs={jobs}")
    extra_args = " ".join(extra_args_parts)
    raw = cli_bridge.run_analyze(directory, fmt="json", extra_args=extra_args)
    task.progress_message = "parsing results"
    parsed = json.loads(raw)
    result = AnalysisResult.model_validate(parsed)
    cache.store(result)
    return result.model_dump_json(by_alias=True, indent=2)
