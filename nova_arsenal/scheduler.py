"""
Scheduled / Continuous Scanning Module.

Provides cron-based scheduling for recurring security scans
and automated engagement execution.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


class ScheduleStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class CronExpression:
    minute: str = "*"
    hour: str = "*"
    day_of_month: str = "*"
    month: str = "*"
    day_of_week: str = "*"

    @classmethod
    def parse(cls, expression: str) -> "CronExpression":
        parts = expression.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {expression}. Expected 5 fields.")

        return cls(
            minute=parts[0],
            hour=parts[1],
            day_of_month=parts[2],
            month=parts[3],
            day_of_week=parts[4],
        )

    def matches(self, dt: datetime) -> bool:
        return (
            self._field_matches(self.minute, dt.minute)
            and self._field_matches(self.hour, dt.hour)
            and self._field_matches(self.day_of_month, dt.day)
            and self._field_matches(self.month, dt.month)
            and self._field_matches(self.day_of_week, dt.weekday())
        )

    def _field_matches(self, field: str, value: int) -> bool:
        if field == "*":
            return True
        if "/" in field:
            base, step = field.split("/")
            if base == "*":
                return value % int(step) == 0
            return value >= int(base) and (value - int(base)) % int(step) == 0
        if "," in field:
            return value in [int(x) for x in field.split(",")]
        if "-" in field:
            low, high = field.split("-")
            return int(low) <= value <= int(high)
        return int(field) == value

    def next_match(self, from_time: Optional[datetime] = None) -> Optional[datetime]:
        dt = (from_time or datetime.now(timezone.utc)).replace(second=0, microsecond=0)

        for _ in range(525600):
            if self.matches(dt):
                return dt
            dt += timedelta(minutes=1)

        return None


@dataclass
class ScheduleEntry:
    name: str
    cron: str
    target: str
    task_type: str = "full_scan"
    objective: str = "Find and exploit all critical vulnerabilities"
    max_steps: int = 20
    status: ScheduleStatus = ScheduleStatus.ACTIVE
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    last_result: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "cron": self.cron,
            "target": self.target,
            "task_type": self.task_type,
            "objective": self.objective,
            "max_steps": self.max_steps,
            "status": self.status.value,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "tags": self.tags,
        }


@dataclass
class ScheduleRunResult:
    entry_name: str
    start_time: datetime
    end_time: datetime
    success: bool
    findings_count: int = 0
    error: str = ""
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_name": self.entry_name,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "success": self.success,
            "findings_count": self.findings_count,
            "error": self.error,
            "summary": self.summary,
        }


RunCallback = Callable[[ScheduleEntry], Coroutine[Any, Any, ScheduleRunResult]]


class NovaScheduler:
    """
    Cron-based scheduler for recurring scans.

    Maintains a list of ScheduleEntry objects and runs them
    according to their cron expressions. Fires callbacks when
    a scheduled task is due.
    """

    def __init__(self) -> None:
        self._entries: List[ScheduleEntry] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._run_history: List[ScheduleRunResult] = []
        self._callbacks: List[RunCallback] = []

    def add_callback(self, callback: RunCallback) -> None:
        self._callbacks.append(callback)

    def remove_callback(self, callback: RunCallback) -> None:
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def add_entry(self, entry: ScheduleEntry) -> None:
        cron = CronExpression.parse(entry.cron)
        entry.next_run = cron.next_match()
        self._entries.append(entry)
        logger.info(f"Added schedule: {entry.name} ({entry.cron}) - next run: {entry.next_run}")

    def remove_entry(self, name: str) -> bool:
        for i, entry in enumerate(self._entries):
            if entry.name == name:
                self._entries.pop(i)
                logger.info(f"Removed schedule: {name}")
                return True
        return False

    def get_entry(self, name: str) -> Optional[ScheduleEntry]:
        for entry in self._entries:
            if entry.name == name:
                return entry
        return None

    def list_entries(self) -> List[ScheduleEntry]:
        return self._entries.copy()

    def pause_entry(self, name: str) -> bool:
        entry = self.get_entry(name)
        if entry:
            entry.status = ScheduleStatus.PAUSED
            return True
        return False

    def resume_entry(self, name: str) -> bool:
        entry = self.get_entry(name)
        if entry:
            entry.status = ScheduleStatus.ACTIVE
            cron = CronExpression.parse(entry.cron)
            entry.next_run = cron.next_match()
            return True
        return False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Scheduler started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Scheduler stopped")

    def get_history(self, limit: int = 10) -> List[ScheduleRunResult]:
        return self._run_history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        active = sum(1 for e in self._entries if e.status == ScheduleStatus.ACTIVE)
        total_runs = sum(e.run_count for e in self._entries)
        total_findings = sum(
            e.last_result.get("findings_count", 0)
            for e in self._entries
            if e.last_result
        )

        return {
            "total_entries": len(self._entries),
            "active_entries": active,
            "paused_entries": len(self._entries) - active,
            "total_runs": total_runs,
            "total_findings": total_findings,
            "history_count": len(self._run_history),
            "running": self._running,
        }

    async def _run_loop(self) -> None:
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                due_entries = [
                    e for e in self._entries
                    if e.status == ScheduleStatus.ACTIVE
                    and e.next_run is not None
                    and now >= e.next_run
                ]

                for entry in due_entries:
                    asyncio.create_task(self._execute_entry(entry))

                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(60)

    async def _execute_entry(self, entry: ScheduleEntry) -> None:
        start_time = datetime.now(timezone.utc)
        logger.info(f"Executing scheduled task: {entry.name} on {entry.target}")

        entry.status = ScheduleStatus.ACTIVE
        result = ScheduleRunResult(
            entry_name=entry.name,
            start_time=start_time,
            end_time=start_time,
            success=False,
        )

        try:
            for callback in self._callbacks:
                run_result = await callback(entry)
                result = run_result
                break

            entry.run_count += 1
            entry.last_run = start_time
            entry.last_result = result.to_dict() if result else None

            cron = CronExpression.parse(entry.cron)
            entry.next_run = cron.next_match(from_time=start_time)

            self._run_history.append(result)
            logger.info(f"Completed scheduled task: {entry.name} ({'success' if result.success else 'failed'})")

        except Exception as e:
            result.error = str(e)
            entry.last_result = result.to_dict()
            logger.error(f"Scheduled task failed: {entry.name}: {e}")

        entry.status = ScheduleStatus.ACTIVE
