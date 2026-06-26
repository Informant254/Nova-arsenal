"""
SQLmap API Client — communicates with sqlmapapi.py (REST API mode).

Allows Nova to:
- Start new scan tasks
- Set target URLs, POST data, headers
- Run checks for SQL injection, XSS, etc.
- Get structured findings (injection points, payloads, DB info)
- Poll task status and results
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SqlmapFinding:
    """A SQL injection finding from sqlmap."""
    url: str
    parameter: str
    technique: str
    title: str
    payload: str = ""
    dbms: str = ""
    severity: str = "high"
    vector: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "technique": self.technique,
            "title": self.title,
            "payload": self.payload[:200],
            "dbms": self.dbms,
            "severity": self.severity,
            "vector": self.vector[:200],
        }


@dataclass
class SqlmapTask:
    """A sqlmap scan task."""
    task_id: str
    url: str
    status: str = "not_running"
    progress: int = 0
    findings: List[SqlmapFinding] = field(default_factory=list)
    dbms: str = ""
    os: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_complete(self) -> bool:
        return self.status == "terminated"

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "url": self.url,
            "status": self.status,
            "progress": self.progress,
            "findings": [f.to_dict() for f in self.findings],
            "dbms": self.dbms,
            "os": self.os,
            "is_complete": self.is_complete,
            "has_findings": self.has_findings,
            "created_at": self.created_at,
        }


class SQLmapAPI:
    """
    REST API client for sqlmapapi.py.

    sqlmap can run in API server mode:
        sqlmapapi.py -s -H 0.0.0.0 -p 8775

    Usage:
        sqlmap = SQLmapAPI("http://127.0.0.1:8775")
        task = await sqlmap.new_task("http://target.com/page?id=1")
        status = await sqlmap.poll_task(task.task_id)
    """

    def __init__(
        self,
        server_url: str = "http://127.0.0.1:8775",
        timeout: int = 300,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self._admin_token: Optional[str] = None

    async def _get_admin_token(self) -> Optional[str]:
        """Get admin token from sqlmap API server."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.server_url}/admin/list",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._admin_token = data.get("admin_token")
                        return self._admin_token
            return None
        except ImportError:
            logger.warning("aiohttp not installed; SQLmapAPI disabled")
            return None
        except Exception as e:
            logger.error(f"Error getting sqlmap admin token: {e}")
            return None

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Make HTTP request to sqlmap API."""
        try:
            import aiohttp

            url = f"{self.server_url}/{endpoint.lstrip('/')}"

            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method, url, json=data,
                    timeout=aiohttp.ClientTimeout(total=timeout or self.timeout),
                ) as resp:
                    if resp.status in (200, 201):
                        return await resp.json()
                    else:
                        text = await resp.text()
                        logger.warning(f"SQLmap API {method} {endpoint}: {resp.status}")
                        return {"error": f"HTTP {resp.status}", "detail": text[:500]}

        except ImportError:
            return {"error": "aiohttp not installed"}
        except Exception as e:
            logger.error(f"SQLmap API error ({method} {endpoint}): {e}")
            return {"error": str(e)}

    async def new_task(self, url: str, options: Optional[Dict[str, Any]] = None) -> SqlmapTask:
        """Create a new sqlmap scan task."""
        # Create task
        result = await self._request("POST", "task/new")
        if not result or "error" in result:
            logger.error(f"Failed to create sqlmap task: {result}")
            return SqlmapTask(task_id="error", url=url, status="failed")

        task_id = result.get("taskid", "")
        if not task_id:
            return SqlmapTask(task_id="error", url=url, status="failed")

        # Set task options (URL is mandatory)
        scan_options = {
            "url": url,
            **self._build_options(options or {}),
        }

        set_result = await self._request(
            "POST", f"option/{task_id}/set", scan_options
        )
        if set_result and "error" in set_result:
            logger.warning(f"Error setting sqlmap options: {set_result}")

        # Start scan
        start_result = await self._request(
            "POST", f"scan/{task_id}/start",
            {},
            timeout=30,
        )

        if start_result and start_result.get("success"):
            logger.info(f"SQLmap scan started: task={task_id}, url={url}")
            return SqlmapTask(task_id=task_id, url=url, status="running")

        logger.error(f"Failed to start sqlmap scan: {start_result}")
        return SqlmapTask(task_id=task_id, url=url, status="failed")

    def _build_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Build sqlmap API options dict from user params."""
        built = {}

        # Basic scan options
        option_map = {
            "data": "data",
            "cookie": "cookie",
            "user_agent": "userAgent",
            "headers": "headers",
            "method": "method",
            "threads": "threads",
            "level": "level",
            "risk": "risk",
            "dbms": "dbms",
            "technique": "technique",
            "batch": "batch",
            "random_agent": "randomAgent",
        }

        for user_key, api_key in option_map.items():
            if user_key in options:
                built[api_key] = options[user_key]

        # Default: batch mode (non-interactive)
        if "batch" not in built:
            built["batch"] = True

        return built

    async def poll_task(self, task_id: str) -> Optional[SqlmapTask]:
        """Poll the status of a running task."""
        status_result = await self._request("GET", f"scan/{task_id}/status")

        if not status_result or "error" in status_result:
            return None

        status_data = status_result.get("data", status_result)
        status = status_data.get("status", "unknown")

        # Get task data (includes findings)
        data_result = await self._request("GET", f"scan/{task_id}/data")
        task_data = data_result.get("data", {}) if data_result else {}

        # Build task
        task = SqlmapTask(
            task_id=task_id,
            url=task_data.get("url", ""),
            status=status,
            progress=status_data.get("progress", 0),
            data=task_data,
        )

        # Parse findings from data
        if "data" in task_data:
            items = task_data["data"]
            if isinstance(items, list):
                task.findings = self._parse_findings(items, task.url)

        # Extract DB and OS info
        if task_data.get("dbms"):
            task.dbms = str(task_data["dbms"])
        if task_data.get("os"):
            task.os = str(task_data["os"])

        return task

    def _parse_findings(
        self, items: List[Dict[str, Any]], url: str
    ) -> List[SqlmapFinding]:
        """Parse raw sqlmap data items into structured findings."""
        findings = []

        technique_names = {
            "1": "Boolean-based blind",
            "2": "Error-based",
            "3": "Time-based blind",
            "4": "Union query",
            "5": "Stacked queries",
            "6": "Out-of-band",
            "7": "Inline queries",
        }

        for item in items:
            if not isinstance(item, dict):
                continue

            parameter = item.get("parameter", item.get("place", "unknown"))
            technique = technique_names.get(str(item.get("technique", "")), "unknown")
            payload = item.get("payload", "")
            dbms = item.get("dbms", "")
            title = item.get("title", f"SQL injection in '{parameter}' via {technique}")

            if technique or payload:
                findings.append(SqlmapFinding(
                    url=url,
                    parameter=str(parameter),
                    technique=str(technique),
                    title=str(title),
                    payload=str(payload)[:500],
                    dbms=str(dbms),
                    severity="high",
                    vector=str(item.get("vector", "")),
                ))

        return findings

    async def wait_for_completion(
        self, task_id: str, poll_interval: float = 2.0, max_time: int = 300
    ) -> SqlmapTask:
        """Poll task until complete with progress tracking."""
        start = datetime.now(timezone.utc)
        last_task: Optional[SqlmapTask] = None

        while (datetime.now(timezone.utc) - start).total_seconds() < max_time:
            task = await self.poll_task(task_id)
            if task is None:
                break

            last_task = task

            if task.is_complete:
                logger.info(
                    f"SQLmap scan {task_id} complete: "
                    f"{len(task.findings)} findings, DBMS={task.dbms}"
                )
                return task

            await asyncio.sleep(poll_interval)

        # Timeout or error
        if last_task:
            last_task.status = "timeout"
            return last_task

        return SqlmapTask(task_id=task_id, url="", status="timeout")

    async def stop_task(self, task_id: str) -> bool:
        """Stop a running task."""
        result = await self._request("GET", f"scan/{task_id}/stop")
        return bool(result and result.get("success"))

    async def kill_task(self, task_id: str) -> bool:
        """Kill a running task."""
        result = await self._request("GET", f"scan/{task_id}/kill")
        return bool(result and result.get("success"))

    async def list_tasks(self) -> List[str]:
        """List all tasks."""
        result = await self._request("GET", "admin/list")
        if result:
            tasks = result.get("tasks", result.get("data", []))
            if isinstance(tasks, list):
                return tasks
        return []

    async def flush_tasks(self) -> bool:
        """Flush/delete all tasks."""
        token = self._admin_token or await self._get_admin_token()
        if not token:
            return False
        result = await self._request("GET", f"admin/{token}/flush")
        return bool(result and result.get("success"))
