"""
Burp Suite REST API Client.

Communicates with Burp Suite's REST API (Burp Extender API or PortSwigger's REST API).

Allows Nova to:
- Start and manage scans
- Pull findings/issues
- Configure extensions and scope
- Generate reports
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BurpIssue:
    """A security issue found by Burp Suite."""
    name: str
    severity: str
    confidence: str
    url: str
    type_index: int
    description: str
    remediation: str
    path: str = ""
    evidence: str = ""
    tool_used: str = "burp"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "type_index": self.type_index,
            "description": self.description[:500],
            "remediation": self.remediation[:500],
            "path": self.path,
            "evidence": self.evidence[:500],
            "tool_used": self.tool_used,
        }


@dataclass
class BurpScanJob:
    """Represents a scan job in Burp."""
    scan_id: str
    url: str
    status: str
    issues: List[BurpIssue] = field(default_factory=list)
    progress: int = 0
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "url": self.url,
            "status": self.status,
            "issues": [i.to_dict() for i in self.issues],
            "progress": self.progress,
            "started_at": self.started_at,
        }


class BurpAPI:
    """
    REST API client for Burp Suite.

    Supports two API modes:
    1. Burp's built-in REST API (PortSwigger) — REST API + GraphQL
    2. Burp Extender API via custom REST extension

    Usage:
        burp = BurpAPI("http://127.0.0.1:1337", api_key="secret")
        job = await burp.start_scan("https://example.com")
        issues = await burp.get_issues(job.scan_id)
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:1337",
        api_key: Optional[str] = None,
        api_version: str = "v0.1",
        timeout: int = 300,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_version = api_version
        self.timeout = timeout
        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    async def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Make an HTTP request to Burp's REST API."""
        try:
            import aiohttp

            url = f"{self.base_url}/{self.api_version}/{path.lstrip('/')}"

            async with aiohttp.ClientSession(headers=self._headers) as session:
                async with session.request(
                    method, url, json=data,
                    timeout=aiohttp.ClientTimeout(total=timeout or self.timeout),
                ) as resp:
                    if resp.status in (200, 201):
                        return await resp.json()
                    elif resp.status == 204:
                        return {"status": "ok"}
                    else:
                        text = await resp.text()
                        logger.warning(f"Burp API {method} {path}: {resp.status} - {text[:200]}")
                        return {"error": f"HTTP {resp.status}", "detail": text[:500]}

        except ImportError:
            logger.warning("aiohttp not installed; BurpAPI disabled")
            return {"error": "aiohttp not installed"}
        except Exception as e:
            logger.error(f"Burp API request error ({method} {path}): {e}")
            return {"error": str(e)}

    async def check_health(self) -> bool:
        """Check if Burp Suite API is accessible."""
        result = await self._request("GET", "")
        return result is not None and "error" not in result

    async def start_scan(
        self,
        url: str,
        scope: Optional[Dict[str, Any]] = None,
        scan_configurations: Optional[List[str]] = None,
    ) -> BurpScanJob:
        """Start an active scan against a URL."""
        payload = {
            "urls": [url],
            "scope": scope or {"include": [{"rule": f".*{url}.*"}], "type": "SimpleScope"},
            "scan_configurations": scan_configurations or [],
        }

        result = await self._request("POST", "scan", payload)
        if result and "scan_id" in result:
            job = BurpScanJob(
                scan_id=str(result["scan_id"]),
                url=url,
                status="pending",
            )
            logger.info(f"Burp scan started: {job.scan_id} for {url}")
            return job

        # Fallback: try GraphQL endpoint
        return await self._start_scan_graphql(url, scope)

    async def _start_scan_graphql(
        self,
        url: str,
        scope: Optional[Dict[str, Any]] = None,
    ) -> BurpScanJob:
        """Start a scan using Burp's GraphQL endpoint."""
        mutation = """
        mutation startScan($urls: [URL!]!) {
            start_scan(urls: $urls) {
                scan_id
                status
            }
        }
        """
        result = await self._request("POST", "graphql", {
            "query": mutation,
            "variables": {"urls": [url]},
        })

        if result and "data" in result:
            scan_data = result["data"].get("start_scan", {})
            job = BurpScanJob(
                scan_id=str(scan_data.get("scan_id", "unknown")),
                url=url,
                status=scan_data.get("status", "pending"),
            )
            logger.info(f"Burp GraphQL scan started: {job.scan_id}")
            return job

        return BurpScanJob(scan_id="error", url=url, status="failed")

    async def get_scan_status(self, scan_id: str) -> Optional[str]:
        """Get the status of a scan."""
        result = await self._request("GET", f"scan/{scan_id}")
        if result:
            return result.get("status", result.get("data", {}).get("status", "unknown"))
        return None

    async def get_issues(self, scan_id: Optional[str] = None) -> List[BurpIssue]:
        """Get all issues/findings from scans."""
        path = f"scan/{scan_id}/issues" if scan_id else "issues"
        result = await self._request("GET", path)

        issues = []
        if not result:
            return issues

        raw = result.get("data", result.get("issues", result))

        if isinstance(raw, list):
            for item in raw:
                issue = self._parse_issue(item)
                if issue:
                    issues.append(issue)

        logger.info(f"Retrieved {len(issues)} Burp issues")
        return issues

    def _parse_issue(self, item: Dict[str, Any]) -> Optional[BurpIssue]:
        """Parse a raw Burp issue into a structured BurpIssue."""
        try:
            return BurpIssue(
                name=item.get("name", item.get("title", "Unknown Issue")),
                severity=item.get("severity", "medium").lower(),
                confidence=item.get("confidence", "certain").lower(),
                url=item.get("url", item.get("path", "")),
                type_index=item.get("type_index", item.get("type", 0)),
                description=item.get("description", item.get("issueDetail", "")),
                remediation=item.get("remediation", item.get("remediationDetail", "")),
                path=item.get("path", ""),
                evidence=item.get("evidence", item.get("request", "")),
            )
        except Exception as e:
            logger.warning(f"Failed to parse Burp issue: {e}")
            return None

    async def configure_scope(self, include: List[str], exclude: Optional[List[str]] = None) -> bool:
        """Configure Burp's target scope."""
        payload = {
            "include": [{"rule": f".*{url}.*", "type": "SimpleScope"} for url in include],
            "exclude": [{"rule": f".*{url}.*", "type": "SimpleScope"} for url in (exclude or [])],
        }
        result = await self._request("PUT", "scope", payload)
        success = result is not None and "error" not in result
        if success:
            logger.info(f"Burp scope configured: {include}")
        return success

    async def get_scan_queue(self) -> List[Dict[str, Any]]:
        """List all scans in the queue."""
        result = await self._request("GET", "scan")
        if result:
            raw = result.get("data", result.get("scans", result))
            if isinstance(raw, list):
                return raw
        return []

    async def generate_report(
        self,
        scan_id: Optional[str] = None,
        format: str = "html",
    ) -> Optional[str]:
        """Generate a report and return the file path."""
        payload = {"format": format}
        if scan_id:
            payload["scan_id"] = scan_id

        result = await self._request("POST", "report", payload)
        if result:
            return result.get("file_path", result.get("data", {}).get("file_path"))
        return None
