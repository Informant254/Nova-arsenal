"""
Metasploit RPC API Client — communicates with msfrpcd REST API.

Allows Nova to:
- Create/list/management resource sessions
- Execute auxiliary and exploit modules
- Get structured results (not raw text)
- Chain modules together
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class MsfModuleResult:
    """Structured result from a Metasploit module execution."""
    module: str
    module_type: str
    status: str
    output: str
    session_id: Optional[int] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "module_type": self.module_type,
            "status": self.status,
            "output": self.output[:2000],
            "session_id": self.session_id,
            "findings": self.findings,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }


class MetasploitRPC:
    """
    REST API client for Metasploit's msfrpcd.

    Connect to msfrpcd (default port 55553) to execute modules,
    manage sessions, and collect structured results.

    Usage:
        msf = MetasploitRPC("https://127.0.0.1:55553", "pass123")
        await msf.login()
        result = await msf.execute_module(
            module="auxiliary/scanner/smb/smb_version",
            options={"RHOSTS": "10.0.0.1"}
        )
    """

    def __init__(
        self,
        host: str = "https://127.0.0.1:55553",
        password: str = "",
        token: Optional[str] = None,
        ssl_verify: bool = False,
    ) -> None:
        self.host = host.rstrip("/")
        self.password = password
        self._token = token
        self.ssl_verify = ssl_verify
        self._session_id: Optional[str] = None
        self._authenticated = False
        self._modules_cache: Dict[str, List[str]] = {}

    async def login(self) -> bool:
        """Authenticate with msfrpcd."""
        try:
            import aiohttp

            payload = {
                "jsonrpc": "2.0",
                "method": "auth.login",
                "params": [self.password],
                "id": 1,
            }

            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=self.ssl_verify)
            ) as session:
                async with session.post(
                    f"{self.host}/api/v1/auth/login",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        logger.error(f"MSF RPC login failed: {resp.status}")
                        return False

                    data = await resp.json()
                    if "token" in data:
                        self._token = data["token"]
                        self._authenticated = True
                        logger.info("MSF RPC authenticated")
                        return True

            # Fallback: try legacy API
            data = await self._rpc_call("auth.login", [self.password])
            if isinstance(data, dict) and "result" in data:
                self._token = str(data.get("result", ""))
                self._authenticated = True
                return True

            return False
        except ImportError:
            logger.warning("aiohttp not installed; MetasploitRPC disabled")
            return False
        except Exception as e:
            logger.error(f"MSF RPC login error: {e}")
            return False

    async def _rpc_call(self, method: str, params: List[Any] = None) -> Dict[str, Any]:
        """Make a JSON-RPC call to msfrpcd."""
        import aiohttp

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": 1,
        }

        headers = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=self.ssl_verify)
        ) as session:
            async with session.post(
                f"{self.host}/api/v1/jsonrpc",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status != 200:
                    logger.error(f"MSF RPC call failed ({method}): {resp.status}")
                    return {"error": f"HTTP {resp.status}"}
                return await resp.json()

    async def get_modules(self, module_type: str = "auxiliary") -> List[str]:
        """List available modules of a given type."""
        if module_type in self._modules_cache:
            return self._modules_cache[module_type]

        try:
            data = await self._rpc_call(f"module.{module_type}")
            if isinstance(data, dict):
                modules = data.get("modules", data.get("result", []))
                if isinstance(modules, list):
                    self._modules_cache[module_type] = modules
                    return modules
        except Exception as e:
            logger.error(f"Error listing MSF {module_type} modules: {e}")
        return []

    async def execute_module(
        self,
        module: str,
        module_type: str = "auxiliary",
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> MsfModuleResult:
        """Execute a Metasploit module and return structured results."""
        options = options or {}
        result = MsfModuleResult(module=module, module_type=module_type, status="failed")

        try:
            import aiohttp

            start = datetime.now(timezone.utc)

            # Check module exists
            mod_path = f"{module_type}/{module}" if "/" not in module else module

            exec_payload = {
                "jsonrpc": "2.0",
                "method": "module.execute",
                "params": [mod_path, options],
                "id": 1,
            }

            headers = {}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"

            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=self.ssl_verify)
            ) as session:
                async with session.post(
                    f"{self.host}/api/v1/jsonrpc",
                    json=exec_payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status != 200:
                        result.output = f"HTTP {resp.status}: {await resp.text()}"
                        return result

                    data = await resp.json()
                    result.duration_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000

                    if "error" in data:
                        result.output = str(data["error"])
                        return result

                    result.status = "completed"
                    raw = data.get("result", data)

                    if isinstance(raw, dict):
                        result.output = raw.get("message", json.dumps(raw, indent=2))
                        result.session_id = raw.get("session_id")

                        # Extract findings from output
                        findings = self._extract_findings(raw, mod_path)
                        result.findings = findings
                    else:
                        result.output = str(raw)

        except asyncio.TimeoutError:
            result.output = f"Module execution timed out after {timeout}s"
        except ImportError:
            result.output = "aiohttp not installed"
        except Exception as e:
            result.output = f"Execution error: {e}"
            logger.error(f"Error executing MSF module {module}: {e}")

        return result

    def _extract_findings(
        self, raw: Dict[str, Any], module: str
    ) -> List[Dict[str, Any]]:
        """Extract security findings from module output."""
        findings = []
        output_text = json.dumps(raw).lower()

        vuln_indicators = {
            "vulnerable": "high",
            "exploit": "critical",
            "open": "medium",
            "credentials": "high",
            "password": "medium",
            "session opened": "critical",
        }

        for indicator, severity in vuln_indicators.items():
            if indicator in output_text:
                findings.append({
                    "title": f"MSF {module}: {indicator.title()}",
                    "severity": severity,
                    "module": module,
                    "indicator": indicator,
                })

        return findings

    async def create_session(self, module: str, options: Dict[str, Any]) -> Optional[int]:
        """Execute an exploit module and return the session ID if successful."""
        result = await self.execute_module(module, "exploit", options)
        return result.session_id

    async def run_module_group(
        self, modules: List[str], shared_options: Optional[Dict[str, Any]] = None
    ) -> List[MsfModuleResult]:
        """Run multiple modules and collect all results."""
        results = []
        shared_options = shared_options or {}
        for mod in modules:
            module_type = "auxiliary"
            if mod.startswith("exploit/"):
                module_type = "exploit"
                mod = mod.replace("exploit/", "", 1)

            result = await self.execute_module(mod, module_type, shared_options)
            results.append(result)
        return results

    async def get_sessions(self) -> Dict[int, Dict[str, Any]]:
        """List active Meterpreter sessions."""
        try:
            data = await self._rpc_call("session.list")
            if isinstance(data, dict):
                raw = data.get("result", data)
                if isinstance(raw, dict):
                    return {int(k): v for k, v in raw.items()}
        except Exception as e:
            logger.error(f"Error listing MSF sessions: {e}")
        return {}

    async def write_report(self, data: Dict[str, Any]) -> str:
        """Write output to msfrpcd for report generation."""
        try:
            result = await self._rpc_call("core.report", [data])
            return json.dumps(result, indent=2)
        except Exception as e:
            logger.error(f"Error writing MSF report: {e}")
            return str(e)
