import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from mcp import MCPServer, Tool, Resource, Prompt, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False


class NovaMcpServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        self.host = host
        self.port = port
        self._mcp_server: Optional[Any] = None
        self._tools: Dict[str, Any] = {}
        self._resources: Dict[str, Any] = {}

    def register_all_tools(self) -> None:
        self._register_tool(
            "nmap_scan",
            "Run an Nmap scan against a target",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "ports": {"type": "string", "description": "Port range (e.g. '80,443' or '1-1000')"},
                    "flags": {"type": "string", "description": "Additional nmap flags (e.g. '-sV -sC')"},
                },
                "required": ["target"],
            },
        )
        self._register_tool(
            "burp_scan",
            "Start a Burp Suite scan against a target URL",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to scan"},
                    "scope": {"type": "array", "items": {"type": "string"}, "description": "URL scope patterns"},
                },
                "required": ["url"],
            },
        )
        self._register_tool(
            "sqlmap_scan",
            "Run SQLmap against a target URL",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "data": {"type": "string", "description": "POST data string"},
                    "level": {"type": "integer", "description": "Test level (1-5)", "default": 3},
                    "risk": {"type": "integer", "description": "Risk level (1-3)", "default": 2},
                },
                "required": ["url"],
            },
        )
        self._register_tool(
            "osint_investigate",
            "Run OSINT chain investigation on a domain",
            input_schema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain"},
                    "phases": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "OSINT phases to run",
                    },
                },
                "required": ["domain"],
            },
        )
        self._register_tool(
            "cve_lookup",
            "Look up CVEs for a detected service",
            input_schema={
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Service type (http, smb, ssh, etc.)"},
                    "version": {"type": "string", "description": "Service version string"},
                },
                "required": ["service"],
            },
        )
        self._register_tool(
            "payload_generate",
            "Generate a payload (reverse shell, webshell, etc.)",
            input_schema={
                "type": "object",
                "properties": {
                    "payload_type": {
                        "type": "string",
                        "enum": ["reverse_shell", "bind_shell", "webshell", "download_exec"],
                        "description": "Type of payload",
                    },
                    "lhost": {"type": "string", "description": "Listener IP"},
                    "lport": {"type": "integer", "description": "Listener port"},
                    "language": {
                        "type": "string",
                        "enum": ["bash", "python", "perl", "ruby", "powershell", "netcat"],
                        "description": "Payload language",
                    },
                },
                "required": ["payload_type", "lhost", "lport"],
            },
        )
        self._register_tool(
            "compliance_check",
            "Map findings to compliance frameworks",
            input_schema={
                "type": "object",
                "properties": {
                    "finding_type": {"type": "string", "description": "Type of finding"},
                    "description": {"type": "string", "description": "Finding description"},
                    "severity": {"type": "string", "description": "Finding severity (low, medium, high, critical)", "default": "medium"},
                },
                "required": ["finding_type"],
            },
        )
        self._register_tool(
            "ctf_solve",
            "Solve a CTF challenge automatically",
            input_schema={
                "type": "object",
                "properties": {
                    "challenge_name": {"type": "string", "description": "Challenge name or identifier"},
                    "challenge_type": {
                        "type": "string",
                        "enum": ["web", "crypto", "stego", "forensics", "reversing", "pwn", "osint", "recon", "misc"],
                        "description": "Type of CTF challenge",
                    },
                    "url": {"type": "string", "description": "Challenge URL"},
                    "files": {"type": "array", "items": {"type": "string"}, "description": "Challenge file paths"},
                },
                "required": ["challenge_name"],
            },
        )
        self._register_tool(
            "swarm_scan",
            "Run multi-agent swarm scan against a target",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "roles": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Agent roles to include",
                    },
                },
                "required": ["target"],
            },
        )
        self._register_tool(
            "zeroday_hunt",
            "High-speed zero-day candidate pipeline (surface, variants, static, fuzz plan, crash triage). Authorized use only.",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Authorized target"},
                    "authorization_ref": {
                        "type": "string",
                        "description": "Engagement / RoE / ticket ID",
                    },
                    "authorized": {
                        "type": "boolean",
                        "description": "Must be true to run",
                        "default": False,
                    },
                    "services": {
                        "type": "object",
                        "description": "Optional service map from recon",
                    },
                    "max_candidates": {
                        "type": "integer",
                        "description": "Max ranked candidates",
                        "default": 50,
                    },
                },
                "required": ["target", "authorization_ref", "authorized"],
            },
        )

    def _register_tool(self, name: str, description: str,
                       input_schema: Dict[str, Any]) -> None:
        self._tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        }

    def register_all_resources(self) -> None:
        self._register_resource(
            "nova://findings",
            "All discovered security findings",
            "application/json",
        )
        self._register_resource(
            "nova://agents",
            "Active and completed agents",
            "application/json",
        )
        self._register_resource(
            "nova://compliance",
            "Compliance mapping summary",
            "application/json",
        )
        self._register_resource(
            "nova://keys",
            "E2E encryption key status",
            "application/json",
        )

    def _register_resource(self, uri: str, description: str,
                           mime_type: str) -> None:
        self._resources[uri] = {
            "uri": uri,
            "description": description,
            "mimeType": mime_type,
        }

    def get_tool_list(self) -> List[Dict[str, Any]]:
        return list(self._tools.values())

    def get_resource_list(self) -> List[Dict[str, Any]]:
        return list(self._resources.values())

    async def handle_tool_call(self, tool_name: str,
                               arguments: Dict[str, Any]) -> str:
        from nova_arsenal.intelligence import CveResearch, OsintChain
        from nova_arsenal.payload_generator import PayloadGenerator
        from nova_arsenal.compliance import ComplianceMapper
        from nova_arsenal.swarm import SwarmOrchestrator
        from nova_arsenal.ctf_solver import CtfSolver, ChallengeType
        from nova_arsenal.integrations import NmapParser

        try:
            if tool_name == "nmap_scan":
                target = str(arguments["target"]).strip()
                ports = str(arguments.get("ports", "")).strip()
                flags = str(arguments.get("flags", "-sV -sC")).split()
                allowed_flags = {"-sV", "-sC", "-sT", "-Pn", "-n", "-O", "--version-light"}
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", target):
                    return json.dumps({"error": "Invalid nmap target"})
                if ports and not re.fullmatch(r"[0-9,-]+", ports):
                    return json.dumps({"error": "Invalid nmap port specification"})
                if any(flag not in allowed_flags for flag in flags):
                    return json.dumps({"error": "Unsupported nmap flag"})

                command = ["nmap", *flags, target]
                if ports:
                    command.extend(["-p", ports])
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                if getattr(proc, "returncode", 0) != 0:
                    return json.dumps({"error": stderr.decode(errors="replace")[:1000] or "nmap failed"})
                return stdout.decode(errors="replace")[:5000]

            elif tool_name == "osint_investigate":
                chain = OsintChain()
                result = await chain.investigate(arguments["domain"])
                return json.dumps({
                    "subdomains": result.subdomains[:20],
                    "emails": result.emails[:20],
                    "technologies": result.technologies,
                    "summary": result.summary,
                }, indent=2)

            elif tool_name == "cve_lookup":
                researcher = CveResearch()
                service = arguments["service"]
                version = arguments.get("version", "")
                result = await researcher.research(service, version, 0)
                return json.dumps({
                    "cves": [c.to_dict() for c in result.cves],
                    "risk_score": result.risk_score,
                    "has_exploit": result.has_exploit,
                    "cve_count": len(result.cves),
                }, indent=2)

            elif tool_name == "payload_generate":
                from nova_arsenal.payload_generator import PayloadType, PayloadLanguage
                generator = PayloadGenerator()
                ptype_str = arguments["payload_type"]
                lhost = arguments["lhost"]
                lport = arguments["lport"]
                lang_str = arguments.get("language", "")

                try:
                    ptype_enum = PayloadType(ptype_str)
                except ValueError:
                    return json.dumps({"error": f"Invalid payload type: {ptype_str}"})

                if lang_str:
                    try:
                        lang_enum = PayloadLanguage(lang_str)
                    except ValueError:
                        return json.dumps({"error": f"Invalid language: {lang_str}"})
                    payload = generator.generate(ptype_enum, lang_enum, lhost, lport)
                    return json.dumps({
                        ptype_str: {lang_str: payload.code},
                        "description": payload.description,
                    }, indent=2)
                else:
                    chain = generator.generate_chain(lhost, lport)
                    result = {}
                    for p in chain:
                        pt_key = p.payload_type.value
                        if pt_key not in result:
                            result[pt_key] = {}
                        result[pt_key][p.language.value] = p.code
                    return json.dumps(result, indent=2)

            elif tool_name == "compliance_check":
                mapper = ComplianceMapper()
                severity = arguments.get("severity", "medium")
                result = mapper.map_finding(
                    arguments["finding_type"],
                    arguments.get("description", ""),
                    severity,
                )
                return json.dumps({
                    "controls": [c.to_dict() for c in result.controls],
                    "frameworks_affected": list(result.frameworks_affected),
                }, indent=2)

            elif tool_name == "ctf_solve":
                solver = CtfSolver()
                ctype_str = arguments.get("challenge_type", "web")
                try:
                    ctype = ChallengeType(ctype_str)
                except ValueError:
                    ctype = ChallengeType.WEB
                challenge = solver.add_challenge(
                    name=arguments["challenge_name"],
                    challenge_type=ctype,
                    url=arguments.get("url", ""),
                    files=arguments.get("files", []),
                )
                flag = await solver.solve_challenge(challenge)
                if flag:
                    return json.dumps({
                        "solved": True,
                        "flag": flag.flag,
                        "method": flag.method,
                        "confidence": flag.confidence,
                    }, indent=2)
                return json.dumps({"solved": False, "reason": "Flag not found"}, indent=2)

            elif tool_name == "swarm_scan":
                roles = arguments.get("roles")
                swarm = SwarmOrchestrator.create_swarm(
                    target=arguments["target"],
                    roles=roles,
                    enable_zeroday=arguments.get("enable_zeroday", True),
                    zeroday_authorized=bool(arguments.get("authorized", False)),
                    zeroday_auth_ref=str(arguments.get("authorization_ref") or ""),
                    execute_live_fuzz=bool(arguments.get("execute_live_fuzz", False)),
                    dry_run_fuzz=bool(arguments.get("dry_run_fuzz", True)),
                )
                result = await swarm.run_swarm()
                return json.dumps({
                    "findings": [
                        {
                            "title": f.title,
                            "severity": f.severity,
                            "agent_role": f.agent_role.value if hasattr(f.agent_role, "value") else f.agent_role,
                            "confidence": f.confidence,
                        }
                        for f in result.findings
                    ],
                    "summary": result.summary,
                    "phases": result.phases,
                    "zeroday_candidates": (
                        (result.zeroday_hunt or {}).get("candidate_count")
                        if result.zeroday_hunt
                        else 0
                    ),
                }, indent=2)

            elif tool_name == "zeroday_hunt":
                from nova_arsenal.zeroday import ZeroDayHunter, ZeroDayHuntConfig

                if not arguments.get("authorized"):
                    return json.dumps({
                        "error": "zeroday_hunt requires authorized=true and a valid authorization_ref",
                    })
                hunter = ZeroDayHunter()
                result = await hunter.hunt(
                    target=arguments["target"],
                    services=arguments.get("services") or {},
                    config=ZeroDayHuntConfig(
                        authorized=True,
                        authorization_ref=str(arguments.get("authorization_ref") or ""),
                        max_candidates=int(arguments.get("max_candidates") or 50),
                    ),
                )
                return json.dumps(result.to_dict(), indent=2)

            else:
                return json.dumps({"error": f"Unknown tool: {tool_name}"})

        except Exception as e:
            logger.error(f"MCP tool error: {e}")
            return json.dumps({"error": str(e)})

    async def run_stdio(self) -> None:
        if not MCP_AVAILABLE:
            logger.warning("MCP package not installed — running in fallback JSON mode")
            await self._run_fallback()
            return

        self.register_all_tools()
        self.register_all_resources()

        mcp_tools = []
        for t in self._tools.values():
            mcp_tools.append(Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["inputSchema"],
            ))

        mcp_resources = []
        for r in self._resources.values():
            mcp_resources.append(Resource(
                uri=r["uri"],
                description=r["description"],
                mimeType=r["mimeType"],
            ))

        self._mcp_server = MCPServer(
            name="nova-arsenal",
            version="1.0.0",
            tools=mcp_tools,
            resources=mcp_resources,
            handler=self.handle_tool_call,
        )
        await self._mcp_server.run()

    async def _run_fallback(self) -> None:
        import sys
        logger.info("Starting MCP fallback mode (JSON-RPC over stdio)")
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, sys.stdin.readline
                )
                if not line:
                    break
                request = json.loads(line)
                req_id = request.get("id")
                method = request.get("method", "")
                params = request.get("params", {})

                if method == "tools/list":
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"tools": self.get_tool_list()},
                    }
                elif method == "tools/call":
                    result = await self.handle_tool_call(
                        params.get("name", ""),
                        params.get("arguments", {}),
                    )
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": result}]},
                    }
                elif method == "resources/list":
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"resources": self.get_resource_list()},
                    }
                elif method == "initialize":
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "serverInfo": {
                                "name": "nova-arsenal",
                                "version": "1.0.0",
                            },
                            "capabilities": {
                                "tools": {},
                                "resources": {},
                            },
                        },
                    }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Method not found: {method}"},
                    }

                line = json.dumps(response) + "\n"
                sys.stdout.write(line)
                sys.stdout.flush()
            except json.JSONDecodeError:
                continue
            except EOFError:
                break
            except Exception as e:
                logger.error(f"MCP fallback error: {e}")


async def run_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = NovaMcpServer(host=host, port=port)
    await server.run_stdio()
