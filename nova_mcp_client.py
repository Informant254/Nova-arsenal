#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🔌 NOVA MCP CLIENT v1.0 — Model Context Protocol Integration              ║
║                                                                              ║
║  Connects Nova to ANY MCP server — the same protocol Claude Desktop,        ║
║  Cursor, and GitHub Copilot use to talk to external tools.                  ║
║                                                                              ║
║  With this, Nova can use:                                                    ║
║  • GitHub MCP  — read/write repos, issues, PRs, search code                ║
║  • Filesystem MCP — read/write local files with path controls               ║
║  • Fetch MCP   — web fetch + HTML extraction                                ║
║  • Git MCP     — git log, diff, blame, commit history                      ║
║  • Puppeteer MCP — headless browser: click, type, screenshot, DOM          ║
║  • Postgres MCP — query databases directly                                  ║
║  • ANY community MCP server (5,000+ published)                              ║
║                                                                              ║
║  MCP tools are auto-converted to Nova Tool format, so they plug straight    ║
║  into nova_orchestrator.py agents.                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    from nova_mcp_client import MCPClient, BUILTIN_SERVERS

    # Use a built-in server
    client = MCPClient(BUILTIN_SERVERS["fetch"])
    tools  = client.discover_tools()   # returns List[Tool] for nova_orchestrator
    result = client.call_tool("fetch", {"url": "https://example.com"})

    # Use any MCP server by command
    client = MCPClient(MCPServer(
        name="my-server",
        command=["npx", "-y", "@modelcontextprotocol/server-everything"],
    ))
    tools = client.discover_tools()
"""

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Lazy import for nova_orchestrator.Tool ─────────────────────────────────────
try:
    from nova_orchestrator import Tool
except ImportError:
    @dataclass
    class Tool:  # type: ignore
        name: str
        description: str
        function: Any
        schema: Dict = field(default_factory=dict)
        def call(self, args):
            return self.function(args)


# ── MCP Server Config ──────────────────────────────────────────────────────────

@dataclass
class MCPServer:
    """Configuration for one MCP server process."""
    name:    str
    command: List[str]                    # e.g. ["npx", "-y", "@mcp/server-fetch"]
    env:     Dict[str, str] = field(default_factory=dict)
    args:    List[str]       = field(default_factory=list)
    timeout: int             = 30


# ── Built-in MCP Servers ───────────────────────────────────────────────────────

BUILTIN_SERVERS: Dict[str, MCPServer] = {
    "fetch": MCPServer(
        name="fetch",
        command=["npx", "-y", "@modelcontextprotocol/server-fetch"],
        env={},
    ),
    "filesystem": MCPServer(
        name="filesystem",
        command=["npx", "-y", "@modelcontextprotocol/server-filesystem",
                 os.path.expanduser("~")],
        env={},
    ),
    "git": MCPServer(
        name="git",
        command=["uvx", "mcp-server-git", "--repository", "."],
        env={},
    ),
    "github": MCPServer(
        name="github",
        command=["npx", "-y", "@modelcontextprotocol/server-github"],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": os.getenv("GITHUB_TOKEN", "")},
    ),
    "puppeteer": MCPServer(
        name="puppeteer",
        command=["npx", "-y", "@modelcontextprotocol/server-puppeteer"],
        env={},
    ),
    "postgres": MCPServer(
        name="postgres",
        command=["npx", "-y", "@modelcontextprotocol/server-postgres"],
        env={"POSTGRES_CONNECTION_STRING": os.getenv("DATABASE_URL", "")},
    ),
    "brave-search": MCPServer(
        name="brave-search",
        command=["npx", "-y", "@modelcontextprotocol/server-brave-search"],
        env={"BRAVE_API_KEY": os.getenv("BRAVE_API_KEY", "")},
    ),
    "memory": MCPServer(
        name="memory",
        command=["npx", "-y", "@modelcontextprotocol/server-memory"],
        env={},
    ),
    "sequential-thinking": MCPServer(
        name="sequential-thinking",
        command=["npx", "-y", "@modelcontextprotocol/server-sequential-thinking"],
        env={},
    ),
}


# ── MCP Protocol Messages ──────────────────────────────────────────────────────

def _mcp_request(method: str, params: Dict = None, req_id: int = 1) -> bytes:
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params or {},
    }) + "\n"
    return msg.encode()


def _mcp_notify(method: str, params: Dict = None) -> bytes:
    msg = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
    }) + "\n"
    return msg.encode()


# ── MCP Client ─────────────────────────────────────────────────────────────────

class MCPClient:
    """
    Connects to one MCP server via stdio transport, discovers its tools,
    and calls them. Converts MCP tools to Nova Tool objects automatically.
    """

    def __init__(self, server: MCPServer):
        self.server   = server
        self._proc:   Optional[subprocess.Popen] = None
        self._req_id  = 0
        self._tools:  List[Dict] = []
        self._lock    = threading.Lock()
        self._started = False

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start the MCP server process."""
        if self._started:
            return True
        cmd = self.server.command + self.server.args
        env = {**os.environ, **self.server.env}
        try:
            self._proc = subprocess.Popen(
                cmd, env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Initialize handshake
            self._send(_mcp_notify("notifications/initialized"))
            init_resp = self._send_recv(_mcp_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "nova-mcp-client", "version": "1.0"},
            }))
            if not init_resp:
                print(f"  ⚠️  MCP {self.server.name}: init failed")
                return False
            self._started = True
            print(f"  ✅ MCP server '{self.server.name}' started")
            return True
        except FileNotFoundError:
            print(f"  ❌ MCP {self.server.name}: command not found — {cmd[0]}")
            print(f"     Install with: npm install -g {cmd[1] if len(cmd)>1 else ''}")
            return False
        except Exception as e:
            print(f"  ❌ MCP {self.server.name}: {e}")
            return False

    def stop(self):
        """Stop the MCP server process."""
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
            self._proc    = None
            self._started = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    # ── Discovery ──────────────────────────────────────────────────────────────

    def discover_tools(self) -> List[Tool]:
        """
        Ask the MCP server for its tool list and convert to Nova Tool objects.
        Returns an empty list if the server fails to start.
        """
        if not self._started and not self.start():
            return []
        resp = self._send_recv(_mcp_request("tools/list", {}, self._next_id()))
        if not resp or "result" not in resp:
            return []
        raw_tools = resp["result"].get("tools", [])
        self._tools = raw_tools
        nova_tools  = [self._convert_tool(t) for t in raw_tools]
        print(f"  🔌 MCP '{self.server.name}': {len(nova_tools)} tools discovered")
        for t in nova_tools:
            print(f"     • {t.name}: {t.description[:60]}")
        return nova_tools

    def call_tool(self, tool_name: str, args: Dict) -> str:
        """Call a tool on the MCP server and return the text result."""
        if not self._started and not self.start():
            return f"ERROR: MCP server {self.server.name} not running"
        resp = self._send_recv(_mcp_request("tools/call", {
            "name": tool_name,
            "arguments": args,
        }, self._next_id()))
        if not resp:
            return f"ERROR: no response from MCP server"
        if "error" in resp:
            return f"ERROR: {resp['error']}"
        content = resp.get("result", {}).get("content", [])
        texts   = []
        for item in content:
            if item.get("type") == "text":
                texts.append(item.get("text", ""))
            elif item.get("type") == "image":
                texts.append(f"[IMAGE: {item.get('mimeType','?')}]")
        return "\n".join(texts) or "(empty result)"

    # ── Conversion ─────────────────────────────────────────────────────────────

    def _convert_tool(self, mcp_tool: Dict) -> Tool:
        """Convert an MCP tool descriptor to a Nova Tool."""
        name   = mcp_tool.get("name", "unknown")
        desc   = mcp_tool.get("description", "")
        schema = mcp_tool.get("inputSchema", {"type": "object", "properties": {}})
        client = self  # capture for closure

        def call_fn(args: Dict, _name=name) -> str:
            return client.call_tool(_name, args)

        return Tool(name=name, description=desc, function=call_fn, schema=schema)

    # ── I/O ────────────────────────────────────────────────────────────────────

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _send(self, data: bytes):
        if self._proc and self._proc.stdin:
            try:
                self._proc.stdin.write(data)
                self._proc.stdin.flush()
            except BrokenPipeError:
                pass

    def _send_recv(self, data: bytes, timeout: float = None) -> Optional[Dict]:
        timeout = timeout or self.server.timeout
        with self._lock:
            self._send(data)
            return self._read_response(timeout)

    def _read_response(self, timeout: float) -> Optional[Dict]:
        if not self._proc or not self._proc.stdout:
            return None
        deadline = time.time() + timeout
        buf = b""
        while time.time() < deadline:
            try:
                self._proc.stdout.settimeout(0.5)
                chunk = self._proc.stdout.readline()
                if chunk:
                    buf += chunk
                    try:
                        return json.loads(buf.decode())
                    except json.JSONDecodeError:
                        continue
            except Exception:
                time.sleep(0.1)
        return None


# ── MCPToolbox ─────────────────────────────────────────────────────────────────

class MCPToolbox:
    """
    Manages multiple MCP servers at once.
    Aggregates all tools across servers into one Nova-compatible list.
    """

    def __init__(self, server_names: List[str] = None, extra_servers: List[MCPServer] = None):
        servers = []
        for name in (server_names or []):
            if name in BUILTIN_SERVERS:
                servers.append(BUILTIN_SERVERS[name])
        servers.extend(extra_servers or [])
        self.clients = [MCPClient(s) for s in servers]
        self._all_tools: List[Tool] = []

    def start_all(self) -> "MCPToolbox":
        for c in self.clients:
            c.start()
        return self

    def stop_all(self):
        for c in self.clients:
            c.stop()

    def discover_all(self) -> List[Tool]:
        self._all_tools = []
        for c in self.clients:
            self._all_tools.extend(c.discover_tools())
        return self._all_tools

    @property
    def tools(self) -> List[Tool]:
        if not self._all_tools:
            self.discover_all()
        return self._all_tools

    def __enter__(self):
        self.start_all()
        return self

    def __exit__(self, *_):
        self.stop_all()


# ── Convenience Helpers ────────────────────────────────────────────────────────

def get_fetch_tool() -> Optional[Tool]:
    """Get the MCP fetch tool (web fetcher), or return None if unavailable."""
    try:
        client = MCPClient(BUILTIN_SERVERS["fetch"])
        if client.start():
            tools = client.discover_tools()
            return next((t for t in tools if "fetch" in t.name.lower()), None)
    except Exception:
        pass
    return None


def get_github_tools(token: str = None) -> List[Tool]:
    """Get GitHub MCP tools if GITHUB_TOKEN is available."""
    t = token or os.getenv("GITHUB_TOKEN", "")
    if not t:
        print("  ⚠️  GITHUB_TOKEN not set — GitHub MCP tools unavailable")
        return []
    server = MCPServer(
        name="github",
        command=["npx", "-y", "@modelcontextprotocol/server-github"],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": t},
    )
    client = MCPClient(server)
    if client.start():
        return client.discover_tools()
    return []


def get_browser_tools() -> List[Tool]:
    """Get Puppeteer MCP tools for browser automation."""
    client = MCPClient(BUILTIN_SERVERS["puppeteer"])
    if client.start():
        return client.discover_tools()
    return []


def list_available_servers() -> Dict[str, bool]:
    """Check which built-in MCP servers are available (have the required command)."""
    import shutil
    available = {}
    for name, server in BUILTIN_SERVERS.items():
        cmd = server.command[0]
        available[name] = shutil.which(cmd) is not None
    return available


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="🔌 Nova MCP Client — connect to any MCP server")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list-servers", help="List available built-in MCP servers")
    p_disco = sub.add_parser("discover", help="Discover tools from a server")
    p_disco.add_argument("server", choices=list(BUILTIN_SERVERS.keys()))
    p_call = sub.add_parser("call", help="Call a tool on a server")
    p_call.add_argument("server", choices=list(BUILTIN_SERVERS.keys()))
    p_call.add_argument("tool",   help="Tool name")
    p_call.add_argument("args",   nargs="?", default="{}", help="JSON args")

    args = parser.parse_args()

    if args.cmd == "list-servers":
        available = list_available_servers()
        print("\n  Built-in MCP Servers:")
        for name, avail in available.items():
            status = "✅ available" if avail else "❌ not installed"
            cmd    = BUILTIN_SERVERS[name].command[0]
            print(f"    {name:<20} {status}  (requires: {cmd})")
        print("\n  Install all with: npm install -g npx && pip install uvx")

    elif args.cmd == "discover":
        with MCPClient(BUILTIN_SERVERS[args.server]) as client:
            tools = client.discover_tools()
            print(f"\n  {len(tools)} tools from '{args.server}':")
            for t in tools:
                print(f"    • {t.name}: {t.description[:80]}")

    elif args.cmd == "call":
        tool_args = json.loads(args.args)
        with MCPClient(BUILTIN_SERVERS[args.server]) as client:
            client.discover_tools()
            result = client.call_tool(args.tool, tool_args)
            print(f"\n  Result:\n{result}")

    else:
        parser.print_help()
