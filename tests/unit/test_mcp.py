"""Tests for MCP Server module."""

import asyncio
import json
import pytest

from nova_arsenal.mcp import NovaMcpServer


class TestNovaMcpServer:
    def test_initialization(self):
        server = NovaMcpServer()
        assert server.host == "127.0.0.1"
        assert server.port == 8765
        assert server._tools == {}
        assert server._resources == {}

    def test_register_all_tools(self):
        server = NovaMcpServer()
        server.register_all_tools()
        tools = server.get_tool_list()
        tool_names = [t["name"] for t in tools]
        assert "nmap_scan" in tool_names
        assert "burp_scan" in tool_names
        assert "sqlmap_scan" in tool_names
        assert "osint_investigate" in tool_names
        assert "cve_lookup" in tool_names
        assert "payload_generate" in tool_names
        assert "compliance_check" in tool_names
        assert "ctf_solve" in tool_names
        assert "swarm_scan" in tool_names
        # Includes baseline tools + zeroday_hunt (and any future registrations)
        assert len(tools) >= 10
        names = {t["name"] for t in tools}
        assert "zeroday_hunt" in names
        assert "nmap_scan" in names

    def test_tool_has_input_schema(self):
        server = NovaMcpServer()
        server.register_all_tools()
        for tool in server.get_tool_list():
            assert "inputSchema" in tool
            assert "properties" in tool["inputSchema"]
            assert "required" in tool["inputSchema"]

    def test_register_all_resources(self):
        server = NovaMcpServer()
        server.register_all_resources()
        resources = server.get_resource_list()
        resource_uris = [r["uri"] for r in resources]
        assert "nova://findings" in resource_uris
        assert "nova://agents" in resource_uris
        assert "nova://compliance" in resource_uris
        assert "nova://keys" in resource_uris
        assert len(resources) == 4

    def test_resource_has_mime_type(self):
        server = NovaMcpServer()
        server.register_all_resources()
        for r in server.get_resource_list():
            assert "mimeType" in r
            assert r["mimeType"] == "application/json"

    def test_custom_host_port(self):
        server = NovaMcpServer(host="0.0.0.0", port=9999)
        assert server.host == "0.0.0.0"
        assert server.port == 9999

    def _run_async(self, coro):
        return asyncio.run(coro)

    def test_nmap_uses_argument_vector_not_shell(self, monkeypatch):
        server = NovaMcpServer()
        calls = []

        class Process:
            async def communicate(self):
                return b"safe output", b""

        async def fake_exec(*args, **kwargs):
            calls.append((args, kwargs))
            return Process()

        async def shell_must_not_run(*args, **kwargs):
            raise AssertionError("nmap must not be launched through a shell")

        monkeypatch.setattr("nova_arsenal.mcp.server.asyncio.create_subprocess_exec", fake_exec)
        monkeypatch.setattr("nova_arsenal.mcp.server.asyncio.create_subprocess_shell", shell_must_not_run)

        result = self._run_async(server.handle_tool_call("nmap_scan", {
            "target": "lab.example.local",
            "ports": "80,443",
            "flags": "-sV -sC",
        }))

        assert result == "safe output"
        assert calls[0][0] == ("nmap", "-sV", "-sC", "lab.example.local", "-p", "80,443")

    def test_handle_tool_call_unknown(self):
        server = NovaMcpServer()
        result = self._run_async(server.handle_tool_call("nonexistent", {}))
        parsed = json.loads(result)
        assert "error" in parsed

    def test_handle_tool_call_cve_lookup(self):
        server = NovaMcpServer()
        result = self._run_async(server.handle_tool_call("cve_lookup", {"service": "http"}))
        parsed = json.loads(result)
        assert "cves" in parsed
        assert "risk_score" in parsed
        assert "has_exploit" in parsed

    def test_handle_tool_call_compliance(self):
        server = NovaMcpServer()
        result = self._run_async(server.handle_tool_call("compliance_check", {
            "finding_type": "sql_injection",
            "description": "SQL injection found in login",
        }))
        parsed = json.loads(result)
        assert "controls" in parsed
        assert "frameworks_affected" in parsed

    def test_handle_tool_call_payload(self):
        server = NovaMcpServer()
        result = self._run_async(server.handle_tool_call("payload_generate", {
            "payload_type": "reverse_shell",
            "lhost": "10.0.0.1",
            "lport": 4444,
            "language": "bash",
        }))
        parsed = json.loads(result)
        assert "reverse_shell" in parsed

    def test_handle_tool_call_ctf(self):
        server = NovaMcpServer()
        result = self._run_async(server.handle_tool_call("ctf_solve", {
            "challenge_name": "test_flag",
            "challenge_type": "web",
        }))
        parsed = json.loads(result)
        assert "solved" in parsed
