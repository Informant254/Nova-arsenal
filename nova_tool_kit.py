#!/usr/bin/env python3
# NOVA TOOL KIT v1.0 - AGENTIC TOOL EXECUTION ENGINE

"""
Gives Nova the same tool access frontier agents have:
| - bash_exec       – run any shell command
| - http_request    – full HTTP control (headers, auth, body)
| - browser_open    – headless Playwright browser
| - browser_click   – click page elements
| - browser_fill    – fill forms
| - browser_source  – get page HTML/JS source
| - browser_eval    – run JavaScript in the page
| - file_read       – read any file
| - file_write      – write any file
| - grep_code       – search code for patterns
| - install_tool    – install missing system tools on demand
"""

import json
import os
import re
import shlex
import importlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import ImportBy, Any, Dict, List, Optional, Tuple

import requests

try:
    from nova_repo_intelligence import query_repo_index, update_index
    from nova_self_improvement import self_remember, self_review, mission_complete
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

MAX_TOOL_TIMEOUT = int(os.getenv("NOVA_TOOL_TIMEOUT", "60"))
NOVA_NEVER_TIMEOUT = ["browser_open", "browser_click", "browser_fill", "browser_eval"]

PERMISSION_PROFILE = os.getenv("NOVA_PERMISSION_PROFILE", "read_only")
WRITE_TOOLS = ["file_write", "file_replace", "patch_and_test", "install_tool", "bash_exec"]
SHELL_TOOLS = ["bash_exec"]
SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|password|token)[=:]["\']([^"\']+)["\']'),
    re.compile(r'(?i)(db[_-]?conn|connection[_-]?string)[=:]["\']([^"\']+)["\']')
]

def redact(text: str) -> str:
    """Redact obvious secrets from outputs before returning tool output to the model/log loop."""
    if not isinstance(text, str):
        return text
    redacted = text
    for pattern in SECRET_PATTERNS:
        matches = pattern.findall(redacted)
        for match in matches:
            if len(match) > 1:
                secret = match[1]
                if len(secret) > 4:
                    redacted = redacted.replace(secret, "[REDACTED]")
    return redacted

def clamp_timeout(timeout_setting: Optional[int]) -> int:
    if timeout_setting is None:
        return 15
    try:
        t = int(timeout_setting)
        return min(max(t, 1), MAX_TOOL_TIMEOUT)
    except Exception:
        return 15

def permission_denied(tool_name: str) -> bool:
    """Enforce local policies before running higher-risk tools."""
    profile = PERMISSION_PROFILE.strip().lower()
    if profile == "full" or profile == "unsafe":
        return False
    if profile == "read_only" and tool_name in WRITE_TOOLS:
        return True
    if profile == "no_network" and tool_name == "http_request":
        return True
    return False

def _git_root(path: str = ".") -> str:
    try:
        result = subprocess.run(
            ["git", "-C", path, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        return result.stdout.strip()
    except Exception:
        return os.path.abspath(path)

# ==========================================
# -- TOOL SCHEMAS --
# ==========================================

TOOL_SCHEMAS = [
    {
        "name": "bash_exec",
        "description": "Execute any single shell command in the environment. Useful for running scanning tools (nmap, nuclei, subfinder, sqlmap), backgrounding long scripts, and analyzing raw utility outputs.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (max 60, default 30)"},
                "workdir": {"type": "string", "description": "Working directory context"}
            },
            "required": ["command"]
        }
    },
    {
        "name": "http_request",
        "description": "Make a raw HTTP/HTTPS request with precise control over headers, payload, cookies, and tracking redirects. Highly useful for targeting API endpoints or crafting custom payloads.",
        "parameters": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"], "default": "GET"},
                "url": {"type": "string", "description": "Target absolute URL"},
                "headers": {"type": "object", "description": "HTTP request headers dictionary"},
                "data": {"type": "string", "description": "Raw string request body payloads"},
                "json_data": {"type": "object", "description": "Structured JSON parameters to encode"},
                "timeout": {"type": "integer", "default": 15},
                "allow_redirects": {"type": "boolean", "default": True}
            },
            "required": ["url"]
        }
    },
    {
        "name": "file_read",
        "description": "Read a raw text or configuration file's contents from local filesystems securely.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to file"},
                "max_bytes": {"type": "integer", "description": "Maximum bytes to slice from file (default 50000)"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "file_write",
        "description": "Write fresh content to a specified local file path. Overwrites by default, or appends cleanly based on mode flag setting.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Target filepath"},
                "content": {"type": "string", "description": "Raw payload string to dump into file"},
                "append": {"type": "boolean", "description": "Append instead of overwrite if True", "default": False}
            },
            "required": ["path", "content"]
        }
    },
    {
        "name": "grep_code",
        "description": "Search for specific regex patterns or variable signatures recursively across the repository codebase structure.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex or keyword to hunt down"},
                "file_glob": {"type": "string", "description": "Filter files by extension (e.g. *.py, *.ts)", "default": "*"}
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "install_tool",
        "description": "Installs an ecosystem tool if missing on the underlying machine (e.g. via pip, apt, or go install commands). Runs only if required.",
        "parameters": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Name of package/binary targets to grab"},
                "method": {"type": "string", "enum": ["pip", "apt", "go", "auto"], "default": "auto"}
            },
            "required": ["package"]
        }
    }
]
# ==========================================
# -- TOOL EXECUTORS --
# ==========================================

def exec_bash_exec(command: str, timeout: Optional[int] = 30, workdir: Optional[str] = None) -> Dict[str, Any]:
    """Execute shell instructions locally securely handling telemetry and execution controls."""
    t = clamp_timeout(timeout)
    cwd = workdir if workdir and os.path.exists(workdir) else _git_root()
    
    try:
        res = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=t, cwd=cwd
        )
        return {
            "success": res.returncode == 0,
            "exit_code": res.returncode,
            "stdout": redact(res.stdout),
            "stderr": redact(res.stderr)
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after running for {t} seconds limit."}
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_http_request(url: str, method: str = "GET", headers: Optional[dict] = None, data: Optional[str] = None, json_data: Optional[dict] = None, timeout: int = 15, allow_redirects: bool = True) -> Dict[str, Any]:
    t = clamp_timeout(timeout)
    try:
        res = requests.request(
            method=method.upper(), url=url, headers=headers, data=data, json=json_data, timeout=t, allow_redirects=allow_redirects
        )
        try:
            body_parsed = res.json()
        except ValueError:
            body_parsed = res.text[:20000]
            
        return {
            "success": res.status_code < 400,
            "status_code": res.status_code,
            "headers": dict(res.headers),
            "body": redact(str(body_parsed))
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_file_read(path: str, max_bytes: int = 50000) -> Dict[str, Any]:
    target = Path(path)
    if not target.is_absolute():
        target = Path(_git_root()) / target
    if not target.exists() or not target.is_file():
        return {"success": False, "error": f"Target file '{path}' does not exist on target partition paths."}
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
        return {"success": True, "path": str(target), "content": content, "truncated": target.stat().st_size > max_bytes}
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_file_write(path: str, content: str, append: bool = False) -> Dict[str, Any]:
    target = Path(path)
    if not target.is_absolute():
        target = Path(_git_root()) / target
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with open(target, mode, encoding="utf-8") as f:
            f.write(content)
        return {"success": True, "path": str(target), "bytes_written": len(content)}
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_grep_code(pattern: str, file_glob: str = "*") -> Dict[str, Any]:
    root = _git_root()
    matches = []
    try:
        reg = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex compilation state: {e}"}
        
    try:
        for p in Path(root).rglob(file_glob):
            if p.is_file() and not ".git" in p.parts:
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        for idx, line in enumerate(f, 1):
                            if reg.search(line):
                                matches.append({"file": str(p.relative_to(root)), "line": idx, "content": line.strip()})
                                if len(matches) >= 100:
                                    return {"success": True, "matches": matches, "limit_reached": True}
                except Exception:
                    continue
        return {"success": True, "matches": matches, "limit_reached": False}
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_install_tool(package: str, method: str = "auto") -> Dict[str, Any]:
    """Dynamically pull in binary packages on the fly using native installers safely."""
    methods_to_try = [method] if method != "auto" else ["pip", "apt", "go"]
    errors = {}
    
    for m in methods_to_try:
        if m == "pip":
            cmd = f"pip install {shlex.quote(package)}"
        elif m == "apt":
            cmd = f"sudo apt-get install -y {shlex.quote(package)}"
        elif m == "go":
            cmd = f"go install {shlex.quote(package)}@latest"
        else:
            continue
            
        res = exec_bash_exec(cmd, timeout=60)
        if res["success"]:
            return {"success": True, "method_used": m, "output": res["stdout"]}
        errors[m] = res["stderr"] or res["error"]
        
    return {"success": False, "error": "All installation workflows failed to satisfy package.", "details": errors}

# ==========================================
# -- DISPATCHER ENGINE --
# ==========================================

def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Central structural tool coordinator enforcing authentication policies prior to launching actions."""
    if permission_denied(tool_name):
        return {
            "success": False, 
            "error": f"Permission denied. Tool '{tool_name}' is blocked by local user safety configurations profile '{PERMISSION_PROFILE}'."
        }
        
    dispatch = {
        "bash_exec": lambda a: exec_bash_exec(**a),
        "http_request": lambda a: exec_http_request(**a),
        "file_read": lambda a: exec_file_read(**a),
        "file_write": lambda a: exec_file_write(**a),
        "grep_code": lambda a: exec_grep_code(**a),
        "install_tool": lambda a: exec_install_tool(**a)
    }
    
    if tool_name not in dispatch:
        return {"success": False, "error": f"Unknown tool execution request: '{tool_name}' mapping not found."}
        
    try:
        return dispatch[tool_name](arguments)
    except TypeError as e:
        return {"success": False, "error": f"Bad argument parameters structure payload: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Internal runtime crash safely contained inside tool wrappers: {str(e)}"}

def tools_summary_for_prompt() -> str:
    """Format total known tools schemas footprint ready for insertion context back down to system loops."""
    return json.dumps(TOOL_SCHEMAS, indent=2)

if __name__ == "__main__":
    print(f"Nova Execution Subsystem Ready. Active Profile: {PERMISSION_PROFILE}")
    print(f"Loaded {len(TOOL_SCHEMAS)} operational system primitives directly.")
