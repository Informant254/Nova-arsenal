#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🛠️  NOVA TOOL KIT v1.0 — AGENTIC TOOL EXECUTION ENGINE       ║
║                                                                  ║
║   Gives Nova the same tool access frontier agents have:         ║
║   • bash_exec      — run any shell command                      ║
║   • http_request   — full HTTP control (headers, auth, body)    ║
║   • browser_open   — headless Playwright browser                ║
║   • browser_click  — click page elements                        ║
║   • browser_fill   — fill forms                                 ║
║   • browser_source — get full page HTML/JS source               ║
║   • browser_eval   — run JavaScript in the page                 ║
║   • file_read      — read any file                              ║
║   • file_write     — write any file                             ║
║   • grep_code      — search code for patterns                   ║
║   • install_tool   — install missing system tools on demand     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional
import requests

# ── TOOL SCHEMAS ──────────────────────────────────────────────────
# Defines every tool available to the agent.
# The LLM reads these descriptions to decide which tool to call.

TOOL_SCHEMAS: List[Dict] = [
    {
        "name": "bash_exec",
        "description": (
            "Execute any shell command in the Linux environment. "
            "Use for: running security tools (nmap, sqlmap, nuclei, subfinder, curl), "
            "installing packages, reading system info, scripting. "
            "Returns stdout + stderr. Timeout: 60s by default."
        ),
        "parameters": {
            "command":  {"type": "string",  "description": "Shell command to execute"},
            "timeout":  {"type": "integer", "description": "Timeout in seconds (default 60)"},
            "workdir":  {"type": "string",  "description": "Working directory (optional)"},
        },
        "required": ["command"],
    },
    {
        "name": "http_request",
        "description": (
            "Make a full HTTP/HTTPS request with complete control over "
            "method, headers, body, cookies, and auth. "
            "Use for: sending exploits, fuzzing parameters, testing endpoints, "
            "fetching responses for analysis."
        ),
        "parameters": {
            "method":   {"type": "string",  "description": "HTTP method: GET POST PUT DELETE PATCH"},
            "url":      {"type": "string",  "description": "Full URL including query string"},
            "headers":  {"type": "object",  "description": "HTTP headers dict (optional)"},
            "body":     {"type": "any",     "description": "Request body — dict (JSON) or string"},
            "cookies":  {"type": "object",  "description": "Cookies dict (optional)"},
            "timeout":  {"type": "integer", "description": "Timeout seconds (default 15)"},
            "allow_redirects": {"type": "boolean", "description": "Follow redirects (default true)"},
        },
        "required": ["method", "url"],
    },
    {
        "name": "browser_open",
        "description": (
            "Open a URL in a real headless Chromium browser (Playwright). "
            "Use when JavaScript execution is needed, for SPAs, or when curl isn't enough. "
            "Returns the page title and visible text content."
        ),
        "parameters": {
            "url":              {"type": "string",  "description": "URL to open"},
            "wait_for":         {"type": "string",  "description": "CSS selector to wait for (optional)"},
            "timeout":          {"type": "integer", "description": "Page load timeout ms (default 10000)"},
        },
        "required": ["url"],
    },
    {
        "name": "browser_source",
        "description": "Get the full HTML source of the currently open browser page. Useful for finding hidden fields, API endpoints, secrets in JS, and form parameters.",
        "parameters": {
            "selector": {"type": "string", "description": "CSS selector to get specific element HTML (optional, defaults to full page)"},
        },
        "required": [],
    },
    {
        "name": "browser_click",
        "description": "Click an element on the current browser page by CSS selector or text.",
        "parameters": {
            "selector": {"type": "string", "description": "CSS selector or text to click"},
            "wait_after_ms": {"type": "integer", "description": "Milliseconds to wait after click (default 500)"},
        },
        "required": ["selector"],
    },
    {
        "name": "browser_fill",
        "description": "Fill a form field on the current browser page.",
        "parameters": {
            "selector": {"type": "string", "description": "CSS selector for the input field"},
            "value":    {"type": "string", "description": "Value to type into the field"},
        },
        "required": ["selector", "value"],
    },
    {
        "name": "browser_eval",
        "description": "Execute JavaScript in the browser page context. Use for reading cookies, localStorage, modifying DOM, or extracting data that isn't in the HTML.",
        "parameters": {
            "script": {"type": "string", "description": "JavaScript to execute in the page"},
        },
        "required": ["script"],
    },
    {
        "name": "file_read",
        "description": "Read a file from the filesystem. Use to examine source code, config files, logs, or previous findings.",
        "parameters": {
            "path":       {"type": "string",  "description": "File path to read"},
            "max_bytes":  {"type": "integer", "description": "Max bytes to read (default 8000)"},
        },
        "required": ["path"],
    },
    {
        "name": "file_write",
        "description": "Write content to a file. Use to save findings, create exploit scripts, or update config.",
        "parameters": {
            "path":    {"type": "string", "description": "File path to write"},
            "content": {"type": "string", "description": "Content to write"},
            "append":  {"type": "boolean","description": "Append instead of overwrite (default false)"},
        },
        "required": ["path", "content"],
    },
    {
        "name": "grep_code",
        "description": "Search files for patterns. Use to find API keys, passwords, endpoints, vulnerable code patterns, or any string in source files.",
        "parameters": {
            "pattern":    {"type": "string", "description": "Regex or literal string to search for"},
            "directory":  {"type": "string", "description": "Directory to search (default: current)"},
            "file_glob":  {"type": "string", "description": "File pattern e.g. '*.py' or '*.ts' (optional)"},
            "max_results":{"type": "integer","description": "Max results to return (default 20)"},
        },
        "required": ["pattern"],
    },
    {
        "name": "install_tool",
        "description": "Install a missing security tool via apt, pip, or direct download. Use when a tool you need isn't available.",
        "parameters": {
            "tool":    {"type": "string", "description": "Tool name to install"},
            "method":  {"type": "string", "description": "Installation method: apt | pip | go | github"},
            "package": {"type": "string", "description": "Package name if different from tool name (optional)"},
        },
        "required": ["tool"],
    },
    {
        "name": "mission_complete",
        "description": "Signal that the mission is complete. Call this when you have found all vulnerabilities and written the report.",
        "parameters": {
            "summary": {"type": "string", "description": "One-paragraph summary of what was found"},
            "findings_file": {"type": "string", "description": "Path to the JSON findings file written"},
        },
        "required": ["summary"],
    },
]

# Build a quick lookup
TOOL_MAP = {t["name"]: t for t in TOOL_SCHEMAS}


# ── BROWSER STATE ─────────────────────────────────────────────────
_browser_page = None
_playwright    = None


def _get_browser_page():
    """Lazy-init Playwright browser."""
    global _browser_page, _playwright
    if _browser_page is not None:
        return _browser_page
    try:
        from playwright.sync_api import sync_playwright
        _playwright   = sync_playwright().start()
        browser       = _playwright.chromium.launch(headless=True, args=["--no-sandbox"])
        context       = browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            ignore_https_errors=True,
        )
        _browser_page = context.new_page()
        return _browser_page
    except ImportError:
        return None
    except Exception as e:
        return None


# ── TOOL EXECUTORS ────────────────────────────────────────────────

def bash_exec(command: str, timeout: int = 60, workdir: str = None) -> Dict:
    """Execute a shell command and return stdout/stderr."""
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=workdir,
        )
        output = result.stdout.strip()
        errors = result.stderr.strip()
        return {
            "success":    result.returncode == 0,
            "returncode": result.returncode,
            "stdout":     output[:4000],
            "stderr":     errors[:1000] if errors else "",
            "combined":   (output + "\n" + errors)[:4000].strip(),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def http_request(
    method: str,
    url: str,
    headers: Dict = None,
    body: Any = None,
    cookies: Dict = None,
    timeout: int = 15,
    allow_redirects: bool = True,
) -> Dict:
    """Make a full HTTP request with complete control."""
    try:
        kwargs = {
            "headers":          headers or {},
            "cookies":          cookies or {},
            "timeout":          timeout,
            "allow_redirects":  allow_redirects,
            "verify":           False,
        }
        if body is not None:
            if isinstance(body, dict):
                kwargs["json"] = body
            else:
                kwargs["data"] = str(body)

        response = requests.request(method.upper(), url, **kwargs)

        # Detect content type
        ct = response.headers.get("Content-Type", "")
        try:
            body_parsed = response.json() if "json" in ct else None
        except Exception:
            body_parsed = None

        return {
            "success":      True,
            "status_code":  response.status_code,
            "headers":      dict(response.headers),
            "body":         response.text[:4000],
            "body_parsed":  body_parsed,
            "url":          str(response.url),
            "cookies":      dict(response.cookies),
            "redirect_history": [str(r.url) for r in response.history],
        }
    except requests.exceptions.SSLError:
        return {"success": False, "error": "SSL error — try with verify=false"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def browser_open(url: str, wait_for: str = None, timeout: int = 10000) -> Dict:
    """Open a URL in the headless browser."""
    page = _get_browser_page()
    if page is None:
        # Fallback to curl
        result = bash_exec(f"curl -sL --max-time 10 '{url}' | head -c 3000")
        return {"success": result["success"], "method": "curl_fallback",
                "content": result["combined"][:2000]}
    try:
        page.goto(url, timeout=timeout, wait_until="domcontentloaded")
        if wait_for:
            page.wait_for_selector(wait_for, timeout=5000)
        title   = page.title()
        content = page.inner_text("body")[:3000] if page.query_selector("body") else ""
        return {
            "success": True,
            "url":     page.url,
            "title":   title,
            "content": content,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "url": url}


def browser_source(selector: str = None) -> Dict:
    """Get page HTML source or element HTML."""
    page = _get_browser_page()
    if page is None:
        return {"success": False, "error": "Browser not available"}
    try:
        if selector:
            element = page.query_selector(selector)
            html    = element.inner_html() if element else ""
        else:
            html    = page.content()
        return {"success": True, "html": html[:5000]}
    except Exception as e:
        return {"success": False, "error": str(e)}


def browser_click(selector: str, wait_after_ms: int = 500) -> Dict:
    """Click an element by CSS selector."""
    page = _get_browser_page()
    if page is None:
        return {"success": False, "error": "Browser not available"}
    try:
        page.click(selector)
        page.wait_for_timeout(wait_after_ms)
        return {"success": True, "clicked": selector}
    except Exception as e:
        return {"success": False, "error": str(e)}


def browser_fill(selector: str, value: str) -> Dict:
    """Fill a form field."""
    page = _get_browser_page()
    if page is None:
        return {"success": False, "error": "Browser not available"}
    try:
        page.fill(selector, value)
        return {"success": True, "filled": selector, "value": value}
    except Exception as e:
        return {"success": False, "error": str(e)}


def browser_eval(script: str) -> Dict:
    """Execute JavaScript in the browser."""
    page = _get_browser_page()
    if page is None:
        return {"success": False, "error": "Browser not available"}
    try:
        result = page.evaluate(script)
        return {"success": True, "result": str(result)[:2000]}
    except Exception as e:
        return {"success": False, "error": str(e)}


def file_read(path: str, max_bytes: int = 8000) -> Dict:
    """Read a file from disk."""
    try:
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            return {"success": False, "error": f"File not found: {path}"}
        size = os.path.getsize(path)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
        return {
            "success": True,
            "path":    path,
            "size":    size,
            "content": content,
            "truncated": size > max_bytes,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def file_write(path: str, content: str, append: bool = False) -> Dict:
    """Write content to a file."""
    try:
        path = os.path.expanduser(path)
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        mode = "a" if append else "w"
        with open(path, mode, encoding="utf-8") as f:
            f.write(content)
        return {"success": True, "path": path, "bytes_written": len(content)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def grep_code(
    pattern: str,
    directory: str = ".",
    file_glob: str = None,
    max_results: int = 20,
) -> Dict:
    """Search files for a pattern using grep."""
    cmd = f"grep -rn --include='{file_glob or '*'}' -m {max_results} '{pattern}' {directory} 2>/dev/null | head -{max_results}"
    result = bash_exec(cmd, timeout=15)
    matches = [l for l in result.get("combined", "").splitlines() if l.strip()]
    return {
        "success": True,
        "pattern": pattern,
        "matches": matches,
        "count":   len(matches),
    }


def install_tool(tool: str, method: str = None, package: str = None) -> Dict:
    """Install a security tool."""
    pkg = package or tool
    methods_to_try = []
    if method:
        methods_to_try = [method]
    else:
        # Auto-detect best install method
        PIP_TOOLS  = {"sqlmap", "semgrep", "requests", "playwright", "scapy", "shodan"}
        APT_TOOLS  = {"nmap", "curl", "wget", "git", "jq", "nuclei", "subfinder"}
        GO_TOOLS   = {"httpx", "subfinder", "amass", "katana", "gau", "waybackurls"}
        if tool in PIP_TOOLS:
            methods_to_try = ["pip"]
        elif tool in GO_TOOLS:
            methods_to_try = ["go", "apt", "pip"]
        elif tool in APT_TOOLS:
            methods_to_try = ["apt"]
        else:
            methods_to_try = ["pip", "apt", "go"]

    for m in methods_to_try:
        if m == "pip":
            r = bash_exec(f"pip install -q {pkg}", timeout=120)
        elif m == "apt":
            r = bash_exec(f"apt-get install -y -q {pkg} 2>/dev/null", timeout=120)
        elif m == "go":
            r = bash_exec(f"go install -v {pkg}@latest 2>&1", timeout=120)
        else:
            continue
        if r.get("success") or r.get("returncode", 1) == 0:
            return {"success": True, "tool": tool, "method": m}

    return {"success": False, "tool": tool, "error": "All install methods failed"}


# ── DISPATCHER ────────────────────────────────────────────────────

def execute_tool(tool_name: str, args: Dict) -> Dict:
    """
    Dispatch a tool call by name with arguments.
    This is what the agent loop calls after parsing LLM output.
    """
    dispatch = {
        "bash_exec":      lambda a: bash_exec(**a),
        "http_request":   lambda a: http_request(**a),
        "browser_open":   lambda a: browser_open(**a),
        "browser_source": lambda a: browser_source(**a),
        "browser_click":  lambda a: browser_click(**a),
        "browser_fill":   lambda a: browser_fill(**a),
        "browser_eval":   lambda a: browser_eval(**a),
        "file_read":      lambda a: file_read(**a),
        "file_write":     lambda a: file_write(**a),
        "grep_code":      lambda a: grep_code(**a),
        "install_tool":   lambda a: install_tool(**a),
        "mission_complete": lambda a: {"success": True, "done": True, **a},
    }

    if tool_name not in dispatch:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    start = time.time()
    try:
        result = dispatch[tool_name](args)
    except TypeError as e:
        result = {"success": False, "error": f"Bad arguments for {tool_name}: {e}"}
    except Exception as e:
        result = {"success": False, "error": str(e)}

    result["_tool"]    = tool_name
    result["_elapsed"] = round(time.time() - start, 2)
    return result


def tools_summary_for_prompt() -> str:
    """Format tool list for injection into the LLM system prompt."""
    lines = ["Available tools (call by outputting JSON with 'action' and 'args'):"]
    for t in TOOL_SCHEMAS:
        params = ", ".join(t.get("required", []))
        lines.append(f"  • {t['name']}({params}) — {t['description'][:80]}")
    return "\n".join(lines)
