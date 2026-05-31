#!/usr/bin/env python3
# NOVA TOOL KIT v2.0 - AGENTIC TOOL EXECUTION ENGINE
"""
Complete tool set — same as frontier agents:
  bash_exec        – run any shell command
  http_request     – full HTTP control (headers, auth, body)
  browser_open     – headless Playwright browser
  browser_click    – click page elements
  browser_fill     – fill forms
  browser_source   – get page HTML/JS source
  browser_eval     – run JavaScript in the page
  file_read        – read any file
  file_write       – write any file
  grep_code        – search code for patterns
  install_tool     – install missing system tools on demand
  self_review      – read recent run reports + identify failures
  self_remember    – persist a lesson to long-term memory
  query_repo_index – look up functions/classes in Nova's codebase

NEW in v2.0 (gap-closing tools):
  visual_analyze   – screenshot URL + LLM vision analysis  [Mythos gap]
  research_cve     – NVD/GitHub/OSV CVE + PoC lookup      [Daybreak gap]
  verify_finding   – triple-confirm + CVSS + H1 report     [Daybreak gap]
  plan_hunt        – generate structured hunt plan         [Claude Code gap]
  parallel_probe   – fire N HTTP probes simultaneously     [performance gap]
"""

import json
import os
import re
import shlex
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import requests as _req
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

# ── Optional gap-closing modules ─────────────────────────────────────────────
try:
    from nova_repo_intelligence import query_repo_index, update_index
    from nova_self_improvement import self_remember, self_review, mission_complete
    _SELF_IMPROVE = True
except ImportError:
    _SELF_IMPROVE = False

try:
    from nova_vision import visual_analyze as _visual_analyze
    _VISION = True
except ImportError:
    _VISION = False

try:
    from nova_web_researcher import research_cve as _research_cve
    _RESEARCHER = True
except ImportError:
    _RESEARCHER = False

try:
    from nova_verify_engine import triple_verify, build_h1_report
    _VERIFY = True
except ImportError:
    _VERIFY = False

try:
    from nova_planner import generate_plan, load_or_create_plan
    _PLANNER = True
except ImportError:
    _PLANNER = False

# ── CONFIG ────────────────────────────────────────────────────────────────────
MAX_TOOL_TIMEOUT = int(os.getenv("NOVA_TOOL_TIMEOUT",      "60"))
PERMISSION_PROFILE = os.getenv("NOVA_PERMISSION_PROFILE",  "full")
WRITE_TOOLS  = ["file_write","install_tool","bash_exec"]
NET_TOOLS    = ["http_request","browser_open","browser_click",
                "browser_fill","browser_source","browser_eval",
                "visual_analyze","research_cve","verify_finding","parallel_probe"]

SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|password|token)[=:]["\']([^"\']{4,})["\']'),
    re.compile(r'(?i)(db[_-]?conn|connection[_-]?string)[=:]["\']([^"\']{4,})["\']'),
]

def redact(text: str) -> str:
    if not isinstance(text, str): return text
    for pat in SECRET_PATTERNS:
        for match in pat.findall(text):
            if len(match) > 1 and len(match[1]) > 4:
                text = text.replace(match[1], "[REDACTED]")
    return text

def permission_denied(tool_name: str) -> bool:
    p = PERMISSION_PROFILE.strip().lower()
    if p in ("full", "unsafe"):    return False
    if p == "read_only"  and tool_name in WRITE_TOOLS: return True
    if p == "no_network" and tool_name in NET_TOOLS:   return True
    return False

def clamp_timeout(t) -> int:
    try: return min(max(int(t), 1), MAX_TOOL_TIMEOUT)
    except Exception: return 15

# ── TOOL SCHEMAS ─────────────────────────────────────────────────────────────
TOOL_SCHEMAS = [
    {
        "name": "bash_exec",
        "description": "Run any shell command. Use for nmap, sqlmap, nuclei, subfinder, curl, custom scripts, git operations.",
        "parameters": {"type":"object","properties":{
            "command":{"type":"string","description":"Shell command to execute"},
            "timeout":{"type":"integer","description":"Timeout seconds (max 60)"},
            "workdir":{"type":"string","description":"Working directory"}
        },"required":["command"]}
    },
    {
        "name": "http_request",
        "description": "Make a raw HTTP request with full control over method, headers, cookies, body, and redirects.",
        "parameters": {"type":"object","properties":{
            "url":{"type":"string"}, "method":{"type":"string","default":"GET"},
            "headers":{"type":"object"}, "data":{"type":"object"},
            "body":{"type":"string"}, "cookies":{"type":"object"},
            "follow_redirects":{"type":"boolean","default":True},
            "timeout":{"type":"integer","default":15}
        },"required":["url"]}
    },
    {
        "name": "browser_open",
        "description": "Open a URL in headless Chromium. Handles JavaScript SPAs, cookie-gated pages, dynamic content.",
        "parameters": {"type":"object","properties":{
            "url":{"type":"string"}, "wait_ms":{"type":"integer","default":2000}
        },"required":["url"]}
    },
    {
        "name": "browser_source",
        "description": "Get the full rendered HTML source of a page after JavaScript execution. Reveals dynamically injected endpoints, tokens, and hidden fields.",
        "parameters": {"type":"object","properties":{
            "url":{"type":"string"}, "wait_ms":{"type":"integer","default":2000}
        },"required":["url"]}
    },
    {
        "name": "browser_click",
        "description": "Click a CSS-selector element in the current browser page.",
        "parameters": {"type":"object","properties":{
            "selector":{"type":"string"}, "url":{"type":"string"}
        },"required":["selector"]}
    },
    {
        "name": "browser_fill",
        "description": "Fill a form field by CSS selector and optionally submit.",
        "parameters": {"type":"object","properties":{
            "selector":{"type":"string"}, "value":{"type":"string"},
            "submit":{"type":"boolean","default":False}, "url":{"type":"string"}
        },"required":["selector","value"]}
    },
    {
        "name": "browser_eval",
        "description": "Execute JavaScript in the browser. Read document.cookie, localStorage, sessionStorage, DOM state.",
        "parameters": {"type":"object","properties":{
            "script":{"type":"string"}, "url":{"type":"string"}
        },"required":["script"]}
    },
    {
        "name": "file_read",
        "description": "Read any file. Use for source code, config, past findings, logs.",
        "parameters": {"type":"object","properties":{
            "path":{"type":"string"}, "max_chars":{"type":"integer","default":8000}
        },"required":["path"]}
    },
    {
        "name": "file_write",
        "description": "Write content to a file. Use to save findings, exploit scripts, reports.",
        "parameters": {"type":"object","properties":{
            "path":{"type":"string"}, "content":{"type":"string"},
            "append":{"type":"boolean","default":False}
        },"required":["path","content"]}
    },
    {
        "name": "grep_code",
        "description": "Search files for a pattern. Finds hardcoded secrets, API keys, SQL sinks, auth bypasses in source.",
        "parameters": {"type":"object","properties":{
            "pattern":{"type":"string"}, "path":{"type":"string","default":"."},
            "extensions":{"type":"array","items":{"type":"string"},"default":[".py",".js",".ts"]},
            "max_results":{"type":"integer","default":30}
        },"required":["pattern"]}
    },
    {
        "name": "install_tool",
        "description": "Install a missing tool on demand using pip, apt, or go.",
        "parameters": {"type":"object","properties":{
            "package":{"type":"string"}, "method":{"type":"string","default":"auto"}
        },"required":["package"]}
    },
    {
        "name": "self_review",
        "description": "Read recent run reports and identify recurring failures or improvement opportunities.",
        "parameters": {"type":"object","properties":{},"required":[]}
    },
    {
        "name": "self_remember",
        "description": "Persist a lesson or finding to Nova's long-term self-improvement memory.",
        "parameters": {"type":"object","properties":{
            "lesson":{"type":"string","description":"What to remember"}
        },"required":["lesson"]}
    },
    {
        "name": "query_repo_index",
        "description": "Look up functions, classes, test files, and suggested commands in Nova's own codebase index.",
        "parameters": {"type":"object","properties":{
            "query":{"type":"string","description":"What to look up (e.g. 'JWT verification', 'login function')"}
        },"required":["query"]}
    },
    {
        "name": "visual_analyze",
        "description": "Take a screenshot of a URL and analyze it visually with a vision model. Finds hidden forms, admin panels, JS-rendered content, auth state — things source code misses. [Mythos capability]",
        "parameters": {"type":"object","properties":{
            "url":{"type":"string"}, "prompt":{"type":"string","description":"Custom visual analysis question (optional)"}
        },"required":["url"]}
    },
    {
        "name": "research_cve",
        "description": "Search NVD, OSV, and GitHub for CVEs and public PoC exploits matching a technology or keyword. [Daybreak / Claude Code capability]",
        "parameters": {"type":"object","properties":{
            "query":{"type":"string","description":"Technology, library, CVE ID, or vulnerability keyword"},
            "include_pocs":{"type":"boolean","default":True}
        },"required":["query"]}
    },
    {
        "name": "verify_finding",
        "description": "Triple-confirm a suspected vulnerability with 3 independent PoC probes. Auto-calculates CVSS 3.1. Generates HackerOne-ready evidence. [Daybreak Stage 2 capability]",
        "parameters": {"type":"object","properties":{
            "vuln_type":{"type":"string","description":"e.g. sqli, xss, ssrf, path_traversal, idor"},
            "endpoint": {"type":"string","description":"Full URL of the vulnerable endpoint"},
            "param":    {"type":"string","description":"Vulnerable parameter name"},
            "value":    {"type":"string","default":"1"}
        },"required":["vuln_type","endpoint"]}
    },
    {
        "name": "plan_hunt",
        "description": "Generate a structured multi-phase attack plan for a target. Returns ordered phases with dependencies, success criteria, and recommended tools. [Claude Code planning capability]",
        "parameters": {"type":"object","properties":{
            "target":    {"type":"string"},
            "objective": {"type":"string"},
            "context":   {"type":"string","description":"Any known info about the target (optional)"}
        },"required":["target","objective"]}
    },
    {
        "name": "parallel_probe",
        "description": "Fire multiple HTTP probes simultaneously and collect all results. Much faster than sequential http_request calls. [Frontier agent performance]",
        "parameters": {"type":"object","properties":{
            "probes":{"type":"array","description":"List of {url, method, headers, data} objects"},
            "timeout":{"type":"integer","default":10}
        },"required":["probes"]}
    },
    {
        "name": "mission_complete",
        "description": "Signal that the hunt is complete. Provide a summary of all findings.",
        "parameters": {"type":"object","properties":{
            "summary":{"type":"string"}, "findings_count":{"type":"integer"}
        },"required":["summary"]}
    },
]

# ── EXECUTORS ─────────────────────────────────────────────────────────────────

def exec_bash_exec(command: str, timeout: int = 30, workdir: str = None) -> Dict:
    t = clamp_timeout(timeout)
    try:
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=t, cwd=workdir or None,
        )
        return {"success": r.returncode == 0,
                "stdout": redact(r.stdout[:8000]),
                "stderr": redact(r.stderr[:2000]),
                "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {t}s", "stdout": "", "stderr": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "stdout": "", "stderr": ""}

def exec_http_request(url: str, method: str = "GET", headers: Dict = None,
                       data: Dict = None, body: str = None, cookies: Dict = None,
                       follow_redirects: bool = True, timeout: int = 15) -> Dict:
    t = clamp_timeout(timeout)
    h = {"User-Agent": "Nova/3.0 Security Research", **(headers or {})}
    if _REQUESTS_OK:
        try:
            import requests
            r = requests.request(
                method.upper(), url, headers=h,
                json=data if data and not body else None,
                data=body, cookies=cookies,
                allow_redirects=follow_redirects, timeout=t, verify=False,
            )
            return {"success": True, "status": r.status_code,
                    "headers": dict(r.headers),
                    "body": redact(r.text[:8000])}
        except Exception as e:
            return {"success": False, "error": str(e)}
    import urllib.request
    try:
        req = urllib.request.Request(url, headers=h, method=method.upper())
        with urllib.request.urlopen(req, timeout=t) as resp:
            return {"success": True, "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": redact(resp.read().decode("utf-8","replace")[:8000])}
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_browser_open(url: str, wait_ms: int = 2000) -> Dict:
    script = f"""
import asyncio, sys
from playwright.async_api import async_playwright
async def run():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        page = await b.new_page()
        r = await page.goto("{url}", wait_until="networkidle", timeout=15000)
        await page.wait_for_timeout({wait_ms})
        title = await page.title()
        print(f"STATUS={{r.status}} TITLE={{title}}")
        await b.close()
asyncio.run(run())
"""
    r = exec_bash_exec(f"python3 -c '{script}'", timeout=30)
    r["success"] = "STATUS=" in r.get("stdout","")
    return r

def exec_browser_source(url: str, wait_ms: int = 2000) -> Dict:
    script = f"""
import asyncio, sys
from playwright.async_api import async_playwright
async def run():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        page = await b.new_page()
        await page.goto("{url}", wait_until="networkidle", timeout=15000)
        await page.wait_for_timeout({wait_ms})
        content = await page.content()
        print(content[:10000])
        await b.close()
asyncio.run(run())
"""
    r = exec_bash_exec(f"python3 -c '{script}'", timeout=30)
    r["content"] = r.get("stdout","")
    return r

def exec_browser_click(selector: str, url: str = None) -> Dict:
    u = url or "about:blank"
    script = f"""
import asyncio
from playwright.async_api import async_playwright
async def run():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        page = await b.new_page()
        if "{u}" != "about:blank":
            await page.goto("{u}", wait_until="networkidle", timeout=10000)
        await page.click("{selector}")
        print("CLICKED:{selector}")
        await b.close()
asyncio.run(run())
"""
    return exec_bash_exec(f"python3 -c '{script}'", timeout=20)

def exec_browser_fill(selector: str, value: str, submit: bool = False, url: str = None) -> Dict:
    u = url or "about:blank"
    sub = "await page.press('" + selector + "', 'Enter')" if submit else ""
    script = f"""
import asyncio
from playwright.async_api import async_playwright
async def run():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        page = await b.new_page()
        if "{u}" != "about:blank":
            await page.goto("{u}", wait_until="networkidle", timeout=10000)
        await page.fill("{selector}", "{value}")
        {sub}
        print("FILLED:{selector}={value[:30]}")
        await b.close()
asyncio.run(run())
"""
    return exec_bash_exec(f"python3 -c '{script}'", timeout=20)

def exec_browser_eval(script: str, url: str = None) -> Dict:
    u = url or "about:blank"
    safe_script = script.replace('"', '\\"').replace('\n', ' ')
    pw_script = f"""
import asyncio
from playwright.async_api import async_playwright
async def run():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        page = await b.new_page()
        if "{u}" != "about:blank":
            await page.goto("{u}", wait_until="networkidle", timeout=10000)
        result = await page.evaluate("{safe_script}")
        print(str(result)[:2000])
        await b.close()
asyncio.run(run())
"""
    return exec_bash_exec(f"python3 -c '{pw_script}'", timeout=20)

def exec_file_read(path: str, max_chars: int = 8000) -> Dict:
    try:
        p = Path(os.path.expanduser(path))
        if not p.exists():
            return {"success": False, "error": f"File not found: {path}"}
        content = p.read_text(errors="replace")[:max_chars]
        return {"success": True, "content": content, "size": p.stat().st_size, "path": str(p)}
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_file_write(path: str, content: str, append: bool = False) -> Dict:
    try:
        p = Path(os.path.expanduser(path))
        p.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        p.write_text(content) if not append else open(p, "a").write(content)
        return {"success": True, "path": str(p), "bytes": len(content)}
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_grep_code(pattern: str, path: str = ".", extensions: List[str] = None,
                    max_results: int = 30) -> Dict:
    exts = extensions or [".py",".js",".ts",".java",".rb",".php",".go"]
    matches = []
    try:
        root = Path(os.path.expanduser(path))
        for f in root.rglob("*"):
            if f.suffix not in exts or not f.is_file(): continue
            if any(d in str(f) for d in ["node_modules",".git","__pycache__"]): continue
            try:
                for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append({"file": str(f), "line": i, "content": line.strip()[:200]})
                        if len(matches) >= max_results:
                            return {"success": True, "matches": matches, "truncated": True}
            except Exception:
                continue
        return {"success": True, "matches": matches}
    except Exception as e:
        return {"success": False, "error": str(e)}

def exec_install_tool(package: str, method: str = "auto") -> Dict:
    methods = [method] if method != "auto" else ["pip","apt","go"]
    errors = {}
    for m in methods:
        cmd = {"pip":f"pip install {shlex.quote(package)}",
               "apt":f"sudo apt-get install -y {shlex.quote(package)}",
               "go": f"go install {shlex.quote(package)}@latest"}.get(m)
        if not cmd: continue
        r = exec_bash_exec(cmd, timeout=60)
        if r["success"]:
            return {"success": True, "method": m, "output": r["stdout"][:500]}
        errors[m] = r.get("stderr","")[:200]
    return {"success": False, "error": "All methods failed", "details": errors}

def exec_self_review(*args, **kwargs) -> Dict:
    if _SELF_IMPROVE:
        try:
            return {"success": True, "result": self_review()}
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "nova_self_improvement not installed"}

def exec_self_remember(lesson: str, **kwargs) -> Dict:
    if _SELF_IMPROVE:
        try:
            self_remember(lesson)
            return {"success": True, "lesson": lesson}
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "nova_self_improvement not installed"}

def exec_query_repo_index(query: str, **kwargs) -> Dict:
    if _SELF_IMPROVE:
        try:
            results = query_repo_index(query)
            return {"success": True, "results": results}
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "nova_repo_intelligence not installed"}

def exec_visual_analyze(url: str, prompt: str = None, **kwargs) -> Dict:
    if _VISION:
        try:
            result = _visual_analyze(url, prompt=prompt)
            return {**result, "success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "nova_vision not installed. Run: pip install playwright && python3 -m playwright install chromium"}

def exec_research_cve(query: str, include_pocs: bool = True, **kwargs) -> Dict:
    if _RESEARCHER:
        try:
            result = _research_cve(query, include_pocs=include_pocs)
            return {**result, "success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "nova_web_researcher not installed"}

def exec_verify_finding(vuln_type: str, endpoint: str, param: str = "",
                         value: str = "1", **kwargs) -> Dict:
    if _VERIFY:
        try:
            finding = triple_verify(vuln_type, endpoint, param, value)
            report  = build_h1_report(finding, target=endpoint)
            return {"success": True, "finding": finding, "h1_report": report}
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "nova_verify_engine not installed"}

def exec_plan_hunt(target: str, objective: str, context: str = "", **kwargs) -> Dict:
    if _PLANNER:
        try:
            plan = generate_plan(target, objective, context)
            return {"success": True, "plan": plan.to_dict(),
                    "context": plan.to_agent_context()}
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": False, "error": "nova_planner not installed"}

def exec_parallel_probe(probes: List[Dict], timeout: int = 10) -> Dict:
    """Fire multiple HTTP probes simultaneously."""
    results = []
    t = clamp_timeout(timeout)

    def probe_one(p: Dict) -> Dict:
        url    = p.get("url","")
        method = p.get("method","GET")
        r = exec_http_request(url, method=method,
                               headers=p.get("headers"),
                               data=p.get("data"),
                               timeout=t)
        r["url"] = url
        return r

    with ThreadPoolExecutor(max_workers=min(len(probes), 10)) as ex:
        futures = {ex.submit(probe_one, p): p for p in probes}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"success": False, "error": str(e)})

    return {"success": True, "results": results, "count": len(results)}

def exec_mission_complete(summary: str, findings_count: int = 0, **kwargs) -> Dict:
    print(f"\n  ✅ MISSION COMPLETE\n  Summary: {summary}\n  Findings: {findings_count}")
    return {"success": True, "done": True, "summary": summary, "findings_count": findings_count}

# ── DISPATCHER ────────────────────────────────────────────────────────────────

_DISPATCH = {
    "bash_exec":        lambda a: exec_bash_exec(**a),
    "http_request":     lambda a: exec_http_request(**a),
    "browser_open":     lambda a: exec_browser_open(**a),
    "browser_source":   lambda a: exec_browser_source(**a),
    "browser_click":    lambda a: exec_browser_click(**a),
    "browser_fill":     lambda a: exec_browser_fill(**a),
    "browser_eval":     lambda a: exec_browser_eval(**a),
    "file_read":        lambda a: exec_file_read(**a),
    "file_write":       lambda a: exec_file_write(**a),
    "grep_code":        lambda a: exec_grep_code(**a),
    "install_tool":     lambda a: exec_install_tool(**a),
    "self_review":      lambda a: exec_self_review(**a),
    "self_remember":    lambda a: exec_self_remember(**a),
    "query_repo_index": lambda a: exec_query_repo_index(**a),
    "visual_analyze":   lambda a: exec_visual_analyze(**a),
    "research_cve":     lambda a: exec_research_cve(**a),
    "verify_finding":   lambda a: exec_verify_finding(**a),
    "plan_hunt":        lambda a: exec_plan_hunt(**a),
    "parallel_probe":   lambda a: exec_parallel_probe(**a),
    "mission_complete": lambda a: exec_mission_complete(**a),
}

def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if permission_denied(tool_name):
        return {"success": False,
                "error": f"Permission denied: '{tool_name}' blocked by profile '{PERMISSION_PROFILE}'"}
    fn = _DISPATCH.get(tool_name)
    if not fn:
        return {"success": False, "error": f"Unknown tool: '{tool_name}'"}
    try:
        return fn(arguments)
    except TypeError as e:
        return {"success": False, "error": f"Bad arguments: {e}"}
    except Exception as e:
        return {"success": False, "error": f"Tool error: {e}"}

def tools_summary_for_prompt() -> str:
    return json.dumps(TOOL_SCHEMAS, indent=2)

if __name__ == "__main__":
    print(f"Nova Tool Kit v2.0 — {len(TOOL_SCHEMAS)} tools loaded")
    print(f"Permission profile: {PERMISSION_PROFILE}")
    gaps = {
        "Vision (Mythos)":       _VISION,
        "CVE Research (Daybreak)": _RESEARCHER,
        "Verify Engine (Daybreak)": _VERIFY,
        "Planner (Claude Code)":  _PLANNER,
        "Self-Improvement":       _SELF_IMPROVE,
    }
    for name, ok in gaps.items():
        print(f"  {'✅' if ok else '❌'} {name}")
