#!/usr/bin/env python3
"""
ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â  ð§ NOVA TOOL KIT â Hardened Tool Governance Engine                        â
â                                                                              â
â  Addresses GAP 2: every tool call now goes through:                        â
â    1. Scope enforcement â target must be in session scope                  â
â    2. Permission model  â read_only | scoped | full (default: scoped)      â
â    3. Hook bus audit    â PreTool / PostTool / ToolError events             â
â    4. Tracer spans      â every call gets a span with full args/result      â
â    5. Redacted logging  â secrets stripped before any log write            â
â    6. Rollback story    â read-only tools never need rollback;              â
â                           destructive tools require explicit confirmation   â
â    7. Rate limiting     â per-tool call budget to prevent runaway loops    â
ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

# ââ Permission Profiles ââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

class PermissionProfile(str, Enum):
    READ_ONLY = "read_only"   # No network writes, no shell writes
    SCOPED    = "scoped"      # Network only to declared scope, shell allow-listed
    FULL      = "full"        # All tools (requires explicit opt-in)

DEFAULT_PROFILE: PermissionProfile = PermissionProfile(
    os.getenv("NOVA_PERMISSION_PROFILE", "scoped"))
STRICT_SCOPE = os.getenv("NOVA_STRICT_SCOPE", "true").lower() != "false"

# ââ Destructive patterns that are BLOCKED in all profiles except explicit âââââ

BLOCKED_SHELL_PATTERNS: List[str] = [
    r"rm\s+-rf?\s+/",
    r">\s*/dev/sd[a-z]",
    r"mkfs\.",
    r"dd\s+if=.*of=/dev/",
    r"chmod\s+777\s+/",
    r"chown\s+root",
    r"DROP\s+TABLE",
    r"DROP\s+DATABASE",
    r"curl\s+.*\|\s*(?:bash|sh)",
    r"wget\s+.*\|\s*(?:bash|sh)",
    r"format\s+[cC]:",
    r"del\s+/[fFqQsS]",
    r"shutdown\s+-[hrH]",
    r"reboot\b",
    r"pkill\s+-9\s+-1",
    r"::\s*\{.*\|.*\}",  # fork bomb
]

ALLOWED_SHELL_COMMANDS: Set[str] = {
    "curl", "nmap", "nslookup", "dig", "whois",
    "subfinder", "httpx", "nuclei", "ffuf", "gau", "katana",
    "python3", "python", "cat", "ls", "echo", "jq", "git",
    "semgrep", "bandit", "pip", "npm", "grep", "awk", "sed",
    "wc", "head", "tail", "find", "file", "strings",
    "openssl", "base64", "xxd", "hexdump",
    "docker", "kubectl",
    "node", "ruby", "go", "cargo",
    "sqlmap", "nikto", "wfuzz",
}

# ââ Secret redaction patterns ââââââââââââââââââââââââââââââââââââââââââââââââââ

REDACT_PATTERNS: List[Tuple[str, str]] = [
    (r"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}",         "[AWS_KEY_REDACTED]"),
    (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}","[GITHUB_TOKEN_REDACTED]"),
    (r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",       "[STRIPE_KEY_REDACTED]"),
    (r"sk-[A-Za-z0-9]{40,}",                      "[OPENAI_KEY_REDACTED]"),
    (r"sk-ant-[A-Za-z0-9\-]{20,}",               "[ANTHROPIC_KEY_REDACTED]"),
    (r"AIza[0-9A-Za-z\-_]{35}",                   "[GOOGLE_KEY_REDACTED]"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[^-]+-----END[^-]+-----",
     "[PRIVATE_KEY_REDACTED]"),
    (r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "password=[REDACTED]"),
    (r"(?:mongodb|postgres|mysql|redis)://[^@\s]{3,}@",
     "[DB_CONN_REDACTED]@"),
]


def redact(text: str) -> str:
    """Strip secrets from a string before logging."""
    for pattern, replacement in REDACT_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


# ââ Tool Audit Log âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

@dataclass
class ToolAuditEntry:
    ts:          str
    tool:        str
    agent:       str
    args:        Dict
    result:      str
    elapsed_ms:  float
    blocked:     bool    = False
    block_reason:str     = ""
    profile:     str     = ""
    cost_est:    float   = 0.0

    def to_dict(self) -> Dict:
        return {
            "ts":           self.ts,
            "tool":         self.tool,
            "agent":        self.agent,
            "args_redacted":redact(json.dumps(self.args, default=str))[:300],
            "result_len":   len(self.result),
            "result_head":  redact(self.result[:200]),
            "elapsed_ms":   round(self.elapsed_ms, 2),
            "blocked":      self.blocked,
            "block_reason": self.block_reason,
            "profile":      self.profile,
        }


class ToolAuditLog:
    """Thread-safe append-only audit log for all tool calls."""
    def __init__(self):
        self._entries: List[ToolAuditEntry] = []
        self._lock     = threading.Lock()
        self._path     = WORKSPACE / "nova_tool_audit.jsonl"

    def record(self, entry: ToolAuditEntry):
        with self._lock:
            self._entries.append(entry)
        try:
            with open(self._path, "a") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except Exception:
            pass

    def recent(self, n: int = 20) -> List[ToolAuditEntry]:
        with self._lock:
            return self._entries[-n:]

    def blocked_calls(self) -> List[ToolAuditEntry]:
        with self._lock:
            return [e for e in self._entries if e.blocked]

    def stats(self) -> Dict:
        with self._lock:
            total   = len(self._entries)
            blocked = sum(1 for e in self._entries if e.blocked)
            by_tool: Dict[str, int] = {}
            for e in self._entries:
                by_tool[e.tool] = by_tool.get(e.tool, 0) + 1
            total_ms = sum(e.elapsed_ms for e in self._entries)
        return {
            "total_calls":   total,
            "blocked_calls": blocked,
            "calls_by_tool": by_tool,
            "total_ms":      round(total_ms, 2),
        }


_AUDIT_LOG = ToolAuditLog()


# ââ Rate Limiter âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

class ToolRateLimiter:
    """Prevent runaway tool loops by capping calls per-tool per-session."""
    def __init__(self, defaults: Dict[str, int] = None):
        self._limits: Dict[str, int] = defaults or {
            "shell":       100,
            "http_probe":  200,
            "read_file":   500,
            "python_eval": 50,
            "grep_code":   100,
            "_default":    300,
        }
        self._counts: Dict[str, int] = {}
        self._lock   = threading.Lock()

    def check(self, tool_name: str) -> Tuple[bool, str]:
        limit = self._limits.get(tool_name, self._limits["_default"])
        with self._lock:
            count = self._counts.get(tool_name, 0)
            if count >= limit:
                return False, f"Rate limit: {tool_name} called {count}/{limit} times this session"
            self._counts[tool_name] = count + 1
        return True, ""


_RATE_LIMITER = ToolRateLimiter()


# ââ Scope Guard ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

class ScopeGuard:
    """Ensures tool calls target only declared in-scope hosts."""
    def __init__(self, scope: List[str] = None):
        self._scope: List[str] = scope or []

    def set_scope(self, scope: List[str]):
        self._scope = scope

    def check_url(self, url: str) -> Tuple[bool, str]:
        if not self._scope or not url:
            return True, "no scope restrictions"
        url_lower = url.lower()
        # Strip scheme
        host = re.sub(r"^https?://", "", url_lower).split("/")[0].split(":")[0]
        for s in self._scope:
            s_clean = s.lower().lstrip("*.")
            if host == s_clean or host.endswith("." + s_clean):
                return True, f"in scope: {s}"
        # Block well-known non-hack targets
        blocked_hosts = [
            "google.com", "facebook.com", "amazon.com", "microsoft.com",
            "apple.com", "cloudflare.com", "github.com", "twitter.com",
        ]
        for b in blocked_hosts:
            if b in host:
                return False, f"blocked: {b} is out of scope"
        if STRICT_SCOPE:
            return False, f"blocked: {host} not in declared scope"
        return True, f"warning: {host} not in declared scope"

    def check_path(self, path: str) -> Tuple[bool, str]:
        """Prevent reading outside workspace or sensitive system paths."""
        p = str(Path(path).resolve())
        sensitive = ["/etc/shadow", "/etc/passwd", "/root/.ssh",
                     "/proc/", "/sys/", "/dev/"]
        for s in sensitive:
            if p.startswith(s):
                return False, f"blocked: sensitive path {s}"
        return True, "ok"


_SCOPE_GUARD = ScopeGuard()


# ââ Governed Tool Wrapper ââââââââââââââââââââââââââââââââââââââââââââââââââââââ

@dataclass
class GovernedTool:
    """
    Wraps any callable with the full governance stack:
    scope check â rate limit â permission check â audit â hook bus â span â call
    """
    name:            str
    description:     str
    function:        Callable[[Dict], str]
    category:        str    = "generic"   # "http", "shell", "file", "eval"
    requires_scope:  bool   = False
    is_destructive:  bool   = False
    min_profile:     PermissionProfile = PermissionProfile.SCOPED
    schema:          Dict   = field(default_factory=dict)

    # Runtime wiring (injected by ToolKit.build())
    _bus:    Any = field(default=None, init=False, repr=False)
    _tracer: Any = field(default=None, init=False, repr=False)
    _scope:  ScopeGuard = field(default=None, init=False, repr=False)
    _profile: PermissionProfile = field(default=DEFAULT_PROFILE, init=False)

    def call(self, args: Dict, agent_name: str = "",
             profile: PermissionProfile = None) -> str:
        profile  = profile or self._profile
        t0       = time.monotonic()
        blocked  = False
        reason   = ""

        # ââ 1. Permission profile check ââââââââââââââââââââââââââââââââââââ
        profile_order = {
            PermissionProfile.READ_ONLY: 0,
            PermissionProfile.SCOPED:    1,
            PermissionProfile.FULL:      2,
        }
        if (profile_order.get(profile, 0) <
                profile_order.get(self.min_profile, 1)):
            blocked = True
            reason  = (f"Profile '{profile}' insufficient; "
                       f"tool '{self.name}' requires '{self.min_profile}'")

        # ââ 2. Destructive tool block ââââââââââââââââââââââââââââââââââââââ
        if not blocked and self.is_destructive and profile != PermissionProfile.FULL:
            blocked = True
            reason  = (f"Destructive tool '{self.name}' requires FULL profile. "
                       f"Current: {profile}")

        # ââ 3. Shell safety check ââââââââââââââââââââââââââââââââââââââââââ
        if not blocked and self.category == "shell":
            cmd = str(args.get("command",""))
            ok, msg = _check_shell_safety(cmd)
            if not ok:
                blocked = True
                reason  = msg

        # ââ 4. Scope check âââââââââââââââââââââââââââââââââââââââââââââââââ
        if not blocked and self.requires_scope and (self._scope or _SCOPE_GUARD):
            guard = self._scope or _SCOPE_GUARD
            url   = args.get("url","") or args.get("target","")
            if url:
                ok, msg = guard.check_url(url)
                if not ok:
                    blocked = True
                    reason  = msg

        # ââ 5. File path safety ââââââââââââââââââââââââââââââââââââââââââââ
        if not blocked and self.category == "file":
            path = str(args.get("path",""))
            if path:
                ok, msg = _SCOPE_GUARD.check_path(path)
                if not ok:
                    blocked = True
                    reason  = msg

        # ââ 6. Rate limit ââââââââââââââââââââââââââââââââââââââââââââââââââ
        if not blocked:
            ok, msg = _RATE_LIMITER.check(self.name)
            if not ok:
                blocked = True
                reason  = msg

        # ââ 7. PreTool hook ââââââââââââââââââââââââââââââââââââââââââââââââ
        if self._bus and not blocked:
            try:
                allow = self._bus.fire_pre_tool(self.name, args, agent=agent_name)
                if allow is False:
                    blocked = True
                    reason  = f"PreTool hook blocked '{self.name}'"
            except Exception:
                pass

        # ââ EXECUTE (or return block message) âââââââââââââââââââââââââââââ
        if blocked:
            result = f"[BLOCKED] {reason}"
            elapsed_ms = 0.0
        else:
            span_ctx = None
            if self._tracer:
                try:
                    span_ctx = self._tracer.span(
                        f"tool.{self.name}", kind="tool",
                        attrs={"agent": agent_name,
                               "args": redact(json.dumps(args, default=str))[:200]})
                except Exception:
                    pass
            try:
                if span_ctx:
                    with span_ctx:
                        result = self.function(args)
                else:
                    result = self.function(args)
            except Exception as e:
                result = f"ERROR: {e}"
                if self._bus:
                    try:
                        self._bus.fire_error(e, {"tool": self.name},
                                              agent=agent_name)
                    except Exception:
                        pass
            elapsed_ms = (time.monotonic() - t0) * 1000

        # ââ 8. PostTool hook âââââââââââââââââââââââââââââââââââââââââââââââ
        if self._bus and not blocked:
            try:
                self._bus.fire_post_tool(
                    self.name, args, result,
                    (time.monotonic() - t0) * 1000, agent=agent_name)
            except Exception:
                pass

        # ââ 9. Audit log (redacted) ââââââââââââââââââââââââââââââââââââââââ
        _AUDIT_LOG.record(ToolAuditEntry(
            ts          = datetime.now().isoformat(),
            tool        = self.name,
            agent       = agent_name,
            args        = args,
            result      = redact(str(result))[:2000],
            elapsed_ms  = (time.monotonic() - t0) * 1000,
            blocked     = blocked,
            block_reason= reason,
            profile     = str(profile),
        ))

        return result or ""

    def schema_str(self) -> str:
        props = self.schema.get("properties", {})
        parts = []
        for k, v in props.items():
            req = k in self.schema.get("required", [])
            parts.append(
                f"  {k} ({'req' if req else 'opt'}): "
                f"{v.get('type','str')} â {v.get('description','')}")
        return "\n".join(parts) or "  (no parameters)"


def _check_shell_safety(cmd: str) -> Tuple[bool, str]:
    """Block dangerous shell commands."""
    for pat in BLOCKED_SHELL_PATTERNS:
        if re.search(pat, cmd, re.IGNORECASE):
            return False, f"Blocked dangerous shell pattern: {pat}"
    parts = cmd.strip().split()
    if not parts:
        return False, "Empty command"
    # Check base command is in allow list
    base = Path(parts[0]).name  # handle /usr/bin/curl â curl
    if base not in ALLOWED_SHELL_COMMANDS:
        return False, (f"'{base}' not in shell allow-list. "
                       f"Allowed: {sorted(ALLOWED_SHELL_COMMANDS)}")
    return True, "ok"


# ââ Tool Factories âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def make_http_probe(scope: ScopeGuard = None) -> GovernedTool:
    import urllib.request as _ur, urllib.error as _ue

    def fn(args: Dict) -> str:
        url     = args.get("url","")
        method  = args.get("method","GET").upper()
        headers = args.get("headers",{})
        body    = args.get("body","")
        timeout = int(args.get("timeout",10))
        follow  = args.get("follow_redirects", True)
        try:
            data = body.encode() if body else None
            req  = _ur.Request(url, data=data, method=method)
            req.add_header("User-Agent","Nova-Governed/4.2")
            for k,v in (headers or {}).items():
                req.add_header(k, v)
            with _ur.urlopen(req, timeout=timeout) as r:
                body_bytes = r.read(16384)
                return json.dumps({
                    "status":       r.status,
                    "url":          url,
                    "headers":      dict(r.headers),
                    "body":         body_bytes.decode("utf-8","replace")[:8000],
                    "content_type": r.headers.get("Content-Type",""),
                    "server":       r.headers.get("Server",""),
                    "x_powered_by": r.headers.get("X-Powered-By",""),
                })
        except _ue.HTTPError as e:
            return json.dumps({"status": e.code, "error": str(e),
                               "body": e.read(2000).decode("utf-8","replace")})
        except Exception as e:
            return json.dumps({"error": str(e), "url": url})

    t = GovernedTool(
        name="http_probe",
        description="Send an HTTP request with full response. Scope-checked.",
        function=fn,
        category="http",
        requires_scope=True,
        min_profile=PermissionProfile.SCOPED,
        schema={"type":"object","properties":{
            "url":              {"type":"string","description":"Full URL"},
            "method":           {"type":"string","description":"GET/POST/PUT/DELETE/PATCH"},
            "headers":          {"type":"object","description":"Extra headers"},
            "body":             {"type":"string","description":"Request body"},
            "timeout":          {"type":"integer","description":"Timeout seconds (default 10)"},
            "follow_redirects": {"type":"boolean","description":"Follow redirects (default true)"},
        },"required":["url"]})
    t._scope = scope or _SCOPE_GUARD
    return t


def make_shell(scope: ScopeGuard = None,
               extra_allowed: List[str] = None) -> GovernedTool:
    if extra_allowed:
        ALLOWED_SHELL_COMMANDS.update(extra_allowed)

    def fn(args: Dict) -> str:
        cmd = args.get("command","")
        # Double-check safety inside the function too
        ok, msg = _check_shell_safety(cmd)
        if not ok:
            return f"ERROR (safety): {msg}"
        env = os.environ.copy()
        env["HOME"] = str(Path.home())
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=90, env=env)
            out = result.stdout[:8000]
            err = result.stderr[:1000] if result.returncode != 0 else ""
            return (out + ("\nSTDERR: " + err if err else "")) or "(no output)"
        except subprocess.TimeoutExpired:
            return "ERROR: command timed out after 90s"
        except Exception as e:
            return f"ERROR: {e}"

    return GovernedTool(
        name="shell",
        description=(f"Run an allow-listed shell command. "
                     f"Blocked: rm -rf /, curl|bash, DROP TABLE, etc."),
        function=fn,
        category="shell",
        requires_scope=False,
        min_profile=PermissionProfile.SCOPED,
        schema={"type":"object","properties":{
            "command":{"type":"string","description":"Shell command to execute"},
        },"required":["command"]})


def make_read_file() -> GovernedTool:
    def fn(args: Dict) -> str:
        path   = args.get("path","")
        offset = int(args.get("offset", 0))
        limit  = int(args.get("limit", 200))
        try:
            ok, msg = _SCOPE_GUARD.check_path(path)
            if not ok:
                return f"BLOCKED: {msg}"
            lines = Path(path).read_text(
                errors="replace").splitlines()
            chunk = lines[offset: offset + min(limit, 500)]
            return "\n".join(f"{offset+i+1}: {l}" for i, l in enumerate(chunk))
        except Exception as e:
            return f"ERROR: {e}"

    return GovernedTool(
        name="read_file",
        description="Read file lines with offset+limit pagination. Path-safety checked.",
        function=fn,
        category="file",
        requires_scope=False,
        min_profile=PermissionProfile.READ_ONLY,
        schema={"type":"object","properties":{
            "path":   {"type":"string","description":"Absolute or relative file path"},
            "offset": {"type":"integer","description":"Start line (0-indexed)"},
            "limit":  {"type":"integer","description":"Max lines (max 500)"},
        },"required":["path"]})


def make_grep_code() -> GovernedTool:
    def fn(args: Dict) -> str:
        pattern = args.get("pattern","")
        path    = args.get("path",".")
        flags   = args.get("flags","")
        # Check path safety
        ok, msg = _SCOPE_GUARD.check_path(path)
        if not ok:
            return f"BLOCKED: {msg}"
        safe_flags = re.sub(r"[^a-zA-Z0-9 '\-]", "", flags)
        try:
            result = subprocess.run(
                f"grep -rn {safe_flags} {json.dumps(pattern)} {json.dumps(path)}",
                shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout[:6000] or f"(no matches for '{pattern}')"
        except Exception as e:
            return f"ERROR: {e}"

    return GovernedTool(
        name="grep_code",
        description="Search codebase for a pattern. Returns file:line:content.",
        function=fn,
        category="file",
        requires_scope=False,
        min_profile=PermissionProfile.READ_ONLY,
        schema={"type":"object","properties":{
            "pattern": {"type":"string","description":"Regex/literal to search for"},
            "path":    {"type":"string","description":"Directory to search"},
            "flags":   {"type":"string","description":"grep flags (safe subset)"},
        },"required":["pattern"]})


def make_python_eval() -> GovernedTool:
    """Safe sandboxed Python eval â no I/O, no imports, no builtins."""
    def fn(args: Dict) -> str:
        import io, contextlib
        code = args.get("code","")
        # Block dangerous patterns
        forbidden = ["import", "__import__", "open(", "exec(", "eval(",
                     "subprocess", "os.system", "socket", "urllib"]
        for fb in forbidden:
            if fb in code.lower():
                return f"BLOCKED: '{fb}' not allowed in eval sandbox"
        safe_globals: Dict[str,Any] = {
            "json": json, "re": re, "__builtins__": {
                "print": print, "len": len, "range": range,
                "str": str, "int": int, "float": float,
                "list": list, "dict": dict, "set": set,
                "sorted": sorted, "enumerate": enumerate,
                "zip": zip, "map": map, "filter": filter,
                "min": min, "max": max, "sum": sum,
                "abs": abs, "round": round, "any": any, "all": all,
            }}
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exec(code, safe_globals)  # noqa: S102
            return buf.getvalue() or "(no output)"
        except Exception as e:
            return f"ERROR: {e}"

    return GovernedTool(
        name="python_eval",
        description="Execute sandboxed Python for data processing. No I/O or imports.",
        function=fn,
        category="eval",
        requires_scope=False,
        min_profile=PermissionProfile.SCOPED,
        schema={"type":"object","properties":{
            "code":{"type":"string","description":"Python code (no imports)"},
        },"required":["code"]})


def make_write_file() -> GovernedTool:
    """Write a file â ONLY within NOVA_WORKSPACE, never outside."""
    def fn(args: Dict) -> str:
        path    = args.get("path","")
        content = args.get("content","")
        # Resolve and validate
        resolved = Path(path).expanduser().resolve()
        ws       = WORKSPACE.resolve()
        if not str(resolved).startswith(str(ws)):
            return (f"BLOCKED: write_file can only write inside "
                    f"NOVA_WORKSPACE ({ws}). Path {resolved} is outside.")
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(content)
            return f"Written {len(content)} bytes to {resolved}"
        except Exception as e:
            return f"ERROR: {e}"

    return GovernedTool(
        name="write_file",
        description=f"Write a file ONLY inside NOVA_WORKSPACE ({WORKSPACE}). Never outside.",
        function=fn,
        category="file",
        is_destructive=False,
        requires_scope=False,
        min_profile=PermissionProfile.SCOPED,
        schema={"type":"object","properties":{
            "path":    {"type":"string","description":"Path (must be inside NOVA_WORKSPACE)"},
            "content": {"type":"string","description":"File content"},
        },"required":["path","content"]})


# ââ ToolKit Assembler ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

class NovaToolKit:
    """
    Assemble and wire a governed tool set for a given profile + scope.
    Usage:
        kit = NovaToolKit(profile=PermissionProfile.SCOPED, scope=["target.com"])
        tools = kit.build(include_destructive=False)
    """

    def __init__(
        self,
        profile: PermissionProfile = DEFAULT_PROFILE,
        scope:   List[str]         = None,
        bus:     Any               = None,
        tracer:  Any               = None,
    ):
        self.profile = profile
        self.scope   = ScopeGuard(scope or [])
        self.bus     = bus
        self.tracer  = tracer

    def build(self, include_eval: bool = True) -> List[GovernedTool]:
        tools: List[GovernedTool] = [
            make_http_probe(self.scope),
            make_shell(),
            make_read_file(),
            make_grep_code(),
            make_write_file(),
        ]
        if include_eval:
            tools.append(make_python_eval())

        # Wire bus, tracer, profile into every tool
        for t in tools:
            t._bus     = self.bus
            t._tracer  = self.tracer
            t._profile = self.profile
            if hasattr(t, "_scope") and not t._scope:
                t._scope = self.scope

        return tools

    def audit_stats(self) -> Dict:
        return _AUDIT_LOG.stats()

    def recent_audit(self, n: int = 20) -> List[Dict]:
        return [e.to_dict() for e in _AUDIT_LOG.recent(n)]

    def blocked_calls(self) -> List[Dict]:
        return [e.to_dict() for e in _AUDIT_LOG.blocked_calls()]


# ââ Module-level default kit âââââââââââââââââââââââââââââââââââââââââââââââââââ

def get_default_kit(scope: List[str] = None) -> NovaToolKit:
    """Get the default governed tool kit. Wire bus/tracer from provider layer."""
    bus, tracer = None, None
    try:
        from nova_hooks import get_bus
        bus = get_bus(verbose=False)
    except Exception:
        pass
    try:
        from nova_observability import Tracer
        tracer = Tracer(verbose=False)
    except Exception:
        pass
    return NovaToolKit(
        profile=DEFAULT_PROFILE,
        scope=scope,
        bus=bus,
        tracer=tracer)


# ââ Backward-compatibility exports matching old nova_tool_kit API âââââââââââââ

class Tool:
    """Thin compatibility shim â wraps GovernedTool."""
    def __init__(self, name, description, function,
                 schema=None, category="generic"):
        self._governed = GovernedTool(
            name=name, description=description, function=function,
            category=category, schema=schema or {})

    def call(self, args, bus=None, agent_name="") -> str:
        self._governed._bus = bus
        return self._governed.call(args, agent_name=agent_name)

    @property
    def name(self): return self._governed.name
    @property
    def description(self): return self._governed.description
    @property
    def schema(self): return self._governed.schema

    def schema_str(self) -> str:
        return self._governed.schema_str()


# ââ Public tool registry used by autonomous agents âââââââââââââââââââââââââââââ

_DEFAULT_TOOLS: Dict[str, GovernedTool] = {}
TOOL_SCHEMAS: Dict[str, Dict] = {}
_ALIAS_MAP: Dict[str, str] = {
    "http_request": "http_probe",
    "bash": "shell",
    "file_read": "read_file",
    "file_write": "write_file",
    "search_code": "grep_code",
}


def _ensure_registry(scope: List[str] = None) -> Dict[str, GovernedTool]:
    global _DEFAULT_TOOLS, TOOL_SCHEMAS
    if not _DEFAULT_TOOLS:
        kit = get_default_kit(scope=scope)
        _DEFAULT_TOOLS = {tool.name: tool for tool in kit.build(include_eval=True)}
        TOOL_SCHEMAS = {name: tool.schema for name, tool in _DEFAULT_TOOLS.items()}
    elif scope:
        for tool in _DEFAULT_TOOLS.values():
            if tool.requires_scope:
                tool._scope = ScopeGuard(scope)
    return _DEFAULT_TOOLS


def register_tool(tool: GovernedTool) -> None:
    """Register a governed tool for agent use."""
    tools = _ensure_registry()
    tools[tool.name] = tool
    TOOL_SCHEMAS[tool.name] = tool.schema


def list_tools() -> List[str]:
    return sorted(_ensure_registry().keys())


def tools_summary_for_prompt() -> str:
    lines = []
    for name, tool in sorted(_ensure_registry().items()):
        lines.append(f"- {name}: {tool.description}")
        schema = tool.schema_str()
        if schema:
            lines.append(schema)
    lines.append("- mission_complete: finish the run with a summary and optional findings")
    return "\n".join(lines)


def _coerce_result(tool_name: str, raw: str) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    text = str(raw or "")
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data.setdefault("success", "error" not in data)
            return data
    except Exception:
        pass
    success = not text.startswith("[BLOCKED]") and not text.startswith("ERROR:")
    return {"success": success, "tool": tool_name, "result": text, "content": text}


def execute_tool(tool_name: str, args: Dict = None, agent_name: str = "nova") -> Dict[str, Any]:
    """Execute a governed tool and return a structured observation."""
    args = args or {}
    canonical = _ALIAS_MAP.get(tool_name, tool_name)
    if canonical == "mission_complete":
        return {"success": True, "summary": args.get("summary", "Mission complete"), "findings": args.get("findings", [])}
    tools = _ensure_registry(scope=args.get("scope"))
    tool = tools.get(canonical)
    if not tool:
        return {"success": False, "tool": tool_name, "error": f"Unknown tool: {tool_name}", "available_tools": list_tools()}
    raw = tool.call(args, agent_name=agent_name)
    result = _coerce_result(canonical, raw)
    result.setdefault("tool", canonical)
    return result
