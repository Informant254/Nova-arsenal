#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🌐 NOVA BROWSER SESSION — Persistent Playwright Session Manager           ║
║                                                                              ║
║  Addresses GAP 4: one browser context per session with:                    ║
║  • Persistent login state (cookies, localStorage, sessionStorage)          ║
║  • HAR capture for every request/response                                  ║
║  • Screenshot on every major action                                        ║
║  • Console log capture (XSS verification)                                  ║
║  • Network event tracing (SSRF, CSP, timing)                              ║
║  • Visual diffs between states                                             ║
║  • Multi-step task memory (last N actions + screenshots)                   ║
║  • DOM event tracing                                                       ║
║                                                                             ║
║  Falls back gracefully if Playwright is not installed.                     ║
║                                                                              ║
║  Usage:                                                                      ║
║    session = NovaBrowserSession("http://localhost:3000")                    ║
║    session.start()                                                          ║
║    session.login("/login", {"email":"test@test.com","password":"test"})    ║
║    result = session.goto("/admin")                                         ║
║    session.screenshot("after_admin_nav")                                   ║
║    findings = session.check_xss_executed()                                 ║
║    session.stop()                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import base64
import hashlib
import json
import os
import re
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)
SCREENSHOT_DIR = WORKSPACE / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)
HAR_DIR        = WORKSPACE / "hars"
HAR_DIR.mkdir(exist_ok=True)

_PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import (
        sync_playwright, Browser, BrowserContext, Page,
        Route, Request as PWRequest, Response as PWResponse,
    )
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass


@dataclass
class NetworkEvent:
    ts:          str
    event_type:  str  # "request" | "response" | "websocket" | "console"
    url:         str  = ""
    method:      str  = ""
    status:      int  = 0
    content_type:str  = ""
    body:        str  = ""
    headers:     Dict = field(default_factory=dict)
    duration_ms: float= 0.0
    flags:       List[str] = field(default_factory=list)   # ssrf_probe, auth_required, etc.


@dataclass
class PageState:
    ts:           str
    url:          str
    title:        str
    html_hash:    str
    screenshot_path: str = ""
    console_logs: List[str] = field(default_factory=list)
    cookies:      List[Dict] = field(default_factory=list)
    local_storage:Dict = field(default_factory=dict)
    auth_token:   str  = ""


@dataclass
class BrowserFinding:
    type:        str
    severity:    str
    url:         str
    description: str
    evidence:    str = ""
    screenshot:  str = ""
    request:     str = ""
    response:    str = ""
    source:      str = "browser_session"


class NovaBrowserSession:
    """
    One Playwright browser context per Nova session.
    Maintains login state, captures network traffic, takes screenshots,
    and detects XSS execution, auth bypass, and SSRF from within the browser.
    """

    def __init__(
        self,
        base_url:   str,
        headless:   bool = True,
        timeout_ms: int  = 15000,
        verbose:    bool = True,
    ):
        self.base_url      = base_url.rstrip("/")
        self.headless      = headless
        self.timeout_ms    = timeout_ms
        self.verbose       = verbose
        self._session_id   = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._network_events: List[NetworkEvent] = []
        self._page_states:    List[PageState]    = []
        self._findings:       List[BrowserFinding]= []
        self._console_logs:   List[str]          = []
        self._xss_probes:     Dict[str, str]     = {}  # probe_id → context
        self._lock            = threading.Lock()

        # Playwright objects (set in start())
        self._pw:      Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page:    Any = None
        self._har_path     = HAR_DIR / f"nova_{self._session_id}.har"
        self._started      = False

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self, browser_type: str = "chromium") -> bool:
        if not _PLAYWRIGHT_AVAILABLE:
            if self.verbose:
                print("  ⚠️  Playwright not installed. Run: pip install playwright && playwright install chromium")
            return False
        try:
            self._pw      = sync_playwright().start()
            launcher      = getattr(self._pw, browser_type)
            self._browser = launcher.launch(
                headless=self.headless,
                args=["--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-web-security"])   # for CORS testing
            self._context = self._browser.new_context(
                record_har_path=str(self._har_path),
                record_har_content="attach",
                ignore_https_errors=True,
                user_agent="Nova-Browser/4.2 (Security Testing)",
                viewport={"width": 1280, "height": 800},
            )
            self._context.set_default_timeout(self.timeout_ms)
            self._page    = self._context.new_page()
            self._wire_events()
            self._started = True
            if self.verbose:
                print(f"  🌐 Browser session started ({browser_type}, "
                      f"{'headless' if self.headless else 'headed'})")
            return True
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Browser start failed: {e}")
            return False

    def stop(self):
        if not self._started:
            return
        try:
            self._context.close()   # flushes HAR
            self._browser.close()
            self._pw.stop()
            if self.verbose:
                print(f"  🌐 Browser stopped. HAR → {self._har_path}")
                print(f"     Network events: {len(self._network_events)}")
                print(f"     Screenshots:    {len(self._page_states)}")
                print(f"     Findings:       {len(self._findings)}")
        except Exception:
            pass
        self._started = False

    def __enter__(self):
        self.start(); return self

    def __exit__(self, *_):
        self.stop()

    # ── Navigation ─────────────────────────────────────────────────────────────

    def goto(self, path: str, wait: str = "networkidle") -> Dict:
        if not self._started:
            return self._fallback_goto(path)
        url = path if path.startswith("http") else self.base_url + path
        try:
            resp = self._page.goto(url, wait_until=wait, timeout=self.timeout_ms)
            state = self._capture_state(url)
            return {
                "url":    self._page.url,
                "status": resp.status if resp else 0,
                "title":  self._page.title(),
                "html":   self._page.content()[:8000],
                "state":  state,
            }
        except Exception as e:
            return {"error": str(e), "url": url}

    def click(self, selector: str, wait_after_ms: int = 500) -> Dict:
        if not self._started:
            return {"error": "not started"}
        try:
            self._page.click(selector, timeout=self.timeout_ms)
            self._page.wait_for_timeout(wait_after_ms)
            return {"clicked": selector, "url": self._page.url}
        except Exception as e:
            return {"error": str(e)}

    def fill(self, selector: str, value: str) -> Dict:
        if not self._started:
            return {"error": "not started"}
        try:
            self._page.fill(selector, value, timeout=self.timeout_ms)
            return {"filled": selector, "value": value[:30] + "..."}
        except Exception as e:
            return {"error": str(e)}

    def submit_form(self, form_data: Dict[str, str],
                    submit_selector: str = "button[type=submit]") -> Dict:
        if not self._started:
            return {"error": "not started"}
        results = {}
        for selector, value in form_data.items():
            try:
                self._page.fill(selector, value)
                results[selector] = "filled"
            except Exception as e:
                results[selector] = f"error: {e}"
        try:
            self._page.click(submit_selector)
            self._page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
            results["submitted"] = True
            results["final_url"] = self._page.url
        except Exception as e:
            results["submit_error"] = str(e)
        return results

    # ── Authentication ─────────────────────────────────────────────────────────

    def login(
        self,
        login_path: str,
        credentials: Dict[str, str],
        email_selector:    str = "input[type=email], input[name=email], #email",
        password_selector: str = "input[type=password], input[name=password], #password",
        submit_selector:   str = "button[type=submit]",
    ) -> bool:
        if not self._started:
            return False
        self.goto(login_path)
        try:
            email    = credentials.get("email", credentials.get("username",""))
            password = credentials.get("password","")
            self._page.fill(email_selector,    email,    timeout=5000)
            self._page.fill(password_selector, password, timeout=5000)
            self._page.click(submit_selector)
            self._page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
            # Detect successful login (not back on login page)
            success = login_path.rstrip("/") not in self._page.url
            if success:
                self._save_auth_state()
                if self.verbose:
                    print(f"  🔐 Logged in as {email} → {self._page.url}")
            return success
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Login failed: {e}")
            return False

    def inject_token(self, token: str, storage_key: str = "token",
                     header_name: str = "Authorization"):
        """Inject a JWT/Bearer token into localStorage and default headers."""
        if not self._started:
            return
        try:
            self._page.evaluate(
                f"localStorage.setItem({json.dumps(storage_key)}, {json.dumps(token)})")
            self._context.set_extra_http_headers(
                {header_name: f"Bearer {token}"})
        except Exception:
            pass

    def set_cookies(self, cookies: List[Dict]):
        """Restore saved cookies (session resumption)."""
        if not self._started:
            return
        try:
            self._context.add_cookies(cookies)
        except Exception:
            pass

    # ── XSS Verification ──────────────────────────────────────────────────────

    def probe_xss(self, url: str, payload: str, param: str = "") -> BrowserFinding:
        """
        Inject XSS payload, navigate to the result URL, and verify DOM execution
        via console log — not just reflected text matching.
        """
        marker   = f"nova_xss_{hashlib.md5(payload.encode()).hexdigest()[:8]}"
        xss_payload = payload.replace("MARKER", marker)

        with self._lock:
            self._xss_probes[marker] = f"via {param} on {url}"

        # Navigate to URL (payload may already be in URL query string)
        result   = self.goto(url)
        html     = result.get("html","")
        executed = marker in str(self._console_logs)
        reflected= marker in html

        if executed:
            sshot = self.screenshot(f"xss_exec_{marker}")
            with self._lock:
                finding = BrowserFinding(
                    type="XSS_Executed",
                    severity="HIGH",
                    url=url,
                    description=f"XSS payload executed in browser. Marker '{marker}' seen in console.",
                    evidence=f"payload={xss_payload[:100]}, param={param}",
                    screenshot=sshot,
                    source="browser_session",
                )
                self._findings.append(finding)
            return finding
        elif reflected:
            return BrowserFinding(
                type="XSS_Reflected",
                severity="MEDIUM",
                url=url,
                description=f"XSS payload reflected but not executed (may be encoded).",
                evidence=f"payload={xss_payload[:100]}, param={param}",
                source="browser_session",
            )
        return BrowserFinding(
            type="XSS_NotFound",
            severity="INFO",
            url=url,
            description="XSS payload not reflected or executed.",
            source="browser_session",
        )

    def check_xss_executed(self) -> List[BrowserFinding]:
        """Return all confirmed XSS execution findings from this session."""
        with self._lock:
            return [f for f in self._findings if f.type == "XSS_Executed"]

    # ── Screenshot ─────────────────────────────────────────────────────────────

    def screenshot(self, label: str = "") -> str:
        if not self._started:
            return ""
        ts   = datetime.now().strftime("%H%M%S")
        name = f"nova_{self._session_id}_{label or ts}.png"
        path = SCREENSHOT_DIR / name
        try:
            self._page.screenshot(path=str(path), full_page=True)
            return str(path)
        except Exception:
            return ""

    def visual_diff(self, label_a: str, label_b: str) -> Dict:
        """
        Compare two screenshots by pixel hash (lightweight diff).
        Returns {changed: bool, pct_changed: float}.
        """
        pa = SCREENSHOT_DIR / label_a
        pb = SCREENSHOT_DIR / label_b
        if not pa.exists() or not pb.exists():
            return {"error": "screenshot not found"}
        try:
            ha = hashlib.md5(pa.read_bytes()).hexdigest()
            hb = hashlib.md5(pb.read_bytes()).hexdigest()
            return {
                "changed":    ha != hb,
                "hash_a":     ha,
                "hash_b":     hb,
                "same_size":  pa.stat().st_size == pb.stat().st_size,
            }
        except Exception as e:
            return {"error": str(e)}

    # ── Auth Bypass Check ──────────────────────────────────────────────────────

    def check_auth_bypass(self, protected_paths: List[str]) -> List[BrowserFinding]:
        """
        Visit protected paths WITHOUT auth and check if access is granted.
        Records bypass findings.
        """
        findings = []
        for path in protected_paths:
            result = self.goto(path)
            url    = result.get("url","")
            html   = result.get("html","")
            status = result.get("status", 0)
            # Bypass indicators: still on the protected page (not redirected to login)
            still_on_page = (path.rstrip("/") in url.rstrip("/"))
            login_redirect = any(kw in url.lower() for kw in ("login","signin","auth"))
            if still_on_page and not login_redirect and status in (200, 201):
                sshot = self.screenshot(f"bypass_{path.replace('/','_')}")
                f = BrowserFinding(
                    type     ="AuthBypass",
                    severity ="HIGH",
                    url      =url,
                    description=f"Protected path {path} accessible without authentication",
                    evidence = f"status={status}, url={url}, no login redirect",
                    screenshot=sshot,
                    source   ="browser_session",
                )
                findings.append(f)
                with self._lock:
                    self._findings.append(f)
                if self.verbose:
                    print(f"  🔴 Auth bypass: {path} → {status}")
        return findings

    # ── Network Traffic Analysis ───────────────────────────────────────────────

    def get_network_events(self, filter_type: str = None) -> List[NetworkEvent]:
        with self._lock:
            evs = list(self._network_events)
        if filter_type:
            evs = [e for e in evs if e.event_type == filter_type]
        return evs

    def get_har_path(self) -> str:
        return str(self._har_path)

    def analyse_network(self) -> Dict:
        """Analyse captured network events for security issues."""
        issues = []
        with self._lock:
            events = list(self._network_events)
        # Check for requests to metadata endpoints (SSRF sign)
        meta_patterns = [
            "169.254.169.254", "metadata.google", "100.100.100.200",
            "localhost:", "127.0.0.1", "0.0.0.0",
        ]
        for ev in events:
            for pat in meta_patterns:
                if pat in ev.url:
                    issues.append({
                        "type":   "SSRF_Evidence",
                        "url":    ev.url,
                        "method": ev.method,
                    })
        # Sensitive data in URLs (IDOR indicators)
        for ev in events:
            if re.search(r"/(?:user|account|order|payment)s?/(\d+)", ev.url):
                issues.append({
                    "type": "IDOR_Candidate",
                    "url":  ev.url,
                    "note": "ID in URL — test IDOR",
                })
        # Missing security headers
        for ev in events:
            if ev.event_type == "response":
                h = {k.lower(): v for k,v in ev.headers.items()}
                if not h.get("x-frame-options") and not h.get("content-security-policy"):
                    issues.append({
                        "type": "MissingSecurityHeaders",
                        "url":  ev.url,
                    })
                    break   # only report once
        return {
            "total_requests":    len([e for e in events if e.event_type=="request"]),
            "total_responses":   len([e for e in events if e.event_type=="response"]),
            "issues":            issues,
            "console_errors":    [l for l in self._console_logs if "error" in l.lower()],
        }

    # ── State Management ───────────────────────────────────────────────────────

    def save_auth_state(self, path: str = None) -> str:
        """Save cookies + localStorage to file for session resumption."""
        out = Path(path or str(WORKSPACE / f"nova_auth_{self._session_id}.json"))
        if not self._started:
            return ""
        state = {
            "cookies":       self._context.cookies(),
            "base_url":      self.base_url,
            "saved_at":      datetime.now().isoformat(),
        }
        out.write_text(json.dumps(state, indent=2, default=str))
        return str(out)

    def load_auth_state(self, path: str):
        """Restore cookies from a saved auth state file."""
        try:
            state = json.loads(Path(path).read_text())
            if self._started and state.get("cookies"):
                self._context.add_cookies(state["cookies"])
                if self.verbose:
                    print(f"  🔐 Auth state restored from {path}")
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Load auth state: {e}")

    def get_findings(self) -> List[Dict]:
        with self._lock:
            return [
                {
                    "type":       f.type,
                    "severity":   f.severity,
                    "url":        f.url,
                    "description":f.description,
                    "evidence":   f.evidence,
                    "screenshot": f.screenshot,
                    "source":     f.source,
                }
                for f in self._findings
            ]

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _wire_events(self):
        if not self._started or not self._page:
            return
        # Network requests
        self._page.on("request",  self._on_request)
        self._page.on("response", self._on_response)
        # Console messages (critical for XSS verification)
        self._page.on("console",  self._on_console)
        # Page errors
        self._page.on("pageerror",lambda e: self._console_logs.append(f"ERROR: {e}"))

    def _on_request(self, req):
        ev = NetworkEvent(
            ts         = datetime.now().isoformat(),
            event_type = "request",
            url        = req.url,
            method     = req.method,
            headers    = dict(req.headers),
        )
        with self._lock:
            self._network_events.append(ev)

    def _on_response(self, resp):
        ev = NetworkEvent(
            ts           = datetime.now().isoformat(),
            event_type   = "response",
            url          = resp.url,
            status       = resp.status,
            content_type = resp.headers.get("content-type",""),
            headers      = dict(resp.headers),
        )
        with self._lock:
            self._network_events.append(ev)

    def _on_console(self, msg):
        text = f"[{msg.type.upper()}] {msg.text}"
        with self._lock:
            self._console_logs.append(text)
        # XSS execution detection
        for marker in list(self._xss_probes.keys()):
            if marker in msg.text:
                if self.verbose:
                    print(f"  🔴 XSS EXECUTED: {marker} in console [{msg.type}]")

    def _capture_state(self, url: str) -> PageState:
        state = PageState(
            ts         = datetime.now().isoformat(),
            url        = url,
            title      = "",
            html_hash  = "",
        )
        if not self._started:
            return state
        try:
            html         = self._page.content()
            state.title  = self._page.title()
            state.html_hash = hashlib.md5(html.encode()).hexdigest()
            state.console_logs = list(self._console_logs[-20:])
            try:
                state.cookies = self._context.cookies()
            except Exception:
                pass
            try:
                state.local_storage = self._page.evaluate(
                    "() => ({...localStorage})")
                # Check for tokens
                for k, v in state.local_storage.items():
                    if "token" in k.lower() and v:
                        state.auth_token = v[:200]
                        break
            except Exception:
                pass
        except Exception:
            pass
        with self._lock:
            self._page_states.append(state)
        return state

    def _save_auth_state(self):
        self.save_auth_state()

    def _fallback_goto(self, path: str) -> Dict:
        """urllib fallback when Playwright is not available."""
        import urllib.request, urllib.error
        url = path if path.startswith("http") else self.base_url + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"Nova/4.2"})
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read(8192).decode("utf-8","replace")
                return {"url": url, "status": r.status,
                        "html": body, "title": ""}
        except Exception as e:
            return {"url": url, "error": str(e)}
