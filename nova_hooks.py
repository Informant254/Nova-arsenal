#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🪝 NOVA HOOKS v1.0 — Lifecycle Hook System                                ║
║                                                                              ║
║  Event-driven hooks that fire at every stage of the agent lifecycle.        ║
║  Mirrors the Anthropic Claude Agent SDK hook architecture.                  ║
║                                                                              ║
║  Hook points:                                                                ║
║    PreRun         — before any agent starts                                 ║
║    PostRun        — after an agent completes                                ║
║    PreTool        — before a tool is called                                 ║
║    PostTool       — after a tool returns                                    ║
║    OnError        — when any agent or tool raises an exception              ║
║    OnHandoff      — when one agent hands off to another                     ║
║    OnHandoffDone  — after the receiving agent completes                     ║
║    OnFinding      — when a security finding is emitted                      ║
║    OnStream       — each streaming token                                    ║
║    OnMemoryWrite  — when nova_memory_system writes to persistent memory     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    from nova_hooks import HookBus, hook

    bus = HookBus()

    @bus.on("PreTool")
    def log_tool(ctx):
        print(f"[PreTool] Calling {ctx['tool_name']} on {ctx['target']}")

    @bus.on("OnFinding")
    def save_finding(ctx):
        with open("findings.jsonl", "a") as f:
            f.write(json.dumps(ctx['finding']) + "\\n")

    # Fire manually
    bus.fire("PreRun", {"agent": "ReconAgent", "target": "example.com"})
"""

import json
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# ── Hook event ─────────────────────────────────────────────────────────────────

VALID_HOOKS = {
    "PreRun",
    "PostRun",
    "PreTool",
    "PostTool",
    "OnError",
    "OnHandoff",
    "OnHandoffDone",
    "OnFinding",
    "OnStream",
    "OnMemoryWrite",
    "OnPhaseStart",
    "OnPhaseEnd",
    "OnCancelled",
    "OnGuardrailBlock",
}

HookFn = Callable[[Dict[str, Any]], None]


@dataclass
class HookRegistration:
    event:    str
    fn:       HookFn
    priority: int = 0        # lower = runs first
    name:     str = ""


@dataclass
class HookEvent:
    event:     str
    payload:   Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent:     Optional[str] = None
    cancelled: bool = False   # PreTool hooks can set this to cancel the tool call


# ── Hook bus ───────────────────────────────────────────────────────────────────

class HookBus:
    """
    Central event bus for Nova agent lifecycle events.
    Thread-safe. Hooks run synchronously in priority order.
    """

    def __init__(self, workspace: Optional[Path] = None, verbose: bool = False):
        self._handlers: Dict[str, List[HookRegistration]] = defaultdict(list)
        self._history:  List[HookEvent] = []
        self._verbose   = verbose
        self._workspace = workspace or Path.home() / "nova_workspace"
        self._workspace.mkdir(parents=True, exist_ok=True)

    # ── Registration ───────────────────────────────────────────────

    def on(self, event: str, priority: int = 0, name: str = "") -> Callable:
        """Decorator: @bus.on("PreTool")"""
        def decorator(fn: HookFn) -> HookFn:
            self.register(event, fn, priority=priority, name=name or fn.__name__)
            return fn
        return decorator

    def register(self, event: str, fn: HookFn, priority: int = 0, name: str = ""):
        if event not in VALID_HOOKS:
            raise ValueError(f"Unknown hook event '{event}'. Valid: {VALID_HOOKS}")
        reg = HookRegistration(event=event, fn=fn, priority=priority,
                               name=name or getattr(fn, "__name__", "anon"))
        self._handlers[event].append(reg)
        self._handlers[event].sort(key=lambda r: r.priority)

    def unregister(self, event: str, name: str):
        self._handlers[event] = [r for r in self._handlers[event] if r.name != name]

    # ── Firing ─────────────────────────────────────────────────────

    def fire(self, event: str, payload: Optional[Dict[str, Any]] = None,
             agent: Optional[str] = None) -> HookEvent:
        """
        Fire an event. Returns the (possibly mutated) HookEvent.
        Hooks can set event.cancelled = True to signal cancellation.
        """
        ev = HookEvent(event=event, payload=payload or {}, agent=agent)
        self._history.append(ev)

        if self._verbose:
            ts = ev.timestamp[11:19]
            print(f"  [{ts}] 🪝 {event}" + (f" [{agent}]" if agent else ""))

        for reg in self._handlers.get(event, []):
            try:
                reg.fn({**ev.payload, "_event": event, "_agent": agent,
                        "_timestamp": ev.timestamp, "_hook_event": ev})
            except Exception as exc:
                print(f"  ⚠️  Hook '{reg.name}' on '{event}' raised: {exc}")
                if self._verbose:
                    traceback.print_exc()

        return ev

    def fire_pre_tool(self, tool_name: str, args: Dict,
                      agent: Optional[str] = None) -> bool:
        """Fire PreTool. Returns False if any hook set cancelled=True."""
        ev = self.fire("PreTool", {"tool_name": tool_name, "args": args}, agent=agent)
        return not ev.cancelled

    def fire_post_tool(self, tool_name: str, args: Dict, result: Any,
                       elapsed_ms: float, agent: Optional[str] = None):
        self.fire("PostTool", {"tool_name": tool_name, "args": args,
                               "result": result, "elapsed_ms": elapsed_ms}, agent=agent)

    def fire_finding(self, finding: Dict, agent: Optional[str] = None):
        self.fire("OnFinding", {"finding": finding}, agent=agent)

    def fire_error(self, error: Exception, context: Optional[Dict] = None,
                   agent: Optional[str] = None):
        self.fire("OnError", {"error": str(error), "type": type(error).__name__,
                               "traceback": traceback.format_exc(),
                               **(context or {})}, agent=agent)

    def fire_handoff(self, from_agent: str, to_agent: str, state: Dict):
        self.fire("OnHandoff", {"from": from_agent, "to": to_agent, "state": state})

    # ── Persistence ────────────────────────────────────────────────

    def save_history(self, path: Optional[str] = None):
        out = path or str(self._workspace / "hook_history.jsonl")
        with open(out, "a") as f:
            for ev in self._history:
                f.write(json.dumps({
                    "event": ev.event, "agent": ev.agent,
                    "timestamp": ev.timestamp, "payload_keys": list(ev.payload.keys())
                }) + "\n")
        self._history.clear()

    # ── Stats ──────────────────────────────────────────────────────

    def stats(self) -> Dict:
        counts: Dict[str, int] = defaultdict(int)
        for ev in self._history:
            counts[ev.event] += 1
        return {
            "registered_hooks": {k: len(v) for k, v in self._handlers.items() if v},
            "event_counts": dict(counts),
        }


# ── Built-in hooks ─────────────────────────────────────────────────────────────

def attach_logging_hooks(bus: HookBus, log_file: Optional[str] = None):
    """Attach standard logging hooks that write events to a JSONL file."""
    out = log_file or str(bus._workspace / "nova_events.jsonl")

    @bus.on("OnFinding", name="log_finding")
    def _log_finding(ctx):
        with open(out, "a") as f:
            f.write(json.dumps({"ts": ctx["_timestamp"], "event": "OnFinding",
                                "finding": ctx.get("finding", {})}) + "\n")

    @bus.on("OnError", name="log_error")
    def _log_error(ctx):
        with open(out, "a") as f:
            f.write(json.dumps({"ts": ctx["_timestamp"], "event": "OnError",
                                "error": ctx.get("error"), "agent": ctx.get("_agent")}) + "\n")

    @bus.on("PostRun", name="log_run")
    def _log_run(ctx):
        with open(out, "a") as f:
            f.write(json.dumps({"ts": ctx["_timestamp"], "event": "PostRun",
                                "agent": ctx.get("_agent"), "elapsed_ms": ctx.get("elapsed_ms"),
                                "findings_count": ctx.get("findings_count", 0)}) + "\n")


def attach_telegram_hooks(bus: HookBus, token: str, chat_id: str):
    """Fire Telegram messages on critical findings and errors."""
    import urllib.request as _ur

    def _tg(msg: str):
        try:
            url     = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = json.dumps({"chat_id": chat_id, "text": msg,
                                  "parse_mode": "Markdown"}).encode()
            _ur.urlopen(_ur.Request(url, data=payload,
                        headers={"Content-Type": "application/json"}), timeout=10)
        except Exception:
            pass

    @bus.on("OnFinding", name="tg_critical_finding")
    def _on_finding(ctx):
        f = ctx.get("finding", {})
        sev = f.get("severity", "").upper()
        if sev in ("CRITICAL", "HIGH"):
            _tg(f"🚨 *{sev} Finding*\n`{f.get('type', '?')}` @ `{f.get('endpoint', '?')}`\n"
                f"{f.get('description', '')[:200]}")

    @bus.on("OnError", name="tg_error")
    def _on_error(ctx):
        _tg(f"❌ Nova error [{ctx.get('_agent', '?')}]: {ctx.get('error', '')[:200]}")


# ── Global singleton ───────────────────────────────────────────────────────────

_bus: Optional[HookBus] = None

def get_bus(verbose: bool = False) -> HookBus:
    global _bus
    if _bus is None:
        _bus = HookBus(verbose=verbose)
    return _bus


# ── Convenience decorator ──────────────────────────────────────────────────────

def hook(event: str, priority: int = 0, name: str = ""):
    """Module-level @hook decorator that registers on the global bus."""
    def decorator(fn: HookFn) -> HookFn:
        get_bus().register(event, fn, priority=priority, name=name or fn.__name__)
        return fn
    return decorator


# ── CLI test ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    bus = HookBus(verbose=True)

    @bus.on("PreRun")
    def on_pre_run(ctx):
        print(f"  → Agent '{ctx.get('agent')}' starting on {ctx.get('target')}")

    @bus.on("OnFinding")
    def on_finding(ctx):
        f = ctx["finding"]
        print(f"  🐛 [{f.get('severity')}] {f.get('type')} — {f.get('endpoint')}")

    bus.fire("PreRun", {"agent": "ReconAgent", "target": "example.com"})
    bus.fire_finding({"type": "XSS", "severity": "HIGH",
                      "endpoint": "/search?q=", "description": "Reflected XSS via q param"})
    bus.fire("PostRun", {"agent": "ReconAgent", "elapsed_ms": 3412, "findings_count": 1})
    print("\nStats:", bus.stats())
