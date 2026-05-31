#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🧩 NOVA CONTEXT MANAGER v1.0 — ROLLING CONTEXT COMPRESSION       ║
║                                                                      ║
║   Closes the long-context gap vs Claude Code (200K tokens).         ║
║                                                                      ║
║   Claude Code can hold entire codebases in context.                 ║
║   Nova's HISTORY_LIMIT just truncates — losing critical findings.   ║
║                                                                      ║
║   This module maintains:                                            ║
║   • A verbatim rolling window of the last N tool calls             ║
║   • A compressed summary of everything before the window           ║
║   • A pinned section: critical findings NEVER compressed away       ║
║   • A plan section: current phase objectives always visible         ║
║                                                                      ║
║   Net effect: Nova can run 200+ step hunts without losing context. ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

OLLAMA_URL   = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("NOVA_LLM_MODEL", "") or "qwen3:8b"
WORKSPACE    = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))

VERBATIM_WINDOW   = int(os.getenv("NOVA_CTX_WINDOW",   "12"))  # last N exchanges kept verbatim
MAX_SUMMARY_CHARS = int(os.getenv("NOVA_CTX_SUMMARY",  "3000")) # compressed summary max length
MAX_PINNED        = int(os.getenv("NOVA_CTX_PINNED",   "10"))   # max pinned critical findings

# ── DATA STRUCTURES ────────────────────────────────────────────────────────────

@dataclass
class PinnedFinding:
    id:        str
    vuln_type: str
    endpoint:  str
    severity:  str
    summary:   str
    confirmed: bool = False
    ts:        str  = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_context_line(self) -> str:
        icon = "🔥" if self.confirmed else "⚠️"
        return (f"  {icon} [{self.severity}] {self.vuln_type} at {self.endpoint} "
                f"{'(CONFIRMED)' if self.confirmed else '(unverified)'} — {self.summary[:100]}")


@dataclass
class ContextWindow:
    session_id:   str
    target:       str
    objective:    str
    step:         int = 0

    # Rolling verbatim history (last VERBATIM_WINDOW exchanges)
    verbatim:     List[Dict] = field(default_factory=list)

    # Compressed summary of everything before verbatim window
    summary:      str = ""
    summary_step: int = 0   # step at which summary was last regenerated

    # Pinned critical findings — NEVER compressed away
    pinned:       List[PinnedFinding] = field(default_factory=list)

    # Current plan context (always visible)
    plan_context: str = ""

    # Token budget tracking (rough char estimate)
    verbatim_chars:  int = 0
    summary_chars:   int = 0

    def add_exchange(self, role: str, content: str):
        """Add one message to the verbatim window."""
        self.verbatim.append({"role": role, "content": content,
                               "step": self.step, "ts": datetime.utcnow().isoformat()})
        self.verbatim_chars += len(content)
        # Trim verbatim window if it grows too large
        if len(self.verbatim) > VERBATIM_WINDOW * 2:
            self._trim_verbatim()

    def _trim_verbatim(self):
        """Keep only the last VERBATIM_WINDOW exchanges, mark overflow for summary."""
        overflow = self.verbatim[:-VERBATIM_WINDOW]
        self.verbatim = self.verbatim[-VERBATIM_WINDOW:]
        self.verbatim_chars = sum(len(m["content"]) for m in self.verbatim)
        # Tag overflow for next summary regeneration
        self._overflow_buffer = getattr(self, "_overflow_buffer", []) + overflow

    def pin_finding(self, vuln_type: str, endpoint: str, severity: str,
                    summary: str, confirmed: bool = False, finding_id: str = None):
        """Pin a critical finding so it's never compressed away."""
        fid = finding_id or f"{vuln_type}_{endpoint}"[:32]
        # Deduplicate
        if any(p.id == fid for p in self.pinned):
            return
        self.pinned.append(PinnedFinding(
            id=fid, vuln_type=vuln_type, endpoint=endpoint,
            severity=severity, summary=summary, confirmed=confirmed,
        ))
        # Keep most critical MAX_PINNED
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.pinned.sort(key=lambda x: sev_order.get(x.severity.upper(), 5))
        self.pinned = self.pinned[:MAX_PINNED]

    def update_plan(self, plan_context: str):
        """Update the always-visible plan section."""
        self.plan_context = plan_context[:1500]

    def get_messages(self, system_prompt: str) -> List[Dict]:
        """
        Build the final messages list for the LLM call.
        Structure:
          [system] = system_prompt + pinned findings + plan + compressed summary
          [user/assistant ...] = verbatim recent history
        """
        # Build enriched system prompt
        sections = [system_prompt]

        if self.pinned:
            sections.append(
                "\n\n── CONFIRMED FINDINGS (never lose track of these) ──\n" +
                "\n".join(p.to_context_line() for p in self.pinned)
            )

        if self.plan_context:
            sections.append(f"\n\n── CURRENT HUNT PLAN ──\n{self.plan_context}")

        if self.summary:
            sections.append(
                f"\n\n── COMPRESSED HISTORY (steps 1–{self.summary_step}) ──\n{self.summary}"
            )

        enriched_system = "\n".join(sections)

        messages = [{"role": "system", "content": enriched_system}]
        # Add verbatim window (only role + content, strip metadata)
        for m in self.verbatim:
            messages.append({"role": m["role"], "content": m["content"]})

        return messages

    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id, "target": self.target,
            "objective": self.objective, "step": self.step,
            "verbatim": self.verbatim, "summary": self.summary,
            "summary_step": self.summary_step,
            "pinned": [asdict(p) for p in self.pinned],
            "plan_context": self.plan_context,
        }

    def save(self, path: Path = None):
        path = path or WORKSPACE / f"nova_context_{self.session_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> "ContextWindow":
        data = json.loads(path.read_text())
        ctx  = cls(session_id=data["session_id"], target=data["target"],
                    objective=data["objective"])
        ctx.step         = data.get("step", 0)
        ctx.verbatim     = data.get("verbatim", [])
        ctx.summary      = data.get("summary", "")
        ctx.summary_step = data.get("summary_step", 0)
        ctx.plan_context = data.get("plan_context", "")
        ctx.pinned       = [PinnedFinding(**p) for p in data.get("pinned", [])]
        return ctx


# ── CONTEXT SUMMARIZER ─────────────────────────────────────────────────────────

SUMMARIZE_SYSTEM = """You are compressing a security research agent's execution history.
Extract and preserve ONLY the critical information a future step needs:
- Every confirmed or suspected vulnerability (type, endpoint, evidence)
- Every credential, token, or secret found
- Every key technical discovery (tech stack, auth mechanism, admin paths)
- What has been tested and found NOT vulnerable (to avoid repeating)
- The current strategy direction

Output as CONCISE bullet points. Max 2000 characters. No fluff."""

def _call_ollama_compress(messages: List[Dict], model: str, timeout: int = 60) -> Optional[str]:
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 800},
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL.rstrip('/')}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        return raw.get("message", {}).get("content", "").strip()
    except Exception:
        return None


def compress_history(exchanges: List[Dict], model: str = None) -> str:
    """
    Compress a list of {role, content} exchanges into a short summary.
    Falls back to extractive summarization if Ollama is unavailable.
    """
    m = model or OLLAMA_MODEL

    # Build compression prompt
    history_text = "\n".join(
        f"[{e['role'].upper()} step {e.get('step','')}]: {e['content'][:500]}"
        for e in exchanges
    )

    messages = [
        {"role": "system", "content": SUMMARIZE_SYSTEM},
        {"role": "user",   "content": f"HISTORY TO COMPRESS:\n{history_text[:6000]}"},
    ]

    result = _call_ollama_compress(messages, m)
    if result:
        return result[:MAX_SUMMARY_CHARS]

    # Extractive fallback: pull key lines without LLM
    lines = history_text.split("\n")
    important = [l for l in lines if any(kw in l.lower() for kw in
        ["found", "confirmed", "token", "admin", "exploit", "sql", "xss", "bypass",
         "success", "critical", "high", "password", "secret", "vuln"])]
    return "\n".join(important[:40])[:MAX_SUMMARY_CHARS]


class ContextManager:
    """
    Wraps ContextWindow and handles automatic compression.
    Drop-in replacement for the raw history list in NovaAgent.
    """

    def __init__(self, session_id: str, target: str, objective: str,
                 compress_every: int = 8):
        self.ctx            = ContextWindow(session_id=session_id,
                                             target=target, objective=objective)
        self.compress_every = compress_every
        self._overflow: List[Dict] = []

    def add(self, role: str, content: str):
        self.ctx.step += 1
        self.ctx.add_exchange(role, content)
        # Check if we should compress
        overflow = getattr(self.ctx, "_overflow_buffer", [])
        if overflow:
            self._overflow.extend(overflow)
            self.ctx._overflow_buffer = []
        if len(self._overflow) >= self.compress_every:
            self._compress_overflow()

    def _compress_overflow(self):
        if not self._overflow:
            return
        print(f"  🧩 Compressing {len(self._overflow)} history entries...")
        new_summary_text = compress_history(self._overflow)
        # Append to existing summary
        if self.ctx.summary:
            self.ctx.summary = (
                self.ctx.summary + "\n\n" + new_summary_text
            )[:MAX_SUMMARY_CHARS]
        else:
            self.ctx.summary = new_summary_text[:MAX_SUMMARY_CHARS]
        self.ctx.summary_step = self.ctx.step
        self._overflow = []

    def pin(self, vuln_type: str, endpoint: str, severity: str,
            summary: str, confirmed: bool = False, finding_id: str = None):
        self.ctx.pin_finding(vuln_type, endpoint, severity, summary,
                              confirmed, finding_id)

    def set_plan(self, plan_context: str):
        self.ctx.update_plan(plan_context)

    def get_messages(self, system_prompt: str) -> List[Dict]:
        return self.ctx.get_messages(system_prompt)

    def save(self):
        self.ctx.save()

    def stats(self) -> str:
        return (f"Context: {len(self.ctx.verbatim)} verbatim msgs, "
                f"{len(self.ctx.summary)} summary chars, "
                f"{len(self.ctx.pinned)} pinned findings, "
                f"step {self.ctx.step}")


if __name__ == "__main__":
    mgr = ContextManager("test", "http://localhost:3000", "Find vulns")
    mgr.add("user",      "TARGET: http://localhost:3000\nOBJECTIVE: find all vulns")
    mgr.add("assistant", '{"thought":"start with recon","action":"bash_exec","args":{"command":"curl -I http://localhost:3000"}}')
    mgr.add("user",      "Tool result: X-Powered-By: Express\nX-Frame-Options: SAMEORIGIN")
    mgr.pin("sqli", "/rest/products/search", "CRITICAL", "' OR 1=1-- returns all users", confirmed=True)
    msgs = mgr.get_messages("You are Nova, a security researcher.")
    print(f"Messages: {len(msgs)}")
    print(f"System prompt length: {len(msgs[0]['content'])} chars")
    print(mgr.stats())
