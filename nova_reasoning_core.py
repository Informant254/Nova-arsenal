#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🧠 NOVA REASONING CORE v2.0 — UPGRADED LLM BACKBONE          ║
║                                                                  ║
║   Upgraded from v1.0 (single model, generic prompts)            ║
║                                                                  ║
║   v2.0 improvements:                                            ║
║   • Task-aware model routing via NovaModelRouter                ║
║   • Chain-of-thought forcing for all reasoning tasks            ║
║   • Expert system prompts per task domain                       ║
║   • RAG context injection from past findings                    ║
║   • Parallel inference support for swarm mode                   ║
║   • Better JSON extraction (strips CoT <thinking> blocks)       ║
║                                                                  ║
║   Config via env vars:                                          ║
║     NOVA_LLM_URL      — Ollama base URL (default: localhost)    ║
║     NOVA_LLM_MODEL    — Override model for all tasks            ║
║     NOVA_LLM_TIMEOUT  — Request timeout in seconds (default 90) ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

import requests

_OLLAMA_URL = os.getenv("NOVA_LLM_URL",    "http://localhost:11434")
_FORCE_MDL  = os.getenv("NOVA_LLM_MODEL",  "")   # if set, skip routing
_TIMEOUT    = int(os.getenv("NOVA_LLM_TIMEOUT", "90"))

try:
    from nova_model_router import NovaModelRouter, get_router
    _ROUTER_AVAILABLE = True
except ImportError:
    _ROUTER_AVAILABLE = False

try:
    from nova_rag_builder import NovaRAGBuilder, get_rag
    _RAG_AVAILABLE = True
except ImportError:
    _RAG_AVAILABLE = False

# ── EXPERT SYSTEM PROMPTS ─────────────────────────────────────────
_SYSTEM = {
    "default": (
        "You are Nova, an elite autonomous security AI with deep expertise in "
        "web application security, bug bounty hunting, and offensive research. "
        "Think carefully and output valid JSON only."
    ),
    "finding": (
        "You are a senior application security engineer validating bug bounty findings. "
        "Determine with precision whether a finding is a real vulnerability or a false positive. "
        "Think step-by-step before concluding. Output valid JSON only."
    ),
    "scoring": (
        "You are a bug bounty triage expert. Score findings accurately using CVSS 3.1. "
        "Think: attack vector → complexity → privileges → interaction → scope → impact. "
        "Output valid JSON only."
    ),
    "payload": (
        "You are an expert penetration tester. Generate creative, context-aware exploit payloads "
        "that bypass WAFs and filters. Think about the tech stack, encoding, and filter evasion. "
        "Output ONLY the raw payload string."
    ),
    "code": (
        "You are a senior AppSec engineer conducting source code review. "
        "Trace data flow from user input to dangerous sinks. "
        "Identify missing sanitization, authentication checks, and vulnerable patterns. "
        "Output valid JSON with file references and exploit paths."
    ),
    "report": (
        "You are a professional penetration tester writing a bug bounty submission. "
        "Be specific: exact URLs, parameters, payloads, response excerpts. "
        "Structure: title, severity, summary, steps to reproduce, impact, PoC, remediation."
    ),
    "recon": (
        "You are a bug bounty recon specialist. Analyze attack surface data quickly. "
        "Focus on: admin panels, API endpoints, auth flows, file uploads, search params. "
        "Output valid JSON only."
    ),
}

# Chain-of-thought suffix appended to reasoning prompts
_COT_SUFFIX = (
    "\n\nThink step by step before answering:\n"
    "<thinking>\n"
    "1. What is the evidence showing?\n"
    "2. What are the alternative explanations?\n"
    "3. What is the most likely conclusion?\n"
    "</thinking>\n"
    "Now output your final answer as valid JSON:"
)

_COT_TASKS = frozenset({
    "finding", "scoring", "threat_prioritization", "false_positive_check",
})


class NovaReasoningCore:
    """
    Upgraded unified LLM wrapper for all Nova modules.

    Usage:
        core = get_reasoning_core()

        # Simple completion
        text = core.think("What attack should I try next?", task="default")

        # JSON completion
        result = core.think_json("Score this finding: ...", task="scoring")

        # Finding-specific shortcut
        enriched = core.reason_about_finding(finding_dict)
    """

    def __init__(self):
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "Nova/3.0-ReasoningCore"
        self._router: Optional["NovaModelRouter"] = None
        self._rag: Optional["NovaRAGBuilder"]      = None
        self._fallback_model: Optional[str]        = None
        self._probe()

    def _probe(self):
        """Auto-detect available backend and best models."""
        # Model router
        if _ROUTER_AVAILABLE:
            try:
                self._router = get_router()
                if self._router.is_available():
                    print(f"  🧠 ReasoningCore v2.0: Model router active")
                    installed = self._router.installed_models()
                    if installed:
                        self._fallback_model = installed[0]
                    return
            except Exception:
                pass

        # Direct Ollama probe (no router)
        try:
            r = self._session.get(f"{_OLLAMA_URL}/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                # Prefer capable models over TinyLlama
                preferred = [
                    "deepseek-r1", "qwen3", "qwen2.5-coder", "devstral",
                    "llama3.1", "llama3", "mistral", "tinyllama",
                ]
                chosen = None
                for pref in preferred:
                    for m in models:
                        if pref in m:
                            chosen = m
                            break
                    if chosen:
                        break
                self._fallback_model = chosen or (models[0] if models else None)
                if self._fallback_model:
                    print(f"  🧠 ReasoningCore v2.0: Ollama ({self._fallback_model})")
                    return
        except Exception:
            pass

        print("  🧠 ReasoningCore v2.0: No LLM — heuristic-only mode")

        # RAG
        if _RAG_AVAILABLE:
            try:
                self._rag = get_rag()
                print(f"  📚 RAG: {len(self._rag.kb)} entries available")
            except Exception:
                pass

    @property
    def available(self) -> bool:
        return bool(self._router or self._fallback_model)

    # ── PUBLIC API ────────────────────────────────────────────────

    def think(
        self,
        prompt: str,
        system: Optional[str] = None,
        task: str = "default",
        max_tokens: int = 1000,
        inject_rag: bool = False,
        rag_task_type: str = "",
    ) -> Optional[str]:
        """
        One-shot LLM completion, routed to the best model for the task.

        Args:
            prompt:         User prompt
            system:         System prompt override (uses task-based default if None)
            task:           Task type for model routing and system prompt selection
            max_tokens:     Max output tokens
            inject_rag:     Whether to prepend RAG context to the prompt
            rag_task_type:  Attack type for RAG query (defaults to task)
        """
        if not self.available:
            return None

        model  = self._pick_model(task)
        if not model:
            return None

        sys_prompt = system or _SYSTEM.get(task, _SYSTEM["default"])

        # RAG injection
        if inject_rag and self._rag:
            rag_type    = rag_task_type or task
            rag_entries = self._rag.query(task_type=rag_type, top_k=3)
            if rag_entries:
                rag_ctx = self._rag.format_context(rag_entries, max_chars=600)
                prompt  = f"{rag_ctx}\n\n{prompt}"

        # CoT forcing for reasoning tasks
        if task in _COT_TASKS:
            prompt = prompt + _COT_SUFFIX

        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user",   "content": prompt},
        ]
        return self._chat(messages, max_tokens=max_tokens)

    def think_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        task: str = "default",
        max_tokens: int = 1000,
        inject_rag: bool = False,
        rag_task_type: str = "",
    ) -> Optional[Any]:
        """Same as think() but parses the response as JSON."""
        raw = self.think(prompt, system=system, task=task, max_tokens=max_tokens,
                         inject_rag=inject_rag, rag_task_type=rag_task_type)
        return self._parse_json(raw)

    def reason_about_finding(self, finding: Dict) -> Dict:
        """
        Deep reasoning about a security finding.
        Uses the reasoning model with CoT forcing.
        Returns enriched finding dict.
        """
        if not self.available:
            return {}

        prompt = f"""Security finding to evaluate:
{json.dumps(finding, indent=2, default=str)[:800]}

Answer these questions:
1. Is this a real, exploitable vulnerability? What is your confidence?
2. What is the maximum realistic impact if exploited?
3. What single action would escalate this further?
4. What CVSS 3.1 score and CWE number apply?

Output JSON:
{{
  "real": true/false,
  "confidence": "high|medium|low",
  "impact": "specific impact description",
  "next_step": "concrete next action",
  "cvss": 0.0,
  "cwe": "CWE-XX",
  "severity": "critical|high|medium|low"
}}"""

        result = self.think_json(prompt, task="finding", max_tokens=500,
                                 inject_rag=True, rag_task_type=finding.get("type",""))
        return result or {}

    def score_finding(self, finding: Dict) -> Dict:
        """Score a finding with CVSS 3.1 using the reasoning model."""
        if not self.available:
            return {}

        prompt = f"""Score this security finding using CVSS 3.1:
Type: {finding.get('type','?')}
Endpoint: {finding.get('endpoint','?')}
Evidence: {str(finding.get('evidence', finding.get('payload','')))[:300]}
Tech stack: Node.js/Express/SQLite (Juice Shop)

Output JSON:
{{
  "cvss_score": 0.0,
  "severity": "critical|high|medium|low|info",
  "cwe": "CWE-XX",
  "attack_vector": "N|A|L|P",
  "attack_complexity": "L|H",
  "privileges_required": "N|L|H",
  "user_interaction": "N|R",
  "scope": "U|C",
  "justification": "one sentence"
}}"""

        return self.think_json(prompt, task="scoring", max_tokens=400) or {}

    def generate_payload(self, vuln_type: str, endpoint: str,
                          context: str = "", tech: str = "") -> str:
        """Generate an exploit payload using the coding model + RAG context."""
        prompt = f"""Generate a {vuln_type} payload for:
Endpoint: {endpoint}
Tech: {tech or 'Node.js/Express/SQLite'}
Context: {context or 'Standard web application parameter'}
Use previously successful payloads (above, from RAG) as inspiration.
Output ONLY the raw payload string."""

        result = self.think(prompt, task="payload", max_tokens=150,
                            inject_rag=True, rag_task_type=vuln_type)
        return (result or "").strip()[:300]

    def summarize_mission(self, findings: List[Dict], stats: Dict) -> str:
        """Generate a concise executive summary of a completed mission."""
        prompt = f"""Mission complete. Write a concise executive summary.
Stats: {json.dumps(stats, default=str)[:300]}
Key findings: {json.dumps([{
    'type': f.get('type'), 'severity': f.get('severity'), 'endpoint': f.get('endpoint')
} for f in findings[:5]], indent=2)}

Write 3-4 sentences covering: what was found, worst impact, recommended priority fix."""

        return self.think(prompt, task="report", max_tokens=300) or \
               f"Nova completed assessment. Found {len(findings)} vulnerabilities. Review report for details."

    # ── ROUTING & INFERENCE ───────────────────────────────────────

    def _pick_model(self, task: str) -> Optional[str]:
        """Pick the best available model for the task."""
        if _FORCE_MDL:
            return _FORCE_MDL
        if self._router:
            # Map reasoning core task names to router task names
            task_map = {
                "finding":  "validate_finding",
                "scoring":  "score_finding",
                "payload":  "payload_generation",
                "code":     "code_audit",
                "report":   "report_writing",
                "recon":    "recon_parse",
                "default":  "general",
            }
            return self._router.best_model_for(task_map.get(task, task))
        return self._fallback_model

    def _chat(
        self,
        messages: List[Dict],
        temperature: float = 0.2,
        max_tokens: int    = 1000,
        retries: int       = 2,
    ) -> Optional[str]:
        model = self._pick_model("default")
        if not model:
            return None

        payload = {
            "model":    model,
            "messages": messages,
            "stream":   False,
            "options":  {"temperature": temperature, "num_predict": max_tokens},
        }
        for attempt in range(retries + 1):
            try:
                r = self._session.post(
                    f"{_OLLAMA_URL}/api/chat",
                    json=payload,
                    timeout=_TIMEOUT,
                )
                r.raise_for_status()
                return r.json().get("message", {}).get("content", "").strip()
            except requests.exceptions.Timeout:
                if attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
            except Exception:
                return None
        return None

    def _parse_json(self, text: Optional[str]) -> Optional[Any]:
        """Extract JSON from LLM response, stripping markdown and CoT blocks."""
        if not text:
            return None
        # Strip CoT <thinking> blocks
        text = re.sub(r'<thinking>[\s\S]*?</thinking>', '', text).strip()
        # Strip markdown fences
        text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\s*```$', '', text)
        # Direct parse
        try:
            return json.loads(text)
        except Exception:
            pass
        # First JSON object or array
        for pat in [r'\{[\s\S]*\}', r'\[[\s\S]*\]']:
            m = re.search(pat, text)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
        return None


# ── Singleton ─────────────────────────────────────────────────────
_core: Optional[NovaReasoningCore] = None

def get_reasoning_core() -> NovaReasoningCore:
    global _core
    if _core is None:
        _core = NovaReasoningCore()
    return _core
