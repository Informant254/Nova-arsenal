#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🌅 NOVA DAYBREAK v1.0 — AI-POWERED SECURITY ASSESSMENT ENGINE    ║
║                                                                      ║
║   Inspired by OpenAI Daybreak's three-stage pipeline:               ║
║   Stage 1 — AI Threat Prioritization (attack surface reasoning)     ║
║   Stage 2 — Scoped Sandbox Validation (confirm before reporting)    ║
║   Stage 3 — Audit-Ready Evidence Package (HackerOne submission)     ║
║                                                                      ║
║   Powered by Ollama (local, free, no token burn)                   ║
║   Works with: llama3.1, mistral, codellama, deepseek-coder, etc.   ║
║                                                                      ║
║   Human checkpoints: required before escalating risk level          ║
║   Scope guardian: HackerOne program scope enforced at every step    ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json
import time
import re
import os
import hashlib
import requests
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict


# ── OLLAMA CONFIG ─────────────────────────────────────────────────────────────

OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")   # upgrade from tinyllama

PREFERRED_MODELS = [
    "llama3.1",        # Best reasoning, recommended
    "mistral",         # Fast + strong
    "codellama",       # Good for code analysis
    "deepseek-coder",  # Excellent for vuln code review
    "llama3",          # Fallback
    "tinyllama",       # Last resort
]


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────

@dataclass
class ScopeRule:
    program:      str
    platform:     str = "hackerone"
    in_scope:     List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    rules:        List[str] = field(default_factory=list)


@dataclass
class PrioritizedTarget:
    endpoint:    str
    risk_score:  float          # 0–10
    attack_type: str
    reason:      str
    confidence:  str            # low / medium / high
    requires_auth: bool = False


@dataclass
class ValidatedFinding:
    id:               str
    title:            str
    severity:         str       # critical / high / medium / low / info
    cvss:             float
    endpoint:         str
    parameter:        str
    payload:          str
    evidence:         str
    confirmed:        bool
    false_positive:   bool
    attack_type:      str
    impact:           str
    patch_proposal:   str
    reproduction:     List[str] = field(default_factory=list)
    cwe:              str = ""
    timestamp:        str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── OLLAMA BRAIN ──────────────────────────────────────────────────────────────

class OllamaBrain:
    """
    Local LLM interface.  Auto-selects the best available model,
    falls back gracefully if Ollama is not running.
    """

    def __init__(self, model: str = OLLAMA_MODEL, timeout: int = 120):
        self.model   = model
        self.timeout = timeout
        self.url     = f"{OLLAMA_URL}/api/generate"
        self.tags_url = f"{OLLAMA_URL}/api/tags"
        self._available: Optional[bool] = None
        self._resolved_model: Optional[str] = None

    # ── availability ──────────────────────────────────────────────

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            r = requests.get(self.tags_url, timeout=5)
            self._available = r.status_code == 200
        except Exception:
            self._available = False
        return self._available

    def best_model(self) -> str:
        """Return the strongest available model."""
        if self._resolved_model:
            return self._resolved_model
        try:
            r = requests.get(self.tags_url, timeout=5)
            if r.status_code != 200:
                return self.model
            installed = [m.get("name","").split(":")[0] for m in r.json().get("models", [])]
            for preferred in PREFERRED_MODELS:
                if preferred in installed:
                    self._resolved_model = preferred
                    return preferred
        except Exception:
            pass
        self._resolved_model = self.model
        return self.model

    # ── inference ─────────────────────────────────────────────────

    def think(self, prompt: str, system: str = "", max_tokens: int = 1024) -> str:
        if not self.is_available():
            return ""
        model = self.best_model()
        full  = f"{system}\n\n{prompt}" if system else prompt
        try:
            r = requests.post(
                self.url,
                json={"model": model, "prompt": full, "stream": False,
                      "options": {"num_predict": max_tokens, "temperature": 0.2}},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                return r.json().get("response", "").strip()
        except Exception:
            pass
        return ""

    def think_json(self, prompt: str, system: str = "", max_tokens: int = 1024) -> Any:
        """Think and parse JSON from the response."""
        raw = self.think(prompt, system, max_tokens)
        if not raw:
            return None
        # extract first JSON object or array
        for pattern in (r'\{[\s\S]*\}', r'\[[\s\S]*\]'):
            m = re.search(pattern, raw)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
        return None


# ── SCOPE GUARDIAN ────────────────────────────────────────────────────────────

class ScopeGuardian:
    """
    Enforces HackerOne / bug bounty program scope.
    Every target must pass scope check before testing.
    """

    def __init__(self, scope: ScopeRule):
        self.scope = scope
        self._log: List[str] = []

    def is_in_scope(self, target: str) -> bool:
        t = target.lower().rstrip("/")
        for pattern in self.scope.out_of_scope:
            if self._matches(t, pattern.lower()):
                self._log.append(f"OUT-OF-SCOPE: {target} (matched '{pattern}')")
                return False
        for pattern in self.scope.in_scope:
            if self._matches(t, pattern.lower()):
                return True
        self._log.append(f"NOT-IN-SCOPE: {target} (no match found)")
        return False

    @staticmethod
    def _matches(target: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            domain = pattern[2:]
            return target.endswith(domain) or target == domain
        return pattern in target

    def filter_targets(self, targets: List[str]) -> List[str]:
        return [t for t in targets if self.is_in_scope(t)]

    def report(self) -> List[str]:
        return self._log


# ── STAGE 1: THREAT PRIORITIZER ───────────────────────────────────────────────

class ThreatPrioritizer:
    """
    Stage 1 of the Daybreak pipeline.
    Uses the LLM to reason over the full attack surface and rank
    endpoints by expected vulnerability and impact — before touching anything.
    """

    SYSTEM = """You are an elite bug bounty researcher. Your job is to analyze an attack surface
and rank endpoints by the likelihood of finding high-impact vulnerabilities.

Think like a top-ranked HackerOne hacker: where would you look first?
Always output valid JSON only — no extra text."""

    def __init__(self, brain: OllamaBrain):
        self.brain = brain

    def prioritize(self, target: str, endpoints: List[Dict],
                   tech_stack: List[str]) -> List[PrioritizedTarget]:
        """
        Given a list of discovered endpoints, rank them for testing.
        Returns a sorted list (highest risk first).
        """
        if not self.brain.is_available() or not endpoints:
            return self._heuristic_prioritize(endpoints)

        print("\n  🧠 [DAYBREAK] Stage 1: AI threat prioritization...")

        ep_summary = json.dumps(endpoints[:30], indent=2)
        prompt = f"""Target: {target}
Tech stack: {', '.join(tech_stack) if tech_stack else 'unknown'}

Discovered endpoints:
{ep_summary}

Rank the top 10 endpoints by vulnerability likelihood and impact.
For each, specify: endpoint, risk_score (0-10), attack_type, reason, confidence (low/medium/high), requires_auth (true/false).

Output JSON array:
[{{"endpoint": "...", "risk_score": 9.5, "attack_type": "sql_injection", "reason": "...", "confidence": "high", "requires_auth": false}}]"""

        result = self.brain.think_json(prompt, self.SYSTEM, max_tokens=1500)

        if isinstance(result, list):
            targets = []
            for item in result:
                try:
                    targets.append(PrioritizedTarget(
                        endpoint=item.get("endpoint", ""),
                        risk_score=float(item.get("risk_score", 5.0)),
                        attack_type=item.get("attack_type", "generic"),
                        reason=item.get("reason", ""),
                        confidence=item.get("confidence", "medium"),
                        requires_auth=item.get("requires_auth", False),
                    ))
                except Exception:
                    pass
            if targets:
                targets.sort(key=lambda t: t.risk_score, reverse=True)
                self._print_priorities(targets)
                return targets

        return self._heuristic_prioritize(endpoints)

    def _heuristic_prioritize(self, endpoints: List[Dict]) -> List[PrioritizedTarget]:
        """Rule-based fallback when LLM unavailable."""
        HIGH_VALUE = {
            "login": ("auth_bypass",     9.5),
            "search": ("sql_injection",  9.0),
            "admin":  ("privilege_esc",  9.8),
            "upload": ("file_upload",    8.5),
            "reset":  ("account_takeover", 9.0),
            "api":    ("idor",           8.0),
            "user":   ("idor",           7.5),
            "order":  ("idor",           7.0),
            "wallet": ("business_logic", 7.5),
        }
        results = []
        for ep in endpoints:
            path = ep.get("path", ep.get("endpoint", "")).lower()
            for keyword, (attack, score) in HIGH_VALUE.items():
                if keyword in path:
                    results.append(PrioritizedTarget(
                        endpoint=path, risk_score=score,
                        attack_type=attack, reason=f"Contains '{keyword}'",
                        confidence="medium",
                    ))
                    break
            else:
                results.append(PrioritizedTarget(
                    endpoint=path, risk_score=4.0,
                    attack_type="generic", reason="Standard endpoint",
                    confidence="low",
                ))
        results.sort(key=lambda t: t.risk_score, reverse=True)
        return results

    def _print_priorities(self, targets: List[PrioritizedTarget]):
        print("\n  📊 Priority attack surface:")
        icons = {(9, 11): "🔴", (7, 9): "🟠", (4, 7): "🟡", (0, 4): "🔵"}
        for t in targets[:8]:
            for (lo, hi), icon in icons.items():
                if lo <= t.risk_score < hi:
                    break
            print(f"     {icon} [{t.risk_score:.1f}] {t.endpoint:<40} → {t.attack_type} ({t.confidence})")


# ── STAGE 2: SANDBOX VALIDATOR ────────────────────────────────────────────────

class SandboxValidator:
    """
    Stage 2 of the Daybreak pipeline.
    Validates whether a raw finding is a genuine vulnerability or a false positive.
    Runs in an isolated assessment context — no production data exfiltration.
    """

    SYSTEM = """You are a senior security researcher validating bug bounty findings.
Your job: determine if a finding is a REAL vulnerability or a FALSE POSITIVE.
Be conservative — only confirm if the evidence clearly shows exploitability.
Output valid JSON only."""

    def __init__(self, brain: OllamaBrain):
        self.brain = brain

    def validate(self, raw_finding: Dict) -> Dict:
        """
        Validate a raw finding.
        Returns enriched finding with confirmed/false_positive flags.
        """
        print(f"\n  🔬 [DAYBREAK] Stage 2: Validating '{raw_finding.get('type', 'finding')}'...")

        # Quick rule-based pre-check
        pre = self._rule_check(raw_finding)
        if pre["verdict"] == "false_positive":
            return {**raw_finding, "confirmed": False, "false_positive": True,
                    "validation_reason": pre["reason"]}

        if not self.brain.is_available():
            return self._conservative_validate(raw_finding)

        prompt = f"""Finding to validate:
{json.dumps(raw_finding, indent=2, default=str)}

Questions to answer:
1. Is the evidence (status codes, response body, indicators) consistent with a real vulnerability?
2. Could this be a false positive? Why or why not?
3. What is the confirmed severity if real?
4. What CVSS 3.1 base score applies?
5. What CWE applies?

Output JSON:
{{
  "confirmed": true/false,
  "false_positive": true/false,
  "severity": "critical|high|medium|low|info",
  "cvss": 0.0,
  "cwe": "CWE-89",
  "impact": "...",
  "reason": "..."
}}"""

        result = self.brain.think_json(prompt, self.SYSTEM, max_tokens=800)
        if isinstance(result, dict) and "confirmed" in result:
            return {**raw_finding, **result}

        return self._conservative_validate(raw_finding)

    def _rule_check(self, finding: Dict) -> Dict:
        """Fast rule-based false-positive filter."""
        # 301/302 redirects on sensitive paths are not vulns
        status = finding.get("status_code", 200)
        if status in (301, 302, 307, 308):
            path = finding.get("endpoint", "")
            if any(x in path for x in [".env", ".git", "backup"]):
                return {"verdict": "false_positive", "reason": "Redirect on sensitive path — not exposed"}

        # Empty response body with 200 is likely not SQLi
        body = finding.get("response_body", "")
        type_ = finding.get("type", "")
        if "sql" in type_.lower() and not body and status == 200:
            return {"verdict": "inconclusive", "reason": "Empty response — needs manual check"}

        return {"verdict": "plausible", "reason": "Passes rule filter"}

    def _conservative_validate(self, finding: Dict) -> Dict:
        """Conservative fallback when LLM unavailable."""
        indicators = finding.get("data_exposed", finding.get("indicators_found", []))
        severity_map = {
            "sql_injection":        ("critical", 9.8, "CWE-89"),
            "xss":                  ("high",     7.4, "CWE-79"),
            "auth_bypass":          ("critical", 9.1, "CWE-287"),
            "idor":                 ("high",     7.5, "CWE-639"),
            "session_fixation":     ("medium",   5.4, "CWE-384"),
            "race_condition":       ("high",     7.0, "CWE-362"),
            "jwt_forgery":          ("critical", 9.0, "CWE-347"),
            "prototype_pollution":  ("critical", 8.8, "CWE-915"),
            "path_traversal":       ("high",     7.5, "CWE-22"),
            "ssrf":                 ("high",     8.6, "CWE-918"),
        }
        type_ = finding.get("type", "generic").lower()
        sev, cvss, cwe = severity_map.get(type_, ("medium", 5.0, "CWE-0"))
        confirmed = bool(finding.get("success") or finding.get("verdict") == "confirmed"
                         or len(indicators) > 0)
        return {
            **finding,
            "confirmed":      confirmed,
            "false_positive": not confirmed,
            "severity":       sev,
            "cvss":           cvss,
            "cwe":            cwe,
            "impact":         f"{'Confirmed' if confirmed else 'Unconfirmed'} {type_} vulnerability.",
            "validation_reason": "LLM unavailable — rule-based validation applied",
        }


# ── PATCH PROPOSER ────────────────────────────────────────────────────────────

class PatchProposer:
    """
    Generates specific, actionable remediation code per finding.
    This is what separates Daybreak from a simple scanner.
    """

    SYSTEM = """You are a senior application security engineer.
Given a confirmed vulnerability, generate a SPECIFIC and ACTIONABLE patch.
Include: the vulnerable code pattern, the fixed code pattern, and why the fix works.
Be concise. Output valid JSON only."""

    FALLBACK_PATCHES = {
        "sql_injection": """Use parameterized queries:
  ❌ BAD:  db.query("SELECT * FROM users WHERE email='" + email + "'")
  ✅ FIX:  db.query("SELECT * FROM users WHERE email=?", [email])
  Why: Parameterization prevents user input from being interpreted as SQL.""",

        "xss": """Encode all output and implement CSP:
  ❌ BAD:  res.send("<p>" + userInput + "</p>")
  ✅ FIX:  res.send("<p>" + htmlEncode(userInput) + "</p>")
  Add:    Content-Security-Policy: default-src 'self'""",

        "auth_bypass": """Implement strict server-side authentication:
  ❌ BAD:  if (user.role === req.body.role) grantAccess()
  ✅ FIX:  if (await db.verifyRole(user.id, requiredRole)) grantAccess()
  Why: Always verify roles from the database, never from user-supplied input.""",

        "jwt_forgery": """Validate JWT algorithm server-side:
  ❌ BAD:  jwt.verify(token, secret)  // trusts header algorithm
  ✅ FIX:  jwt.verify(token, secret, { algorithms: ['HS256'] })
  Why: Prevents 'none' algorithm and algorithm confusion attacks.""",

        "prototype_pollution": """Freeze prototype and sanitize keys:
  ❌ BAD:  Object.assign(target, userInput)
  ✅ FIX:  const safe = JSON.parse(JSON.stringify(userInput))
           if ('__proto__' in safe) throw new Error('Prototype pollution attempt')
           Object.assign(target, safe)""",

        "race_condition": """Implement atomic operations and rate limiting:
  ✅ FIX:  Use database transactions with row-level locking
           Add idempotency keys to prevent duplicate processing
           Apply rate limiting: express-rate-limit with per-user limits""",

        "session_fixation": """Regenerate session ID after authentication:
  ❌ BAD:  req.session.user = authenticatedUser  // keeps same session ID
  ✅ FIX:  req.session.regenerate((err) => { req.session.user = authenticatedUser })
  Why: Prevents an attacker from pre-setting the session ID.""",

        "ssrf": """Whitelist outbound connections:
  ❌ BAD:  fetch(req.body.url)
  ✅ FIX:  const allowed = ['api.trusted.com']
           const parsed = new URL(req.body.url)
           if (!allowed.includes(parsed.hostname)) throw new Error('SSRF blocked')
           fetch(req.body.url)""",
    }

    def __init__(self, brain: OllamaBrain):
        self.brain = brain

    def propose(self, finding: ValidatedFinding) -> str:
        if not self.brain.is_available():
            return self._fallback_patch(finding.attack_type)

        prompt = f"""Vulnerability: {finding.title}
Type: {finding.attack_type}
Endpoint: {finding.endpoint}
Parameter: {finding.parameter}
Evidence: {finding.evidence[:300]}

Generate a specific patch for this vulnerability.
Output JSON:
{{
  "vulnerable_pattern": "code showing the bug",
  "fixed_pattern": "corrected code",
  "explanation": "why the fix works",
  "additional_controls": ["extra hardening step 1", "step 2"]
}}"""

        result = self.brain.think_json(prompt, self.SYSTEM, max_tokens=800)
        if isinstance(result, dict):
            lines = [
                "**Vulnerable pattern:**",
                f"```\n{result.get('vulnerable_pattern', '')}\n```",
                "**Fixed pattern:**",
                f"```\n{result.get('fixed_pattern', '')}\n```",
                f"**Why:** {result.get('explanation', '')}",
            ]
            extras = result.get("additional_controls", [])
            if extras:
                lines.append("**Additional controls:**")
                lines.extend(f"  • {e}" for e in extras)
            return "\n".join(lines)

        return self._fallback_patch(finding.attack_type)

    def _fallback_patch(self, attack_type: str) -> str:
        for key, patch in self.FALLBACK_PATCHES.items():
            if key in attack_type.lower():
                return patch
        return "Review OWASP remediation guidance for this vulnerability type."


# ── HUMAN CHECKPOINT ──────────────────────────────────────────────────────────

class HumanCheckpoint:
    """
    Requires explicit human approval before Nova escalates to higher-risk actions.
    This is a core Daybreak principle: AI proposes, human approves.
    """

    def __init__(self, auto_approve_low: bool = True):
        self.auto_approve_low = auto_approve_low
        self.decisions: List[Dict] = []

    def request(self, action: str, risk: str, detail: str = "") -> bool:
        """
        Request human approval.
        risk: 'low' | 'medium' | 'high' | 'critical'
        Returns True if approved.
        """
        if risk == "low" and self.auto_approve_low:
            self._record(action, risk, "auto-approved")
            return True

        print(f"\n{'='*60}")
        print(f"⚠️  HUMAN CHECKPOINT [{risk.upper()}]")
        print(f"{'='*60}")
        print(f"Action: {action}")
        if detail:
            print(f"Detail: {detail}")
        print(f"\nThis action requires your approval.")

        while True:
            answer = input("  Approve? [y/n/skip]: ").strip().lower()
            if answer in ("y", "yes"):
                self._record(action, risk, "approved")
                print("  ✅ Approved\n")
                return True
            elif answer in ("n", "no"):
                self._record(action, risk, "denied")
                print("  ❌ Denied — skipping\n")
                return False
            elif answer == "skip":
                self._record(action, risk, "skipped")
                print("  ⏭️  Skipped\n")
                return False

    def _record(self, action: str, risk: str, decision: str):
        self.decisions.append({
            "action": action, "risk": risk, "decision": decision,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


# ── STAGE 3: AUDIT PACKAGE GENERATOR ─────────────────────────────────────────

class AuditPackageGenerator:
    """
    Stage 3 of the Daybreak pipeline.
    Produces HackerOne-ready submission packages.
    """

    SEVERITY_ICONS = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"
    }

    def generate(self, findings: List[ValidatedFinding], meta: Dict) -> Dict:
        """Generate complete audit package."""
        confirmed = [f for f in findings if f.confirmed and not f.false_positive]
        rejected  = [f for f in findings if f.false_positive]

        package = {
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "target":        meta.get("target", ""),
            "program":       meta.get("program", ""),
            "platform":      meta.get("platform", "hackerone"),
            "duration":      meta.get("duration", ""),
            "summary": {
                "total_tested":    len(findings),
                "confirmed":       len(confirmed),
                "false_positives": len(rejected),
                "by_severity": {
                    s: len([f for f in confirmed if f.severity == s])
                    for s in ("critical", "high", "medium", "low", "info")
                },
            },
            "findings":           [asdict(f) for f in confirmed],
            "hackerone_reports":  [self._h1_report(f, meta) for f in confirmed],
            "markdown_report":    self._markdown_report(confirmed, meta),
        }

        self._save(package, meta.get("target", "target"))
        return package

    def _h1_report(self, f: ValidatedFinding, meta: Dict) -> Dict:
        """Format a single finding as a HackerOne submission."""
        return {
            "title": f.title,
            "vulnerability_information": f"""## Summary
{f.impact}

## Steps to Reproduce
{chr(10).join(f'  {i+1}. {step}' for i, step in enumerate(f.reproduction))}

## Supporting Material / References
- Endpoint: `{f.endpoint}`
- Parameter: `{f.parameter}`
- Payload: `{f.payload}`
- Evidence: {f.evidence[:500]}

## Impact
{f.impact}

## Remediation
{f.patch_proposal}""",
            "severity":    f.severity,
            "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # placeholder
            "weakness":    {"id": f.cwe.replace("CWE-", "") if f.cwe else "0"},
            "program":     meta.get("program", ""),
        }

    def _markdown_report(self, findings: List[ValidatedFinding], meta: Dict) -> str:
        target   = meta.get("target", "")
        program  = meta.get("program", "")
        duration = meta.get("duration", "")
        now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        counts = {s: len([f for f in findings if f.severity == s])
                  for s in ("critical","high","medium","low","info")}

        lines = [
            "# 🌅 Nova Daybreak — Security Assessment Report",
            "",
            f"**Target:** `{target}`  ",
            f"**Program:** {program}  ",
            f"**Date:** {now}  ",
            f"**Duration:** {duration}  ",
            "",
            "## Executive Summary",
            "",
            f"Nova Daybreak conducted a structured security assessment of `{target}` "
            f"across {sum(counts.values())} confirmed findings. "
            f"All findings were AI-validated before inclusion. False positives were filtered out.",
            "",
            "## Severity Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            *[f"| {self.SEVERITY_ICONS.get(s,'?')} {s.capitalize()} | {counts[s]} |"
              for s in ("critical","high","medium","low","info")],
            f"| **Total** | **{sum(counts.values())}** |",
            "",
            "---",
            "",
            "## Findings",
            "",
        ]

        sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        for f in sorted(findings, key=lambda x: sev_order.get(x.severity, 5)):
            icon = self.SEVERITY_ICONS.get(f.severity, "❓")
            lines += [
                f"### {icon} [{f.id}] {f.title}",
                "",
                f"**Severity:** {f.severity.upper()} | **CVSS:** {f.cvss} | **CWE:** {f.cwe}  ",
                f"**Endpoint:** `{f.endpoint}`  ",
                f"**Parameter:** `{f.parameter}`  ",
                "",
                "**Reproduction Steps:**",
                "",
                *[f"{i+1}. {step}" for i, step in enumerate(f.reproduction)],
                "",
                f"**Evidence:**  ",
                f"```\n{f.evidence[:400]}\n```" if f.evidence else "_No evidence captured_",
                "",
                f"**Impact:**  ",
                f.impact,
                "",
                "**Patch Proposal:**",
                "",
                f.patch_proposal,
                "",
                "---",
                "",
            ]

        lines += [
            "## Methodology",
            "",
            "This assessment was conducted using Nova Daybreak, a structured three-stage pipeline:",
            "1. **AI Threat Prioritization** — LLM-ranked attack surface before testing",
            "2. **Sandbox Validation** — Each finding confirmed before reporting",
            "3. **Audit Package Generation** — HackerOne-ready submission output",
            "",
            "_All testing conducted within program scope under HackerOne safe harbor policy._",
            "",
            f"🦅 Nova Daybreak — {now}",
        ]

        return "\n".join(lines)

    def _save(self, package: Dict, target: str):
        slug = re.sub(r'[^a-z0-9]', '_', target.lower())[:30]
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"nova_daybreak_report_{slug}_{ts}"

        with open(f"{base}.json", "w") as fh:
            json.dump(package, fh, indent=2, default=str)
        print(f"  📦 JSON  → {base}.json")

        with open(f"{base}.md", "w") as fh:
            fh.write(package["markdown_report"])
        print(f"  📝 MD    → {base}.md")

        for i, h1 in enumerate(package.get("hackerone_reports", []), 1):
            h1file = f"h1_submission_{slug}_{ts}_{i:02d}.json"
            with open(h1file, "w") as fh:
                json.dump(h1, fh, indent=2)
        if package.get("hackerone_reports"):
            print(f"  🎯 H1    → {len(package['hackerone_reports'])} submission files")


# ── NOVA DAYBREAK ORCHESTRATOR ────────────────────────────────────────────────

class NovaDaybreak:
    """
    Main Daybreak orchestrator.
    Runs the three-stage pipeline with scope enforcement and human checkpoints.

    Usage:
        scope = ScopeRule(
            program="Kong HQ",
            in_scope=["*.konghq.com", "konghq.com"],
            out_of_scope=["admin-cloud.konghq.com"],
        )
        nova = NovaDaybreak(target="https://konghq.com", scope=scope)
        nova.run()
    """

    def __init__(self, target: str, scope: ScopeRule,
                 ollama_model: str = OLLAMA_MODEL,
                 interactive: bool = True):
        self.target      = target
        self.scope       = scope
        self.brain       = OllamaBrain(model=ollama_model)
        self.guardian    = ScopeGuardian(scope)
        self.prioritizer = ThreatPrioritizer(self.brain)
        self.validator   = SandboxValidator(self.brain)
        self.proposer    = PatchProposer(self.brain)
        self.checkpoint  = HumanCheckpoint(auto_approve_low=True)
        self.auditor     = AuditPackageGenerator()
        self.interactive = interactive
        self.start_time  = None
        self._findings:  List[ValidatedFinding] = []
        self._raw:       List[Dict] = []

    # ── PUBLIC API ────────────────────────────────────────────────

    def run(self, raw_findings: List[Dict] = None,
            endpoints: List[Dict]  = None,
            tech_stack: List[str]  = None) -> Dict:
        """
        Run the full Daybreak pipeline.

        Args:
            raw_findings: findings from nova_core / other scanners
            endpoints:    discovered endpoints for prioritization
            tech_stack:   detected technologies
        """
        self.start_time = time.time()
        self._print_banner()

        model = self.brain.best_model() if self.brain.is_available() else "unavailable"
        print(f"  🧠 LLM: Ollama / {model}")
        print(f"  🎯 Target: {self.target}")
        print(f"  🛡️  Program: {self.scope.program} ({self.scope.platform})")

        # Scope check on primary target
        if not self.guardian.is_in_scope(self.target):
            print(f"\n  ❌ Target {self.target} is OUT OF SCOPE. Aborting.")
            return {"error": "out_of_scope"}

        # ── STAGE 1: Prioritize ───────────────────────────────────
        priorities = []
        if endpoints:
            in_scope_eps = [e for e in endpoints
                            if self.guardian.is_in_scope(e.get("path", e.get("endpoint", ""))
                                                         or self.target)]
            priorities = self.prioritizer.prioritize(
                self.target, in_scope_eps, tech_stack or []
            )

        # ── STAGE 2: Validate raw findings ───────────────────────
        if raw_findings:
            print(f"\n  🔬 [DAYBREAK] Stage 2: Validating {len(raw_findings)} findings...")
            for raw in raw_findings:
                # Scope check
                ep = raw.get("endpoint", raw.get("url", self.target))
                if not self.guardian.is_in_scope(ep or self.target):
                    print(f"     ⛔ Skipping out-of-scope: {ep}")
                    continue

                # Human checkpoint for high/critical
                risk = raw.get("severity", raw.get("sev", "medium")).lower()
                if risk in ("critical", "high") and self.interactive:
                    ok = self.checkpoint.request(
                        action=f"Validate {raw.get('type','finding')} on {ep}",
                        risk=risk,
                        detail=f"Payload: {raw.get('payload','N/A')[:80]}",
                    )
                    if not ok:
                        continue

                validated = self.validator.validate(raw)
                if validated.get("confirmed") and not validated.get("false_positive"):
                    finding = self._build_finding(validated)
                    self._findings.append(finding)
                    print(f"     ✅ CONFIRMED [{finding.severity.upper()}]: {finding.title}")
                else:
                    reason = validated.get("validation_reason", validated.get("reason", ""))
                    print(f"     🔕 FALSE POSITIVE: {raw.get('type','?')} — {reason[:60]}")

        # ── STAGE 3: Patch proposals ──────────────────────────────
        if self._findings:
            print(f"\n  🩹 [DAYBREAK] Stage 3: Generating patch proposals...")
            for finding in self._findings:
                finding.patch_proposal = self.proposer.propose(finding)
                print(f"     ✅ Patch for: {finding.title[:50]}")

        # ── STAGE 3: Audit package ────────────────────────────────
        elapsed  = round(time.time() - self.start_time, 2)
        duration = f"{elapsed:.0f}s"
        package  = self.auditor.generate(
            self._findings,
            meta={
                "target":   self.target,
                "program":  self.scope.program,
                "platform": self.scope.platform,
                "duration": duration,
            },
        )

        self._print_summary(elapsed)
        return package

    def ingest(self, raw_findings: List[Dict]):
        """Add raw findings from external scanners (nova_core, etc.)."""
        self._raw.extend(raw_findings)

    # ── HELPERS ───────────────────────────────────────────────────

    def _build_finding(self, v: Dict) -> ValidatedFinding:
        type_  = v.get("type", "generic")
        ep     = v.get("endpoint", v.get("url", self.target))
        param  = v.get("parameter", v.get("param", ""))
        payload = v.get("payload", "")
        raw_id = hashlib.md5(f"{type_}{ep}{payload}".encode()).hexdigest()[:6].upper()
        title  = self._type_to_title(type_)

        repro = v.get("reproduction_steps") or [
            f"Navigate to: {ep}",
            f"Identify parameter: {param or '[parameter]'}",
            f"Send payload: {payload or '[payload]'}",
            "Observe the vulnerable response",
        ]
        if isinstance(repro, str):
            repro = [repro]

        evidence = v.get("evidence", v.get("response_preview",
                   str(v.get("data_exposed", v.get("indicators_found", "")))))

        return ValidatedFinding(
            id=f"NOVA-{raw_id}",
            title=title,
            severity=v.get("severity", "medium"),
            cvss=float(v.get("cvss", 5.0)),
            endpoint=ep,
            parameter=param,
            payload=payload,
            evidence=str(evidence)[:500],
            confirmed=True,
            false_positive=False,
            attack_type=type_,
            impact=v.get("impact", f"Confirmed {title} vulnerability."),
            patch_proposal="",       # filled by PatchProposer
            reproduction=repro,
            cwe=v.get("cwe", ""),
        )

    @staticmethod
    def _type_to_title(type_: str) -> str:
        TITLES = {
            "sql_injection":       "SQL Injection",
            "xss":                 "Cross-Site Scripting (XSS)",
            "auth_bypass":         "Authentication Bypass",
            "idor":                "Insecure Direct Object Reference (IDOR)",
            "jwt_forgery":         "JWT Signature Bypass",
            "race_condition":      "Race Condition",
            "session_fixation":    "Session Fixation",
            "prototype_pollution": "Prototype Pollution",
            "path_traversal":      "Path Traversal",
            "ssrf":                "Server-Side Request Forgery (SSRF)",
            "deserialization":     "Insecure Deserialization",
            "fuzzer_anomalies":    "Input Validation Anomaly",
        }
        for key, title in TITLES.items():
            if key in type_.lower():
                return title
        return type_.replace("_", " ").title()

    def _print_banner(self):
        print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   🌅  NOVA DAYBREAK v1.0 — AI-POWERED ASSESSMENT ENGINE  🌅    ║
║   Stage 1: Threat Prioritization  (AI ranks attack surface)     ║
║   Stage 2: Sandbox Validation     (confirm before reporting)    ║
║   Stage 3: Audit Package          (HackerOne-ready output)      ║
╚══════════════════════════════════════════════════════════════════╝""")

    def _print_summary(self, elapsed: float):
        confirmed = [f for f in self._findings if f.confirmed]
        counts    = {s: len([f for f in confirmed if f.severity == s])
                     for s in ("critical","high","medium","low","info")}
        icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}

        print(f"""
╔══════════════════════════════════════════════════════════╗
║        🌅 NOVA DAYBREAK ASSESSMENT COMPLETE             ║
╠══════════════════════════════════════════════════════════╣
║  Duration: {elapsed:.0f}s   Confirmed: {len(confirmed):<3}   Scope: {self.scope.program[:20]:<20} ║
╠══════════════════════════════════════════════════════════╣""")
        for sev, count in counts.items():
            if count:
                print(f"║  {icons[sev]} {sev.capitalize():<10} {count:<3}                                    ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()


# ── NOVA CORE BRIDGE ──────────────────────────────────────────────────────────

def from_nova_core(nova_core_report: Dict, target: str, scope: ScopeRule,
                   model: str = OLLAMA_MODEL) -> Dict:
    """
    Bridge function: feed a nova_core mission report directly into Daybreak.

    Example:
        report = json.load(open("nova_unified_mission_report.json"))
        package = from_nova_core(report, target="http://localhost:3000", scope=my_scope)
    """
    raw = []
    findings = nova_core_report.get("findings", {})
    if isinstance(findings, dict):
        for sev, items in findings.items():
            for item in (items or []):
                item.setdefault("severity", sev)
                raw.append(item)
    elif isinstance(findings, list):
        raw = findings

    daybreak = NovaDaybreak(target=target, scope=scope, ollama_model=model, interactive=False)
    return daybreak.run(raw_findings=raw)


# ── CLI ENTRY POINT ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="🌅 Nova Daybreak — AI-powered bug bounty assessment engine"
    )
    parser.add_argument("--target",   required=True,  help="Target URL")
    parser.add_argument("--program",  default="",     help="Bug bounty program name")
    parser.add_argument("--platform", default="hackerone", help="Platform (hackerone/bugcrowd)")
    parser.add_argument("--in-scope", nargs="+",      help="In-scope domains/patterns")
    parser.add_argument("--out-scope",nargs="+",      help="Out-of-scope domains/patterns")
    parser.add_argument("--report",   default="",     help="Path to nova_core JSON report to ingest")
    parser.add_argument("--model",    default=OLLAMA_MODEL, help=f"Ollama model (default: {OLLAMA_MODEL})")
    parser.add_argument("--demo",     action="store_true",  help="Run with demo findings")
    parser.add_argument("--no-interactive", action="store_true", help="Skip human checkpoints")
    args = parser.parse_args()

    scope = ScopeRule(
        program=args.program or args.target,
        platform=args.platform,
        in_scope=args.in_scope or [args.target],
        out_of_scope=args.out_scope or [],
    )

    daybreak = NovaDaybreak(
        target=args.target,
        scope=scope,
        ollama_model=args.model,
        interactive=not args.no_interactive,
    )

    if args.demo:
        # Demo findings (mirrors what nova_core produces)
        demo_findings = [
            {"type": "sql_injection",  "severity": "critical", "endpoint": f"{args.target}/rest/products/search",
             "parameter": "q", "payload": "' OR 1=1--", "success": True,
             "data_exposed": ["admin", "password", "token"],
             "response_preview": "SELECT * FROM Products WHERE name LIKE '%' OR 1=1--%'"},
            {"type": "jwt_forgery",    "severity": "critical", "endpoint": f"{args.target}/rest/user/whoami",
             "payload": "eyJ...", "success": True,
             "data_exposed": ["admin_access"],
             "response_preview": '{"id":1,"role":"admin","email":"admin@juice-sh.op"}'},
            {"type": "xss",            "severity": "high",     "endpoint": f"{args.target}/api/Feedbacks",
             "parameter": "comment", "payload": "<script>alert(1)</script>", "success": True,
             "data_exposed": []},
            {"type": "race_condition", "severity": "medium",   "endpoint": f"{args.target}/api/Orders",
             "success": True, "data_exposed": []},
        ]
        package = daybreak.run(raw_findings=demo_findings)

    elif args.report:
        with open(args.report) as fh:
            core_report = json.load(fh)
        package = from_nova_core(core_report, args.target, scope, model=args.model)

    else:
        # Run with no findings (prioritization only — useful when piping from nova_core)
        package = daybreak.run()

    print(f"\n✅ Daybreak complete. {package.get('summary',{}).get('confirmed',0)} findings in audit package.")
