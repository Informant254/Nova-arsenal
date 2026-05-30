#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   🦅 NOVA MODEL ROUTER v1.0 — INTELLIGENT TASK-BASED ROUTING   ║
║                                                                  ║
║   Routes each task to the best available Ollama model.          ║
║   Closes the gap with frontier models (Mythos, Claude Code,     ║
║   Daybreak) by using the right tool for each job — zero cost.   ║
║                                                                  ║
║   Task → Model mapping:                                         ║
║     security    → xploiter/the-xploiter  (attack-chain expert)  ║
║     reasoning   → deepseek-r1:32b        (visible CoT)          ║
║     coding      → devstral-small         (agentic code audit)   ║
║     fast        → qwen3:8b               (quick checks)         ║
║     general     → qwen3:30b              (best overall)         ║
╚══════════════════════════════════════════════════════════════════╝
"""

import requests
from typing import Dict, List, Optional, Tuple

OLLAMA_URL = "http://localhost:11434"

# ── MODEL PRIORITY TIERS ──────────────────────────────────────────
# Each tier lists models in preference order.
# The router picks the first one that is actually installed.
MODEL_TIERS: Dict[str, List[str]] = {
    # Deep security reasoning — thinks like a senior attacker
    "security": [
        "xploiter/the-xploiter",
        "the-xploiter",
        "deepseek-r1:32b",
        "deepseek-r1:14b",
        "qwen3:30b",
        "qwen3:14b",
        "llama3.1:70b",
        "llama3.1:8b",
        "llama3",
        "mistral",
    ],
    # Multi-step reasoning — shows chain of thought, great for scoring & validation
    "reasoning": [
        "deepseek-r1:32b",
        "deepseek-r1:14b",
        "deepseek-r1:8b",
        "phi-4-reasoning",
        "qwen3:30b",
        "qwen3:14b",
        "qwen3:8b",
        "llama3.1:8b",
        "llama3",
        "mistral",
    ],
    # Code auditing and payload generation — understands codebases
    "coding": [
        "devstral-small",
        "devstral-small-2",
        "qwen2.5-coder:32b",
        "qwen2.5-coder:14b",
        "qwen2.5-coder:7b",
        "qwen3-coder:30b",
        "codestral:22b",
        "deepseek-coder-v2",
        "llama3.1:8b",
        "llama3",
        "mistral",
    ],
    # Fast lightweight calls — recon parsing, quick checks, formatting
    "fast": [
        "qwen3:8b",
        "phi4-mini",
        "phi3.5-mini",
        "llama3.2:3b",
        "llama3.1:8b",
        "llama3",
        "mistral",
        "tinyllama",
    ],
    # Best general-purpose — planning, summarisation, report writing
    "general": [
        "qwen3:30b",
        "qwen3:14b",
        "llama4:scout",
        "llama3.1:70b",
        "llama3.1:8b",
        "llama3",
        "mistral",
        "tinyllama",
    ],
}

# ── TASK-TYPE CLASSIFICATION ──────────────────────────────────────
# Maps Nova task names → tier
TASK_TO_TIER: Dict[str, str] = {
    # Security attack tasks
    "sql_injection":        "security",
    "xss":                  "security",
    "ssrf":                 "security",
    "auth_bypass":          "security",
    "jwt_forge":            "security",
    "prototype_pollution":  "security",
    "race_condition":       "security",
    "deserialization":      "security",
    "path_traversal":       "security",
    "payload_generation":   "security",
    "attack_planning":      "security",
    "exploit_synthesis":    "security",
    "waf_bypass":           "security",
    # Reasoning / validation tasks
    "validate_finding":     "reasoning",
    "score_finding":        "reasoning",
    "false_positive_check": "reasoning",
    "threat_prioritization":"reasoning",
    "chain_of_thought":     "reasoning",
    "cvss_scoring":         "reasoning",
    # Code-focused tasks
    "code_audit":           "coding",
    "source_review":        "coding",
    "patch_proposal":       "coding",
    "dependency_analysis":  "coding",
    "code_comprehension":   "coding",
    # Fast lightweight tasks
    "recon_parse":          "fast",
    "endpoint_classify":    "fast",
    "header_analysis":      "fast",
    "tech_fingerprint":     "fast",
    "scope_check":          "fast",
    # General tasks
    "mission_planning":     "general",
    "report_writing":       "general",
    "summary":              "general",
    "rag_query":            "general",
}


class NovaModelRouter:
    """
    Intelligently routes Nova tasks to the best available Ollama model.

    Usage:
        router = NovaModelRouter()
        model  = router.best_model_for("validate_finding")
        # → "deepseek-r1:32b" if installed, else next best available
    """

    def __init__(self, ollama_url: str = OLLAMA_URL):
        self.ollama_url      = ollama_url
        self._installed: Optional[List[str]] = None
        self._cache: Dict[str, str]          = {}

    # ── PUBLIC API ────────────────────────────────────────────────

    def best_model_for(self, task: str) -> Optional[str]:
        """
        Return the best installed Ollama model for a given task.
        Returns None if Ollama is unreachable or no models installed.
        """
        if task in self._cache:
            return self._cache[task]

        tier  = TASK_TO_TIER.get(task, "general")
        model = self._pick_from_tier(tier)

        if model:
            self._cache[task] = model
        return model

    def best_model_for_tier(self, tier: str) -> Optional[str]:
        """Return best model for a named tier directly."""
        return self._pick_from_tier(tier)

    def installed_models(self) -> List[str]:
        """Return all installed Ollama models (cached after first call)."""
        if self._installed is not None:
            return self._installed
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if r.status_code == 200:
                self._installed = [m["name"] for m in r.json().get("models", [])]
                return self._installed
        except Exception:
            pass
        self._installed = []
        return self._installed

    def is_available(self) -> bool:
        """True if Ollama is reachable and at least one model is installed."""
        return len(self.installed_models()) > 0

    def capabilities_report(self) -> Dict:
        """Show which tier is covered by which model."""
        installed = self.installed_models()
        report    = {"installed": installed, "routing": {}}
        for tier in MODEL_TIERS:
            chosen = self._pick_from_tier(tier)
            report["routing"][tier] = chosen or "NO MODEL — heuristic fallback"
        return report

    def print_capabilities(self):
        """Pretty-print current routing table to stdout."""
        report = self.capabilities_report()
        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║   🦅 NOVA MODEL ROUTER — Current Routing Table              ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        icons = {
            "security":  "🔴 Security  ",
            "reasoning": "🟠 Reasoning ",
            "coding":    "🟡 Coding    ",
            "fast":      "🔵 Fast      ",
            "general":   "⚪ General   ",
        }
        for tier, model in report["routing"].items():
            icon  = icons.get(tier, "   " + tier.ljust(10))
            short = model[:50] if model else "heuristic fallback"
            print(f"║  {icon} → {short:<48} ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  Installed models: {len(report['installed']):<43}║")
        print("╚══════════════════════════════════════════════════════════════╝\n")

    def recommend_installs(self) -> List[Tuple[str, str]]:
        """
        Return (model, reason) pairs for models worth installing.
        Call this to guide the user on what to pull.
        """
        installed = set(self.installed_models())
        suggestions = [
            ("xploiter/the-xploiter", "Security-specialized — thinks like a senior attacker"),
            ("deepseek-r1:32b",       "Best chain-of-thought reasoning, shows its work"),
            ("devstral-small",        "Best agentic coding + codebase comprehension"),
            ("qwen3:30b",             "Best general-purpose reasoning (needs ~20GB VRAM)"),
            ("qwen2.5-coder:32b",     "Best for payload generation and code auditing"),
            ("qwen3:8b",              "Fast lightweight checks (<8GB VRAM)"),
        ]
        return [(m, r) for m, r in suggestions
                if not any(m.split(":")[0] in i for i in installed)]

    # ── INTERNAL ──────────────────────────────────────────────────

    def _pick_from_tier(self, tier: str) -> Optional[str]:
        """Walk the tier preference list, return first installed match."""
        installed = self.installed_models()
        if not installed:
            return None
        candidates = MODEL_TIERS.get(tier, MODEL_TIERS["general"])
        for preferred in candidates:
            # Exact match
            if preferred in installed:
                return preferred
            # Prefix match (e.g. "qwen3:30b" matches "qwen3:30b-instruct-q4")
            base = preferred.split(":")[0]
            for inst in installed:
                if inst.startswith(base):
                    return inst
        # Last resort: return whatever is installed
        return installed[0] if installed else None


# ── Singleton ─────────────────────────────────────────────────────
_router: Optional[NovaModelRouter] = None

def get_router() -> NovaModelRouter:
    global _router
    if _router is None:
        _router = NovaModelRouter()
    return _router


if __name__ == "__main__":
    router = NovaModelRouter()
    router.print_capabilities()

    recs = router.recommend_installs()
    if recs:
        print("📦 Recommended installs to close the gap with frontier models:")
        for model, reason in recs:
            print(f"   ollama pull {model:<35} # {reason}")
    else:
        print("✅ All recommended models installed.")
