#!/usr/bin/env python3
"""
🦅 NOVA ARSENAL — Features Discovery Tool

Lists all available features after installation.
Helps users understand what's now possible.

Usage:
    python3 nova_features.py                    # Show all features
    python3 nova_features.py --by-role          # Show features grouped by user role
    python3 nova_features.py --beginner         # Show beginner features only
    python3 nova_features.py --intermediate    # Show intermediate features only
    python3 nova_features.py --advanced        # Show advanced features only
    python3 nova_features.py --check            # Verify all features are available
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import Dict, List

class NovaFeatures:
    """Feature discovery and verification for Nova Arsenal."""

    FEATURES = {
        "beginner": [
            {
                "name": "One-Command Hunt",
                "command": "nova hunt http://target.com",
                "description": "Scan a web app and find all vulnerabilities",
                "time": "5-30 minutes",
                "requires": "Nothing",
                "example": "python3 nova.py 'Hunt http://localhost:3000 for vulnerabilities'"
            },
            {
                "name": "Full Pipeline",
                "command": "nova full ./my-app",
                "description": "Map + SAST + SCA + Active scan + Report (everything)",
                "time": "15-45 minutes",
                "requires": "Nothing",
                "example": "python3 nova.py 'Full stack pipeline on ./my-app'"
            },
            {
                "name": "Codebase Mapping",
                "command": "nova map ./my-app",
                "description": "Discover all routes, tech stack, frameworks, secrets",
                "time": "2-15 seconds",
                "requires": "Nothing",
                "example": "nova map ./my-app --brief"
            },
            {
                "name": "View Report",
                "command": "nova report",
                "description": "View latest hunt results (HTML dashboard)",
                "time": "1 second",
                "requires": "1 completed hunt",
                "example": "nova report --latest --format html"
            },
            {
                "name": "Health Check",
                "command": "nova status",
                "description": "Verify all 35+ modules are working",
                "time": "5 seconds",
                "requires": "Nothing",
                "example": "nova status --verbose"
            },
        ],
        "intermediate": [
            {
                "name": "Specific Vulnerability Scan",
                "command": "nova scan <type>",
                "description": "Scan for specific vulnerability types",
                "time": "5-15 minutes per type",
                "requires": "Target URL",
                "example": "nova scan sqli http://target.com\nnova scan xss http://target.com\nnova scan idor http://target.com"
            },
            {
                "name": "Multi-Agent Orchestration",
                "command": "nova orch http://target.com",
                "description": "LLM-driven agents: Recon → Attack → Report (hands-off)",
                "time": "30-60 minutes",
                "requires": "LLM API key or Ollama",
                "example": "nova orch http://target.com --provider anthropic"
            },
            {
                "name": "Real-Time File Watcher",
                "command": "nova-watch ./my-app --staged",
                "description": "Automatically scan code as it's written; blocks commits on HIGH severity",
                "time": "Continuous",
                "requires": "Git pre-commit hook (optional)",
                "example": "nova-watch ./my-app --staged\nnova-watch ./my-app --on-commit"
            },
            {
                "name": "Session Management",
                "command": "nova session <list|resume|export>",
                "description": "Resume interrupted hunts; export findings",
                "time": "1 second",
                "requires": "Completed hunt",
                "example": "nova session list\nnova session resume abc123\nnova session export abc123 --format json"
            },
            {
                "name": "Vulnerability Database",
                "command": "nova vuln-db <list|search|trend>",
                "description": "Query all findings from past hunts; trend analysis",
                "time": "1 second",
                "requires": "SQLite database populated",
                "example": "nova vuln-db list --severity HIGH\nnova vuln-db search 'SQL Injection'\nnova vuln-db trend"
            },
            {
                "name": "Telegram Notifications",
                "command": "Set TELEGRAM_BOT_TOKEN",
                "description": "Real-time alerts on mobile when findings discovered",
                "time": "Real-time",
                "requires": "Telegram bot + chat ID",
                "example": "export TELEGRAM_BOT_TOKEN=...\npython3 nova.py 'Hunt http://target.com'"
            },
            {
                "name": "Custom Reporting",
                "command": "nova report --template <executive|technical>",
                "description": "Generate C-suite or developer-focused reports",
                "time": "5 seconds",
                "requires": "Completed hunt",
                "example": "nova report --template executive --format html"
            },
        ],
        "advanced": [
            {
                "name": "Threat Modeling",
                "command": "python3 nova_threat_model.py <path>",
                "description": "STRIDE threat model + attack vectors",
                "time": "5-10 seconds",
                "requires": "Source code path",
                "example": "python3 nova_threat_model.py ./my-app"
            },
            {
                "name": "Automated Patch Generation",
                "command": "nova generate-patch <finding-id>",
                "description": "AI generates code-level fixes for vulnerabilities",
                "time": "10-30 seconds",
                "requires": "LLM provider + vulnerability finding",
                "example": "nova generate-patch finding_12345"
            },
            {
                "name": "Detection Rule Generation",
                "command": "nova generate-detection <finding-id>",
                "description": "Generates Sigma rules for SIEM/SOC automation",
                "time": "5-10 seconds",
                "requires": "LLM provider + vulnerability finding",
                "example": "nova generate-detection finding_12345 --format sigma"
            },
            {
                "name": "Cloud Hunting (24/7)",
                "command": "nova-cloud hunt http://target.com",
                "description": "Hunt on GitHub's free cloud runners; no local resources needed",
                "time": "30-60 minutes",
                "requires": "GitHub account + token",
                "example": "nova-cloud hunt https://target.com\nnova-cloud watch <job-id>\nnova-cloud results <job-id>"
            },
            {
                "name": "Self-Evolution",
                "command": "python3 nova_evolution.py --goal '...'",
                "description": "Nova modifies her own code to improve; syntax+import validated",
                "time": "5-15 minutes",
                "requires": "NOVA_ALLOW_EVOLUTION=true (local only)",
                "example": "python3 nova_evolution.py --file nova_attack.py --goal 'Improve blind SQLi detection'"
            },
            {
                "name": "Multi-Model Routing",
                "command": "Set OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.",
                "description": "Automatically selects best LLM per task; fallback chain",
                "time": "Automatic",
                "requires": "API keys (optional; Ollama is free fallback)",
                "example": "export OPENAI_API_KEY=sk-...\nexport ANTHROPIC_API_KEY=sk-ant-...\nnova hunt http://target.com"
            },
            {
                "name": "Knowledge Base (RAG)",
                "command": "python3 nova_rag_builder.py <path>",
                "description": "Learn from past hunts; searchable knowledge base",
                "time": "2-5 minutes",
                "requires": "Past hunt reports",
                "example": "python3 nova_rag_builder.py ~/nova_workspace/reports"
            },
            {
                "name": "Benchmark Evaluation",
                "command": "nova_eval.py --quick|--live|--full",
                "description": "Test Nova's accuracy on 20 deterministic missions",
                "time": "2-30 minutes (depending on mode)",
                "requires": "Nothing for --quick; targets for --live",
                "example": "nova_eval.py --quick\nEVAL_JUICE_SHOP=http://localhost:3000 nova_eval.py --live"
            },
            {
                "name": "Tool Governance Audit",
                "command": "cat ~/nova_workspace/logs/nova_tool_audit.jsonl",
                "description": "View all tool calls: who, when, what (redacted secrets)",
                "time": "1 second",
                "requires": "Completed hunts",
                "example": "tail -f ~/nova_workspace/logs/nova_tool_audit.jsonl | grep 'bash_exec'"
            },
            {
                "name": "Custom System Prompts",
                "command": "Export NOVA_CUSTOM_<AGENT>_PROMPT",
                "description": "Override LLM system prompts for specialized agents",
                "time": "N/A (editing only)",
                "requires": "Python knowledge",
                "example": "export NOVA_CUSTOM_ATTACK_PROMPT='You are a bug bounty hacker...'\npython3 nova.py 'Hunt http://target.com'"
            },
        ]
    }

    SCANNERS = {
        "SQL Injection": "nova scan sqli",
        "Cross-Site Scripting (XSS)": "nova scan xss",
        "IDOR / BOLA": "nova scan idor",
        "Server-Side Request Forgery": "nova scan ssrf",
        "JWT Vulnerabilities": "nova scan jwt",
        "CSRF": "nova scan csrf",
        "Race Conditions": "nova scan race",
        "GraphQL Injection": "nova scan graphql",
        "Business Logic Flaws": "nova scan business-logic",
        "LLM Prompt Injection": "nova scan llm-injection",
    }

    MODULES = {
        "Phase 0 - Codebase Mapping": [
            ("nova_codebase_mapper.py", "30+ languages, 25+ frameworks, routes, secrets, CVEs"),
        ],
        "Phase 1 - Static Analysis": [
            ("nova_source_auditor.py", "SAST: code flaws, injection points"),
            ("nova_sca_scanner.py", "Dependency CVE detection"),
            ("nova_git_scanner.py", "Secret scanning in git history"),
            ("nova_cicd_scanner.py", "CI/CD pipeline misconfigs"),
            ("nova_container_scanner.py", "Dockerfile & K8s security"),
        ],
        "Phase 2 - Active Scanning": [
            ("nova_fuzzer.py", "SQLi, XSS fuzzing"),
            ("nova_idor_scanner.py", "IDOR/BOLA testing"),
            ("nova_graphql_tester.py", "GraphQL attacks"),
            ("nova_csrf_tester.py", "CSRF token validation"),
            ("nova_jwt_forge.py", "JWT manipulation (alg:none, etc.)"),
            ("nova_business_logic.py", "Logic flaw testing"),
            ("nova_race_engine.py", "Race condition detection"),
            ("nova_llm_injection.py", "Prompt injection testing"),
        ],
        "Phase 3 - Intelligence": [
            ("nova_ast_intel.py", "AST analysis, dataflow tracing"),
            ("nova_verify_engine.py", "Triple-confirm findings"),
            ("nova_browser_session.py", "XSS execution via Playwright"),
            ("nova_triage.py", "H1-ready prioritization"),
            ("nova_zero_day_correlator.py", "Live CVE correlation"),
        ],
        "Phase 4 - Output": [
            ("nova_patch_generator.py", "AI-generated patches"),
            ("nova_detection_engineer.py", "Sigma detection rules"),
            ("nova_audit_reporter.py", "Multi-format reporting"),
            ("nova_vuln_tracker.py", "SQLite vulnerability DB"),
        ],
        "Orchestration": [
            ("nova_orchestrator.py", "Multi-agent (Recon → Attack → Report)"),
            ("nova_code_agent.py", "Autonomous coding loop: map → patch → test → retry"),
            ("nova_cli.py", "Structured CLI"),
            ("nova_eval.py", "20-mission benchmark"),
            ("nova_diff_watcher.py", "Real-time file watcher"),
        ],
        "Provider Layer": [
            ("nova_llm_router.py", "LLM routing (OpenAI → Anthropic → Ollama)"),
            ("nova_sessions.py", "Scan state persistence"),
            ("nova_tool_kit.py", "Governed tools + audit log"),
            ("nova_hooks.py", "Event lifecycle"),
            ("nova_context.py", "Shared RunContext"),
        ],
        "Advanced": [
            ("nova_evolution.py", "Self-code improvement (safe)"),
            ("nova_threat_model.py", "STRIDE threat modeling"),
            ("nova_rag_builder.py", "Knowledge base from past hunts"),
            ("nova_memory_system.py", "Learning across hunts"),
        ],
    }

    def __init__(self):
        self.nova_dir = Path(__file__).parent

    def print_header(self, title: str, level: int = 1):
        """Print a formatted header."""
        if level == 1:
            print(f"\n{'='*70}")
            print(f"  {title}")
            print(f"{'='*70}\n")
        else:
            print(f"\n{'-'*70}")
            print(f"  {title}")
            print(f"{'-'*70}\n")

    def print_features_by_role(self, role: str):
        """Print features for a specific role."""
        if role not in self.FEATURES:
            print(f"❌ Unknown role: {role}")
            return

        features = self.FEATURES[role]
        role_title = role.upper().replace("-", " ")
        
        self.print_header(f"🦅 Nova Arsenal — {role_title} Features", 1)
        
        for i, feature in enumerate(features, 1):
            print(f"{i}. {feature['name']}")
            print(f"   Command:     {feature['command']}")
            print(f"   Time:        {feature['time']}")
            print(f"   Requires:    {feature['requires']}")
            print(f"   Description: {feature['description']}")
            print(f"   Example:")
            for line in feature['example'].split('\\n'):
                print(f"     {line}")
            print()

    def print_all_features(self):
        """Print all features organized by role."""
        for role in ["beginner", "intermediate", "advanced"]:
            self.print_features_by_role(role)

    def print_scanners(self):
        """Print available scanners."""
        self.print_header("🔍 Available Vulnerability Scanners", 2)
        
        for vuln_type, command in self.SCANNERS.items():
            print(f"  • {vuln_type:40} → {command}")
        print()

    def print_modules(self):
        """Print all modules by category."""
        self.print_header("🔧 Core Modules (35+)", 2)
        
        for category, modules in self.MODULES.items():
            print(f"  {category}")
            for module_name, description in modules:
                print(f"    ✓ {module_name:35} — {description}")
            print()

    MODULE_ATTRS = {
        "nova.py": "dispatch",
        "nova_cli.py": "main",
        "nova_tool_kit.py": "execute_tool",
        "nova_agent_core.py": "NovaAgent",
        "nova_code_agent.py": "NovaCodeAgent",
        "nova_codebase_mapper.py": "NovaCodebaseMapper",
        "nova_source_auditor.py": "NovaSourceAuditor",
        "nova_llm_router.py": "LLMRouter",
    }

    def _import_check(self, module_name: str) -> bool:
        module = module_name[:-3]
        attr = self.MODULE_ATTRS.get(module_name)
        code = f"import {module}\n"
        if attr:
            code += f"assert hasattr({module}, '{attr}'), 'missing {attr}'\n"
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=self.nova_dir,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()[-1:]
            print(f"  import check failed: {detail[0] if detail else 'unknown error'}")
            return False
        return True

    def check_features(self) -> bool:
        """Verify expected modules exist and core modules import."""
        self.print_header("✅ Feature Verification", 1)

        missing = []
        import_failures = []
        all_modules = []

        for category, modules in self.MODULES.items():
            for module_name, _ in modules:
                all_modules.append(module_name)
                filepath = self.nova_dir / module_name
                if not filepath.exists():
                    print(f"✗ {module_name} (MISSING)")
                    missing.append(module_name)
                    continue
                print(f"✓ {module_name}")
                if module_name in self.MODULE_ATTRS and not self._import_check(module_name):
                    import_failures.append(module_name)

        print()
        present = len(all_modules) - len(missing)
        print(f"Summary: {present}/{len(all_modules)} modules present; {len(import_failures)} core import failure(s)")

        if missing:
            print(f"\n⚠️  Missing modules: {', '.join(missing)}")
        if import_failures:
            print(f"\n❌ Import failures: {', '.join(import_failures)}")
        if missing or import_failures:
            return False

        print("\n✅ All modules verified!")
        return True

    def run(self):
        """Main entry point."""
        if "--beginner" in sys.argv:
            self.print_features_by_role("beginner")
        elif "--intermediate" in sys.argv:
            self.print_features_by_role("intermediate")
        elif "--advanced" in sys.argv:
            self.print_features_by_role("advanced")
        elif "--by-role" in sys.argv:
            self.print_all_features()
        elif "--scanners" in sys.argv:
            self.print_scanners()
        elif "--modules" in sys.argv:
            self.print_modules()
        elif "--check" in sys.argv:
            self.check_features()
        else:
            # Default: show all + scanners + check
            self.print_all_features()
            self.print_scanners()
            self.print_modules()
            print("\n" + "="*70)
            print("💡 Run: python3 nova_features.py --help for more options")
            print("="*70 + "\n")


if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
    else:
        features = NovaFeatures()
        features.run()
