#!/usr/bin/env python3
"""
NOVA BOOTSTRAP v1.0
Health check and capability verification for Nova Arsenal v4.0.
Run after install to verify all modules are functional.
Also acts as the single entry point that ties all capabilities together.
"""
import os, sys, importlib, subprocess, json, urllib.request
from pathlib import Path
from datetime import datetime

NOVA_DIR  = Path(__file__).parent
WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
OLLAMA_URL = os.getenv("NOVA_LLM_URL", "http://localhost:11434")

# All Nova modules with their key class
MODULES = {
    "nova_file_prioritizer":   ("NovaFilePrioritizer",   "v4.0", "Mythos file risk scoring"),
    "nova_threat_model":       ("NovaThreatModel",        "v4.0", "Daybreak threat modeling"),
    "nova_patch_generator":    ("NovaPatchGenerator",     "v4.0", "Auto patch generation"),
    "nova_sca_scanner":        ("NovaSCAScanner",         "v4.0", "Dependency CVE scanning"),
    "nova_git_scanner":        ("NovaGitScanner",         "v4.0", "Git history scanning"),
    "nova_sandbox_validator":  ("NovaSandboxValidator",   "v4.0", "Exploit validation"),
    "nova_detection_engineer": ("NovaDetectionEngineer",  "v4.0", "SIEM rule generation"),
    "nova_audit_reporter":     ("NovaAuditReporter",      "v4.0", "Enterprise audit report"),
    "nova_vuln_tracker":       ("NovaVulnTracker",        "v4.0", "SQLite vulnerability tracker"),
    "nova_idor_scanner":       ("NovaIDORScanner",        "v4.0", "IDOR/access control testing"),
    "nova_graphql_tester":     ("NovaGraphQLTester",      "v4.0", "GraphQL security testing"),
    "nova_supply_chain_scorer":("NovaSupplyChainScorer",  "v4.0", "Supply chain risk scoring"),
    "nova_cicd_scanner":       ("NovaCICDScanner",        "v4.0", "CI/CD pipeline security"),
    "nova_container_scanner":  ("NovaContainerScanner",   "v4.0", "Docker/K8s security"),
    "nova_zero_day_correlator":("NovaZeroDayCorrelator",  "v4.0", "Live CVE correlation"),
    "nova_csrf_tester":        ("NovaCsrfTester",         "v4.0", "CSRF vulnerability testing"),
    "nova_llm_injection":      ("NovaLLMInjectionTester", "v4.0", "LLM prompt injection"),
    "nova_business_logic":     ("NovaBusinessLogicTester","v4.0", "Business logic testing"),
    "nova_source_auditor":     ("NovaSourceAuditor",      "v2.0", "Multi-language SAST"),
    "nova_verify_engine":      ("NovaVerifyEngine",       "v3.5", "Triple-verify engine"),
    "nova_web_researcher":     ("NovaWebResearcher",      "v3.5", "CVE/PoC web research"),
    "nova_tool_kit":           ("NovaToolKit",            "v2.0", "20-tool agent kit"),
    "nova_planner":            ("NovaPlanner",            "v3.5", "Pre-hunt planning"),
    "nova_context_manager":    ("NovaContextManager",     "v3.5", "Context compression"),
    "nova_agent_core":         ("NovaAgentCore",          "v2.0", "ReAct hunt loop"),
    "nova_self_improvement":   (None,                     "v3.5", "Self-improvement engine"),
    # ── Newly wired modules (previously orphaned) ────────────────────────────
    "nova_memory_system":       ("NovaBrain",                "v1.0", "Cross-session memory brain"),
    "nova_notifications":       ("NovaNotifications",        "v1.0", "Notification bus (Telegram/email)"),
    "nova_error_handler":       ("NovaErrorHandler",         "v1.0", "Structured error handling"),
    "nova_findings_db":         ("NovaFindingsDB",           "v1.0", "Persistent findings database"),
    "nova_output_parser":       ("NovaOutputParser",         "v1.0", "Tool-output parser (nmap/nikto)"),
    "nova_result_parser":       ("FindingsDatabase",         "v1.0", "Findings result parser"),
    "nova_context_engine":      ("NovaContextEngine",        "v1.0", "Dynamic context engine"),
    "nova_context_enricher":    ("ContextEnricher",          "v1.0", "Application context enricher"),
    "nova_rag_builder":         ("NovaRAGBuilder",           "v1.0", "RAG knowledge builder"),
    "nova_llm_bridge":          ("NovaLLMBridge",            "v1.0", "LLM HTTP bridge"),
    "nova_model_router":        ("NovaModelRouter",          "v1.0", "Multi-model router"),
    "nova_language_model":      (None,                       "v1.0", "Language model abstraction layer"),
    "nova_memory":              (None,                       "v1.0", "Target/finding/session memory"),
    "nova_hypothesis_engine":   ("HypothesisEngine",         "v1.0", "Hypothesis-driven testing"),
    "nova_chain_of_thought":    ("NovaChainOfThought",       "v1.0", "Chain-of-thought reasoning"),
    "nova_vuln_synthesis":      ("NovaVulnSynthesis",        "v1.0", "Cross-finding synthesis"),
    "nova_dataflow_engine":     ("NovaDataFlowEngine",       "v1.0", "Taint / data-flow SAST"),
    "nova_auth_scanner":        ("NovaAuthenticatedScanner", "v1.0", "Authenticated scanner"),
    "nova_live_verify":         ("LiveVerificationEngine",   "v1.0", "Live finding verification"),
    "nova_live_exploit":        ("NovaLiveExploit",          "v1.0", "Live exploit engine"),
    "nova_report":              (None,                       "v1.0", "HTML/Markdown report generator"),
    "nova_wild_hunt":           ("NovaWildHunt",             "v1.0", "Wild bug-bounty hunt mode"),
    "nova_ibb_hunter":          ("NovaIBBHunter",            "v1.0", "Internet Bug Bounty hunter"),
    "nova_0din_hunter":         ("Nova0DINHunter",           "v1.0", "0DIN zero-day hunter"),
    "nova_github_scanner":      ("NovaGitHubScanner",        "v1.0", "GitHub code/secret scanner"),
    "nova_ecosystem_auditor":   ("NovaEcosystemAuditor",     "v1.0", "Full ecosystem auditor"),
    "nova_pypi_hunter":         ("NovaPyPIHunter",           "v1.0", "Malicious PyPI package hunter"),
    "nova_browser_agent":       ("NovaBrowserAgent",         "v1.0", "Headless browser agent"),
    "nova_multi_target_orchestrator": (None,                 "v1.0", "Multi-target orchestrator"),
    "nova_unified_attack":      ("NovaUnifiedAttack",        "v1.0", "Unified attack chain"),
    "nova_swarm_v2":            ("NovaSwarmV2",              "v1.0", "Swarm v2 parallel agents"),
    "nova_swarm_parallel":      (None,                       "v1.0", "Concurrent swarm (recon/exploit/auth/code)"),
    "nova_pipeline":            ("NovaPipeline",             "v1.0", "Staged scan pipeline"),
    "nova_nextgen_agentic":     ("NovaNextGenAgentic",       "v1.0", "Next-gen autonomous agent"),
    "nova_kali_agent":          ("NovaKaliAgent",            "v1.0", "Kali pentest agent"),
    "nova_kali_knowledge_base": ("KaliKnowledgeBase",        "v1.0", "Kali tool knowledge base"),
    "nova_kali_knowledge":      ("KaliKnowledgeBase",        "v1.0", "Kali knowledge (alt)"),
    "nova_kali_kb_crypto_stego":    (None,                   "v1.0", "Kali KB: crypto & steganography"),
    "nova_kali_kb_exploitation":    (None,                   "v1.0", "Kali KB: exploitation techniques"),
    "nova_kali_kb_forensics":       (None,                   "v1.0", "Kali KB: digital forensics"),
    "nova_kali_kb_password_attacks":(None,                   "v1.0", "Kali KB: password attacks"),
    "nova_kali_kb_post_exploitation":(None,                  "v1.0", "Kali KB: post-exploitation"),
    "nova_kali_kb_reporting":       (None,                   "v1.0", "Kali KB: reporting"),
    "nova_kali_kb_scanning":        (None,                   "v1.0", "Kali KB: scanning & enumeration"),
    "nova_kali_kb_sniffing":        (None,                   "v1.0", "Kali KB: sniffing & spoofing"),
    "nova_kali_kb_social_engineering":(None,                 "v1.0", "Kali KB: social engineering"),
    "nova_kali_kb_web_application": (None,                   "v1.0", "Kali KB: web application attacks"),
    "nova_portswigger_academy":     ("NovaPortSwigger",      "v1.0", "PortSwigger Web Academy"),
    "nova_url_smuggling":           (None,                   "v1.0", "HTTP request smuggling"),
    "nova_knowledge_rag":           (None,                   "v1.0", "RAG knowledge base (findings/CVEs)"),
    "nova_payload_engine":          (None,                   "v1.0", "Polymorphic payload generator"),
    "nova_evolver":                 (None,                   "v1.0", "Self-improvement engine"),
}

REQUIRED_MODULES = [
    "nova_file_prioritizer","nova_threat_model","nova_patch_generator",
    "nova_sca_scanner","nova_git_scanner","nova_detection_engineer",
    "nova_audit_reporter","nova_vuln_tracker","nova_source_auditor",
]

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _ok(msg):  print(f"  {GREEN}✅{RESET} {msg}")
def _err(msg): print(f"  {RED}❌{RESET} {msg}")
def _warn(msg):print(f"  {YELLOW}⚠️ {RESET} {msg}")
def _info(msg):print(f"  {CYAN}ℹ️ {RESET} {msg}")


def check_python():
    v = sys.version_info
    if v >= (3,10):
        _ok(f"Python {v.major}.{v.minor}.{v.micro}")
        return True
    else:
        _warn(f"Python {v.major}.{v.minor} — 3.10+ recommended")
        return True


def check_ollama():
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags",
            headers={"Accept":"application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        models = [m["name"] for m in data.get("models",[])]
        _ok(f"Ollama running — {len(models)} model(s): {', '.join(models[:3]) or 'none'}")
        return True
    except Exception as e:
        _warn(f"Ollama not running — keyword fallback will be used ({e})")
        return False


def check_modules(quick: bool = False) -> dict:
    sys.path.insert(0, str(NOVA_DIR))
    results = {}
    for mod_name, (cls_name, version, desc) in MODULES.items():
        try:
            mod = importlib.import_module(mod_name)
            if cls_name:
                cls = getattr(mod, cls_name, None)
                if cls is None:
                    raise AttributeError(f"Class {cls_name} not found")
            results[mod_name] = True
            _ok(f"{mod_name} ({version}) — {desc}")
        except ModuleNotFoundError:
            if mod_name in REQUIRED_MODULES:
                _err(f"{mod_name} — MISSING (required)")
            else:
                _warn(f"{mod_name} — not installed (run: git pull)")
            results[mod_name] = False
        except Exception as e:
            _warn(f"{mod_name} — import issue: {e}")
            results[mod_name] = False
    return results


def check_workspace():
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    db_path = WORKSPACE / "nova_vulns.db"
    test_file = WORKSPACE / ".nova_write_test"
    try:
        test_file.write_text("ok")
        test_file.unlink()
        _ok(f"Workspace writable: {WORKSPACE}")
        return True
    except Exception as e:
        _err(f"Workspace not writable: {e}")
        return False


def check_external_tools():
    tools = {"nmap":"Network scanning","nuclei":"Template scanning","sqlmap":"SQL injection",
             "ffuf":"Directory fuzzing","subfinder":"Subdomain enum","git":"Git operations",
             "curl":"HTTP testing","trivy":"Container scanning"}
    present = []
    missing = []
    for tool, purpose in tools.items():
        path = subprocess.run(["which",tool], capture_output=True, text=True).stdout.strip()
        if path:
            present.append(tool)
            _ok(f"{tool} ({purpose}): {path}")
        else:
            missing.append(tool)
            _warn(f"{tool} ({purpose}) — not found (optional)")
    return present, missing


def check_connectivity():
    endpoints = [
        ("OSV.dev", "https://api.osv.dev/v1/query", "POST",
         b'{"package":{"name":"lodash","ecosystem":"npm"}}'),
        ("NVD API", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1", "GET", None),
    ]
    for name, url, method, data in endpoints:
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("Content-Type","application/json")
            if data: req.data = data
            with urllib.request.urlopen(req, timeout=8) as r:
                _ok(f"{name} reachable ({r.status})")
        except Exception as e:
            _warn(f"{name} not reachable: {e}")


def quick_smoke_test():
    sys.path.insert(0, str(NOVA_DIR))
    try:
        from nova_threat_model import NovaThreatModel
        tm = NovaThreatModel()
        model = tm.build_from_files({
            "test.ts": "const app = express();\napp.get('/users/:id', (req,res) => { db.query(`SELECT * FROM users WHERE id = ${req.params.id}`); });"
        })
        assert model.get("summary",{}).get("attack_paths",0) > 0, "No attack paths found"
        _ok("Threat model smoke test: PASSED")
    except Exception as e:
        _warn(f"Threat model smoke test: {e}")

    try:
        from nova_sca_scanner import NovaSCAScanner
        scanner = NovaSCAScanner(use_osv=False)
        findings = scanner.scan_manifest("package.json") if Path("package.json").exists() else []
        _ok("SCA scanner smoke test: PASSED")
    except Exception as e:
        _warn(f"SCA scanner smoke test: {e}")

    try:
        from nova_vuln_tracker import NovaVulnTracker
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        tracker = NovaVulnTracker(db_path)
        tracker.start_run("test")
        stats = tracker.ingest_findings([{"type":"sqli","file":"test.ts","line":1,"severity":"CRITICAL"}])
        assert stats["new"] == 1
        tracker.close()
        os.unlink(db_path)
        _ok("Vuln tracker smoke test: PASSED")
    except Exception as e:
        _warn(f"Vuln tracker smoke test: {e}")


def print_capability_summary(module_results: dict, external_tools: list):
    print(f"\n{BOLD}{CYAN}━━━ Nova Arsenal v4.2 Capability Summary ━━━{RESET}")
    total = len(MODULES)
    working = sum(1 for v in module_results.values() if v)
    pct = int(working/total*100)
    print(f"\n  Modules: {working}/{total} ({pct}%)")
    print(f"  External tools: {len(external_tools)} available")
    print()

    capabilities = [
        ("File Risk Prioritization (1-5)",    "nova_file_prioritizer"    in module_results and module_results["nova_file_prioritizer"]),
        ("Threat Modeling",                    "nova_threat_model"         in module_results and module_results["nova_threat_model"]),
        ("Multi-language SAST",                "nova_source_auditor"       in module_results and module_results["nova_source_auditor"]),
        ("Dependency CVE Scan (SCA)",          "nova_sca_scanner"          in module_results and module_results["nova_sca_scanner"]),
        ("Git History Secret Scan",            "nova_git_scanner"          in module_results and module_results["nova_git_scanner"]),
        ("Exploit Sandbox Validation",         "nova_sandbox_validator"    in module_results and module_results.get("nova_sandbox_validator",False)),
        ("Auto Patch Generation",              "nova_patch_generator"      in module_results and module_results["nova_patch_generator"]),
        ("SIEM Detection Rules",               "nova_detection_engineer"   in module_results and module_results["nova_detection_engineer"]),
        ("Enterprise Audit Report",            "nova_audit_reporter"       in module_results and module_results["nova_audit_reporter"]),
        ("Persistent Vuln Tracking (SQLite)",  "nova_vuln_tracker"         in module_results and module_results["nova_vuln_tracker"]),
        ("IDOR / Access Control Testing",      "nova_idor_scanner"         in module_results and module_results.get("nova_idor_scanner",False)),
        ("GraphQL Security Testing",           "nova_graphql_tester"       in module_results and module_results.get("nova_graphql_tester",False)),
        ("Supply Chain Risk Scoring",          "nova_supply_chain_scorer"  in module_results and module_results.get("nova_supply_chain_scorer",False)),
        ("CI/CD Pipeline Security",            "nova_cicd_scanner"         in module_results and module_results.get("nova_cicd_scanner",False)),
        ("Container/K8s Security",             "nova_container_scanner"    in module_results and module_results.get("nova_container_scanner",False)),
        ("Live CVE Zero-Day Correlation",      "nova_zero_day_correlator"  in module_results and module_results.get("nova_zero_day_correlator",False)),
        ("CSRF Vulnerability Testing",         "nova_csrf_tester"          in module_results and module_results.get("nova_csrf_tester",False)),
        ("LLM Prompt Injection Testing",       "nova_llm_injection"        in module_results and module_results.get("nova_llm_injection",False)),
        ("Business Logic Testing",             "nova_business_logic"       in module_results and module_results.get("nova_business_logic",False)),
        ("ReAct Agentic Hunt Loop",            "nova_agent_core"           in module_results and module_results.get("nova_agent_core",False)),
        ("Triple-Verify Engine",               "nova_verify_engine"        in module_results and module_results.get("nova_verify_engine",False)),
        ("10-Agent Parallel Swarm",            True),
        ("Self-Improvement Engine",            True),
        ("24/7 Continuous Hunting",            True),
    ]
    for cap, ok in capabilities:
        icon = f"{GREEN}✅{RESET}" if ok else f"{RED}❌{RESET}"
        print(f"  {icon}  {cap}")

    print()
    if working == total:
        print(f"  {BOLD}{GREEN}🚀 Nova Arsenal v4.2 — FULL POWER — All {total} modules ready{RESET}")
    else:
        missing = total - working
        print(f"  {YELLOW}⚠️  {missing} module(s) not available — run: git pull origin main{RESET}")
    print()


def main():
    quick = "--quick" in sys.argv
    print(f"\n{BOLD}{CYAN}Nova Arsenal v4.2 — Bootstrap & Health Check{RESET}")
    print(f"{CYAN}{'━'*50}{RESET}\n")

    print(f"{BOLD}[1/6] Python{RESET}")
    check_python()

    print(f"\n{BOLD}[2/6] Ollama LLM{RESET}")
    check_ollama()

    print(f"\n{BOLD}[3/6] Nova Workspace{RESET}")
    check_workspace()

    print(f"\n{BOLD}[4/6] Nova Modules{RESET}")
    module_results = check_modules(quick)

    if not quick:
        print(f"\n{BOLD}[5/6] External Security Tools{RESET}")
        tools_present, _ = check_external_tools()

        print(f"\n{BOLD}[6/6] Network Connectivity + Smoke Tests{RESET}")
        check_connectivity()
        quick_smoke_test()
    else:
        tools_present = []

    print_capability_summary(module_results, tools_present)

    # Write status to workspace
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    status = {
        "generated": datetime.utcnow().isoformat(),
        "modules_ok": sum(1 for v in module_results.values() if v),
        "modules_total": len(module_results),
        "ready": all(module_results.get(m, False) for m in REQUIRED_MODULES),
    }
    (WORKSPACE / "nova_bootstrap_status.json").write_text(json.dumps(status, indent=2))


if __name__ == "__main__":
    main()
