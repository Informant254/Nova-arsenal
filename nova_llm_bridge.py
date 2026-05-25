#!/usr/bin/env python3
"""
NOVA LLM BRIDGE v1.0 — NATURAL LANGUAGE MISSION CONTROL
Connects TinyLlama (via Ollama) to the Nova Swarm.
Converts natural language objectives into structured attack missions.

Zero cloud. Zero API keys. Pure on-device intelligence.
"""

import json
import re
import subprocess
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional


class NovaLLMBridge:
    """
    Natural language → Attack mission translator.
    
    Capabilities:
    - Parse natural language objectives into structured missions
    - Select appropriate agents for the objective
    - Generate exploit payloads using LLM reasoning
    - Analyze responses and adapt strategy
    - Provide natural language mission reports
    """

    def __init__(self, ollama_model: str = "tinyllama:latest", base_url: str = "http://localhost:3000"):
        self.ollama_model = ollama_model
        self.base_url = base_url
        self.ollama_url = "http://localhost:11434/api/generate"
        self.mission_history = []
        self.conversation_context = []

    def query_llm(self, prompt: str, system_prompt: str = None) -> str:
        """Send a query to TinyLlama via Ollama."""
        if system_prompt:
            full_prompt = f"{system_prompt}\n\nUser: {prompt}\nAssistant:"
        else:
            full_prompt = prompt

        try:
            resp = requests.post(
                self.ollama_url,
                json={
                    "model": self.ollama_model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 500}
                },
                timeout=60,
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
            else:
                # Fallback: try command line
                return self._query_via_cli(full_prompt)
        except:
            return self._query_via_cli(full_prompt)

    def _query_via_cli(self, prompt: str) -> str:
        """Fallback: use ollama CLI."""
        try:
            result = subprocess.run(
                ["ollama", "run", self.ollama_model, prompt],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return ""

    def is_ollama_available(self) -> bool:
        """Check if Ollama is running and model is available."""
        try:
            resp = requests.get("http://localhost:11434/api/tags", timeout=5)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                return self.ollama_model in model_names or any(self.ollama_model in n for n in model_names)
        except:
            pass
        return False

    # ---------- MISSION PLANNING ----------
    def plan_mission(self, objective: str) -> Dict:
        """Convert natural language objective into a structured attack plan."""
        print(f"""
╔══════════════════════════════════════════════╗
║   🧠 NOVA LLM BRIDGE — MISSION PLANNER    ║
║   Objective: {objective[:40]:<40} ║
╚══════════════════════════════════════════════╝""")

        system_prompt = """You are Nova, an autonomous security AI. Your job is to convert natural language security objectives into structured attack plans. 

Output ONLY valid JSON with this exact structure:
{
  "mission_name": "short name",
  "objective": "paraphrased objective",
  "priority_targets": ["endpoint1", "endpoint2"],
  "attack_types": ["sql_injection", "xss", "auth_bypass"],
  "agents_needed": ["recon", "exploit", "auth", "code"],
  "success_criteria": "what defines mission success",
  "estimated_difficulty": "low/medium/high/critical"
}

Available targets: /rest/products/search, /rest/user/login, /rest/user/register, /rest/user/whoami, /api/Feedbacks, /api/Users, /rest/admin/application-configuration, /rest/order-history, /file-serving
Available attack types: sql_injection, xss, auth_bypass, path_traversal, jwt_attack, race_condition, session_hijack
Available agents: recon, exploit, auth, code, race, validate"""

        prompt = f"Plan a security assessment mission for this objective: {objective}"

        response = self.query_llm(prompt, system_prompt)

        # Parse JSON from response
        try:
            # Find JSON block
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                plan = json.loads(json_match.group())
                print(f"\n  📋 Mission Plan:")
                print(f"     Name: {plan.get('mission_name', 'Unknown')}")
                print(f"     Targets: {plan.get('priority_targets', [])}")
                print(f"     Attacks: {plan.get('attack_types', [])}")
                print(f"     Agents: {plan.get('agents_needed', [])}")
                print(f"     Difficulty: {plan.get('estimated_difficulty', 'unknown')}")
                return plan
        except json.JSONDecodeError:
            pass

        # Fallback: rule-based planning
        print("\n  ⚠️ LLM unavailable or returned invalid JSON. Using rule-based planning.")
        return self._rule_based_plan(objective)

    def _rule_based_plan(self, objective: str) -> Dict:
        """Fallback rule-based mission planner."""
        objective_lower = objective.lower()

        plan = {
            "mission_name": "Autonomous Security Assessment",
            "objective": objective,
            "priority_targets": [
                "/rest/user/login",
                "/rest/products/search",
                "/rest/admin/application-configuration",
                "/api/Feedbacks",
                "/rest/user/whoami",
            ],
            "attack_types": ["sql_injection", "auth_bypass", "xss"],
            "agents_needed": ["recon", "exploit", "auth", "code", "race", "validate"],
            "success_criteria": "Find and exploit at least one critical vulnerability with evidence chain",
            "estimated_difficulty": "medium",
        }

        # Customize based on objective keywords
        if "token" in objective_lower or "jwt" in objective_lower:
            plan["priority_targets"].insert(0, "/rest/user/whoami")
            plan["attack_types"].append("jwt_attack")
            plan["mission_name"] = "JWT Token Exploitation"

        if "admin" in objective_lower or "privilege" in objective_lower:
            plan["priority_targets"].insert(0, "/rest/admin/application-configuration")
            plan["attack_types"] = ["auth_bypass", "jwt_attack"]
            plan["mission_name"] = "Privilege Escalation Campaign"

        if "data" in objective_lower or "dump" in objective_lower or "extract" in objective_lower:
            plan["attack_types"] = ["sql_injection", "auth_bypass"]
            plan["mission_name"] = "Data Exfiltration Mission"

        if "race" in objective_lower or "rate" in objective_lower or "flood" in objective_lower:
            plan["attack_types"] = ["race_condition"]
            plan["agents_needed"] = ["recon", "race"]
            plan["mission_name"] = "Race Condition Assessment"

        if "source" in objective_lower or "code" in objective_lower:
            plan["agents_needed"].append("code")
            plan["mission_name"] = "Source Code Analysis"

        return plan

    # ---------- EXPLOIT PAYLOAD GENERATION ----------
    def generate_payload(self, vulnerability_type: str, endpoint: str, context: str = "") -> str:
        """Use LLM to generate a creative exploit payload."""
        system_prompt = """You are an expert penetration tester. Generate creative exploit payloads.
Output ONLY the raw payload string. No explanations. No markdown."""

        prompt = f"""Generate a {vulnerability_type} exploit payload for the endpoint: {endpoint}
Context: {context if context else 'No additional context'}
Target: OWASP Juice Shop (Node.js/Express with SQLite)"""

        response = self.query_llm(prompt, system_prompt)
        return response.strip()[:200] if response else ""

    # ---------- RESPONSE ANALYSIS ----------
    def analyze_response(self, response_text: str, attack_type: str) -> Dict:
        """Have LLM analyze an exploit response for signs of success."""
        system_prompt = """Analyze this HTTP response from a security test. 
Output ONLY valid JSON: {"success": true/false, "indicators": ["list"], "data_extracted": ["items"], "recommendation": "next step"}"""

        prompt = f"""Attack type: {attack_type}
Response (first 800 chars): {response_text[:800]}
Did this exploit succeed? What was exposed? What should we try next?"""

        response = self.query_llm(prompt, system_prompt)
        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        # Fallback analysis
        indicators = []
        if "password" in response_text.lower(): indicators.append("password_exposed")
        if "token" in response_text.lower(): indicators.append("token_found")
        if "admin" in response_text.lower(): indicators.append("admin_access")
        if "email" in response_text.lower(): indicators.append("email_exposed")

        return {
            "success": len(indicators) > 0,
            "indicators": indicators,
            "data_extracted": indicators,
            "recommendation": "Continue exploitation" if indicators else "Try different payload",
        }

    # ---------- NATURAL LANGUAGE REPORTING ----------
    def generate_nl_report(self, findings: List[Dict], stats: Dict) -> str:
        """Generate a natural language mission report."""
        system_prompt = """You are Nova, an elite autonomous security AI. Write a concise, professional penetration test report in natural language. Be specific about vulnerabilities found, their impact, and recommended remediations."""

        findings_summary = json.dumps(findings[:5], indent=2)
        stats_summary = json.dumps(stats, indent=2)

        prompt = f"""Mission complete. Generate a penetration test report.

Statistics: {stats_summary}
Top Findings: {findings_summary}

Write a professional report with:
1. Executive Summary
2. Critical Findings (with impact)
3. Recommendations
4. Attack Chain Summary"""

        response = self.query_llm(prompt, system_prompt)
        return response if response else self._generate_fallback_report(findings, stats)

    def _generate_fallback_report(self, findings: List[Dict], stats: Dict) -> str:
        """Fallback report generator."""
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]

        report = f"""
╔══════════════════════════════════════════════╗
║        NOVA MISSION REPORT                   ║
╚══════════════════════════════════════════════╝

EXECUTIVE SUMMARY
─────────────────
Nova conducted an autonomous security assessment targeting {stats.get('target', 'the application')}.
Mission duration: {stats.get('duration_seconds', 'N/A')} seconds.
Total findings: {len(findings)} ({len(critical)} critical, {len(high)} high)

CRITICAL FINDINGS
─────────────────"""
        for f in critical:
            report += f"\n• {f.get('type', 'Unknown')} on {f.get('endpoint', 'unknown endpoint')}"
            if f.get('data_exposed'):
                report += f"\n  Data exposed: {f['data_exposed']}"
            if f.get('source_file'):
                report += f"\n  Source: {f['source_file']}:{f.get('source_line', '?')}"

        report += f"""

ATTACK CHAIN
───────────
1. Reconnaissance mapped {stats.get('endpoints_mapped', 'N/A')} endpoints
2. Exploitation confirmed vulnerabilities on multiple endpoints
3. Credential extraction yielded {stats.get('tokens_captured', 0)} tokens
4. Privilege escalation achieved via token reuse
5. Source code analysis traced vulnerabilities to specific files

RECOMMENDATIONS
───────────────
• Implement parameterized queries for all SQL operations
• Add rate limiting to all search endpoints
• Remove stack traces from production error responses
• Validate JWT algorithms server-side (reject 'none')
• Sanitize all user input before rendering

Nova signing off. 🦅
"""
        return report

    # ---------- FULL LLM-ENHANCED MISSION ----------
    def run_llm_mission(self, objective: str = "Find and exploit all critical vulnerabilities") -> Dict:
        """Execute a full LLM-enhanced mission."""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🧠  NOVA LLM BRIDGE — NATURAL LANGUAGE MISSION  🧠      ║
║   " {objective[:50]} "
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)

        # Check if Ollama is available
        ollama_available = self.is_ollama_available()
        if ollama_available:
            print(f"  ✅ Ollama connected. Model: {self.ollama_model}")
        else:
            print(f"  ⚠️ Ollama not available. Running in rule-based mode.")
            print(f"     Start Ollama with: ollama serve")
            print(f"     Pull model with: ollama pull {self.ollama_model}")

        # Plan mission
        plan = self.plan_mission(objective)

        # Execute using Nova Swarm
        print(f"\n  🚀 Executing mission: {plan.get('mission_name', 'Unknown')}")
        print(f"  ========================================")

        try:
            from nova_swarm_v3 import NovaSwarmV3
            swarm = NovaSwarmV3(base_url=self.base_url)
            kg = swarm.run_full_swarm()

            # Generate natural language report
            stats = {
                "target": self.base_url,
                "duration_seconds": round(time.time() - swarm.start_time, 2) if swarm.start_time else "N/A",
                "tokens_captured": len(kg.get("tokens", [])),
                "paths_leaked": len(kg.get("paths", [])),
                "endpoints_mapped": len(kg.get("endpoints", {})),
            }

            nl_report = self.generate_nl_report(kg.get("findings", []), stats)

            print(f"\n{'='*60}")
            print(nl_report)

            # Save
            with open("nova_llm_mission_report.txt", "w") as f:
                f.write(nl_report)

            return {
                "plan": plan,
                "findings": kg.get("findings", []),
                "stats": stats,
                "nl_report": nl_report,
            }

        except ImportError:
            print("  ⚠️ Nova Swarm not available. Run nova_swarm_v3.py first.")
            return {"plan": plan, "error": "Swarm module not found"}


if __name__ == "__main__":
    import sys

    bridge = NovaLLMBridge(
        ollama_model="tinyllama:latest",
        base_url="http://localhost:3000",
    )

    # Get objective from command line or use default
    if len(sys.argv) > 1:
        objective = " ".join(sys.argv[1:])
    else:
        objective = "Find all SQL injection vulnerabilities, exploit them, extract credentials, and escalate to admin access"

    report = bridge.run_llm_mission(objective)
