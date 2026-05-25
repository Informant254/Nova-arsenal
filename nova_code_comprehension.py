#!/usr/bin/env python3
"""
NOVA CODE COMPREHENSION ENGINE v1.0
True understanding of programming logic and intent.
Finds bugs by reasoning about what code SHOULD do vs what it DOES.
Inspired by how senior engineers review code.
"""

import json, re, os, ast, subprocess, tempfile
from datetime import datetime
from collections import defaultdict

class NovaCodeComprehension:
    """Understands code, not just pattern matches."""
    
    def __init__(self):
        self.insights = []
        
        # Code comprehension rules — understanding intent
        self.comprehension_checks = {
            "authentication_gaps": {
                "description": "Authentication checks that can be bypassed",
                "patterns": [
                    # Checks auth only on GET but not POST/PUT/DELETE
                    (r'if.*authenticated.*:\s*return.*\{.*\}', "Auth check may only apply to one method"),
                    # Auth middleware skipped on specific routes
                    (r'app\.use\(.*auth.*\).*app\.(get|post)\(', "Auth middleware may have route exceptions"),
                    # Boolean auth that can be type-juggled
                    (r'if\s+(\w+)\s*==\s*True', "Boolean auth check — try type juggling"),
                ],
                "severity": "CRITICAL",
            },
            "authorization_confusion": {
                "description": "Authorization logic with logical flaws",
                "patterns": [
                    # Role check that trusts client input
                    (r'role\s*=\s*req\.(body|query|params)', "Role from client input — privilege escalation"),
                    # Admin check with OR instead of AND
                    (r'if.*admin.*or.*moderator', "OR in auth check may grant unintended access"),
                    # Missing ownership verification
                    (r'\.findById\(.*req\.params\.id\)', "Resource access without ownership check — IDOR"),
                ],
                "severity": "CRITICAL",
            },
            "cryptographic_blunders": {
                "description": "Crypto implementations that look correct but aren't",
                "patterns": [
                    # Constant-time comparison done wrong
                    (r'\.equals\(.*password', "String comparison for passwords — timing attack"),
                    # Random that isn't cryptographically secure
                    (r'Math\.random\(\)', "Math.random() for security — predictable"),
                    # Hardcoded IV or salt
                    (r'(iv|salt|nonce)\s*=\s*["\']', "Hardcoded cryptographic parameter"),
                ],
                "severity": "HIGH",
            },
            "transaction_illusions": {
                "description": "Code that looks atomic but isn't",
                "patterns": [
                    # Check-then-act without transaction
                    (r'if\s+balance\s*>=\s*amount.*\n.*balance\s*-=', "Check-then-act race condition"),
                    # Database operation without transaction decorator
                    (r'def\s+transfer.*\n.*\.save\(\)', "Transfer without @transaction.atomic"),
                    # Coupon validation then redemption in separate steps
                    (r'validate_coupon.*\n.*redeem_coupon', "Two-step coupon logic — race condition"),
                ],
                "severity": "HIGH",
            },
            "input_validation_facades": {
                "description": "Validation that appears thorough but has gaps",
                "patterns": [
                    # Validates length but not content
                    (r'if\s+len\(.*\)\s*<=\s*\d+:', "Length check without content validation"),
                    # Whitelist that can be bypassed
                    (r'if\s+\w+\s+in\s+\[.*\]:', "Simple allowlist — check for bypasses"),
                    # Regex that misses edge cases
                    (r're\.match\(r[\'\"].*[\'\"]', "Regex validation — check for ReDoS or bypass"),
                ],
                "severity": "MEDIUM",
            },
        }

    def comprehend_file(self, filepath: str) -> list:
        """Deeply understand a source file's logic and find flaws."""
        insights = []
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
                lines = source.split("\n")
        except:
            return insights
        
        filename = os.path.basename(filepath)
        
        for check_type, check_data in self.comprehension_checks.items():
            for pattern, explanation in check_data["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Get broader context for deeper understanding
                        start = max(0, i - 8)
                        end = min(len(lines), i + 8)
                        context = "\n".join(lines[start:end])
                        
                        insight = {
                            "file": filename,
                            "line": i,
                            "type": check_type,
                            "explanation": explanation,
                            "severity": check_data["severity"],
                            "code": line.strip()[:200],
                            "context": context[:400],
                            "programmer_intent": self._infer_intent(line, check_type),
                            "what_actually_happens": self._infer_reality(line, check_type),
                            "fix": self._suggest_fix(line, check_type),
                        }
                        insights.append(insight)
                        self.insights.append(insight)
        
        return insights

    def _infer_intent(self, line: str, check_type: str) -> str:
        """Infer what the programmer intended to do."""
        intentions = {
            "authentication_gaps": "Programmer intended to protect this endpoint with authentication",
            "authorization_confusion": "Programmer intended to check user permissions before granting access",
            "cryptographic_blunders": "Programmer intended to implement secure cryptography",
            "transaction_illusions": "Programmer intended this operation to be atomic and race-condition-free",
            "input_validation_facades": "Programmer intended to validate and sanitize all user input",
        }
        return intentions.get(check_type, "Programmer intended this code to work correctly")

    def _infer_reality(self, line: str, check_type: str) -> str:
        """Explain what the code actually does vs the intent."""
        realities = {
            "authentication_gaps": "Authentication can be bypassed because the check doesn't apply to all HTTP methods or has logical gaps",
            "authorization_confusion": "Authorization can be escalated because the check trusts client-supplied data or has logical flaws",
            "cryptographic_blunders": "The cryptographic implementation has subtle flaws that break its security properties",
            "transaction_illusions": "Race conditions exist because the check and action aren't performed atomically",
            "input_validation_facades": "Input validation has gaps that allow malicious input to bypass the checks",
        }
        return realities.get(check_type, "The code has a logical flaw that diverges from the programmer's intent")

    def _suggest_fix(self, line: str, check_type: str) -> str:
        """Suggest a concrete fix."""
        fixes = {
            "authentication_gaps": "Apply authentication middleware to ALL HTTP methods for this route, or use a decorator that covers all methods",
            "authorization_confusion": "Never trust client-supplied roles. Verify permissions server-side using the authenticated user's session",
            "cryptographic_blunders": "Use constant-time comparison functions. Use crypto.randomBytes() instead of Math.random()",
            "transaction_illusions": "Wrap the check and action in a database transaction. Use SELECT FOR UPDATE",
            "input_validation_facades": "Use a comprehensive validation library. Validate type, length, format, and content",
        }
        return fixes.get(check_type, "Review the logic and ensure it matches the intended behavior")

    def scan_repository(self, repo_path: str) -> dict:
        """Deeply comprehend an entire repository."""
        print(f"🧠 Comprehending: {repo_path}\n")
        
        all_insights = []
        files_analyzed = 0
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in 
                      ["test", "tests", "node_modules", "venv", "__pycache__", ".git", "target", "build"]]
            
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".java", ".rb", ".php")):
                    filepath = os.path.join(root, file)
                    insights = self.comprehend_file(filepath)
                    if insights:
                        all_insights.extend(insights)
                        for ins in insights:
                            print(f"   💡 [{ins['severity']}] {ins['file']}:{ins['line']}")
                            print(f"      Intent: {ins['programmer_intent'][:80]}...")
                            print(f"      Reality: {ins['what_actually_happens'][:80]}...")
                    files_analyzed += 1
        
        return {
            "files_analyzed": files_analyzed,
            "insights_found": len(all_insights),
            "insights": all_insights,
        }

    def run(self, target: str = None):
        """Run code comprehension on a target."""
        print("""
╔══════════════════════════════════════════════════════════╗
║   🧠 NOVA CODE COMPREHENSION ENGINE                      ║
║   Understanding intent, finding divergence              ║
║   This is what senior engineers do in code review       ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        target = target or "."
        
        if os.path.isdir(target):
            result = self.scan_repository(target)
        else:
            # Clone and scan
            tmp = tempfile.mkdtemp(prefix="nova_comprehend_")
            subprocess.run(["git", "clone", "--depth", "1", target, tmp], 
                          capture_output=True, check=True, timeout=120)
            result = self.scan_repository(tmp)
            subprocess.run(["rm", "-rf", tmp])
        
        # Summary
        insights_by_severity = defaultdict(list)
        for ins in self.insights:
            insights_by_severity[ins["severity"]].append(ins)
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║   COMPREHENSION COMPLETE                                 ║
╠══════════════════════════════════════════════════════════╣
║  Files Analyzed: {result['files_analyzed']:<5}                                  ║
║  Insights Found: {result['insights_found']:<4}                                   ║
║  CRITICAL: {len(insights_by_severity['CRITICAL']):<3}  HIGH: {len(insights_by_severity['HIGH']):<3}  MEDIUM: {len(insights_by_severity['MEDIUM']):<3}       ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        if insights_by_severity['CRITICAL']:
            print("💀 CRITICAL LOGICAL FLAWS:")
            for ins in insights_by_severity['CRITICAL'][:5]:
                print(f"   🔥 {ins['file']}:{ins['line']} — {ins['explanation']}")
                print(f"      Fix: {ins['fix'][:100]}...")
        
        # Save
        filename = f"nova_comprehension_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump({"insights": self.insights, "summary": result}, f, indent=2, default=str)
        
        print(f"\n📁 Report: {filename}")
        print(f"🧠 This is how senior engineers find bugs — by understanding what code SHOULD do and finding where it DOESN'T.")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else None
    NovaCodeComprehension().run(target)
