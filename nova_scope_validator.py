#!/usr/bin/env python3
"""
Nova Arsenal scope validator.
Usage: python3 nova_scope_validator.py <domain>
Exits 0 always; prints IN_SCOPE:<prog>, OUT_OF_SCOPE:<prog>, or UNVERIFIED.
"""
import json, sys, os

domain = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DOMAIN", "")
domain = domain.replace("https://", "").replace("http://", "").split("/")[0].lower()

if not domain:
    print("UNVERIFIED"); sys.exit(0)

try:
    with open("targets_scope_map.json") as f:
        scope = json.load(f)
except Exception as e:
    print(f"UNKNOWN", flush=True)
    print(f"[scope-validator] Could not load targets_scope_map.json: {e}", file=sys.stderr)
    sys.exit(0)

def matches(domain, pattern):
    pattern = pattern.replace("https://","").replace("http://","").lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain == suffix or domain.endswith("." + suffix)
    return domain == pattern or domain.endswith("." + pattern)

for prog_name, prog in scope.get("programs", {}).items():
    if prog.get("authorized") == False:
        continue
    out_scope = prog.get("out_of_scope", [])
    in_scope  = prog.get("in_scope_wildcards", []) + prog.get("in_scope_explicit", [])
    if any(matches(domain, p) for p in out_scope):
        print(f"OUT_OF_SCOPE:{prog_name}"); sys.exit(0)
    if any(matches(domain, p) for p in in_scope):
        print(f"IN_SCOPE:{prog_name}"); sys.exit(0)

print("UNVERIFIED")
