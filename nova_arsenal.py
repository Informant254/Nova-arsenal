#!/usr/bin/env python3
"""
Nova Arsenal - Main Entry Point
Orchestrates all arsenal modules for bug bounty hunting.
"""

import argparse
import json
import sys
from pathlib import Path

BANNER = r"""
 _   _                      _                                   _
| \ | |  ___ __   __  __ _ | |  ___   __ _  _ __  ___   ___  | |
|  \| | / _ \\ \ / / / _` || | / _ \ / _` || '__|/ __| / _ \ | |
| |\  || (_) |\ V / | (_| || ||  __/| (_| || |   \__ \|  __/ | |
|_| \_| \___/  \_/   \__,_||_| \___| \__,_||_|   |___/ \___| |_|

                     Bug Bounty Arsenal v2.0
         [ Windows Exploits | LLM Jailbreaks | SSRF | Recon ]
"""

def load_scope_map(path="targets_scope_map.json"):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Nova Arsenal — Bug Bounty Toolkit")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("ssrf",         help="Run SSRF scanner across cloud metadata endpoints")
    sub.add_parser("scope",        help="Validate a target against the scope map")
    sub.add_parser("cve",          help="Search local CVE/PoC cache for relevant exploits")
    sub.add_parser("jailbreak",    help="Run LLM jailbreak against an AI endpoint")
    sub.add_parser("recon",        help="Full recon pipeline on a target")
    sub.add_parser("list-modules", help="List all loaded arsenal modules")

    parser.add_argument("--target",  "-t", help="Target host or URL")
    parser.add_argument("--program", "-p", help="Bug bounty program name (from scope map)")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if args.command == "list-modules":
        from modules import list_modules
        list_modules()

    elif args.command == "ssrf":
        from modules.recon.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner(target=args.target, verbose=args.verbose)
        scanner.run()

    elif args.command == "scope":
        if not args.target:
            print("[!] --target required for scope validation")
            sys.exit(1)
        from modules.recon.scope_validator import ScopeValidator
        scope = load_scope_map()
        v = ScopeValidator(scope)
        result = v.check(args.target, program=args.program)
        print(f"[{'✓' if result['in_scope'] else '✗'}] {args.target} — {result['reason']}")

    elif args.command == "cve":
        from modules.cve_watch.cve_monitor import CVEMonitor
        mon = CVEMonitor()
        mon.search_local(keywords=["Defender", "BitLocker", "SYSTEM", "LPE", "TOCTOU"])

    elif args.command == "jailbreak":
        from modules.llm_jailbreak.cka_adapter import CKAAdapter
        adapter = CKAAdapter()
        adapter.run_interactive()

    elif args.command == "recon":
        if not args.target:
            print("[!] --target required for recon")
            sys.exit(1)
        from modules.recon.ssrf_scanner import SSRFScanner
        from modules.recon.scope_validator import ScopeValidator
        scope = load_scope_map()
        print(f"[*] Starting full recon on: {args.target}")
        v = ScopeValidator(scope)
        result = v.check(args.target)
        print(f"    Scope: {'IN-SCOPE' if result['in_scope'] else 'OUT-OF-SCOPE'} — {result['reason']}")
        if result["in_scope"] or args.verbose:
            scanner = SSRFScanner(target=args.target, verbose=args.verbose)
            scanner.run()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
