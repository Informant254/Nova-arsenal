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

                     Bug Bounty Arsenal v2.2
  [ Windows Exploits | LLM Jailbreaks | SSRF | Recon | Cracking | SMB ]
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

    # ── crack ──────────────────────────────────────────────────
    crack_p = sub.add_parser("crack", help="Password cracking chain (hashcat + impacket + kerbrute)")
    crack_p.add_argument("--hashcat",    metavar="FILE",  help="Crack a hash file with hashcat")
    crack_p.add_argument("--type",       metavar="TYPE",  default="ntlm",
                         help="Hash type: ntlm|ntlmv2|md5|sha1|sha256|sha512|bcrypt|kerberoast|asreproast|wpa2 (default: ntlm)")
    crack_p.add_argument("--wordlist",   metavar="FILE",  help="Custom wordlist (default: rockyou from SecLists)")
    crack_p.add_argument("--mask",       metavar="MASK",  help="Brute-force mask e.g. ?u?l?l?l?d?d")
    crack_p.add_argument("--kerberoast", action="store_true", help="Run impacket Kerberoast against AD")
    crack_p.add_argument("--asreproast", action="store_true", help="Run AS-REP Roast (no creds needed)")
    crack_p.add_argument("--enum",       action="store_true", help="Kerbrute username enumeration")
    crack_p.add_argument("--spray",      metavar="PASS",  help="Kerbrute password spray with this password")
    crack_p.add_argument("--chain",      action="store_true", help="Full AD chain: enum → AS-REP roast → crack")
    crack_p.add_argument("--modes",      action="store_true", help="List all supported hash types")
    crack_p.add_argument("--wordlists",  action="store_true", help="List available SecLists wordlists")
    crack_p.add_argument("--smb",        metavar="TARGET", help="Validate cracked creds against SMB target, auto-dump if admin")
    crack_p.add_argument("--cracked",    metavar="FILE",  help="Hashcat outfile to validate (used with --smb)")
    crack_p.add_argument("--domain",  "-d", metavar="DOMAIN", help="AD domain (e.g. corp.local)")
    crack_p.add_argument("--dc",         metavar="IP",    help="Domain controller IP")
    crack_p.add_argument("--user",    "-u", metavar="USER", help="AD username for authenticated attacks")
    crack_p.add_argument("--password","-P", metavar="PASS", help="AD password for authenticated attacks")
    crack_p.add_argument("--hashes",  "-H", metavar="HASH", help="NTLM hash for pass-the-hash (--smb)")
    crack_p.add_argument("--userlist","-U", metavar="FILE", help="User list file for enum/spray/asreproast")
    crack_p.add_argument("--sam",        action="store_true", help="Dump SAM hashes after SMB auth")
    crack_p.add_argument("--lsa",        action="store_true", help="Dump LSA secrets after SMB auth")
    crack_p.add_argument("--ntds",       action="store_true", help="DCSync NTDS.dit (domain admin required)")

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

    elif args.command == "crack":
        from modules.crack.crack_chain import CrackChain
        cc = CrackChain(verbose=args.verbose)

        if args.modes:
            cc.show_modes()

        elif args.wordlists:
            cc.list_wordlists()

        elif args.smb:
            from modules.crack.smb_validator import SMBValidator
            smb = SMBValidator(verbose=args.verbose)
            target = args.smb

            if args.cracked:
                # Validate every cracked hash:plaintext pair
                smb.validate_cracked_file(args.cracked, target, domain=args.domain or "")
            elif args.ntds:
                if not args.user:
                    print("[!] --user required for --ntds")
                    sys.exit(1)
                smb.dump_ntds(target, args.user, args.password or "",
                              args.hashes or "", args.domain or "")
            elif args.sam:
                if not args.user:
                    print("[!] --user required for --sam")
                    sys.exit(1)
                smb.dump_sam(target, args.user, args.password or "",
                             args.hashes or "", args.domain or "")
            elif args.lsa:
                if not args.user:
                    print("[!] --user required for --lsa")
                    sys.exit(1)
                smb.dump_lsa(target, args.user, args.password or "",
                             args.hashes or "", args.domain or "")
            else:
                # Auto chain: validate → dump if admin
                if not args.user:
                    print("[!] --user required for --smb")
                    sys.exit(1)
                smb.auto_chain(target, args.user, args.password or "",
                               args.hashes or "", args.domain or "")

        elif args.chain:
            if not args.domain or not args.dc:
                print("[!] --domain and --dc required for --chain")
                sys.exit(1)
            cc.full_ad_chain(args.domain, args.dc, args.userlist)

        elif args.hashcat:
            cc.crack_hashcat(args.hashcat, hash_type=args.type,
                             wordlist=args.wordlist, brute=args.mask)

        elif args.kerberoast:
            if not all([args.domain, args.dc, args.user, args.password]):
                print("[!] --domain, --dc, --user, --password required for --kerberoast")
                sys.exit(1)
            cc.kerberoast(args.domain, args.user, args.password, args.dc)

        elif args.asreproast:
            if not all([args.domain, args.dc]):
                print("[!] --domain and --dc required for --asreproast")
                sys.exit(1)
            cc.asrep_roast(args.domain, args.dc, args.userlist or "users.txt")

        elif args.enum:
            if not all([args.domain, args.dc]):
                print("[!] --domain and --dc required for --enum")
                sys.exit(1)
            cc.kerbrute_enum(args.domain, args.dc, args.userlist)

        elif args.spray:
            if not all([args.domain, args.dc, args.userlist]):
                print("[!] --domain, --dc, --userlist required for --spray")
                sys.exit(1)
            cc.kerbrute_spray(args.domain, args.dc, args.userlist, args.spray)

        else:
            crack_p.print_help()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
