"""
NOVA TOOL DEPENDENCY MANAGER
==============================
Detects missing Kali Linux tools required for a given task,
prompts the user, then installs via apt first, falling back to git clone.

Features:
- Detect missing tools before a scan starts
- Ask user permission before installing
- Try apt-get first, fallback to git clone
- Support pip install where applicable
- Integrate with KaliKnowledgeBase for task-based detection

Usage:
    from nova_tool_dependency_manager import NovaToolDependencyManager

    manager = NovaToolDependencyManager()

    # Check tools needed for a task
    report = manager.check_for_task("web scanning and sql injection")

    # Check a specific list of tools
    report = manager.check_tools(["nmap", "sqlmap", "nikto", "gobuster"])

    # Check and prompt to install missing ones
    manager.ensure_tools(["nmap", "nikto", "gobuster"])

    # Full auto — detect from task, prompt, install
    manager.prepare_for_task("find open ports and scan for web vulnerabilities")
"""

import os
import sys
import shutil
import subprocess
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from nova_kali_knowledge_base import KaliKnowledgeBase, KaliTool
    HAS_KB = True
except ImportError:
    HAS_KB = False
    logger.warning("KaliKnowledgeBase not found — tool metadata will be limited")


# ──────────────────────────────────────────────
# TOOL INSTALLATION REGISTRY
# Maps tool name -> install sources
# ──────────────────────────────────────────────

TOOL_INSTALL_REGISTRY: Dict[str, Dict] = {
    # ── Recon / OSINT ──
    "nmap":          {"apt": "nmap",          "pip": None,           "git": None},
    "masscan":       {"apt": "masscan",        "pip": None,           "git": "https://github.com/robertdavidgraham/masscan"},
    "whois":         {"apt": "whois",          "pip": None,           "git": None},
    "dig":           {"apt": "dnsutils",       "pip": None,           "git": None},
    "nslookup":      {"apt": "dnsutils",       "pip": None,           "git": None},
    "dnsrecon":      {"apt": "dnsrecon",       "pip": "dnsrecon",     "git": "https://github.com/darkoperator/dnsrecon"},
    "dnsenum":       {"apt": "dnsenum",        "pip": None,           "git": "https://github.com/fwaeytens/dnsenum"},
    "theHarvester":  {"apt": "theharvester",   "pip": None,           "git": "https://github.com/laramies/theHarvester"},
    "amass":         {"apt": "amass",          "pip": None,           "git": "https://github.com/owasp-amass/amass"},
    "sublist3r":     {"apt": "sublist3r",      "pip": "sublist3r",    "git": "https://github.com/aboul3la/Sublist3r"},
    "recon-ng":      {"apt": "recon-ng",       "pip": None,           "git": "https://github.com/lanmaster53/recon-ng"},
    "shodan":        {"apt": None,             "pip": "shodan",       "git": None},
    "maltego":       {"apt": "maltego",        "pip": None,           "git": None},

    # ── Scanning ──
    "netdiscover":   {"apt": "netdiscover",    "pip": None,           "git": None},
    "arp-scan":      {"apt": "arp-scan",       "pip": None,           "git": None},
    "hping3":        {"apt": "hping3",         "pip": None,           "git": None},

    # ── Web ──
    "nikto":         {"apt": "nikto",          "pip": None,           "git": "https://github.com/sullo/nikto"},
    "gobuster":      {"apt": "gobuster",       "pip": None,           "git": "https://github.com/OJ/gobuster"},
    "dirb":          {"apt": "dirb",           "pip": None,           "git": None},
    "wfuzz":         {"apt": "wfuzz",          "pip": "wfuzz",        "git": "https://github.com/xmendez/wfuzz"},
    "ffuf":          {"apt": "ffuf",           "pip": None,           "git": "https://github.com/ffuf/ffuf"},
    "sqlmap":        {"apt": "sqlmap",         "pip": None,           "git": "https://github.com/sqlmapproject/sqlmap"},
    "whatweb":       {"apt": "whatweb",        "pip": None,           "git": "https://github.com/urbanadventurer/WhatWeb"},
    "wafw00f":       {"apt": "wafw00f",        "pip": "wafw00f",      "git": "https://github.com/EnableSecurity/wafw00f"},
    "commix":        {"apt": "commix",         "pip": None,           "git": "https://github.com/commixproject/commix"},
    "xsser":         {"apt": "xsser",          "pip": None,           "git": "https://github.com/epsylon/xsser"},
    "burpsuite":     {"apt": "burpsuite",      "pip": None,           "git": None},
    "zaproxy":       {"apt": "zaproxy",        "pip": None,           "git": None},

    # ── Password ──
    "hydra":         {"apt": "hydra",          "pip": None,           "git": "https://github.com/vanhauser-thc/thc-hydra"},
    "john":          {"apt": "john",           "pip": None,           "git": "https://github.com/openwall/john"},
    "hashcat":       {"apt": "hashcat",        "pip": None,           "git": "https://github.com/hashcat/hashcat"},
    "medusa":        {"apt": "medusa",         "pip": None,           "git": None},
    "hashid":        {"apt": "hashid",         "pip": "hashid",       "git": "https://github.com/psypanda/hashID"},
    "crunch":        {"apt": "crunch",         "pip": None,           "git": None},
    "cewl":          {"apt": "cewl",           "pip": None,           "git": "https://github.com/digininja/CeWL"},

    # ── Wireless ──
    "aircrack-ng":   {"apt": "aircrack-ng",    "pip": None,           "git": "https://github.com/aircrack-ng/aircrack-ng"},
    "airodump-ng":   {"apt": "aircrack-ng",    "pip": None,           "git": None},
    "airmon-ng":     {"apt": "aircrack-ng",    "pip": None,           "git": None},
    "wifite":        {"apt": "wifite",         "pip": None,           "git": "https://github.com/derv82/wifite2"},

    # ── Exploitation ──
    "msfconsole":    {"apt": "metasploit-framework", "pip": None,     "git": None},
    "metasploit":    {"apt": "metasploit-framework", "pip": None,     "git": None},
    "msfvenom":      {"apt": "metasploit-framework", "pip": None,     "git": None},
    "searchsploit":  {"apt": "exploitdb",      "pip": None,           "git": "https://github.com/offensive-security/exploitdb"},
    "beef-xss":      {"apt": "beef-xss",       "pip": None,           "git": "https://github.com/beefproject/beef"},

    # ── Post-Exploitation ──
    "netcat":        {"apt": "netcat-openbsd", "pip": None,           "git": None},
    "nc":            {"apt": "netcat-openbsd", "pip": None,           "git": None},
    "socat":         {"apt": "socat",          "pip": None,           "git": None},
    "linpeas":       {"apt": None,             "pip": None,           "git": "https://github.com/carlospolop/PEASS-ng"},
    "winpeas":       {"apt": None,             "pip": None,           "git": "https://github.com/carlospolop/PEASS-ng"},
    "mimikatz":      {"apt": None,             "pip": None,           "git": "https://github.com/gentilkiwi/mimikatz"},

    # ── Sniffing ──
    "wireshark":     {"apt": "wireshark",      "pip": None,           "git": None},
    "tshark":        {"apt": "tshark",         "pip": None,           "git": None},
    "tcpdump":       {"apt": "tcpdump",        "pip": None,           "git": None},
    "ettercap":      {"apt": "ettercap-text-only", "pip": None,       "git": None},

    # ── Forensics ──
    "binwalk":       {"apt": "binwalk",        "pip": "binwalk",      "git": "https://github.com/ReFirmLabs/binwalk"},
    "volatility":    {"apt": "volatility",     "pip": None,           "git": "https://github.com/volatilityfoundation/volatility3"},
    "autopsy":       {"apt": "autopsy",        "pip": None,           "git": None},
    "foremost":      {"apt": "foremost",       "pip": None,           "git": None},
    "strings":       {"apt": "binutils",       "pip": None,           "git": None},
    "strace":        {"apt": "strace",         "pip": None,           "git": None},

    # ── Reverse Engineering ──
    "gdb":           {"apt": "gdb",            "pip": None,           "git": None},
    "radare2":       {"apt": "radare2",        "pip": None,           "git": "https://github.com/radareorg/radare2"},
    "ghidra":        {"apt": None,             "pip": None,           "git": "https://github.com/NationalSecurityAgency/ghidra"},
    "pwndbg":        {"apt": None,             "pip": None,           "git": "https://github.com/pwndbg/pwndbg"},

    # ── Vuln Analysis ──
    "openvas":       {"apt": "openvas",        "pip": None,           "git": None},
    "gvm":           {"apt": "gvm",            "pip": None,           "git": None},
    "lynis":         {"apt": "lynis",          "pip": None,           "git": "https://github.com/CISOfy/lynis"},

    # ── Social Engineering ──
    "setoolkit":     {"apt": "set",            "pip": None,           "git": "https://github.com/trustedsec/social-engineer-toolkit"},

    # ── Utilities ──
    "curl":          {"apt": "curl",           "pip": None,           "git": None},
    "wget":          {"apt": "wget",           "pip": None,           "git": None},
    "git":           {"apt": "git",            "pip": None,           "git": None},
    "python3":       {"apt": "python3",        "pip": None,           "git": None},
    "pip":           {"apt": "python3-pip",    "pip": None,           "git": None},
    "pip3":          {"apt": "python3-pip",    "pip": None,           "git": None},
    "tmux":          {"apt": "tmux",           "pip": None,           "git": None},
    "screen":        {"apt": "screen",         "pip": None,           "git": None},
    "proxychains":   {"apt": "proxychains4",   "pip": None,           "git": None},
    "tor":           {"apt": "tor",            "pip": None,           "git": None},
}


# ──────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────

@dataclass
class ToolStatus:
    name: str
    is_installed: bool
    install_path: Optional[str] = None
    apt_package: Optional[str] = None
    pip_package: Optional[str] = None
    git_url: Optional[str] = None
    install_method_used: Optional[str] = None
    install_success: Optional[bool] = None
    install_error: Optional[str] = None
    checked_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class DependencyReport:
    task_description: str
    tools_checked: List[str]
    installed: List[ToolStatus]
    missing: List[ToolStatus]
    installed_now: List[ToolStatus]
    failed: List[ToolStatus]
    skipped: List[ToolStatus]
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def all_ready(self) -> bool:
        return len(self.missing) == 0 and len(self.failed) == 0

    def summary(self) -> str:
        lines = [
            f"Task       : {self.task_description}",
            f"Checked    : {len(self.tools_checked)} tools",
            f"Installed  : {len(self.installed)} already available",
            f"Missing    : {len(self.missing)} not found",
            f"Installed now: {len(self.installed_now)} just installed",
            f"Failed     : {len(self.failed)} failed to install",
            f"Skipped    : {len(self.skipped)} skipped by user",
            f"Ready      : {'YES' if self.all_ready else 'NO — some tools unavailable'}",
        ]
        return "\n".join(lines)


# ──────────────────────────────────────────────
# INSTALLER
# ──────────────────────────────────────────────

class ToolInstaller:
    """
    Handles installation of tools.
    Strategy: apt first → pip fallback → git clone fallback.
    """

    def __init__(self, clone_dir: str = "/opt/nova-tools"):
        self.clone_dir = clone_dir
        os.makedirs(clone_dir, exist_ok=True)

    def install(self, status: ToolStatus, verbose: bool = True) -> ToolStatus:
        """
        Attempt to install a tool.
        Tries apt → pip → git clone in order.
        """
        # Try apt first
        if status.apt_package:
            success, error = self._apt_install(status.apt_package, verbose)
            if success:
                status.install_method_used = "apt"
                status.install_success = True
                status.is_installed = True
                return status
            else:
                if verbose:
                    print(f"  [!] apt failed: {error}")

        # Try pip
        if status.pip_package:
            success, error = self._pip_install(status.pip_package, verbose)
            if success:
                status.install_method_used = "pip"
                status.install_success = True
                status.is_installed = True
                return status
            else:
                if verbose:
                    print(f"  [!] pip failed: {error}")

        # Try git clone
        if status.git_url:
            success, error = self._git_clone(status.name, status.git_url, verbose)
            if success:
                status.install_method_used = "git"
                status.install_success = True
                status.is_installed = True
                return status
            else:
                if verbose:
                    print(f"  [!] git clone failed: {error}")

        # All methods failed
        status.install_success = False
        status.install_error = "All installation methods failed"
        return status

    def _apt_install(self, package: str, verbose: bool) -> Tuple[bool, str]:
        if verbose:
            print(f"  [*] Trying: apt-get install -y {package}")
        try:
            result = subprocess.run(
                ["apt-get", "install", "-y", package],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                if verbose:
                    print(f"  [+] apt install successful: {package}")
                return True, ""
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "apt install timed out"
        except FileNotFoundError:
            return False, "apt-get not found (not on Debian/Kali)"
        except Exception as e:
            return False, str(e)

    def _pip_install(self, package: str, verbose: bool) -> Tuple[bool, str]:
        if verbose:
            print(f"  [*] Trying: pip install {package}")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package,
                 "--break-system-packages", "--quiet"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                if verbose:
                    print(f"  [+] pip install successful: {package}")
                return True, ""
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "pip install timed out"
        except Exception as e:
            return False, str(e)

    def _git_clone(self, tool_name: str, git_url: str, verbose: bool) -> Tuple[bool, str]:
        dest = os.path.join(self.clone_dir, tool_name)
        if os.path.exists(dest):
            if verbose:
                print(f"  [+] Already cloned at {dest} — pulling latest")
            try:
                result = subprocess.run(
                    ["git", "-C", dest, "pull"],
                    capture_output=True, text=True, timeout=120
                )
                return result.returncode == 0, result.stderr.strip()
            except Exception as e:
                return False, str(e)

        if verbose:
            print(f"  [*] Trying: git clone {git_url} -> {dest}")
        try:
            result = subprocess.run(
                ["git", "clone", git_url, dest],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                if verbose:
                    print(f"  [+] Cloned to {dest}")
                return True, ""
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "git clone timed out"
        except FileNotFoundError:
            return False, "git not found — install git first"
        except Exception as e:
            return False, str(e)


# ──────────────────────────────────────────────
# DEPENDENCY MANAGER — Main Class
# ──────────────────────────────────────────────

class NovaToolDependencyManager:
    """
    Detects missing Kali tools, prompts user, and installs them.

    Strategy:
    1. Check if tool binary exists (shutil.which)
    2. If missing — show user and ask permission
    3. Try apt-get install first
    4. Fallback to git clone
    5. Fallback to pip where applicable

    Example:
        manager = NovaToolDependencyManager()

        # Check tools for a task and auto-handle
        manager.prepare_for_task("web scanning and directory enumeration")

        # Or check specific tools
        manager.ensure_tools(["nmap", "gobuster", "nikto"])
    """

    def __init__(
        self,
        clone_dir: str = "/opt/nova-tools",
        auto_update_apt: bool = False,
        verbose: bool = True
    ):
        self.verbose = verbose
        self.auto_update_apt = auto_update_apt
        self.installer = ToolInstaller(clone_dir=clone_dir)

        if HAS_KB:
            self.kb = KaliKnowledgeBase()
        else:
            self.kb = None

        self._checked_cache: Dict[str, ToolStatus] = {}

        if auto_update_apt:
            self._apt_update()

    # ── Public API ────────────────────────────

    def check_tool(self, tool_name: str) -> ToolStatus:
        """Check if a single tool is installed"""
        if tool_name in self._checked_cache:
            return self._checked_cache[tool_name]

        registry = TOOL_INSTALL_REGISTRY.get(tool_name, {})
        path = shutil.which(tool_name)

        # Also check clone directory
        clone_path = os.path.join(self.installer.clone_dir, tool_name)
        if not path and os.path.exists(clone_path):
            path = clone_path

        status = ToolStatus(
            name=tool_name,
            is_installed=path is not None,
            install_path=path,
            apt_package=registry.get("apt"),
            pip_package=registry.get("pip"),
            git_url=registry.get("git"),
        )

        self._checked_cache[tool_name] = status
        return status

    def check_tools(self, tool_names: List[str]) -> DependencyReport:
        """Check multiple tools and return a dependency report"""
        installed = []
        missing = []

        for name in tool_names:
            status = self.check_tool(name)
            if status.is_installed:
                installed.append(status)
            else:
                missing.append(status)

        return DependencyReport(
            task_description="manual check",
            tools_checked=tool_names,
            installed=installed,
            missing=missing,
            installed_now=[],
            failed=[],
            skipped=[]
        )

    def check_for_task(self, task_description: str) -> DependencyReport:
        """
        Detect which tools are needed for a task and check if they're installed.
        Uses KaliKnowledgeBase to recommend tools for the task.
        """
        tool_names = self._tools_for_task(task_description)

        if self.verbose:
            print(f"\n[*] Task: '{task_description}'")
            print(f"[*] Tools identified: {', '.join(tool_names)}")

        report = self.check_tools(tool_names)
        report.task_description = task_description
        return report

    def ensure_tools(self, tool_names: List[str]) -> DependencyReport:
        """
        Check tools, prompt user for missing ones, install approved ones.
        This is the main method to call before running a scan.
        """
        report = self.check_tools(tool_names)
        report = self._handle_missing(report)
        return report

    def prepare_for_task(self, task_description: str) -> DependencyReport:
        """
        Full pipeline:
        1. Identify tools needed for task
        2. Check which are missing
        3. Prompt user
        4. Install approved ones

        Returns final DependencyReport.
        """
        report = self.check_for_task(task_description)

        if not report.missing:
            if self.verbose:
                print(f"[+] All {len(report.installed)} tools already installed. Ready to go!")
            return report

        report = self._handle_missing(report)
        return report

    def print_report(self, report: DependencyReport):
        """Print a formatted dependency report"""
        print("\n" + "=" * 55)
        print("NOVA TOOL DEPENDENCY REPORT")
        print("=" * 55)
        print(report.summary())

        if report.installed:
            print(f"\n✓ AVAILABLE ({len(report.installed)}):")
            for s in report.installed:
                path = s.install_path or "in PATH"
                print(f"  {s.name:<20} {path}")

        if report.installed_now:
            print(f"\n↓ JUST INSTALLED ({len(report.installed_now)}):")
            for s in report.installed_now:
                print(f"  {s.name:<20} via {s.install_method_used}")

        if report.failed:
            print(f"\n✗ FAILED TO INSTALL ({len(report.failed)}):")
            for s in report.failed:
                print(f"  {s.name:<20} {s.install_error or 'unknown error'}")
                if s.git_url:
                    print(f"  {'':20} Manual: git clone {s.git_url}")

        if report.skipped:
            print(f"\n⊘ SKIPPED BY USER ({len(report.skipped)}):")
            for s in report.skipped:
                print(f"  {s.name}")
                if s.git_url:
                    print(f"  {'':>4}Manual clone: git clone {s.git_url}")
                elif s.apt_package:
                    print(f"  {'':>4}Manual install: apt-get install {s.apt_package}")

        print("=" * 55)

    # ── Internal ──────────────────────────────

    def _tools_for_task(self, task_description: str) -> List[str]:
        """Determine which tools are needed for a task"""
        tools = []

        if self.kb:
            recommended = self.kb.recommend(task_description)
            tools = [t.name for t in recommended]

        # Keyword-based fallback / augmentation
        task_lower = task_description.lower()
        keyword_map = {
            "port":          ["nmap", "masscan"],
            "scan":          ["nmap"],
            "web":           ["nikto", "gobuster", "whatweb"],
            "directory":     ["gobuster", "dirb", "ffuf"],
            "fuzz":          ["wfuzz", "ffuf"],
            "sql":           ["sqlmap"],
            "sqli":          ["sqlmap"],
            "xss":           ["xsser"],
            "password":      ["hydra", "john", "hashcat"],
            "crack":         ["john", "hashcat"],
            "brute":         ["hydra", "medusa"],
            "hash":          ["hashid", "john", "hashcat"],
            "subdomain":     ["sublist3r", "amass", "dnsrecon"],
            "dns":           ["dig", "dnsrecon", "dnsenum"],
            "osint":         ["theHarvester", "recon-ng", "shodan"],
            "wireless":      ["aircrack-ng", "airodump-ng", "wifite"],
            "wifi":          ["aircrack-ng", "airodump-ng", "wifite"],
            "sniff":         ["wireshark", "tcpdump"],
            "packet":        ["wireshark", "tcpdump"],
            "mitm":          ["ettercap"],
            "exploit":       ["metasploit", "searchsploit"],
            "payload":       ["msfvenom"],
            "reverse shell": ["netcat", "socat"],
            "privesc":       ["linpeas"],
            "forensic":      ["binwalk", "volatility"],
            "memory":        ["volatility"],
            "recon":         ["whois", "dig", "theHarvester"],
            "vuln":          ["openvas", "nmap"],
        }

        for keyword, kw_tools in keyword_map.items():
            if keyword in task_lower:
                for t in kw_tools:
                    if t not in tools:
                        tools.append(t)

        return list(dict.fromkeys(tools))  # Deduplicate while preserving order

    def _handle_missing(self, report: DependencyReport) -> DependencyReport:
        """Prompt user about missing tools and install approved ones"""
        if not report.missing:
            return report

        print(f"\n[!] {len(report.missing)} required tool(s) are missing:\n")

        for i, status in enumerate(report.missing, 1):
            install_opts = []
            if status.apt_package:
                install_opts.append(f"apt: {status.apt_package}")
            if status.pip_package:
                install_opts.append(f"pip: {status.pip_package}")
            if status.git_url:
                install_opts.append(f"git: {status.git_url}")

            opts_str = " | ".join(install_opts) if install_opts else "No auto-install available"
            print(f"  {i}. {status.name:<20} [{opts_str}]")

        print()

        # Ask how to handle missing tools
        choice = self._prompt_install_choice(report.missing)

        if choice == "all":
            to_install = report.missing
            to_skip = []
        elif choice == "none":
            to_install = []
            to_skip = report.missing
        elif choice == "select":
            to_install, to_skip = self._prompt_select(report.missing)
        else:
            to_install = []
            to_skip = report.missing

        # Install approved tools
        for status in to_install:
            print(f"\n[*] Installing: {status.name}")
            updated = self.installer.install(status, verbose=self.verbose)
            # Invalidate cache
            self._checked_cache.pop(status.name, None)

            if updated.install_success:
                report.installed_now.append(updated)
            else:
                report.failed.append(updated)

        report.skipped.extend(to_skip)
        report.missing = [
            s for s in report.missing
            if s not in to_install and s not in to_skip
        ]

        return report

    def _prompt_install_choice(self, missing: List[ToolStatus]) -> str:
        """Prompt user to choose install strategy"""
        print("How would you like to handle missing tools?")
        print("  [1] Install all missing tools")
        print("  [2] Let me choose which ones to install")
        print("  [3] Skip all — I'll install manually")
        print()

        while True:
            try:
                choice = input("Enter choice [1/2/3]: ").strip()
                if choice == "1":
                    return "all"
                elif choice == "2":
                    return "select"
                elif choice == "3":
                    return "none"
                else:
                    print("  Please enter 1, 2, or 3")
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Skipping all installations")
                return "none"

    def _prompt_select(
        self, missing: List[ToolStatus]
    ) -> Tuple[List[ToolStatus], List[ToolStatus]]:
        """Let user select which tools to install"""
        to_install = []
        to_skip = []

        print()
        for status in missing:
            try:
                answer = input(f"  Install '{status.name}'? [y/N]: ").strip().lower()
                if answer in ("y", "yes"):
                    to_install.append(status)
                else:
                    to_skip.append(status)
            except (EOFError, KeyboardInterrupt):
                to_skip.append(status)

        return to_install, to_skip

    def _apt_update(self):
        """Run apt-get update before installing"""
        if self.verbose:
            print("[*] Running apt-get update...")
        try:
            subprocess.run(
                ["apt-get", "update", "-qq"],
                capture_output=True, timeout=60
            )
        except Exception:
            pass


# ──────────────────────────────────────────────
# INTEGRATION HELPER
# ──────────────────────────────────────────────

def attach_dependency_manager(agent, **kwargs) -> NovaToolDependencyManager:
    """
    Attach the dependency manager to an existing NovaKaliAgent.

    Usage:
        from nova_tool_dependency_manager import attach_dependency_manager
        dep_manager = attach_dependency_manager(nova)

        # Before running a task
        dep_manager.prepare_for_task(nova.current_task)
    """
    manager = NovaToolDependencyManager(**kwargs)
    agent.dependency_manager = manager
    return manager


# ──────────────────────────────────────────────
# DEMO
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("NOVA TOOL DEPENDENCY MANAGER — DEMO")
    print("=" * 55)

    manager = NovaToolDependencyManager(verbose=True)

    # Demo 1: Check specific tools
    print("\n[1] Checking common tools...")
    report = manager.check_tools(["nmap", "whois", "dig", "gobuster", "sqlmap", "nikto"])
    manager.print_report(report)

    # Demo 2: Task-based detection
    print("\n[2] Task-based tool detection...")
    report2 = manager.check_for_task("web directory enumeration and sql injection testing")
    print(f"\nTools identified for task: {report2.tools_checked}")
    print(f"Installed: {[s.name for s in report2.installed]}")
    print(f"Missing:   {[s.name for s in report2.missing]}")

    # Demo 3: Show what prepare_for_task would do
    print("\n[3] Integration example:")
    print("""
    from nova_tool_dependency_manager import NovaToolDependencyManager

    manager = NovaToolDependencyManager()

    # Before any scan — checks and installs what's needed
    report = manager.prepare_for_task("find open ports and scan for web vulnerabilities")

    if report.all_ready:
        print("All tools ready — starting scan")
        optimizer.run_parallel(commands, target)
    else:
        print(f"Warning: {len(report.failed)} tools unavailable")
    """)

    print("\nAttach to Nova agent:")
    print("  from nova_tool_dependency_manager import attach_dependency_manager")
    print("  dep_manager = attach_dependency_manager(nova)")
    print("  dep_manager.prepare_for_task(task_description)")
