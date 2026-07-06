"""
Kali Blueprint - Complete knowledge base of Kali Linux.

Every tool, path, config, service, attack pattern, NSE script category,
Metasploit module, wordlist, and tool combination mapped.
The agent uses this to know exactly what's available and how to use it.
"""

import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class ToolInfo:
    """Complete information about a Kali tool."""
    name: str
    category: str
    description: str
    install_path: str
    binary: str
    usage: str
    examples: List[str]
    flags: Dict[str, str]
    depends_on: List[str] = field(default_factory=list)
    man_page: str = ""
    config_files: List[str] = field(default_factory=list)
    output_formats: List[str] = field(default_factory=list)
    tool_combos: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class ServiceInfo:
    """Information about a system service."""
    name: str
    port: int
    protocol: str
    config_path: str
    log_path: str
    start_cmd: str
    stop_cmd: str
    status_cmd: str
    description: str
    default_creds: List[str] = field(default_factory=list)
    common_vulns: List[str] = field(default_factory=list)


@dataclass
class PathInfo:
    """Information about a filesystem path."""
    path: str
    description: str
    permissions: str
    owner: str
    contents: List[str] = field(default_factory=list)


@dataclass
class NSEScript:
    """Nmap NSE script information."""
    name: str
    category: str
    description: str
    usage: str
    example: str


@dataclass
class MetasploitModule:
    """Metasploit module information."""
    name: str
    path: str
    description: str
    platform: str
    options: Dict[str, str] = field(default_factory=dict)
    payload: str = ""


@dataclass
class Wordlist:
    """Wordlist information."""
    name: str
    path: str
    description: str
    size: str
    use_cases: List[str] = field(default_factory=list)


class KaliBlueprint:
    """
    Complete knowledge base of Kali Linux.

    The agent uses this to:
    - Know every installed tool and how to use it
    - Navigate the filesystem
    - Understand service configurations
    - Chain tools together for complex attacks
    - Write custom scripts when needed
    - Know which NSE scripts to use
    - Know which Metasploit modules to use
    - Know which wordlists to use
    - Discover what's actually installed on the system
    """

    def __init__(self) -> None:
        self.tools: Dict[str, ToolInfo] = {}
        self.services: Dict[str, ServiceInfo] = {}
        self.paths: Dict[str, PathInfo] = {}
        self.tool_categories: Dict[str, List[str]] = {}
        self.attack_chains: Dict[str, List[str]] = {}
        self.nse_scripts: Dict[str, NSEScript] = {}
        self.metasploit_modules: Dict[str, MetasploitModule] = {}
        self.wordlists: Dict[str, Wordlist] = {}
        self._installed_cache: Optional[Set[str]] = None
        self._build_blueprint()

    def _build_blueprint(self) -> None:
        """Build the complete Kali knowledge base."""
        self._register_tools_from_data()
        self._register_services()
        self._register_filesystem()
        self._register_nse_scripts()
        self._register_metasploit_modules()
        self._register_wordlists()
        self._register_attack_chains()

    # ── Load tools from external data ─────────────────────────────────────

    def _register_tools_from_data(self) -> None:
        """Import and register all tools from kali_tools_data and kali_tools_extended."""
        from nova_arsenal.kali_tools_data import (
            RECON_TOOLS, WEB_TOOLS, NETWORK_TOOLS, EXPLOITATION_TOOLS,
            PASSWORD_TOOLS, FORENSICS_TOOLS, WIRELESS_TOOLS,
            REVERSE_ENGINEERING_TOOLS, SNIFFING_SPOOFING_TOOLS,
            POST_EXPLOIT_TOOLS, STEGANOGRAPHY_TOOLS, TOOL_COMBINATIONS,
        )
        from nova_arsenal.kali_tools_extended import (
            MOBILE_TOOLS, CLOUD_TOOLS, AD_TOOLS, C2_TOOLS, API_FUZZING_TOOLS,
            CODE_ANALYSIS_TOOLS, CONTAINER_TOOLS, SOCIAL_ENGINEERING_TOOLS,
            FUZZING_TOOLS, IOT_SCADA_TOOLS, BLUETOOTH_TOOLS,
            REVERSE_ENGINEERING_EXTRA, LOG_FORENSICS_TOOLS, ANONYMITY_TOOLS,
            EXPLOIT_DEV_TOOLS, AI_SECURITY_TOOLS, HARDWARE_TOOLS, VEHICLE_TOOLS,
        )
        all_tools = (
            RECON_TOOLS + WEB_TOOLS + NETWORK_TOOLS + EXPLOITATION_TOOLS +
            PASSWORD_TOOLS + FORENSICS_TOOLS + WIRELESS_TOOLS +
            REVERSE_ENGINEERING_TOOLS + SNIFFING_SPOOFING_TOOLS +
            POST_EXPLOIT_TOOLS + STEGANOGRAPHY_TOOLS +
            MOBILE_TOOLS + CLOUD_TOOLS + AD_TOOLS + C2_TOOLS +
            API_FUZZING_TOOLS + CODE_ANALYSIS_TOOLS + CONTAINER_TOOLS +
            SOCIAL_ENGINEERING_TOOLS + FUZZING_TOOLS + IOT_SCADA_TOOLS +
            BLUETOOTH_TOOLS + REVERSE_ENGINEERING_EXTRA + LOG_FORENSICS_TOOLS +
            ANONYMITY_TOOLS + EXPLOIT_DEV_TOOLS + AI_SECURITY_TOOLS +
            HARDWARE_TOOLS + VEHICLE_TOOLS
        )
        self._add_tools(all_tools)
        self._tool_combos_data = TOOL_COMBINATIONS

    # ── Services ──────────────────────────────────────────────────────────

    def _register_services(self) -> None:
        self.services = {
            "ssh": ServiceInfo("sshd", 22, "tcp", "/etc/ssh/sshd_config", "/var/log/auth.log", "systemctl start ssh", "systemctl stop ssh", "systemctl status ssh", "OpenSSH server", ["root:toor", "kali:kali", "admin:admin"], ["Weak ciphers", "Root login enabled", "Password auth"]),
            "apache": ServiceInfo("apache2", 80, "tcp", "/etc/apache2/", "/var/log/apache2/", "systemctl start apache2", "systemctl stop apache2", "systemctl status apache2", "Apache HTTP server", [], ["Default page", "Directory listing", "Server info disclosure"]),
            "nginx": ServiceInfo("nginx", 80, "tcp", "/etc/nginx/", "/var/log/nginx/", "systemctl start nginx", "systemctl stop nginx", "systemctl status nginx", "Nginx web server"),
            "mysql": ServiceInfo("mysql", 3306, "tcp", "/etc/mysql/", "/var/log/mysql/", "systemctl start mysql", "systemctl stop mysql", "systemctl status mysql", "MySQL database server", ["root:root", "root:password", "admin:admin"], ["Empty root password", "Remote root login"]),
            "postgresql": ServiceInfo("postgresql", 5432, "tcp", "/etc/postgresql/", "/var/log/postgresql/", "systemctl start postgresql", "systemctl stop postgresql", "systemctl status postgresql", "PostgreSQL database server", ["postgres:postgres"]),
            "smb": ServiceInfo("smbd", 445, "tcp", "/etc/samba/smb.conf", "/var/log/samba/", "systemctl start smbd", "systemctl stop smbd", "systemctl status smbd", "SMB/CIFS file sharing", ["admin:admin", "guest:guest", "administrator:administrator"], ["Null session", "Anonymous access", "SMBv1 enabled"]),
            "ftp": ServiceInfo("vsftpd", 21, "tcp", "/etc/vsftpd.conf", "/var/log/vsftpd.log", "systemctl start vsftpd", "systemctl stop vsftpd", "systemctl status vsftpd", "FTP server", ["anonymous:anonymous", "ftp:ftp"], ["Anonymous login", "Weak credentials"]),
            "rdp": ServiceInfo("xrdp", 3389, "tcp", "/etc/xrdp/", "/var/log/xrdp.log", "systemctl start xrdp", "systemctl stop xrdp", "systemctl status xrdp", "Remote Desktop Protocol", [], ["Weak password", "NLA disabled"]),
            "telnet": ServiceInfo("telnetd", 23, "tcp", "/etc/inetd.conf", "/var/log/syslog", "systemctl start inetd", "systemctl stop inetd", "systemctl status inetd", "Telnet server", [], ["Cleartext credentials"]),
            "snmp": ServiceInfo("snmpd", 161, "udp", "/etc/snmp/snmpd.conf", "/var/log/syslog", "systemctl start snmpd", "systemctl stop snmpd", "systemctl status snmpd", "SNMP agent", ["public:public", "private:private"], ["Default community strings", "SNMPv1/v2c no encryption"]),
            "dns": ServiceInfo("named", 53, "tcp/udp", "/etc/bind/", "/var/log/syslog", "systemctl start named", "systemctl stop named", "systemctl status named", "DNS server (BIND)", [], ["Zone transfer allowed", "Open recursion"]),
            "ldap": ServiceInfo("slapd", 389, "tcp", "/etc/ldap/", "/var/log/syslog", "systemctl start slapd", "systemctl stop slapd", "systemctl status slapd", "LDAP directory server", ["cn=admin:admin"], ["Anonymous bind", "Weak authentication"]),
        }

    # ── Filesystem ────────────────────────────────────────────────────────

    def _register_filesystem(self) -> None:
        self.paths = {
            "/usr/share/wordlists": PathInfo("/usr/share/wordlists", "Password and directory wordlists", "drwxr-xr-x", "root", ["rockyou.txt", "dirb/", "dirbuster/", "seclists/"]),
            "/usr/share/seclists": PathInfo("/usr/share/seclists", "Security wordlists (SecLists by Daniel Miessler)", "drwxr-xr-x", "root", ["Passwords/", "Discovery/", "Web-Content/", "Fuzzing/", "Usernames/"]),
            "/usr/share/nmap/scripts": PathInfo("/usr/share/nmap/scripts", "Nmap NSE scripts (600+)", "drwxr-xr-x", "root", ["*.nse"]),
            "/usr/share/metasploit-framework": PathInfo("/usr/share/metasploit-framework", "Metasploit framework", "drwxr-xr-x", "root", ["modules/", "plugins/", "scripts/", "data/"]),
            "/usr/share/nuclei-templates": PathInfo("/usr/share/nuclei-templates", "Nuclei vulnerability templates (9000+)", "drwxr-xr-x", "root", ["cves/", "technologies/", "misconfigurations/", "exposures/"]),
            "/usr/share/exploitdb/exploits": PathInfo("/usr/share/exploitdb/exploits", "Exploit-DB exploits", "drwxr-xr-x", "root", ["linux/", "windows/", "macos/", "webapps/"]),
            "/etc/": PathInfo("/etc/", "System configuration", "drwxr-xr-x", "root", ["ssh/", "nginx/", "apache2/", "mysql/", "samba/", "snmp/"]),
            "/var/log": PathInfo("/var/log", "System logs", "drwxr-xr-x", "root", ["syslog", "auth.log", "kern.log", "apache2/"]),
            "/opt": PathInfo("/opt", "Optional software", "drwxr-xr-x", "root", ["metasploit-framework/", "ghidra/"]),
            "/tmp": PathInfo("/tmp", "Temporary directory (world-writable)", "drwxrwxrwt", "root", []),
            "/root": PathInfo("/root", "Root home directory", "drwx------", "root", [".msf4/", ".john/", ".hashcat/"]),
        }

    # ── NSE Scripts ───────────────────────────────────────────────────────

    def _register_nse_scripts(self) -> None:
        from nova_arsenal.kali_tools_data import NSE_SCRIPTS
        for script in NSE_SCRIPTS:
            self.nse_scripts[script.name] = script

    # ── Metasploit Modules ────────────────────────────────────────────────

    def _register_metasploit_modules(self) -> None:
        from nova_arsenal.kali_tools_data import METASPLOIT_MODULES
        for module in METASPLOIT_MODULES:
            self.metasploit_modules[module.name] = module

    # ── Wordlists ─────────────────────────────────────────────────────────

    def _register_wordlists(self) -> None:
        from nova_arsenal.kali_tools_data import WORDLISTS
        for wl in WORDLISTS:
            self.wordlists[wl.name] = wl

    # ── Attack Chains ─────────────────────────────────────────────────────

    def _register_attack_chains(self) -> None:
        from nova_arsenal.kali_tools_data import TOOL_COMBINATIONS
        for chain_name, chain_data in TOOL_COMBINATIONS.items():
            self.attack_chains[chain_name] = chain_data["steps"]

    # ═══════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    def _add_tools(self, tools: List[ToolInfo]) -> None:
        for tool in tools:
            self.tools[tool.name] = tool
            if tool.category not in self.tool_categories:
                self.tool_categories[tool.category] = []
            self.tool_categories[tool.category].append(tool.name)

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        return self.tools.get(name)

    def get_tools_by_category(self, category: str) -> List[ToolInfo]:
        names = self.tool_categories.get(category, [])
        return [self.tools[n] for n in names if n in self.tools]

    def get_attack_chain(self, chain_name: str) -> List[str]:
        return self.attack_chains.get(chain_name, [])

    def get_all_categories(self) -> List[str]:
        return sorted(self.tool_categories.keys())

    def get_service(self, name: str) -> Optional[ServiceInfo]:
        return self.services.get(name)

    def get_path_info(self, path: str) -> Optional[PathInfo]:
        return self.paths.get(path)

    def get_nse_scripts(self, category: Optional[str] = None) -> List[NSEScript]:
        scripts = list(self.nse_scripts.values())
        if category:
            scripts = [s for s in scripts if s.category == category]
        return scripts

    def get_metasploit_modules(self, platform: Optional[str] = None) -> List[MetasploitModule]:
        modules = list(self.metasploit_modules.values())
        if platform:
            modules = [m for m in modules if m.platform == platform]
        return modules

    def get_wordlists(self, use_case: Optional[str] = None) -> List[Wordlist]:
        wls = list(self.wordlists.values())
        if use_case:
            wls = [w for w in wls if use_case in w.use_cases]
        return wls

    def suggest_tools(self, task: str) -> List[str]:
        """Suggest tools based on task description."""
        task_lower = task.lower()
        suggestions = []
        keyword_map = {
            "scan": ["nmap", "masscan", "rustscan"],
            "port": ["nmap", "masscan"],
            "web": ["nuclei", "nikto", "whatweb", "ffuf", "gobuster"],
            "directory": ["ffuf", "gobuster", "dirsearch"],
            "subdomain": ["subfinder", "amass", "assetfinder"],
            "sql": ["sqlmap"],
            "inject": ["sqlmap", "commix"],
            "xss": ["xsstrike", "dalfox"],
            "password": ["hashcat", "john", "hydra", "medusa"],
            "brute": ["hydra", "medusa", "ncrack"],
            "smb": ["enum4linux-ng", "smbclient", "crackmapexec"],
            "ssh": ["hydra", "medusa"],
            "exploit": ["metasploit", "searchsploit"],
            "reverse": ["netcat", "socat", "msfconsole"],
            "shell": ["netcat", "socat", "msfconsole"],
            "privilege": ["linpeas", "linux-exploit-suggester"],
            "forensic": ["volatility3", "binwalk", "yara"],
            "memory": ["volatility3"],
            "firmware": ["binwalk"],
            "wifi": ["aircrack-ng", "wifite"],
            "capture": ["wireshark", "tcpdump"],
            "sniff": ["wireshark", "tcpdump", "bettercap"],
            "spoof": ["bettercap", "responder", "arpspoof"],
            "recon": ["subfinder", "amass", "httpx", "katana"],
            "enumerate": ["nmap", "enum4linux-ng", "gobuster"],
            "dump": ["sqlmap", "hashcat", "john"],
            "crack": ["hashcat", "john"],
            "hash": ["hashcat", "john"],
            "mitm": ["ettercap", "bettercap", "mitmproxy"],
            "arp": ["arpspoof", "bettercap", "arping"],
            "wpscan": ["wpscan"],
            "wordpress": ["wpscan"],
            "stego": ["steghide", "stegseek", "zsteg", "exiftool"],
            "metadata": ["exiftool"],
            "gadget": ["ropper"],
            "binary": ["checksec", "file", "strings", "objdump"],
            "disassemble": ["objdump", "radare2", "ghidra"],
            "debug": ["gdb", "pwndbg", "gef"],
            "trace": ["strace", "ltrace"],
            "snmp": ["onesixtyone", "snmpwalk", "snmp-check"],
            "ssl": ["sslscan", "testssl"],
            "certificate": ["sslscan", "testssl"],
            "kerberos": ["kerbrute", "impacket", "hashcat"],
            "kerberoast": ["kerbrute", "impacket", "hashcat"],
            "active directory": ["bloodhound", "crackmapexec", "enum4linux-ng"],
            "docker": ["trivy", "grype", "syft"],
            "container": ["trivy", "grype", "syft", "kube-hunter"],
            "kubernetes": ["kube-hunter", "kubeaudit", "trivy"],
            "android": ["apktool", "jadx", "objection", "frida"],
            "apk": ["apktool", "jadx", "dex2jar"],
            "api": ["arjun", "ffuf", "kiterunner"],
            "cloud": ["cloud_enum", "s3scanner", "pacu"],
            "s3": ["s3scanner"],
            "bluetooth": ["bluelog", "bluesnarfer", "btscanner"],
            "iot": ["binwalk", "firmwalker"],
            "scada": ["nmap", "mbtget", "s7exploit"],
            "fuzz": ["ffuf", "wfuzz", "honggfuzz", "afl++"],
            "anonymity": ["tor", "proxychains"],
            "vpn": ["openvpn"],
            "password spray": ["hydra", "crackmapexec"],
            "hash crack": ["hashcat", "john"],
            "volatility": ["volatility3"],
            "yara": ["yara"],
            "log analysis": ["volatility3", "log-parser"],
        }
        for keyword, tool_list in keyword_map.items():
            if keyword in task_lower:
                suggestions.extend(tool_list)
        return list(dict.fromkeys(suggestions))

    # ═══════════════════════════════════════════════════════════════════════
    # SYSTEM PROFILER
    # ═══════════════════════════════════════════════════════════════════════

    def _detect_installed_tools(self) -> Set[str]:
        """Detect which tools are actually installed on the system."""
        if self._installed_cache is not None:
            return self._installed_cache
        installed = set()
        for tool in self.tools.values():
            try:
                result = subprocess.run(
                    ["which", tool.binary],
                    capture_output=True, timeout=3
                )
                if result.returncode == 0:
                    installed.add(tool.name)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        self._installed_cache = installed
        return installed

    def get_installed_tools(self) -> List[str]:
        """Return list of tool names that are actually installed."""
        return sorted(self._detect_installed_tools())

    def get_missing_tools(self) -> List[str]:
        """Return list of tool names that are NOT installed."""
        installed = self._detect_installed_tools()
        return sorted([t for t in self.tools if t not in installed])

    def get_system_profile(self) -> Dict[str, Any]:
        """Get a full profile of the system's security tools."""
        installed = self._detect_installed_tools()
        return {
            "total_tools": len(self.tools),
            "installed": len(installed),
            "missing": len(self.tools) - len(installed),
            "installed_tools": sorted(installed),
            "categories": {
                cat: len([t for t in names if t in installed])
                for cat, names in self.tool_categories.items()
            },
        }

    # ═══════════════════════════════════════════════════════════════════════
    # CONTEXT GENERATION (Tiered for LLM)
    # ═══════════════════════════════════════════════════════════════════════

    def get_full_context(self) -> str:
        """Get the complete Kali knowledge base as context for the LLM."""
        lines = ["# KALI LINUX BLUEPRINT", ""]

        # Filesystem
        lines.append("## Filesystem Layout")
        for path, info in self.paths.items():
            lines.append(f"  {path} - {info.description}")

        # Tools by category
        lines.extend(["", "## Installed Tools by Category"])
        for category in sorted(self.tool_categories.keys()):
            lines.append(f"\n### {category.upper()}")
            for tool_name in self.tool_categories[category]:
                tool = self.tools[tool_name]
                lines.append(f"  {tool.name}: {tool.description}")
                lines.append(f"    Usage: {tool.usage}")
                if tool.examples:
                    lines.append(f"    Example: {tool.examples[0]}")
                if tool.notes:
                    lines.append(f"    Note: {tool.notes}")

        # Services
        lines.extend(["", "## Services"])
        for name, svc in self.services.items():
            creds = f" | Default creds: {', '.join(svc.default_creds)}" if svc.default_creds else ""
            vulns = f" | Vulns: {', '.join(svc.common_vulns)}" if svc.common_vulns else ""
            lines.append(f"  {name}: port {svc.port} ({svc.description}){creds}{vulns}")

        # NSE Scripts
        lines.extend(["", "## Key NSE Scripts"])
        for script in self.nse_scripts.values():
            lines.append(f"  {script.name}: {script.description} ({script.example})")

        # Metasploit
        lines.extend(["", "## Key Metasploit Modules"])
        for module in self.metasploit_modules.values():
            opts = ", ".join(f"{k}={v}" for k, v in module.options.items())
            lines.append(f"  {module.path}: {module.description} [{module.platform}] ({opts})")

        # Wordlists
        lines.extend(["", "## Wordlists"])
        for wl in self.wordlists.values():
            lines.append(f"  {wl.name}: {wl.path} ({wl.size}) - {wl.description}")

        # Attack Chains
        lines.extend(["", "## Attack Chains"])
        for chain_name, steps in self.attack_chains.items():
            lines.append(f"\n  {chain_name}:")
            for i, step in enumerate(steps, 1):
                lines.append(f"    {i}. {step}")

        return "\n".join(lines)

    def get_context_for_task(self, task: str) -> str:
        """Get relevant context for a specific task (reduced token usage)."""
        task_lower = task.lower()
        lines = [f"# Context for: {task}", ""]

        # Suggest tools
        suggested = self.suggest_tools(task)
        if suggested:
            lines.append("## Recommended Tools")
            for name in suggested:
                tool = self.tools.get(name)
                if tool:
                    lines.append(f"  {tool.name}: {tool.description}")
                    lines.append(f"    Usage: {tool.usage}")
                    if tool.examples:
                        lines.append(f"    Example: {tool.examples[0]}")
                    if tool.notes:
                        lines.append(f"    Note: {tool.notes}")
                    lines.append("")

        # Relevant attack chains
        for chain_name, steps in self.attack_chains.items():
            if any(kw in chain_name.lower() for kw in task_lower.split()):
                lines.append(f"## Attack Chain: {chain_name}")
                for i, step in enumerate(steps, 1):
                    lines.append(f"  {i}. {step}")
                lines.append("")

        # Relevant services
        if any(kw in task_lower for kw in ["ssh", "web", "http", "smb", "ftp", "mysql", "dns", "ldap"]):
            lines.append("## Relevant Services")
            for name, svc in self.services.items():
                if any(kw in name for kw in task_lower.split()):
                    creds = f" | Default creds: {', '.join(svc.default_creds)}" if svc.default_creds else ""
                    lines.append(f"  {name}: port {svc.port} ({svc.description}){creds}")

        return "\n".join(lines)

    def get_tool_help(self, tool_name: str) -> str:
        """Get detailed help for a specific tool."""
        tool = self.tools.get(tool_name)
        if not tool:
            return f"Tool '{tool_name}' not found in blueprint."
        lines = [
            f"# {tool.name} - {tool.description}",
            f"Binary: {tool.binary}",
            f"Path: {tool.install_path}",
            f"Usage: {tool.usage}",
            "",
            "## Flags",
        ]
        for flag, desc in tool.flags.items():
            lines.append(f"  {flag}: {desc}")
        if tool.examples:
            lines.extend(["", "## Examples"])
            for ex in tool.examples:
                lines.append(f"  $ {ex}")
        if tool.tool_combos:
            lines.extend(["", "## Tool Combinations"])
            for combo in tool.tool_combos:
                lines.append(f"  - {combo}")
        if tool.notes:
            lines.extend(["", f"## Notes\n  {tool.notes}"])
        return "\n".join(lines)
