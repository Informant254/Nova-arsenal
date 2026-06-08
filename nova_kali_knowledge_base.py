"""
NOVA KALI KNOWLEDGE BASE
=========================
Comprehensive mapping of Kali Linux tools for NovaKaliAgent.

Covers:
- Reconnaissance & OSINT
- Scanning & Enumeration
- Web Application Testing
- Password Attacks
- Wireless Attacks
- Exploitation Frameworks
- Post-Exploitation
- Forensics & Reverse Engineering
- Reporting

Each tool includes:
- Category & subcategory
- Description
- Syntax
- Common flags
- Use cases
- Output formats
- Average execution time (seconds)
- Risk level

Usage:
    from nova_kali_knowledge_base import KaliKnowledgeBase

    kb = KaliKnowledgeBase()

    # Get all tools in a category
    recon_tools = kb.by_category("recon")

    # Find best tool for a task
    tools = kb.recommend("find open ports")

    # Get tool details
    tool = kb.get("nmap")
    print(tool.syntax)

    # Search tools
    results = kb.search("sql injection")
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


# ──────────────────────────────────────────────
# ENUMS
# ──────────────────────────────────────────────

class Category(str, Enum):
    RECON           = "recon"
    SCANNING        = "scanning"
    WEB             = "web"
    PASSWORD        = "password"
    WIRELESS        = "wireless"
    EXPLOITATION    = "exploitation"
    POST_EXPLOIT    = "post_exploitation"
    FORENSICS       = "forensics"
    REPORTING       = "reporting"
    SNIFFING        = "sniffing"
    SOCIAL_ENG      = "social_engineering"
    REVERSE_ENG     = "reverse_engineering"
    CRYPTO          = "crypto"
    VULN_ANALYSIS   = "vuln_analysis"


class RiskLevel(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ──────────────────────────────────────────────
# TOOL DATA MODEL
# ──────────────────────────────────────────────

@dataclass
class KaliTool:
    name: str
    category: Category
    subcategory: str
    description: str
    syntax: str
    common_flags: Dict[str, str]        # flag -> description
    use_cases: List[str]
    output_formats: List[str]
    avg_time_seconds: int
    risk_level: RiskLevel
    keywords: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":             self.name,
            "category":         self.category.value,
            "subcategory":      self.subcategory,
            "description":      self.description,
            "syntax":           self.syntax,
            "common_flags":     self.common_flags,
            "use_cases":        self.use_cases,
            "output_formats":   self.output_formats,
            "avg_time_seconds": self.avg_time_seconds,
            "risk_level":       self.risk_level.value,
            "keywords":         self.keywords,
            "notes":            self.notes,
        }


# ──────────────────────────────────────────────
# TOOL DEFINITIONS
# ──────────────────────────────────────────────

KALI_TOOLS: List[KaliTool] = [

    # ══════════════════════════════════════════
    # RECONNAISSANCE & OSINT
    # ══════════════════════════════════════════

    KaliTool(
        name="nmap",
        category=Category.SCANNING,
        subcategory="port_scanning",
        description="Network mapper — port scanning, service detection, OS fingerprinting, NSE scripting",
        syntax="nmap [options] <target>",
        common_flags={
            "-sV":          "Service/version detection",
            "-sS":          "SYN stealth scan",
            "-sU":          "UDP scan",
            "-O":           "OS detection",
            "-A":           "Aggressive scan (OS, version, scripts, traceroute)",
            "-p-":          "Scan all 65535 ports",
            "-p <ports>":   "Scan specific ports e.g. -p 80,443,8080",
            "-T4":          "Faster timing template",
            "-oX <file>":   "XML output",
            "-oN <file>":   "Normal output",
            "-oG <file>":   "Grepable output",
            "--script <s>": "Run NSE script",
            "--script vuln":"Run all vuln scripts",
            "-Pn":          "Skip host discovery",
            "--open":       "Show only open ports",
        },
        use_cases=[
            "Discover open ports on a target",
            "Identify running services and versions",
            "OS fingerprinting",
            "Vulnerability scanning via NSE scripts",
            "Network topology mapping",
        ],
        output_formats=["xml", "normal", "grepable", "json (via nmap-formatter)"],
        avg_time_seconds=20,
        risk_level=RiskLevel.MEDIUM,
        keywords=["port", "scan", "service", "network", "discovery", "fingerprint"],
    ),

    KaliTool(
        name="masscan",
        category=Category.SCANNING,
        subcategory="port_scanning",
        description="Fast port scanner — scans the entire internet in under 6 minutes",
        syntax="masscan <target> -p<ports> [options]",
        common_flags={
            "-p1-65535":     "All ports",
            "-p80,443":      "Specific ports",
            "--rate=<n>":    "Packets per second (e.g. --rate=10000)",
            "--banners":     "Grab banners",
            "-oX <file>":    "XML output",
            "--open-only":   "Only show open ports",
        },
        use_cases=[
            "Rapid port discovery on large IP ranges",
            "Internet-wide scanning in labs",
            "Pre-scan before detailed nmap",
        ],
        output_formats=["xml", "binary", "list"],
        avg_time_seconds=10,
        risk_level=RiskLevel.MEDIUM,
        keywords=["port", "fast", "scan", "large", "range", "speed"],
    ),

    KaliTool(
        name="whois",
        category=Category.RECON,
        subcategory="osint",
        description="Query WHOIS databases for domain/IP registration info",
        syntax="whois <domain_or_ip>",
        common_flags={
            "-h <server>": "Use specific WHOIS server",
        },
        use_cases=[
            "Find domain registrant info",
            "Identify IP block owner",
            "Find abuse contact for an IP",
            "Discover registration dates",
        ],
        output_formats=["text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["domain", "ip", "registrant", "owner", "osint", "recon"],
    ),

    KaliTool(
        name="dig",
        category=Category.RECON,
        subcategory="dns",
        description="DNS lookup utility — query DNS records",
        syntax="dig [options] <name> [type]",
        common_flags={
            "A":        "IPv4 address record",
            "AAAA":     "IPv6 address record",
            "MX":       "Mail exchange record",
            "NS":       "Name server record",
            "TXT":      "Text record",
            "ANY":      "All records",
            "AXFR":     "Zone transfer attempt",
            "+short":   "Short output",
            "@<server>":"Query specific DNS server",
        },
        use_cases=[
            "DNS enumeration",
            "Zone transfer attempts",
            "Mail server discovery",
            "SPF/DKIM record analysis",
        ],
        output_formats=["text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["dns", "domain", "records", "zone", "transfer", "lookup"],
    ),

    KaliTool(
        name="nslookup",
        category=Category.RECON,
        subcategory="dns",
        description="Query DNS servers interactively or non-interactively",
        syntax="nslookup [options] <name> [server]",
        common_flags={
            "-type=MX":  "Mail records",
            "-type=NS":  "Name server records",
            "-type=ANY": "All records",
        },
        use_cases=["DNS lookups", "Reverse DNS lookups", "Mail server enumeration"],
        output_formats=["text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["dns", "lookup", "reverse", "domain"],
    ),

    KaliTool(
        name="dnsrecon",
        category=Category.RECON,
        subcategory="dns",
        description="Advanced DNS enumeration — brute force subdomains, zone transfers, cache snooping",
        syntax="dnsrecon -d <domain> [options]",
        common_flags={
            "-d <domain>":  "Target domain",
            "-t std":       "Standard enumeration",
            "-t brt":       "Brute force subdomains",
            "-t axfr":      "Zone transfer",
            "-D <wordlist>":"Wordlist for brute force",
            "-j <file>":    "JSON output",
        },
        use_cases=[
            "Subdomain enumeration",
            "Zone transfer testing",
            "DNS cache snooping",
            "Reverse lookup ranges",
        ],
        output_formats=["text", "json", "xml", "csv"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["dns", "subdomain", "enum", "zone", "brute", "recon"],
    ),

    KaliTool(
        name="theHarvester",
        category=Category.RECON,
        subcategory="osint",
        description="Gather emails, subdomains, hosts, employee names from public sources",
        syntax="theHarvester -d <domain> -b <source>",
        common_flags={
            "-d <domain>": "Target domain",
            "-b all":      "Use all sources",
            "-b google":   "Use Google",
            "-b shodan":   "Use Shodan",
            "-b linkedin": "Use LinkedIn",
            "-l <limit>":  "Limit results",
            "-f <file>":   "Output to file (html/xml)",
        },
        use_cases=[
            "Email harvesting",
            "Subdomain discovery",
            "Employee name enumeration",
            "OSINT gathering",
        ],
        output_formats=["text", "html", "xml"],
        avg_time_seconds=60,
        risk_level=RiskLevel.LOW,
        keywords=["email", "osint", "harvest", "subdomain", "employees", "recon"],
    ),

    KaliTool(
        name="maltego",
        category=Category.RECON,
        subcategory="osint",
        description="Visual link analysis tool for OSINT and threat intelligence",
        syntax="maltego  (GUI application)",
        common_flags={},
        use_cases=[
            "Visual relationship mapping",
            "Infrastructure OSINT",
            "Social network analysis",
            "Threat intelligence",
        ],
        output_formats=["gui", "export"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["osint", "graph", "visual", "relationship", "intelligence"],
        notes="GUI only — not suitable for automation",
    ),

    KaliTool(
        name="recon-ng",
        category=Category.RECON,
        subcategory="osint",
        description="Full-featured web reconnaissance framework with modular design",
        syntax="recon-ng",
        common_flags={
            "marketplace install all": "Install all modules",
            "modules load <module>":   "Load a module",
            "options set SOURCE <t>":  "Set target",
            "run":                     "Execute module",
        },
        use_cases=[
            "Automated OSINT gathering",
            "Contact information harvesting",
            "Geolocation discovery",
            "Credential exposure checking",
        ],
        output_formats=["database", "csv", "json", "xml"],
        avg_time_seconds=120,
        risk_level=RiskLevel.LOW,
        keywords=["osint", "recon", "framework", "modular", "automated"],
    ),

    KaliTool(
        name="shodan",
        category=Category.RECON,
        subcategory="osint",
        description="Search engine for internet-connected devices via Shodan API",
        syntax="shodan <command> [options]",
        common_flags={
            "search <query>":  "Search Shodan",
            "host <ip>":       "Get info about an IP",
            "download <query>":"Download results",
            "parse <file>":    "Parse downloaded results",
        },
        use_cases=[
            "Discover exposed services",
            "Find vulnerable devices",
            "Banner grabbing at scale",
            "Passive reconnaissance",
        ],
        output_formats=["json", "text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["internet", "exposed", "devices", "passive", "osint", "api"],
        notes="Requires API key: shodan init <api_key>",
    ),

    KaliTool(
        name="amass",
        category=Category.RECON,
        subcategory="subdomain",
        description="In-depth subdomain enumeration and attack surface mapping",
        syntax="amass enum -d <domain> [options]",
        common_flags={
            "enum -d <domain>":     "Passive enumeration",
            "enum -active -d <d>":  "Active enumeration",
            "enum -brute -d <d>":   "Brute force subdomains",
            "-o <file>":            "Output file",
            "-json <file>":         "JSON output",
        },
        use_cases=[
            "Comprehensive subdomain discovery",
            "Attack surface mapping",
            "Certificate transparency search",
        ],
        output_formats=["text", "json", "graphdb"],
        avg_time_seconds=180,
        risk_level=RiskLevel.LOW,
        keywords=["subdomain", "enum", "attack surface", "passive", "active"],
    ),

    KaliTool(
        name="sublist3r",
        category=Category.RECON,
        subcategory="subdomain",
        description="Fast subdomain enumeration using OSINT and brute force",
        syntax="sublist3r -d <domain> [options]",
        common_flags={
            "-d <domain>": "Target domain",
            "-b":          "Enable brute force",
            "-o <file>":   "Output file",
            "-t <n>":      "Threads",
            "-v":          "Verbose",
        },
        use_cases=["Subdomain discovery", "OSINT reconnaissance"],
        output_formats=["text"],
        avg_time_seconds=60,
        risk_level=RiskLevel.LOW,
        keywords=["subdomain", "enum", "osint", "brute"],
    ),

    KaliTool(
        name="dnsenum",
        category=Category.RECON,
        subcategory="dns",
        description="Multithreaded DNS enumeration — zone transfers, brute force, Google scraping",
        syntax="dnsenum <domain> [options]",
        common_flags={
            "--enum":          "Full enumeration",
            "--dnsserver <s>": "Use specific DNS server",
            "-f <wordlist>":   "Brute force wordlist",
            "--threads <n>":   "Thread count",
        },
        use_cases=["DNS zone transfer", "Subdomain brute force", "MX/NS discovery"],
        output_formats=["text", "xml"],
        avg_time_seconds=45,
        risk_level=RiskLevel.LOW,
        keywords=["dns", "zone", "transfer", "enum", "brute", "subdomain"],
    ),

    # ══════════════════════════════════════════
    # WEB APPLICATION TESTING
    # ══════════════════════════════════════════

    KaliTool(
        name="nikto",
        category=Category.WEB,
        subcategory="web_scanning",
        description="Web server scanner — checks for dangerous files, outdated software, misconfigurations",
        syntax="nikto -h <host> [options]",
        common_flags={
            "-h <host>":       "Target host",
            "-p <port>":       "Target port",
            "-ssl":            "Force SSL",
            "-o <file>":       "Output file",
            "-Format xml":     "XML output",
            "-Format csv":     "CSV output",
            "-Tuning <n>":     "Tuning options (0-9)",
            "-id <user:pass>": "HTTP authentication",
            "-useproxy":       "Use proxy",
        },
        use_cases=[
            "Web server misconfiguration detection",
            "Outdated software identification",
            "Default file/directory discovery",
            "HTTP method testing",
        ],
        output_formats=["text", "xml", "csv", "html", "nbe"],
        avg_time_seconds=60,
        risk_level=RiskLevel.MEDIUM,
        keywords=["web", "scan", "misconfiguration", "outdated", "server"],
    ),

    KaliTool(
        name="gobuster",
        category=Category.WEB,
        subcategory="directory_enum",
        description="Directory/file/DNS/vhost brute force tool",
        syntax="gobuster <mode> -u <url> -w <wordlist> [options]",
        common_flags={
            "dir":            "Directory enumeration mode",
            "dns":            "DNS subdomain mode",
            "vhost":          "Virtual host mode",
            "-u <url>":       "Target URL",
            "-w <wordlist>":  "Wordlist path",
            "-t <n>":         "Threads (default 10)",
            "-x <ext>":       "File extensions e.g. php,html,txt",
            "-o <file>":      "Output file",
            "-s <codes>":     "Valid status codes",
            "-k":             "Skip TLS verification",
            "-b <codes>":     "Blacklisted status codes",
        },
        use_cases=[
            "Web directory enumeration",
            "File discovery",
            "Subdomain brute force",
            "Virtual host discovery",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["directory", "brute", "file", "enum", "web", "fuzzing"],
    ),

    KaliTool(
        name="dirb",
        category=Category.WEB,
        subcategory="directory_enum",
        description="Web content scanner using dictionary-based attacks",
        syntax="dirb <url> [wordlist] [options]",
        common_flags={
            "-a <agent>":  "Set user agent",
            "-c <cookie>": "Set cookie",
            "-o <file>":   "Output file",
            "-r":          "Don't search recursively",
            "-z <ms>":     "Milliseconds delay",
            "-X <ext>":    "File extensions",
        },
        use_cases=["Web directory discovery", "Hidden file finding"],
        output_formats=["text"],
        avg_time_seconds=45,
        risk_level=RiskLevel.MEDIUM,
        keywords=["directory", "web", "scan", "dictionary", "content"],
    ),

    KaliTool(
        name="wfuzz",
        category=Category.WEB,
        subcategory="fuzzing",
        description="Web application fuzzer — fuzz any HTTP parameter",
        syntax="wfuzz -c -w <wordlist> <url_with_FUZZ>",
        common_flags={
            "-c":              "Colorize output",
            "-w <wordlist>":   "Wordlist",
            "-z file,<list>":  "Use file as payload",
            "--hc <codes>":    "Hide response codes",
            "--hl <lines>":    "Hide by line count",
            "--hw <words>":    "Hide by word count",
            "-d <data>":       "POST data",
            "-H <header>":     "Add header",
            "-b <cookie>":     "Cookie",
            "-t <n>":          "Concurrent connections",
        },
        use_cases=[
            "Parameter fuzzing",
            "Directory brute force",
            "Authentication bypass testing",
            "API endpoint discovery",
        ],
        output_formats=["text", "html", "json"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["fuzz", "web", "parameter", "brute", "api", "http"],
    ),

    KaliTool(
        name="sqlmap",
        category=Category.WEB,
        subcategory="sql_injection",
        description="Automated SQL injection detection and exploitation tool",
        syntax="sqlmap -u <url> [options]",
        common_flags={
            "-u <url>":        "Target URL",
            "-p <param>":      "Test specific parameter",
            "--data <data>":   "POST data",
            "--cookie <c>":    "HTTP cookie",
            "--dbs":           "Enumerate databases",
            "--tables":        "Enumerate tables",
            "--dump":          "Dump table data",
            "--dump-all":      "Dump all databases",
            "--dbms <type>":   "Force DBMS (mysql, mssql, oracle...)",
            "--level <1-5>":   "Test level",
            "--risk <1-3>":    "Risk level",
            "--batch":         "Never ask for input",
            "--random-agent":  "Random user agent",
            "--tor":           "Use Tor",
            "--technique <t>": "SQLi technique (B,E,U,S,T,Q)",
            "--os-shell":      "OS shell if FILE privilege",
            "--form":          "Parse and test forms",
        },
        use_cases=[
            "SQL injection detection",
            "Database enumeration",
            "Data extraction",
            "Authentication bypass",
        ],
        output_formats=["text", "csv", "json", "html", "xml"],
        avg_time_seconds=120,
        risk_level=RiskLevel.HIGH,
        keywords=["sql", "injection", "database", "sqli", "mysql", "oracle", "mssql"],
    ),

    KaliTool(
        name="burpsuite",
        category=Category.WEB,
        subcategory="proxy",
        description="Integrated web application security testing platform",
        syntax="burpsuite  (GUI application)",
        common_flags={
            "Proxy":      "Intercept HTTP traffic",
            "Scanner":    "Active/passive scanning",
            "Intruder":   "Automated attack tool",
            "Repeater":   "Manual request modification",
            "Decoder":    "Encode/decode data",
            "Comparer":   "Compare responses",
        },
        use_cases=[
            "HTTP traffic interception",
            "Manual web app testing",
            "Automated vulnerability scanning",
            "Authentication testing",
            "Session management testing",
        ],
        output_formats=["gui", "xml", "html"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["proxy", "web", "intercept", "http", "scan", "manual"],
        notes="GUI only — Community edition free, Pro requires license",
    ),

    KaliTool(
        name="zaproxy",
        category=Category.WEB,
        subcategory="proxy",
        description="OWASP ZAP — open source web application security scanner",
        syntax="zaproxy  (GUI or CLI)",
        common_flags={
            "-daemon":          "Headless mode",
            "-port <n>":        "Listen port",
            "-quickurl <url>":  "Quick scan URL",
            "-quickout <file>": "Output file",
        },
        use_cases=[
            "Automated web scanning",
            "Manual web testing via proxy",
            "API security testing",
            "CI/CD pipeline integration",
        ],
        output_formats=["html", "xml", "json", "markdown"],
        avg_time_seconds=300,
        risk_level=RiskLevel.HIGH,
        keywords=["proxy", "web", "owasp", "scan", "zap", "automated"],
    ),

    KaliTool(
        name="whatweb",
        category=Category.WEB,
        subcategory="fingerprinting",
        description="Web fingerprinting — identify CMS, frameworks, server software",
        syntax="whatweb [options] <url>",
        common_flags={
            "-a <1-4>":    "Aggression level",
            "-v":          "Verbose",
            "--log-json":  "JSON output",
            "--log-xml":   "XML output",
            "-t <n>":      "Threads",
            "--proxy":     "Use proxy",
        },
        use_cases=[
            "CMS identification (WordPress, Drupal...)",
            "Technology stack fingerprinting",
            "Version detection",
        ],
        output_formats=["text", "json", "xml", "csv"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["fingerprint", "cms", "web", "technology", "identify"],
    ),

    KaliTool(
        name="wafw00f",
        category=Category.WEB,
        subcategory="waf_detection",
        description="Web Application Firewall detection and fingerprinting",
        syntax="wafw00f <url> [options]",
        common_flags={
            "-a":       "Test all WAFs",
            "-v":       "Verbose",
            "-o <f>":   "Output file",
            "-f <fmt>": "Output format (json/csv)",
        },
        use_cases=["WAF detection before testing", "Identify filtering rules"],
        output_formats=["text", "json", "csv"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["waf", "firewall", "detect", "web", "bypass"],
    ),

    KaliTool(
        name="ffuf",
        category=Category.WEB,
        subcategory="fuzzing",
        description="Fast web fuzzer — directory, parameter, vhost fuzzing",
        syntax="ffuf -u <url/FUZZ> -w <wordlist> [options]",
        common_flags={
            "-u <url>":    "Target URL (use FUZZ as placeholder)",
            "-w <list>":   "Wordlist",
            "-H <header>": "Add header",
            "-d <data>":   "POST data",
            "-mc <codes>": "Match HTTP codes",
            "-fc <codes>": "Filter HTTP codes",
            "-t <n>":      "Threads",
            "-o <file>":   "Output file",
            "-of json":    "JSON output format",
            "-recursion":  "Recursive fuzzing",
        },
        use_cases=[
            "Directory fuzzing",
            "Parameter discovery",
            "Virtual host enumeration",
            "API endpoint discovery",
        ],
        output_formats=["text", "json", "csv", "html", "md"],
        avg_time_seconds=20,
        risk_level=RiskLevel.MEDIUM,
        keywords=["fuzz", "fast", "directory", "parameter", "api", "web"],
    ),

    KaliTool(
        name="commix",
        category=Category.WEB,
        subcategory="command_injection",
        description="Automated command injection detection and exploitation",
        syntax="commix --url=<url> [options]",
        common_flags={
            "--url=<url>":     "Target URL",
            "--data=<data>":   "POST data",
            "--cookie=<c>":    "Cookie",
            "--os-cmd=<cmd>":  "Execute OS command",
            "--all":           "Test all parameters",
            "--batch":         "Non-interactive",
        },
        use_cases=[
            "OS command injection detection",
            "Command injection exploitation",
            "Filter bypass testing",
        ],
        output_formats=["text"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["command", "injection", "os", "rce", "web"],
    ),

    KaliTool(
        name="xsser",
        category=Category.WEB,
        subcategory="xss",
        description="Cross-Site Scripting detection and exploitation framework",
        syntax="xsser --url <url> [options]",
        common_flags={
            "--url <url>":  "Target URL",
            "--auto":       "Automatic testing",
            "--Coo":        "XSS via cookies",
            "--Hea":        "XSS via headers",
            "--Dom":        "DOM XSS",
            "--Dos":        "DoS payloads",
            "--reverse-check": "Verify exploitation",
        },
        use_cases=["XSS detection", "XSS exploitation", "DOM XSS testing"],
        output_formats=["text", "html"],
        avg_time_seconds=30,
        risk_level=RiskLevel.HIGH,
        keywords=["xss", "cross-site", "scripting", "web", "inject"],
    ),

    # ══════════════════════════════════════════
    # PASSWORD ATTACKS
    # ══════════════════════════════════════════

    KaliTool(
        name="hydra",
        category=Category.PASSWORD,
        subcategory="online_brute_force",
        description="Fast network login cracker supporting many protocols",
        syntax="hydra -l <user> -P <wordlist> <target> <protocol>",
        common_flags={
            "-l <user>":         "Single username",
            "-L <file>":         "Username list",
            "-p <pass>":         "Single password",
            "-P <file>":         "Password list",
            "-t <n>":            "Parallel tasks per target (default 16)",
            "-f":                "Stop after first valid pair",
            "-s <port>":         "Custom port",
            "-S":                "SSL",
            "-v":                "Verbose",
            "-o <file>":         "Output file",
            "-x <min:max:set>":  "Generate passwords",
        },
        use_cases=[
            "SSH brute force",
            "FTP brute force",
            "HTTP form brute force",
            "RDP brute force",
            "SMTP/POP3 brute force",
        ],
        output_formats=["text"],
        avg_time_seconds=180,
        risk_level=RiskLevel.HIGH,
        keywords=["brute", "force", "password", "login", "crack", "online"],
        notes="Supported protocols: ssh, ftp, http-get, http-post-form, rdp, smb, smtp, pop3, imap, mysql, mssql, vnc, telnet",
    ),

    KaliTool(
        name="john",
        category=Category.PASSWORD,
        subcategory="offline_cracking",
        description="John the Ripper — offline password hash cracker",
        syntax="john [options] <hashfile>",
        common_flags={
            "--wordlist=<f>":    "Wordlist attack",
            "--rules":           "Apply mangling rules",
            "--incremental":     "Incremental brute force",
            "--format=<fmt>":    "Hash format (md5, sha256, bcrypt...)",
            "--show":            "Show cracked passwords",
            "--pot=<file>":      "Custom pot file",
            "--session=<name>":  "Session name for resuming",
            "--restore":         "Restore previous session",
        },
        use_cases=[
            "Crack password hashes",
            "Hash format identification",
            "Dictionary + rule attacks",
            "/etc/shadow cracking",
        ],
        output_formats=["text"],
        avg_time_seconds=300,
        risk_level=RiskLevel.HIGH,
        keywords=["hash", "crack", "password", "offline", "dictionary", "brute"],
    ),

    KaliTool(
        name="hashcat",
        category=Category.PASSWORD,
        subcategory="offline_cracking",
        description="World's fastest password cracker — GPU-accelerated hash cracking",
        syntax="hashcat -m <hash_type> <hashfile> <wordlist> [options]",
        common_flags={
            "-m <type>":      "Hash type (0=MD5, 1000=NTLM, 1800=sha512crypt...)",
            "-a <mode>":      "Attack mode (0=dict, 1=combo, 3=brute, 6=hybrid)",
            "-r <rules>":     "Rules file",
            "--show":         "Show cracked",
            "-o <file>":      "Output file",
            "--status":       "Enable status timer",
            "--force":        "Ignore warnings (use on Termux/VM)",
            "-w <1-4>":       "Workload profile",
            "--increment":    "Incremental mask attack",
        },
        use_cases=[
            "GPU-accelerated hash cracking",
            "NTLM/NTLMv2 cracking",
            "WPA/WPA2 cracking",
            "Rule-based attacks",
        ],
        output_formats=["text", "potfile"],
        avg_time_seconds=300,
        risk_level=RiskLevel.HIGH,
        keywords=["hash", "crack", "gpu", "password", "fast", "ntlm", "wpa"],
        notes="Use --force on VMs/Termux. Hash types: https://hashcat.net/wiki/doku.php?id=hashcat",
    ),

    KaliTool(
        name="medusa",
        category=Category.PASSWORD,
        subcategory="online_brute_force",
        description="Speedy parallel network login auditor",
        syntax="medusa -h <host> -u <user> -P <wordlist> -M <module>",
        common_flags={
            "-h <host>":    "Target host",
            "-u <user>":    "Username",
            "-U <file>":    "Username file",
            "-p <pass>":    "Password",
            "-P <file>":    "Password file",
            "-M <module>":  "Module (ssh, ftp, http...)",
            "-t <n>":       "Parallel logins",
            "-f":           "Stop after first success",
        },
        use_cases=["SSH/FTP/HTTP brute force", "Parallel login testing"],
        output_formats=["text"],
        avg_time_seconds=120,
        risk_level=RiskLevel.HIGH,
        keywords=["brute", "force", "login", "parallel", "password"],
    ),

    KaliTool(
        name="hashid",
        category=Category.PASSWORD,
        subcategory="hash_identification",
        description="Identify hash types from their format",
        syntax="hashid <hash>",
        common_flags={
            "-m": "Show hashcat mode",
            "-j": "Show john format",
            "-e": "Extended detection",
        },
        use_cases=["Identify unknown hash type before cracking"],
        output_formats=["text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["hash", "identify", "type", "md5", "sha", "bcrypt"],
    ),

    KaliTool(
        name="crunch",
        category=Category.PASSWORD,
        subcategory="wordlist_generation",
        description="Generate custom wordlists based on pattern/charset",
        syntax="crunch <min> <max> [charset] [options]",
        common_flags={
            "-o <file>":  "Output file",
            "-t <pat>":   "Pattern (@=lowercase, ,=uppercase, %=digit, ^=symbol)",
            "-f <file>":  "Use charset from file",
            "-d <n>":     "Limit consecutive duplicate characters",
            "-b <size>":  "Max file size",
        },
        use_cases=[
            "Custom wordlist generation",
            "Pattern-based password generation",
            "Targeted brute force prep",
        ],
        output_formats=["text", "piped to other tools"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["wordlist", "generate", "custom", "charset", "pattern"],
    ),

    KaliTool(
        name="cewl",
        category=Category.PASSWORD,
        subcategory="wordlist_generation",
        description="Spider a website and generate a custom wordlist from its content",
        syntax="cewl <url> [options]",
        common_flags={
            "-d <n>":      "Spider depth",
            "-m <n>":      "Minimum word length",
            "-w <file>":   "Output wordlist",
            "--email":     "Include emails",
            "-a":          "Include metadata",
            "--with-numbers": "Include words with numbers",
        },
        use_cases=[
            "Generate target-specific wordlist",
            "Password policy-aware wordlist",
        ],
        output_formats=["text"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["wordlist", "spider", "custom", "website", "generate"],
    ),

    # ══════════════════════════════════════════
    # WIRELESS
    # ══════════════════════════════════════════

    KaliTool(
        name="aircrack-ng",
        category=Category.WIRELESS,
        subcategory="wpa_cracking",
        description="Complete suite for 802.11 WEP/WPA/WPA2 cracking",
        syntax="aircrack-ng [options] <capture_file>",
        common_flags={
            "-w <wordlist>": "Wordlist for WPA cracking",
            "-b <bssid>":    "Target BSSID",
            "-e <essid>":    "Target ESSID",
            "-j <file>":     "Hashcat output file",
        },
        use_cases=["WEP cracking", "WPA/WPA2 handshake cracking", "PTW attack"],
        output_formats=["text"],
        avg_time_seconds=300,
        risk_level=RiskLevel.HIGH,
        keywords=["wifi", "wpa", "wep", "wireless", "crack", "handshake"],
        notes="Part of aircrack-ng suite: airmon-ng, airodump-ng, aireplay-ng",
    ),

    KaliTool(
        name="airodump-ng",
        category=Category.WIRELESS,
        subcategory="wifi_capture",
        description="802.11 packet capture — capture WPA handshakes and scan networks",
        syntax="airodump-ng [options] <interface>",
        common_flags={
            "--bssid <b>":   "Filter by BSSID",
            "--channel <c>": "Lock to channel",
            "-w <file>":     "Write capture file",
            "--band <b>":    "Band (a/b/g)",
        },
        use_cases=["WiFi network discovery", "WPA handshake capture"],
        output_formats=["pcap", "csv", "netxml"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["wifi", "capture", "handshake", "monitor", "wireless"],
    ),

    KaliTool(
        name="airmon-ng",
        category=Category.WIRELESS,
        subcategory="monitor_mode",
        description="Enable/disable monitor mode on wireless interfaces",
        syntax="airmon-ng <start|stop> <interface> [channel]",
        common_flags={
            "start <iface>": "Enable monitor mode",
            "stop <iface>":  "Disable monitor mode",
            "check kill":    "Kill interfering processes",
        },
        use_cases=["Enable monitor mode for wireless testing"],
        output_formats=["text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.MEDIUM,
        keywords=["monitor", "mode", "wifi", "interface", "wireless"],
    ),

    KaliTool(
        name="wifite",
        category=Category.WIRELESS,
        subcategory="automated_wifi",
        description="Automated wireless auditing tool",
        syntax="wifite [options]",
        common_flags={
            "--wpa":        "Only attack WPA",
            "--wep":        "Only attack WEP",
            "--wps":        "Only attack WPS",
            "-i <iface>":   "Interface",
            "--dict <f>":   "Wordlist",
            "--kill":       "Kill interfering processes",
        },
        use_cases=["Automated WPA/WEP/WPS cracking", "Wireless pen testing"],
        output_formats=["text"],
        avg_time_seconds=300,
        risk_level=RiskLevel.HIGH,
        keywords=["wifi", "automated", "wpa", "wep", "wps", "wireless"],
    ),

    # ══════════════════════════════════════════
    # EXPLOITATION FRAMEWORKS
    # ══════════════════════════════════════════

    KaliTool(
        name="metasploit",
        category=Category.EXPLOITATION,
        subcategory="framework",
        description="World's most used penetration testing framework",
        syntax="msfconsole",
        common_flags={
            "search <term>":          "Search modules",
            "use <module>":           "Load module",
            "info":                   "Module info",
            "show options":           "Show required options",
            "set <option> <value>":   "Set option",
            "run / exploit":          "Execute module",
            "sessions":               "List active sessions",
            "sessions -i <id>":       "Interact with session",
            "background":             "Background session",
            "db_nmap <options> <t>":  "Run nmap and import results",
        },
        use_cases=[
            "Vulnerability exploitation",
            "Post-exploitation",
            "Payload generation",
            "Session management",
            "Pivoting",
        ],
        output_formats=["console", "database"],
        avg_time_seconds=600,
        risk_level=RiskLevel.CRITICAL,
        keywords=["exploit", "framework", "payload", "session", "msf", "meterpreter"],
    ),

    KaliTool(
        name="msfvenom",
        category=Category.EXPLOITATION,
        subcategory="payload_generation",
        description="Generate and encode Metasploit payloads",
        syntax="msfvenom -p <payload> [options] -f <format> -o <file>",
        common_flags={
            "-p <payload>":    "Payload e.g. windows/meterpreter/reverse_tcp",
            "-f <format>":     "Output format (exe, elf, php, py, raw...)",
            "-o <file>":       "Output file",
            "LHOST=<ip>":      "Listener host",
            "LPORT=<port>":    "Listener port",
            "-e <encoder>":    "Encoder",
            "-i <n>":          "Encoding iterations",
            "-b <chars>":      "Bad characters to avoid",
            "--list payloads": "List all payloads",
            "--list formats":  "List output formats",
        },
        use_cases=[
            "Generate reverse shell payloads",
            "Create encoded executables",
            "Payload format conversion",
        ],
        output_formats=["exe", "elf", "php", "py", "ps1", "raw", "jar", "apk"],
        avg_time_seconds=5,
        risk_level=RiskLevel.CRITICAL,
        keywords=["payload", "generate", "shellcode", "reverse", "shell", "encode"],
    ),

    KaliTool(
        name="searchsploit",
        category=Category.EXPLOITATION,
        subcategory="exploit_search",
        description="Search Exploit-DB from the command line",
        syntax="searchsploit <search_term>",
        common_flags={
            "-t":             "Search in title only",
            "-e":             "Exact match",
            "--id":           "Show EDB-IDs",
            "-p <id>":        "Show full path",
            "--nmap <xml>":   "Check nmap results against exploits",
            "-m <id>":        "Copy exploit to current directory",
            "-u":             "Update database",
        },
        use_cases=[
            "Find exploits for identified software versions",
            "CVE-to-exploit mapping",
            "Offline exploit database search",
        ],
        output_formats=["text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.MEDIUM,
        keywords=["exploit", "search", "cve", "vulnerability", "exploitdb"],
    ),

    KaliTool(
        name="beef-xss",
        category=Category.EXPLOITATION,
        subcategory="browser_exploitation",
        description="Browser Exploitation Framework — hook browsers via XSS",
        syntax="beef-xss  (web interface at http://localhost:3000/ui/panel)",
        common_flags={},
        use_cases=[
            "Browser exploitation via XSS",
            "Client-side attack demonstration",
            "Session hijacking",
            "Social engineering campaigns",
        ],
        output_formats=["web_ui"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["xss", "browser", "exploit", "hook", "client", "javascript"],
        notes="Start with: beef-xss. Hook URL: http://<server>:3000/hook.js",
    ),

    # ══════════════════════════════════════════
    # POST-EXPLOITATION
    # ══════════════════════════════════════════

    KaliTool(
        name="mimikatz",
        category=Category.POST_EXPLOIT,
        subcategory="credential_dumping",
        description="Windows credential extraction — dump NTLM hashes, plaintext passwords, Kerberos tickets",
        syntax="mimikatz.exe  (Windows binary)",
        common_flags={
            "sekurlsa::logonpasswords": "Dump plaintext creds from memory",
            "sekurlsa::wdigest":        "Enable WDigest (older Windows)",
            "lsadump::sam":             "Dump SAM database",
            "lsadump::dcsync":          "DCSync attack",
            "kerberos::list":           "List Kerberos tickets",
            "kerberos::golden":         "Golden ticket",
            "privilege::debug":         "Enable debug privilege",
            "token::elevate":           "Elevate token",
        },
        use_cases=[
            "Credential dumping",
            "Pass-the-hash attacks",
            "Pass-the-ticket attacks",
            "Golden/silver ticket creation",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.CRITICAL,
        keywords=["credentials", "dump", "ntlm", "kerberos", "windows", "hash", "pass-the-hash"],
        notes="Requires SYSTEM or SeDebugPrivilege. Windows only.",
    ),

    KaliTool(
        name="linpeas",
        category=Category.POST_EXPLOIT,
        subcategory="privilege_escalation",
        description="Linux Privilege Escalation Awesome Script — automated Linux privesc enumeration",
        syntax="./linpeas.sh [options]",
        common_flags={
            "-a":   "All checks",
            "-s":   "Superfast (less output)",
            "-q":   "Quiet mode",
            "-o <s>":"Only specific checks",
        },
        use_cases=[
            "Linux privilege escalation enumeration",
            "SUID/SGID binary discovery",
            "Cron job analysis",
            "Kernel exploit suggestion",
        ],
        output_formats=["text", "colored"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["privesc", "linux", "escalation", "privilege", "enum", "suid"],
        notes="Download: curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
    ),

    KaliTool(
        name="winpeas",
        category=Category.POST_EXPLOIT,
        subcategory="privilege_escalation",
        description="Windows Privilege Escalation Awesome Script",
        syntax="winpeas.exe [options]",
        common_flags={
            "all":        "All checks",
            "systeminfo": "System info only",
            "userinfo":   "User info only",
            "servicesinfo": "Services info",
        },
        use_cases=[
            "Windows privilege escalation enumeration",
            "Unquoted service path discovery",
            "Weak registry permissions",
            "AlwaysInstallElevated check",
        ],
        output_formats=["text", "colored"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["privesc", "windows", "escalation", "privilege", "enum"],
    ),

    KaliTool(
        name="netcat",
        category=Category.POST_EXPLOIT,
        subcategory="networking",
        description="TCP/UDP networking utility — reverse shells, port forwarding, file transfer",
        syntax="nc [options] <host> <port>",
        common_flags={
            "-l":          "Listen mode",
            "-p <port>":   "Local port",
            "-e <prog>":   "Execute program on connect",
            "-v":          "Verbose",
            "-n":          "No DNS resolution",
            "-z":          "Port scan mode",
            "-u":          "UDP mode",
            "-w <secs>":   "Timeout",
        },
        use_cases=[
            "Reverse shell listener",
            "Bind shell",
            "File transfer",
            "Port scanning",
            "Banner grabbing",
            "Port forwarding",
        ],
        output_formats=["text", "piped"],
        avg_time_seconds=5,
        risk_level=RiskLevel.HIGH,
        keywords=["shell", "reverse", "bind", "listener", "tcp", "transfer"],
        notes="Use ncat (from nmap) for more features. On Termux: pkg install netcat-openbsd",
    ),

    KaliTool(
        name="socat",
        category=Category.POST_EXPLOIT,
        subcategory="networking",
        description="Advanced netcat — full duplex data transfer between two streams",
        syntax="socat <address1> <address2>",
        common_flags={
            "TCP-LISTEN:<port>,reuseaddr,fork": "Listen for TCP",
            "TCP:<host>:<port>":                "Connect TCP",
            "EXEC:<cmd>":                       "Execute command",
            "PTY,raw,echo=0":                   "Upgrade to PTY shell",
            "SSL-LISTEN":                       "SSL listener",
        },
        use_cases=[
            "Fully interactive TTY shell upgrade",
            "Encrypted reverse shells",
            "Port forwarding",
            "Pivoting",
        ],
        output_formats=["text", "piped"],
        avg_time_seconds=5,
        risk_level=RiskLevel.HIGH,
        keywords=["shell", "tty", "upgrade", "forward", "pivot", "encrypted"],
    ),

    # ══════════════════════════════════════════
    # SNIFFING & SPOOFING
    # ══════════════════════════════════════════

    KaliTool(
        name="wireshark",
        category=Category.SNIFFING,
        subcategory="packet_analysis",
        description="GUI network protocol analyzer — capture and analyze packets",
        syntax="wireshark  (GUI) | tshark [options]  (CLI)",
        common_flags={
            "-i <iface>":       "Interface",
            "-f <filter>":      "Capture filter",
            "-Y <filter>":      "Display filter",
            "-r <file>":        "Read pcap file",
            "-w <file>":        "Write pcap file",
            "-T fields":        "Field output",
            "-e <field>":       "Extract field",
        },
        use_cases=[
            "Network traffic analysis",
            "Credential capture on HTTP/FTP",
            "Protocol analysis",
            "Malware traffic analysis",
        ],
        output_formats=["pcap", "pcapng", "text", "json", "xml"],
        avg_time_seconds=0,
        risk_level=RiskLevel.MEDIUM,
        keywords=["packet", "capture", "sniff", "analyze", "network", "traffic"],
    ),

    KaliTool(
        name="tcpdump",
        category=Category.SNIFFING,
        subcategory="packet_capture",
        description="Command-line packet analyzer",
        syntax="tcpdump [options] [expression]",
        common_flags={
            "-i <iface>":    "Interface",
            "-w <file>":     "Write to pcap",
            "-r <file>":     "Read pcap",
            "-n":            "No DNS resolution",
            "-v":            "Verbose",
            "-A":            "Print ASCII",
            "-X":            "Print hex + ASCII",
            "port <n>":      "Filter by port",
            "host <ip>":     "Filter by host",
            "-c <n>":        "Capture n packets",
        },
        use_cases=[
            "Packet capture on CLI",
            "Traffic filtering and analysis",
            "Remote capture via SSH",
        ],
        output_formats=["pcap", "text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.MEDIUM,
        keywords=["capture", "packet", "cli", "traffic", "filter", "sniff"],
    ),

    KaliTool(
        name="ettercap",
        category=Category.SNIFFING,
        subcategory="mitm",
        description="Man-in-the-middle attack suite — ARP poisoning, sniffing, filtering",
        syntax="ettercap [options] [target1] [target2]",
        common_flags={
            "-T":             "Text mode",
            "-G":             "GTK GUI",
            "-i <iface>":     "Interface",
            "-M arp":         "ARP poisoning MITM",
            "-P <plugin>":    "Load plugin",
            "-w <file>":      "Write pcap",
            "//":             "All hosts on subnet",
        },
        use_cases=[
            "ARP poisoning",
            "Network sniffing",
            "Credential interception on HTTP",
            "DNS spoofing",
        ],
        output_formats=["text", "pcap"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["mitm", "arp", "poison", "sniff", "intercept", "credential"],
    ),

    # ══════════════════════════════════════════
    # FORENSICS & REVERSE ENGINEERING
    # ══════════════════════════════════════════

    KaliTool(
        name="binwalk",
        category=Category.FORENSICS,
        subcategory="firmware_analysis",
        description="Firmware analysis — extract and analyze binary files",
        syntax="binwalk [options] <file>",
        common_flags={
            "-e":          "Extract files",
            "-M":          "Recursive extraction",
            "-B":          "Signature scan",
            "-E":          "Entropy analysis",
            "-A":          "Opcodes scan",
            "--dd=<type>": "Extract specific type",
        },
        use_cases=[
            "Firmware extraction",
            "Hidden file detection",
            "Binary analysis",
            "CTF file analysis",
        ],
        output_formats=["text", "extracted files"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["firmware", "binary", "extract", "forensics", "ctf", "analyze"],
    ),

    KaliTool(
        name="volatility",
        category=Category.FORENSICS,
        subcategory="memory_forensics",
        description="Advanced memory forensics framework",
        syntax="volatility -f <memory_dump> --profile=<profile> <plugin>",
        common_flags={
            "-f <file>":          "Memory dump file",
            "--profile=<p>":      "OS profile",
            "imageinfo":          "Identify profile",
            "pslist":             "List processes",
            "pstree":             "Process tree",
            "cmdline":            "Command lines",
            "netscan":            "Network connections",
            "filescan":           "Scan for files",
            "dumpfiles":          "Extract files",
            "hashdump":           "Extract hashes",
            "malfind":            "Find injected code",
        },
        use_cases=[
            "Memory dump analysis",
            "Malware detection in memory",
            "Credential extraction from RAM",
            "Process and network analysis",
        ],
        output_formats=["text", "json", "sqlite"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["memory", "forensics", "dump", "malware", "analysis", "ram"],
    ),

    KaliTool(
        name="autopsy",
        category=Category.FORENSICS,
        subcategory="disk_forensics",
        description="Digital forensics platform — disk image analysis",
        syntax="autopsy  (web interface)",
        common_flags={},
        use_cases=[
            "Disk image analysis",
            "Deleted file recovery",
            "Timeline analysis",
            "Keyword search",
        ],
        output_formats=["html", "gui"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["forensics", "disk", "image", "deleted", "recovery", "analysis"],
        notes="GUI only. Access at http://localhost:9999/autopsy",
    ),

    KaliTool(
        name="gdb",
        category=Category.REVERSE_ENG,
        subcategory="debugging",
        description="GNU Debugger — debug binaries, analyze memory, set breakpoints",
        syntax="gdb [options] <binary>",
        common_flags={
            "run":              "Run program",
            "break <loc>":      "Set breakpoint",
            "info breakpoints": "List breakpoints",
            "continue":         "Continue execution",
            "next":             "Step over",
            "step":             "Step into",
            "print <var>":      "Print variable",
            "x/<n>x <addr>":    "Examine memory",
            "disassemble":      "Disassemble",
            "info registers":   "Show registers",
        },
        use_cases=[
            "Binary debugging",
            "Buffer overflow analysis",
            "Exploit development",
            "CTF binary challenges",
        ],
        output_formats=["text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["debug", "binary", "exploit", "buffer", "overflow", "ctf", "reverse"],
        notes="Install pwndbg or peda for enhanced GDB experience",
    ),

    KaliTool(
        name="radare2",
        category=Category.REVERSE_ENG,
        subcategory="disassembly",
        description="Open-source reverse engineering framework",
        syntax="r2 [options] <binary>",
        common_flags={
            "aaa":      "Analyze all",
            "afl":      "List functions",
            "pdf":      "Disassemble function",
            "px":       "Print hexdump",
            "iz":       "List strings",
            "iI":       "Binary info",
            "s <addr>": "Seek to address",
            "V":        "Visual mode",
        },
        use_cases=[
            "Binary reverse engineering",
            "Malware analysis",
            "CTF reverse engineering",
            "Vulnerability research",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["reverse", "disassemble", "binary", "analysis", "malware", "ctf"],
    ),

    KaliTool(
        name="strings",
        category=Category.REVERSE_ENG,
        subcategory="static_analysis",
        description="Extract printable strings from binary files",
        syntax="strings [options] <file>",
        common_flags={
            "-n <min>":  "Minimum string length (default 4)",
            "-a":        "Scan entire file",
            "-e l":      "16-bit little-endian",
            "-e b":      "16-bit big-endian",
        },
        use_cases=[
            "Extract URLs/IPs from malware",
            "Find hardcoded credentials in binaries",
            "CTF challenge analysis",
        ],
        output_formats=["text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["strings", "binary", "static", "credentials", "hardcoded", "ctf"],
    ),

    KaliTool(
        name="strace",
        category=Category.REVERSE_ENG,
        subcategory="dynamic_analysis",
        description="Trace system calls made by a process",
        syntax="strace [options] <command>",
        common_flags={
            "-p <pid>":    "Attach to running process",
            "-o <file>":   "Output to file",
            "-e <calls>":  "Filter system calls",
            "-f":          "Follow forks",
            "-v":          "Verbose",
        },
        use_cases=[
            "Dynamic binary analysis",
            "Malware behavior analysis",
            "Debugging file/network access",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["syscall", "trace", "dynamic", "analysis", "binary"],
    ),

    # ══════════════════════════════════════════
    # VULNERABILITY ANALYSIS
    # ══════════════════════════════════════════

    KaliTool(
        name="openvas",
        category=Category.VULN_ANALYSIS,
        subcategory="vulnerability_scanner",
        description="Open Vulnerability Assessment System — comprehensive vuln scanner",
        syntax="gvm-start  (web interface at https://localhost:9392)",
        common_flags={},
        use_cases=[
            "Comprehensive vulnerability assessment",
            "CVE scanning",
            "Compliance checking",
            "Network vulnerability reports",
        ],
        output_formats=["html", "pdf", "xml", "csv"],
        avg_time_seconds=900,
        risk_level=RiskLevel.MEDIUM,
        keywords=["vuln", "scan", "cve", "assessment", "comprehensive", "openvas", "gvm"],
        notes="Setup: gvm-setup && gvm-start. Web UI: https://localhost:9392",
    ),

    KaliTool(
        name="lynis",
        category=Category.VULN_ANALYSIS,
        subcategory="system_audit",
        description="Security auditing tool for Linux/Unix systems",
        syntax="lynis audit system",
        common_flags={
            "audit system":    "Full system audit",
            "audit dockerfile":"Audit Dockerfile",
            "--pentest":       "Non-privileged pentest mode",
            "--quick":         "Quick scan",
            "--report-file":   "Output report path",
        },
        use_cases=[
            "Linux security hardening",
            "System misconfiguration detection",
            "Compliance auditing (PCI, HIPAA)",
        ],
        output_formats=["text", "report file"],
        avg_time_seconds=60,
        risk_level=RiskLevel.LOW,
        keywords=["audit", "linux", "hardening", "compliance", "misconfiguration"],
    ),

    # ══════════════════════════════════════════
    # SOCIAL ENGINEERING
    # ══════════════════════════════════════════

    KaliTool(
        name="setoolkit",
        category=Category.SOCIAL_ENG,
        subcategory="phishing",
        description="Social Engineering Toolkit — phishing, credential harvesting, payloads",
        syntax="setoolkit  (interactive menu)",
        common_flags={
            "1": "Social-Engineering Attacks",
            "2": "Penetration Testing (Fast-Track)",
            "3": "Third Party Modules",
        },
        use_cases=[
            "Credential harvesting pages",
            "Spear phishing emails",
            "USB infection attacks",
            "Payload delivery",
        ],
        output_formats=["interactive", "logs"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["phishing", "credential", "harvest", "social", "engineering", "set"],
        notes="Only use on authorized targets. Highly illegal if misused.",
    ),

    # ══════════════════════════════════════════
    # REPORTING
    # ══════════════════════════════════════════

    KaliTool(
        name="pipal",
        category=Category.REPORTING,
        subcategory="password_analysis",
        description="Password analyzer — statistics and patterns from cracked password lists",
        syntax="pipal <password_file>",
        common_flags={
            "--top <n>":    "Show top N results",
            "--output <f>": "Output file",
        },
        use_cases=[
            "Analyze password patterns after cracking",
            "Password policy reporting",
            "Show most common passwords found",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["password", "analyze", "pattern", "statistics", "report"],
    ),

    KaliTool(
        name="recordmydesktop",
        category=Category.REPORTING,
        subcategory="screen_capture",
        description="Record desktop during pen test for evidence/reporting",
        syntax="recordmydesktop [options]",
        common_flags={
            "--no-sound":       "Disable audio",
            "-o <file>":        "Output file",
            "--fps <n>":        "Frames per second",
            "--width/--height": "Dimensions",
        },
        use_cases=["Screen recording for pentest evidence", "Report documentation"],
        output_formats=["ogv"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["record", "screen", "evidence", "report", "documentation"],
    ),
]


# ──────────────────────────────────────────────
# KNOWLEDGE BASE CLASS
# ──────────────────────────────────────────────

class KaliKnowledgeBase:
    """
    Complete Kali Linux tool knowledge base.

    Usage:
        kb = KaliKnowledgeBase()

        # Get tool by name
        tool = kb.get("nmap")

        # Get tools by category
        web_tools = kb.by_category("web")

        # Recommend tools for a task
        tools = kb.recommend("find open ports")

        # Search
        results = kb.search("sql injection")

        # Get command template
        cmd = kb.build_command("nmap", target="192.168.1.1", flags=["-sV", "-T4"])
    """

    def __init__(self):
        self._tools: Dict[str, KaliTool] = {t.name: t for t in KALI_TOOLS}

    def get(self, name: str) -> Optional[KaliTool]:
        """Get a tool by name"""
        return self._tools.get(name.lower())

    def all_tools(self) -> List[KaliTool]:
        """Return all tools"""
        return list(self._tools.values())

    def by_category(self, category: str) -> List[KaliTool]:
        """Get all tools in a category"""
        cat = Category(category.lower()) if category.lower() in [c.value for c in Category] else None
        if not cat:
            return []
        return [t for t in self._tools.values() if t.category == cat]

    def by_risk(self, risk: str) -> List[KaliTool]:
        """Get tools by risk level"""
        r = RiskLevel(risk.upper())
        return [t for t in self._tools.values() if t.risk_level == r]

    def search(self, query: str) -> List[KaliTool]:
        """
        Search tools by name, description, keywords, or use cases.
        Returns results sorted by relevance.
        """
        query_lower = query.lower()
        scored = []

        for tool in self._tools.values():
            score = 0
            if query_lower in tool.name:
                score += 10
            if query_lower in tool.description.lower():
                score += 5
            for kw in tool.keywords:
                if query_lower in kw or kw in query_lower:
                    score += 3
            for uc in tool.use_cases:
                if query_lower in uc.lower():
                    score += 2
            if score > 0:
                scored.append((score, tool))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored]

    def recommend(self, task_description: str) -> List[KaliTool]:
        """
        Recommend tools for a given task description.
        Returns top 5 most relevant tools.
        """
        results = self.search(task_description)
        return results[:5]

    def fastest_for_category(self, category: str) -> List[KaliTool]:
        """Get tools for a category sorted by speed"""
        tools = self.by_category(category)
        return sorted(tools, key=lambda t: t.avg_time_seconds)

    def build_command(
        self,
        tool_name: str,
        target: str,
        flags: Optional[List[str]] = None
    ) -> str:
        """
        Build a command string for a tool.

        Example:
            kb.build_command("nmap", "192.168.1.1", ["-sV", "-T4"])
            -> "nmap -sV -T4 192.168.1.1"
        """
        tool = self.get(tool_name)
        if not tool:
            return f"{tool_name} {target}"
        flags_str = " ".join(flags) if flags else ""
        base = tool.syntax.split()[0]
        return f"{base} {flags_str} {target}".strip()

    def summary(self) -> Dict[str, Any]:
        """Return a summary of the knowledge base"""
        by_cat = {}
        for tool in self._tools.values():
            cat = tool.category.value
            by_cat[cat] = by_cat.get(cat, 0) + 1
        return {
            "total_tools": len(self._tools),
            "by_category": by_cat,
            "categories": [c.value for c in Category],
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export full knowledge base as dict"""
        return {name: tool.to_dict() for name, tool in self._tools.items()}


# ──────────────────────────────────────────────
# DEMO
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import json

    kb = KaliKnowledgeBase()

    print("=" * 60)
    print("NOVA KALI KNOWLEDGE BASE — DEMO")
    print("=" * 60)

    summary = kb.summary()
    print(f"\nTotal tools mapped: {summary['total_tools']}")
    print("\nBy category:")
    for cat, count in sorted(summary["by_category"].items()):
        print(f"  {cat:<25} {count} tools")

    print("\n--- Tool lookup: nmap ---")
    nmap = kb.get("nmap")
    if nmap:
        print(f"  Name     : {nmap.name}")
        print(f"  Category : {nmap.category.value}")
        print(f"  Syntax   : {nmap.syntax}")
        print(f"  Risk     : {nmap.risk_level.value}")
        print(f"  Use cases: {', '.join(nmap.use_cases[:2])}")

    print("\n--- Recommend tools for 'find open ports' ---")
    for t in kb.recommend("find open ports"):
        print(f"  {t.name:<15} [{t.category.value}] — {t.description[:60]}")

    print("\n--- Recommend tools for 'crack password hash' ---")
    for t in kb.recommend("crack password hash"):
        print(f"  {t.name:<15} [{t.category.value}] — {t.description[:60]}")

    print("\n--- Fastest web tools ---")
    for t in kb.fastest_for_category("web"):
        print(f"  {t.name:<15} ~{t.avg_time_seconds}s")

    print("\n--- Build command ---")
    cmd = kb.build_command("nmap", "192.168.1.1", ["-sV", "-T4", "-p-"])
    print(f"  {cmd}")

    print("\n--- Search: 'sql injection' ---")
    for t in kb.search("sql injection"):
        print(f"  {t.name}")

    print("\n" + "=" * 60)
    print("Integration with NovaKaliAgent:")
    print("  from nova_kali_knowledge_base import KaliKnowledgeBase")
    print("  self.kali_knowledge = KaliKnowledgeBase()")
    print("  tools = self.kali_knowledge.recommend(task_description)")
    print("=" * 60)
