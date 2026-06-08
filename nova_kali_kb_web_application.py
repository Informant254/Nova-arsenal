"""
NOVA KALI KNOWLEDGE BASE — WEB APPLICATION EXPANSION
======================================================
Full expansion of the Web Application Testing category.
Add this to nova_kali_knowledge_base.py by importing and extending KALI_TOOLS.

Subcategories covered:
- CMS Scanning
- Web Crawling & Spidering
- API Testing
- WebDAV Testing
- Authentication Testing
- HTTP Analysis & Manipulation
- JavaScript & Client-Side Testing
- Web Vulnerability Scanners
- CMS-Specific Tools
- File Inclusion Testing
- CORS & Header Analysis
- Web Shells & Upload Testing

Usage:
    from nova_kali_kb_web_application import WEB_APPLICATION_TOOLS
    from nova_kali_knowledge_base import KALI_TOOLS, KaliKnowledgeBase

    KALI_TOOLS.extend(WEB_APPLICATION_TOOLS)
    kb = KaliKnowledgeBase()
"""

from nova_kali_knowledge_base import KaliTool, Category, RiskLevel

WEB_APPLICATION_TOOLS = [

    # ══════════════════════════════════════════
    # CMS SCANNING
    # ══════════════════════════════════════════

    KaliTool(
        name="wpscan",
        category=Category.WEB,
        subcategory="cms_scanning",
        description="WordPress vulnerability scanner — enumerate plugins, themes, users, and known CVEs",
        syntax="wpscan --url <url> [options]",
        common_flags={
            "--url <url>":              "Target WordPress URL",
            "--enumerate p":            "Enumerate plugins",
            "--enumerate t":            "Enumerate themes",
            "--enumerate u":            "Enumerate users",
            "--enumerate vp":           "Vulnerable plugins only",
            "--enumerate vt":           "Vulnerable themes only",
            "--enumerate ap":           "All plugins",
            "--api-token <token>":      "WPScan API token (for CVE data)",
            "--passwords <file>":       "Password brute force",
            "--usernames <file>":       "Username list",
            "--plugins-detection aggressive": "Aggressive plugin detection",
            "--force":                  "Force scan even if not WordPress",
            "-o <file>":                "Output file",
            "--format json":            "JSON output",
            "--proxy <proxy>":          "Use proxy",
            "--random-user-agent":      "Random user agent",
        },
        use_cases=[
            "WordPress version detection",
            "Vulnerable plugin/theme discovery",
            "WordPress user enumeration",
            "xmlrpc.php brute force",
            "WordPress security auditing",
        ],
        output_formats=["text", "json", "cli"],
        avg_time_seconds=60,
        risk_level=RiskLevel.MEDIUM,
        keywords=["wordpress", "wp", "cms", "plugin", "theme", "user", "enum", "vuln"],
        notes="Install: apt install wpscan. Get free API token at wpscan.com for CVE data.",
    ),

    KaliTool(
        name="joomscan",
        category=Category.WEB,
        subcategory="cms_scanning",
        description="Joomla vulnerability scanner — detect Joomla version, components, and vulnerabilities",
        syntax="joomscan -u <url> [options]",
        common_flags={
            "-u <url>":         "Target Joomla URL",
            "-ec":              "Enumerate components",
            "--cookie <c>":     "Set cookie",
            "--user-agent <u>": "Custom user agent",
            "--proxy <p>":      "Use proxy",
            "--timeout <n>":    "Timeout",
            "--about":          "About the tool",
        },
        use_cases=[
            "Joomla version fingerprinting",
            "Component vulnerability detection",
            "Joomla misconfiguration discovery",
            "Admin panel detection",
        ],
        output_formats=["text"],
        avg_time_seconds=45,
        risk_level=RiskLevel.MEDIUM,
        keywords=["joomla", "cms", "component", "vuln", "scan", "version"],
        notes="Install: apt install joomscan. OWASP project.",
    ),

    KaliTool(
        name="droopescan",
        category=Category.WEB,
        subcategory="cms_scanning",
        description="Plugin-based CMS scanner — supports Drupal, SilverStripe, WordPress, Joomla",
        syntax="droopescan scan <cms> -u <url>",
        common_flags={
            "scan drupal -u <url>":     "Scan Drupal site",
            "scan silverstripe -u <url>":"Scan SilverStripe",
            "scan wordpress -u <url>":  "Scan WordPress",
            "-t <n>":                   "Threads",
            "--output json":            "JSON output",
            "-U <file>":                "URL list file",
        },
        use_cases=[
            "Drupal version and plugin enumeration",
            "Multi-CMS scanning",
            "Batch CMS scanning from URL list",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=60,
        risk_level=RiskLevel.MEDIUM,
        keywords=["drupal", "cms", "scan", "plugin", "silverstripe", "multi"],
        notes="Install: pip install droopescan. Best for Drupal scanning.",
    ),

    KaliTool(
        name="plecost",
        category=Category.WEB,
        subcategory="cms_scanning",
        description="WordPress plugin finder and vulnerability identifier",
        syntax="plecost [options] <url>",
        common_flags={
            "-u <url>":         "Target URL",
            "-n <n>":           "Number of plugins to check",
            "--update":         "Update plugin list",
            "--proxy <p>":      "Use proxy",
            "-o <file>":        "Output file",
        },
        use_cases=[
            "WordPress plugin vulnerability scanning",
            "Quick WordPress plugin enumeration",
        ],
        output_formats=["text", "json", "xml"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["wordpress", "plugin", "vuln", "scan", "enum"],
        notes="Install: apt install plecost.",
    ),

    # ══════════════════════════════════════════
    # WEB CRAWLING & SPIDERING
    # ══════════════════════════════════════════

    KaliTool(
        name="skipfish",
        category=Category.WEB,
        subcategory="web_crawling",
        description="Active web application security recon — recursive crawl with dictionary-based probes",
        syntax="skipfish -o <output_dir> <url>",
        common_flags={
            "-o <dir>":         "Output directory (required)",
            "-W <wordlist>":    "Custom wordlist",
            "-S <wordlist>":    "Include wordlist",
            "-u <user:pass>":   "HTTP auth credentials",
            "-c <cookie>":      "Cookie string",
            "-b <browser>":     "Browser type (ie/ffox/phone)",
            "-m <n>":           "Max request rate",
            "-t <n>":           "Timeout",
            "-g <n>":           "Max descendants per node",
            "-r <n>":           "Max requests total",
            "--auth-form <u>":  "Form-based auth URL",
            "--auth-user <u>":  "Form auth username",
            "--auth-pass <p>":  "Form auth password",
        },
        use_cases=[
            "Comprehensive web app crawling and probing",
            "Automated vulnerability detection (XSS, SQLi, etc.)",
            "Sitemap generation",
            "Web application security assessment",
        ],
        output_formats=["html report", "directory"],
        avg_time_seconds=300,
        risk_level=RiskLevel.MEDIUM,
        keywords=["crawl", "spider", "scan", "automated", "recon", "web", "sitemap"],
        notes="Install: apt install skipfish. Opens HTML report in output dir.",
    ),

    KaliTool(
        name="httrack",
        category=Category.WEB,
        subcategory="web_crawling",
        description="Website copier — mirror entire websites for offline analysis",
        syntax="httrack <url> -O <output_dir> [options]",
        common_flags={
            "-O <dir>":         "Output directory",
            "-r <n>":           "Mirror depth",
            "-c <n>":           "Connections",
            "-%e0":             "Get all files",
            "-A <n>":           "Max file size",
            "--robots=0":       "Ignore robots.txt",
            "-u2":              "User agent: Firefox",
        },
        use_cases=[
            "Mirror website for offline analysis",
            "Discover hidden files and directories",
            "Analyze site structure",
            "Phishing page cloning (authorized)",
        ],
        output_formats=["mirrored website files"],
        avg_time_seconds=120,
        risk_level=RiskLevel.LOW,
        keywords=["mirror", "clone", "crawl", "offline", "website", "copy", "spider"],
        notes="Install: apt install httrack.",
    ),

    KaliTool(
        name="parsero",
        category=Category.WEB,
        subcategory="web_crawling",
        description="robots.txt auditor — read and test paths listed in robots.txt",
        syntax="parsero -u <url> [options]",
        common_flags={
            "-u <url>":     "Target URL",
            "-sb":          "Search Bing for disallowed paths",
            "-p":           "Check all paths with HTTP request",
        },
        use_cases=[
            "Find hidden directories via robots.txt",
            "Discover admin panels and sensitive paths",
            "Test if disallowed paths are actually accessible",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["robots", "txt", "hidden", "disallow", "directory", "path", "discover"],
        notes="Install: apt install parsero. Robots.txt disallowed paths often reveal sensitive areas.",
    ),

    # ══════════════════════════════════════════
    # API TESTING
    # ══════════════════════════════════════════

    KaliTool(
        name="arjun",
        category=Category.WEB,
        subcategory="api_testing",
        description="HTTP parameter discovery — find hidden GET/POST parameters in web apps and APIs",
        syntax="arjun -u <url> [options]",
        common_flags={
            "-u <url>":         "Target URL",
            "-m <GET|POST>":    "HTTP method",
            "-w <wordlist>":    "Parameter wordlist",
            "-o <file>":        "Output JSON file",
            "--stable":         "Stable mode (slower but accurate)",
            "-t <n>":           "Threads",
            "--include <p>":    "Include params always",
            "--headers <h>":    "Custom headers",
        },
        use_cases=[
            "Discover hidden API parameters",
            "Find undocumented GET/POST parameters",
            "API endpoint parameter fuzzing",
            "Mass assignment vulnerability discovery",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["api", "parameter", "hidden", "discover", "get", "post", "fuzz"],
        notes="Install: pip install arjun. Essential for API security testing.",
    ),

    KaliTool(
        name="kiterunner",
        category=Category.WEB,
        subcategory="api_testing",
        description="Contextual content discovery for APIs — find API endpoints and routes",
        syntax="kr scan <url> -w <wordlist>",
        common_flags={
            "scan <url>":       "Scan target URL",
            "brute <url>":      "Brute force routes",
            "-w <wordlist>":    "API routes wordlist",
            "-A <spec>":        "Use OpenAPI/Swagger spec",
            "-x <n>":           "Threads",
            "--delay <ms>":     "Delay between requests",
            "-o <file>":        "Output file",
            "--fail-status-codes <c>": "Codes to ignore",
        },
        use_calls=[
            "API endpoint discovery",
            "REST API route enumeration",
            "Find undocumented API routes",
            "OpenAPI spec-based scanning",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["api", "endpoint", "route", "discover", "rest", "openapi", "swagger"],
        notes="git clone https://github.com/assetnote/kiterunner. Best tool for API route discovery.",
    ),

    KaliTool(
        name="jwt-tool",
        category=Category.WEB,
        subcategory="api_testing",
        description="JWT (JSON Web Token) testing toolkit — decode, forge, and attack JWTs",
        syntax="python3 jwt_tool.py <token> [options]",
        common_flags={
            "-t <token>":       "JWT token to analyze",
            "-d":               "Decode token",
            "-C -d <wordlist>": "Crack HS256 secret",
            "-X a":             "Alg:none attack",
            "-X s":             "Self-signed RS/EC key",
            "-X k":             "Key confusion attack",
            "-S hs256 -p <s>":  "Sign with new secret",
            "-I -hc <c> <v>":   "Inject claim",
            "--proxy <p>":      "Use proxy",
        },
        use_cases=[
            "Decode and analyze JWT tokens",
            "Test alg:none vulnerability",
            "Crack weak JWT secrets",
            "Key confusion attacks (RS256 -> HS256)",
            "JWT claim injection",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.HIGH,
        keywords=["jwt", "token", "crack", "forge", "alg", "none", "api", "auth"],
        notes="git clone https://github.com/ticarpi/jwt_tool. Essential for API auth testing.",
    ),

    # ══════════════════════════════════════════
    # WEBDAV TESTING
    # ══════════════════════════════════════════

    KaliTool(
        name="davtest",
        category=Category.WEB,
        subcategory="webdav_testing",
        description="Test WebDAV servers — check which file types can be uploaded and executed",
        syntax="davtest -url <url> [options]",
        common_flags={
            "-url <url>":       "Target WebDAV URL",
            "-auth <u:p>":      "Basic auth credentials",
            "-cleanup":         "Delete uploaded files after test",
            "-directory <d>":   "Upload to specific directory",
            "-uploadfile <f>":  "Upload specific file",
            "-uploadloc <p>":   "Upload to specific path",
            "-move":            "Use MOVE method to bypass filters",
            "-copy":            "Use COPY method",
        },
        use_cases=[
            "Test WebDAV file upload capabilities",
            "Determine executable file types on WebDAV",
            "WebDAV misconfiguration discovery",
            "Remote code execution via WebDAV upload",
        ],
        output_formats=["text"],
        avg_time_seconds=15,
        risk_level=RiskLevel.HIGH,
        keywords=["webdav", "upload", "execute", "file", "dav", "rce", "misconfiguration"],
        notes="Install: apt install davtest.",
    ),

    KaliTool(
        name="cadaver",
        category=Category.WEB,
        subcategory="webdav_testing",
        description="Command-line WebDAV client — browse, upload, download, and manage WebDAV resources",
        syntax="cadaver <url>",
        common_flags={
            "ls":               "List directory",
            "put <file>":       "Upload file",
            "get <file>":       "Download file",
            "delete <file>":    "Delete file",
            "mkdir <dir>":      "Create directory",
            "move <src> <dst>": "Move/rename file",
            "open <url>":       "Open new URL",
            "close":            "Close connection",
        },
        use_cases=[
            "Interactive WebDAV browsing",
            "Upload shells to WebDAV servers",
            "Download files from WebDAV",
            "Test WebDAV write permissions",
        ],
        output_formats=["interactive", "text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.HIGH,
        keywords=["webdav", "client", "upload", "browse", "dav", "interactive", "shell"],
        notes="Install: apt install cadaver. Use with davtest to upload shells.",
    ),

    # ══════════════════════════════════════════
    # AUTHENTICATION TESTING
    # ══════════════════════════════════════════

    KaliTool(
        name="crowbar",
        category=Category.WEB,
        subcategory="authentication_testing",
        description="Brute force tool for RDP, VNC, OpenVPN, SSH key-based auth",
        syntax="crowbar -b <service> -s <target> -u <user> -C <wordlist>",
        common_flags={
            "-b rdp":           "RDP brute force",
            "-b vnc":           "VNC brute force",
            "-b openvpn":       "OpenVPN brute force",
            "-b sshkey":        "SSH key brute force",
            "-s <target>":      "Target IP/CIDR",
            "-u <user>":        "Username",
            "-U <file>":        "Username file",
            "-C <wordlist>":    "Password/key wordlist",
            "-n <n>":           "Threads",
            "-o <file>":        "Output file",
            "-v":               "Verbose",
        },
        use_cases=[
            "RDP credential brute force",
            "VNC password brute force",
            "SSH private key brute force",
            "OpenVPN credential testing",
        ],
        output_formats=["text"],
        avg_time_seconds=120,
        risk_level=RiskLevel.HIGH,
        keywords=["rdp", "vnc", "brute", "force", "ssh", "key", "openvpn", "auth"],
        notes="Install: apt install crowbar. Specialized for protocols Hydra struggles with.",
    ),

    KaliTool(
        name="changeme",
        category=Category.WEB,
        subcategory="authentication_testing",
        description="Default credential scanner — test hundreds of devices for default passwords",
        syntax="changeme [options] <target>",
        common_flags={
            "<target>":         "Target IP, range, or URL",
            "--protocols <p>":  "Protocols to test",
            "--threads <n>":    "Threads",
            "--timeout <n>":    "Timeout",
            "--output <file>":  "Output file",
            "--fingerprint":    "Fingerprint only, no auth",
            "--dryrun":         "Don't actually attempt auth",
        },
        use_cases=[
            "Scan for default credentials on network devices",
            "Test routers, cameras, printers for defaults",
            "Post-compromise default cred sweep",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["default", "credentials", "password", "router", "camera", "iot", "scan"],
        notes="git clone https://github.com/ztgrace/changeme. Covers 500+ device default creds.",
    ),

    # ══════════════════════════════════════════
    # HTTP ANALYSIS & MANIPULATION
    # ══════════════════════════════════════════

    KaliTool(
        name="mitmproxy",
        category=Category.WEB,
        subcategory="http_analysis",
        description="Interactive HTTPS proxy — intercept, inspect, modify and replay HTTP/HTTPS traffic",
        syntax="mitmproxy [options]  |  mitmdump [options]  |  mitmweb [options]",
        common_flags={
            "-p <port>":            "Listen port (default 8080)",
            "-m transparent":       "Transparent proxy mode",
            "-m socks5":            "SOCKS5 proxy mode",
            "--ssl-insecure":       "Skip SSL verification",
            "-s <script>":          "Load addon script",
            "-w <file>":            "Write traffic to file",
            "-r <file>":            "Read traffic from file",
            "--set upstream_cert=false": "Don't fetch upstream cert",
            "mitmdump -w <file>":   "Capture traffic to file",
            "mitmweb":              "Web UI interface",
        },
        use_cases=[
            "Intercept and modify HTTPS traffic",
            "Mobile app traffic analysis",
            "API traffic inspection",
            "Replay and modify requests",
            "Script-based traffic manipulation",
        ],
        output_formats=["interactive", "flow files", "har"],
        avg_time_seconds=0,
        risk_level=RiskLevel.MEDIUM,
        keywords=["proxy", "intercept", "https", "mitm", "traffic", "modify", "replay", "mobile"],
        notes="Install: apt install mitmproxy. Install cert on device: mitm.it",
    ),

    KaliTool(
        name="hurl",
        category=Category.WEB,
        subcategory="http_analysis",
        description="HTTP request runner — run and test HTTP requests defined in plain text files",
        syntax="hurl <file.hurl>",
        common_flags={
            "--test":           "Test mode (assert responses)",
            "--variables-file": "Variables file",
            "--variable <k=v>": "Set variable",
            "--proxy <p>":      "Use proxy",
            "--insecure":       "Skip SSL verification",
            "--verbose":        "Verbose output",
            "--json":           "JSON output",
            "--html <file>":    "HTML report",
        },
        use_cases=[
            "API testing with plain text request files",
            "Automate HTTP request sequences",
            "Test REST APIs with assertions",
        ],
        output_formats=["text", "json", "html"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["http", "request", "api", "test", "automate", "rest", "plain text"],
        notes="Install: apt install hurl. Alternative to curl for complex request sequences.",
    ),

    KaliTool(
        name="httprint",
        category=Category.WEB,
        subcategory="http_analysis",
        description="Web server fingerprinting — identify web server type and version via banner analysis",
        syntax="httprint -h <host> -s <signatures>",
        common_flags={
            "-h <host>":        "Target host",
            "-s <sigfile>":     "Signatures file",
            "-o <file>":        "Output file (html/xml/text)",
            "-P0":              "No ping",
            "-t <n>":           "Timeout",
        },
        use_cases=[
            "Web server version fingerprinting",
            "Identify server type even with modified banners",
            "Web server banner analysis",
        ],
        output_formats=["text", "html", "xml"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["fingerprint", "server", "banner", "version", "identify", "http"],
        notes="Install: apt install httprint.",
    ),

    KaliTool(
        name="padbuster",
        category=Category.WEB,
        subcategory="http_analysis",
        description="Automated padding oracle attack tool — decrypt and encrypt CBC-mode encrypted data",
        syntax="padbuster <url> <encrypted_sample> <block_size> [options]",
        common_flags={
            "<url>":            "Target URL with encrypted param",
            "<sample>":         "Encrypted sample value",
            "<blocksize>":      "Block size (8 or 16)",
            "-encoding <n>":    "0=Base64, 1=HEX, 2=NET, 3=URL, 4=NET_URL",
            "-cookies <c>":     "Cookie string",
            "-post <data>":     "POST data",
            "-plaintext <p>":   "Plaintext to encrypt",
            "-prefix <p>":      "Prefix for payload",
        },
        use_cases=[
            "Exploit padding oracle vulnerabilities",
            "Decrypt CBC-encrypted session tokens",
            "Forge encrypted values",
            "POODLE-style attacks",
        ],
        output_formats=["text"],
        avg_time_seconds=120,
        risk_level=RiskLevel.HIGH,
        keywords=["padding", "oracle", "cbc", "decrypt", "encrypt", "session", "token", "crypto"],
        notes="Install: apt install padbuster.",
    ),

    # ══════════════════════════════════════════
    # WEB VULNERABILITY SCANNERS
    # ══════════════════════════════════════════

    KaliTool(
        name="w3af",
        category=Category.WEB,
        subcategory="web_vuln_scanner",
        description="Web Application Attack and Audit Framework — comprehensive web vuln scanner",
        syntax="w3af_console  |  w3af_gui",
        common_flags={
            "plugins":                  "List available plugins",
            "plugins audit xss,sqli":   "Enable XSS and SQLi plugins",
            "target set target <url>":  "Set target URL",
            "start":                    "Start scan",
            "plugins output html_file": "HTML output plugin",
            "http-settings":            "HTTP settings",
        },
        use_cases=[
            "Comprehensive web vulnerability scanning",
            "XSS, SQLi, LFI, RFI detection",
            "CSRF detection",
            "Authentication bypass testing",
            "Web application fuzzing",
        ],
        output_formats=["text", "html", "xml", "json"],
        avg_time_seconds=600,
        risk_level=RiskLevel.HIGH,
        keywords=["web", "vuln", "scan", "xss", "sqli", "lfi", "rfi", "comprehensive", "framework"],
        notes="Install: apt install w3af. Use w3af_console for CLI. Most comprehensive free web scanner.",
    ),

    KaliTool(
        name="vega",
        category=Category.WEB,
        subcategory="web_vuln_scanner",
        description="GUI web vulnerability scanner — automated and manual web app testing",
        syntax="vega  (GUI application)",
        common_flags={
            "Scanner":          "Automated scan mode",
            "Proxy":            "Manual testing via proxy",
            "Identity":         "Set scan identity",
            "Authentication":   "Configure auth",
        },
        use_cases=[
            "GUI-based web vulnerability scanning",
            "XSS, SQLi, header injection detection",
            "Manual testing via integrated proxy",
            "Beginner-friendly web scanning",
        ],
        output_formats=["gui", "html"],
        avg_time_seconds=0,
        risk_level=RiskLevel.MEDIUM,
        keywords=["gui", "web", "scan", "xss", "sqli", "visual", "proxy", "beginner"],
        notes="Install: apt install vega. Java-based GUI tool.",
    ),

    KaliTool(
        name="wapiti",
        category=Category.WEB,
        subcategory="web_vuln_scanner",
        description="Web application vulnerability scanner — crawls and fuzzes web apps for common vulns",
        syntax="wapiti -u <url> [options]",
        common_flags={
            "-u <url>":             "Target URL",
            "-m <modules>":         "Modules to use (xss,sql,ssrf,xxe,etc.)",
            "--list-modules":       "List all modules",
            "-o <file>":            "Output report file",
            "-f <format>":          "Output format (html/json/xml/txt)",
            "--scope <scope>":      "Scan scope (url/page/folder/domain)",
            "-l <level>":           "Verbosity level",
            "--max-parameters <n>": "Max parameters to fuzz",
            "-p <proxy>":           "Use proxy",
            "--cookie <c>":         "Cookie string",
            "--auth-type <type>":   "Auth type (basic/digest/ntlm)",
            "--auth-cred <u:p>":    "Auth credentials",
        },
        use_cases=[
            "Automated web vulnerability scanning",
            "XSS, SQLi, SSRF, XXE, LFI, RFI detection",
            "Command injection detection",
            "CRLF injection testing",
            "Open redirect detection",
        ],
        output_formats=["html", "json", "xml", "txt"],
        avg_time_seconds=180,
        risk_level=RiskLevel.MEDIUM,
        keywords=["web", "scan", "xss", "sqli", "ssrf", "xxe", "lfi", "automated", "crawl"],
        notes="Install: apt install wapiti. Good open-source alternative to commercial scanners.",
    ),

    KaliTool(
        name="uniscan",
        category=Category.WEB,
        subcategory="web_vuln_scanner",
        description="Web vulnerability scanner — LFI, RFI, RCE, XSS, SQLi detection with Google dorking",
        syntax="uniscan [options]",
        common_flags={
            "-u <url>":     "Target URL",
            "-q":           "Directory check",
            "-w":           "File check",
            "-e":           "robots.txt and sitemap check",
            "-d":           "Dynamic tests (XSS, LFI, RFI, RCE)",
            "-s":           "Static tests",
            "-r":           "Stress tests",
            "-g":           "Google search for target",
            "-j":           "Server fingerprint",
        },
        use_cases=[
            "LFI/RFI vulnerability detection",
            "XSS and SQLi scanning",
            "Google dork-based recon",
            "Directory and file discovery",
        ],
        output_formats=["text", "html"],
        avg_time_seconds=60,
        risk_level=RiskLevel.MEDIUM,
        keywords=["lfi", "rfi", "xss", "sqli", "rce", "web", "scan", "google", "dork"],
        notes="Install: apt install uniscan.",
    ),

    # ══════════════════════════════════════════
    # FILE INCLUSION TESTING
    # ══════════════════════════════════════════

    KaliTool(
        name="fimap",
        category=Category.WEB,
        subcategory="file_inclusion",
        description="Automatic LFI/RFI finder and exploiter — find and exploit file inclusion vulns",
        syntax="fimap [options]",
        common_flags={
            "-u <url>":         "Target URL",
            "-b":               "Blind mode",
            "-H":               "Use HTTP POST",
            "-D":               "Enable auto-hacking",
            "--force-run":      "Force execution",
            "--googler <query>":"Google dork for targets",
            "-x <exploit>":     "Exploit mode",
            "--proc-stdout":    "Read /proc/self/fd/ stdout",
        },
        use_cases=[
            "Automatic LFI/RFI discovery",
            "Local File Inclusion exploitation",
            "Remote File Inclusion exploitation",
            "Log poisoning via LFI",
        ],
        output_formats=["text"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["lfi", "rfi", "file", "inclusion", "local", "remote", "exploit", "auto"],
        notes="Install: apt install fimap.",
    ),

    # ══════════════════════════════════════════
    # CORS & HEADER ANALYSIS
    # ══════════════════════════════════════════

    KaliTool(
        name="corsair",
        category=Category.WEB,
        subcategory="cors_testing",
        description="CORS misconfiguration scanner — test for exploitable CORS policies",
        syntax="python3 corsair.py -u <url>",
        common_flags={
            "-u <url>":         "Target URL",
            "-H <headers>":     "Custom headers",
            "--proxy <p>":      "Use proxy",
            "-v":               "Verbose",
        },
        use_cases=[
            "CORS misconfiguration detection",
            "Wildcard origin testing",
            "Null origin testing",
            "Pre-flight request analysis",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.MEDIUM,
        keywords=["cors", "origin", "header", "misconfiguration", "wildcard", "null"],
        notes="git clone https://github.com/s0md3v/Corsy for a more feature-rich CORS scanner.",
    ),

    KaliTool(
        name="corsy",
        category=Category.WEB,
        subcategory="cors_testing",
        description="CORS misconfiguration scanner — comprehensive CORS bypass testing",
        syntax="python3 corsy.py -u <url>",
        common_flags={
            "-u <url>":         "Single target URL",
            "-i <file>":        "Input file with URLs",
            "-t <n>":           "Threads",
            "--headers <h>":    "Custom headers (JSON)",
            "-q":               "Quiet mode",
            "-d <delay>":       "Delay between requests",
        },
        use_cases=[
            "Bulk CORS misconfiguration scanning",
            "Test all CORS bypass techniques",
            "Origin reflection detection",
            "Pre-domain bypass testing",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.MEDIUM,
        keywords=["cors", "bypass", "origin", "reflection", "misconfiguration", "bulk"],
        notes="git clone https://github.com/s0md3v/Corsy.",
    ),

    KaliTool(
        name="shcheck",
        category=Category.WEB,
        subcategory="header_analysis",
        description="Security headers checker — analyze HTTP security headers on web servers",
        syntax="python3 shcheck.py <url>",
        common_flags={
            "-d":               "Allow HTTP redirects",
            "-i":               "Ignore certificate errors",
            "--json":           "JSON output",
            "--proxy <p>":      "Use proxy",
            "-H <header>":      "Custom request header",
        },
        use_cases=[
            "Check missing security headers (CSP, HSTS, X-Frame-Options)",
            "Web server security header audit",
            "Compliance checking for security headers",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["headers", "security", "csp", "hsts", "xframe", "audit", "check"],
        notes="git clone https://github.com/santoru/shcheck.",
    ),

    # ══════════════════════════════════════════
    # SSRF TESTING
    # ══════════════════════════════════════════

    KaliTool(
        name="ssrfmap",
        category=Category.WEB,
        subcategory="ssrf_testing",
        description="Automatic SSRF fuzzer and exploiter",
        syntax="python3 ssrfmap.py -r <request_file> -p <param>",
        common_flags={
            "-r <file>":        "Request file (Burp format)",
            "-p <param>":       "Parameter to fuzz",
            "-m <module>":      "Module (portscan, readfiles, etc.)",
            "--lhost <ip>":     "Local host for callbacks",
            "--lport <port>":   "Local port for callbacks",
        },
        use_cases=[
            "SSRF vulnerability detection",
            "Internal port scanning via SSRF",
            "Cloud metadata extraction via SSRF",
            "File read via SSRF",
        ],
        output_formats=["text"],
        avg_time_seconds=30,
        risk_level=RiskLevel.HIGH,
        keywords=["ssrf", "server", "side", "request", "forgery", "internal", "cloud"],
        notes="git clone https://github.com/swisskyrepo/SSRFmap.",
    ),

    # ══════════════════════════════════════════
    # XXE TESTING
    # ══════════════════════════════════════════

    KaliTool(
        name="xxetester",
        category=Category.WEB,
        subcategory="xxe_testing",
        description="XXE (XML External Entity) injection testing and exploitation",
        syntax="python3 xxetester.py [options]",
        common_flags={
            "-u <url>":         "Target URL",
            "-f <file>":        "XML file to send",
            "--lhost <ip>":     "Local host for OOB",
            "--lport <port>":   "Local port for OOB",
            "--read <path>":    "File to read via XXE",
        },
        use_cases=[
            "XXE vulnerability detection",
            "File read via XXE",
            "Out-of-band XXE (blind)",
            "SSRF via XXE",
            "DoS via entity expansion",
        ],
        output_formats=["text"],
        avg_time_seconds=15,
        risk_level=RiskLevel.HIGH,
        keywords=["xxe", "xml", "external", "entity", "injection", "oob", "blind", "file"],
        notes="Use Burp Suite XXE extension for more comprehensive testing.",
    ),

    # ══════════════════════════════════════════
    # TEMPLATE INJECTION
    # ══════════════════════════════════════════

    KaliTool(
        name="tplmap",
        category=Category.WEB,
        subcategory="template_injection",
        description="Server-Side Template Injection (SSTI) detection and exploitation",
        syntax="python3 tplmap.py -u <url>",
        common_flags={
            "-u <url>":         "Target URL",
            "-d <data>":        "POST data",
            "-H <header>":      "Custom header",
            "--engine <e>":     "Force template engine",
            "--os-cmd <cmd>":   "Execute OS command",
            "--os-shell":       "Interactive OS shell",
            "--upload <f>":     "Upload file",
            "--download <f>":   "Download file",
            "--tpl-shell":      "Template shell",
        },
        use_cases=[
            "SSTI vulnerability detection",
            "Jinja2/Twig/Mako/Smarty injection",
            "RCE via template injection",
            "File read/write via SSTI",
        ],
        output_formats=["text"],
        avg_time_seconds=30,
        risk_level=RiskLevel.HIGH,
        keywords=["ssti", "template", "injection", "jinja2", "twig", "rce", "server", "side"],
        notes="git clone https://github.com/epinna/tplmap.",
    ),

    # ══════════════════════════════════════════
    # SUBDOMAIN & VHOST TAKEOVER
    # ══════════════════════════════════════════

    KaliTool(
        name="subjack",
        category=Category.WEB,
        subcategory="subdomain_takeover",
        description="Subdomain takeover tool — find subdomains vulnerable to takeover",
        syntax="subjack -w <subdomains> -t <n> -o <output>",
        common_flags={
            "-w <file>":        "Subdomain wordlist",
            "-t <n>":           "Threads",
            "-o <file>":        "Output file",
            "-ssl":             "Check HTTPS",
            "-c <config>":      "Fingerprints config",
            "-v":               "Verbose",
            "-m":               "Manual mode",
        },
        use_cases=[
            "Find dangling DNS records",
            "Identify subdomain takeover opportunities",
            "Azure/AWS/GitHub pages takeover detection",
        ],
        output_formats=["text"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["subdomain", "takeover", "dangling", "dns", "azure", "aws", "github"],
        notes="git clone https://github.com/haccer/subjack.",
    ),

    # ══════════════════════════════════════════
    # WEB CACHE & DESERIALIZATION
    # ══════════════════════════════════════════

    KaliTool(
        name="ysoserial",
        category=Category.WEB,
        subcategory="deserialization",
        description="Java deserialization payload generator — generate gadget chain payloads",
        syntax="java -jar ysoserial.jar <gadget> <command>",
        common_flags={
            "CommonsCollections1 <cmd>": "CC1 gadget chain",
            "CommonsCollections6 <cmd>": "CC6 gadget chain",
            "Spring1 <cmd>":            "Spring gadget chain",
            "URLDNS <url>":             "DNS-based blind detection",
            "--help":                   "List all gadget chains",
        },
        use_cases=[
            "Java deserialization exploitation",
            "Generate gadget chain payloads",
            "Blind deserialization detection via DNS",
            "RCE via Java deserialization",
        ],
        output_formats=["binary payload"],
        avg_time_seconds=2,
        risk_level=RiskLevel.CRITICAL,
        keywords=["java", "deserialize", "gadget", "payload", "rce", "chain", "exploit"],
        notes="Download: https://github.com/frohoff/ysoserial/releases. Requires Java.",
    ),

    KaliTool(
        name="sqlninja",
        category=Category.WEB,
        subcategory="sql_injection",
        description="SQL injection tool targeting Microsoft SQL Server — focus on OS access",
        syntax="sqlninja [options]",
        common_flags={
            "-m <mode>":        "Mode: t(test), f(fingerprint), e(exploit), x(xp_cmdshell)",
            "-f <config>":      "Config file",
            "-v <1-3>":         "Verbosity",
            "-p <port>":        "Local port for reverse shell",
            "-h":               "Help",
        },
        use_cases=[
            "MSSQL injection exploitation",
            "xp_cmdshell command execution",
            "OS access via MSSQL injection",
            "Privilege escalation via MSSQL",
        ],
        output_formats=["text"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["mssql", "sql", "injection", "xp_cmdshell", "os", "access", "windows"],
        notes="Install: apt install sqlninja. Specifically targets Microsoft SQL Server.",
    ),

    KaliTool(
        name="jsql-injection",
        category=Category.WEB,
        subcategory="sql_injection",
        description="Java-based SQL injection tool with GUI — multiple DB types and injection methods",
        syntax="java -jar jsql-injection.jar  (GUI)",
        common_flags={
            "URL field":        "Enter target URL",
            "Strategy":         "Select injection strategy",
            "Database":         "Browse databases",
            "Shell":            "Get web shell",
        },
        use_cases=[
            "GUI-based SQL injection testing",
            "MySQL, PostgreSQL, SQLite, MSSQL, Oracle injection",
            "Automated database extraction",
        ],
        output_formats=["gui"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["sql", "injection", "gui", "java", "mysql", "postgresql", "oracle", "mssql"],
        notes="Download: https://github.com/ron190/jsql-injection/releases. GUI alternative to sqlmap.",
    ),

    KaliTool(
        name="dirsearch",
        category=Category.WEB,
        subcategory="directory_enum",
        description="Advanced web path scanner — fast directory and file brute forcing",
        syntax="dirsearch -u <url> [options]",
        common_flags={
            "-u <url>":         "Target URL",
            "-e <ext>":         "File extensions (e.g. php,html,js)",
            "-w <wordlist>":    "Custom wordlist",
            "-t <n>":           "Threads",
            "-r":               "Recursive scanning",
            "--include-status": "Include specific status codes",
            "--exclude-status": "Exclude specific status codes",
            "-o <file>":        "Output file",
            "--format <fmt>":   "Output format (plain/json/xml/md/csv)",
            "-H <header>":      "Custom header",
            "--proxy <p>":      "Use proxy",
            "-x <codes>":       "Exclude status codes",
            "--random-agent":   "Random user agent",
        },
        use_cases=[
            "Web directory and file brute forcing",
            "Find hidden admin panels",
            "Backup file discovery (.bak, .old)",
            "API endpoint discovery",
            "Recursive directory scanning",
        ],
        output_formats=["text", "json", "xml", "csv", "md"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["directory", "file", "brute", "scan", "hidden", "backup", "fast", "web"],
        notes="Install: apt install dirsearch. More features than gobuster. Built-in wordlists.",
    ),

    KaliTool(
        name="webscarab",
        category=Category.WEB,
        subcategory="http_analysis",
        description="Web application security testing proxy framework — older but feature-rich",
        syntax="webscarab  (GUI application)",
        common_flags={
            "Proxy":            "Intercept HTTP traffic",
            "Spider":           "Crawl website",
            "Fuzzer":           "Fuzz parameters",
            "SessionID Analysis": "Analyze session tokens",
            "XSS/CRLF":        "Test for XSS and CRLF injection",
        },
        use_cases=[
            "HTTP traffic interception and analysis",
            "Session ID analysis",
            "Manual web application testing",
            "Request fuzzing",
        ],
        output_formats=["gui"],
        avg_time_seconds=0,
        risk_level=RiskLevel.MEDIUM,
        keywords=["proxy", "web", "intercept", "session", "fuzz", "gui", "analysis"],
        notes="Install: apt install webscarab. Largely superseded by Burp Suite and ZAP.",
    ),

    KaliTool(
        name="webshag",
        category=Category.WEB,
        subcategory="web_vuln_scanner",
        description="Multi-threaded web server auditor — port scan, spider, URL fuzzing, file scanning",
        syntax="webshag-cli [options] <target>  |  webshag-gui",
        common_flags={
            "-u <url>":         "Target URL",
            "-p <proxy>":       "Use proxy",
            "pscan":            "Port scan mode",
            "spider":           "Spider mode",
            "fuzz":             "URL fuzzing mode",
            "scan":             "File scanning mode",
        },
        use_cases=[
            "Combined port scanning and web crawling",
            "URL fuzzing",
            "Web server file scanning",
        ],
        output_formats=["text", "gui"],
        avg_time_seconds=60,
        risk_level=RiskLevel.MEDIUM,
        keywords=["web", "audit", "spider", "fuzz", "scan", "multi", "thread"],
        notes="Install: apt install webshag.",
    ),
]

# Fix for kiterunner typo
for tool in WEB_APPLICATION_TOOLS:
    if hasattr(tool, 'use_calls'):
        tool.use_cases = tool.use_calls
        del tool.use_calls


# ── Quick stats ───────────────────────────────
if __name__ == "__main__":
    print(f"Web Application expansion: {len(WEB_APPLICATION_TOOLS)} tools")

    subcats = {}
    for t in WEB_APPLICATION_TOOLS:
        subcats[t.subcategory] = subcats.get(t.subcategory, 0) + 1

    print("\nBy subcategory:")
    for sub, count in sorted(subcats.items()):
        print(f"  {sub:<30} {count} tools")

    print("\nIntegrate with knowledge base:")
    print("  from nova_kali_kb_web_application import WEB_APPLICATION_TOOLS")
    print("  from nova_kali_knowledge_base import KALI_TOOLS")
    print("  KALI_TOOLS.extend(WEB_APPLICATION_TOOLS)")
