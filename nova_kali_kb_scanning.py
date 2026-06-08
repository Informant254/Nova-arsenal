"""
NOVA KALI KNOWLEDGE BASE — SCANNING & ENUMERATION EXPANSION
=============================================================
Full expansion of the Scanning & Enumeration category.
Add this to nova_kali_knowledge_base.py by importing and extending KALI_TOOLS.

Subcategories covered:
- Host Discovery
- Port Scanning
- Service Enumeration
- SMB Enumeration
- SNMP Enumeration
- SMTP Enumeration
- SSL/TLS Analysis
- NFS/RPC Enumeration
- Database Enumeration
- Automated Enumeration Frameworks
- Banner Grabbing
- Firewall & IDS Evasion

Usage:
    from nova_kali_kb_scanning import SCANNING_TOOLS
    from nova_kali_knowledge_base import KALI_TOOLS, KaliKnowledgeBase

    KALI_TOOLS.extend(SCANNING_TOOLS)
    kb = KaliKnowledgeBase()
"""

from nova_kali_knowledge_base import KaliTool, Category, RiskLevel

SCANNING_TOOLS = [

    # ══════════════════════════════════════════
    # HOST DISCOVERY
    # ══════════════════════════════════════════

    KaliTool(
        name="netdiscover",
        category=Category.SCANNING,
        subcategory="host_discovery",
        description="Active/passive ARP reconnaissance — discover hosts on local networks without DHCP",
        syntax="netdiscover -r <range> [options]",
        common_flags={
            "-r <range>":   "Scan range (e.g. 192.168.1.0/24)",
            "-i <iface>":   "Network interface",
            "-p":           "Passive mode — only sniff, don't send",
            "-f":           "Fast mode (recommended for auto)",
            "-l <file>":    "Scan ranges from file",
            "-m <file>":    "Scan known MACs from file",
            "-s <ms>":      "Sleep time between ARP requests (ms)",
            "-c <n>":       "Times to send each ARP request",
            "-P":           "Print results parseable format then stop",
            "-N":           "No header (use with -P or -L)",
            "-S":           "Hardcore mode — suppress sleep",
        },
        use_cases=[
            "Discover live hosts on local subnet",
            "Wireless network host discovery without DHCP",
            "Passive ARP traffic analysis",
            "MAC address and vendor identification",
        ],
        output_formats=["text", "parseable"],
        avg_time_seconds=15,
        risk_level=RiskLevel.LOW,
        keywords=["arp", "host", "discover", "local", "network", "mac", "passive", "active"],
        notes="Install: apt install netdiscover. Best for local LAN/WLAN discovery.",
    ),

    KaliTool(
        name="arp-scan",
        category=Category.SCANNING,
        subcategory="host_discovery",
        description="ARP scanner — send ARP packets to discover hosts and identify vendors",
        syntax="arp-scan [options] <target>",
        common_flags={
            "-l / --localnet":      "Scan local network",
            "-I <iface>":           "Network interface",
            "--interface=<iface>":  "Interface (long form)",
            "-r <n>":               "Retry count",
            "-t <ms>":              "Timeout per host (ms)",
            "--bandwidth=<n>":      "Bandwidth limit",
            "--destaddr=<mac>":     "Custom destination MAC",
            "-v":                   "Verbose",
            "-x":                   "Plain output format",
        },
        use_cases=[
            "Fast local network host discovery",
            "Identify device vendors from MAC OUI",
            "Find hosts that block ICMP ping",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["arp", "scan", "local", "host", "vendor", "mac", "oui", "discover"],
        notes="Install: apt install arp-scan. Use: arp-scan --localnet",
    ),

    KaliTool(
        name="hping3",
        category=Category.SCANNING,
        subcategory="host_discovery",
        description="Active network tool — send custom TCP/IP packets, firewall testing, OS fingerprinting",
        syntax="hping3 [options] <target>",
        common_flags={
            "-S":               "SYN flag",
            "-A":               "ACK flag",
            "-F":               "FIN flag",
            "-U":               "URG flag",
            "-R":               "RST flag",
            "-p <port>":        "Destination port",
            "--scan <ports>":   "Port scan mode",
            "-c <n>":           "Packet count",
            "-i <ms>":          "Interval between packets",
            "--flood":          "Send packets as fast as possible",
            "-a <ip>":          "Spoof source IP",
            "--rand-source":    "Random source IP",
            "-d <size>":        "Data size",
            "-1":               "ICMP mode",
            "-2":               "UDP mode",
            "-9 <sig>":         "Listen mode",
            "--traceroute":     "Traceroute mode",
            "-V":               "Verbose",
        },
        use_cases=[
            "Custom packet crafting for firewall testing",
            "OS fingerprinting via TCP/IP stack analysis",
            "Bypass firewall rules with crafted packets",
            "Network testing and stress testing",
            "Idle scan (zombie scan) preparation",
            "Traceroute with custom protocols",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.MEDIUM,
        keywords=["packet", "craft", "tcp", "icmp", "udp", "firewall", "bypass", "flood", "spoof"],
        notes="Install: apt install hping3. Requires root for raw socket access.",
    ),

    KaliTool(
        name="fping",
        category=Category.SCANNING,
        subcategory="host_discovery",
        description="Fast parallel ICMP ping — sweep multiple hosts simultaneously",
        syntax="fping [options] <targets>",
        common_flags={
            "-g <range>":   "Generate target list (e.g. 192.168.1.1/24)",
            "-a":           "Show alive hosts only",
            "-u":           "Show unreachable hosts only",
            "-c <n>":       "Ping count per host",
            "-t <ms>":      "Timeout per host",
            "-q":           "Quiet mode",
            "-s":           "Print summary stats",
            "-A":           "Show IP addresses",
            "-d":           "DNS resolution",
            "-f <file>":    "Read targets from file",
        },
        use_cases=[
            "Fast ICMP sweep of large subnets",
            "Identify live hosts before port scanning",
            "Network availability monitoring",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["ping", "sweep", "icmp", "fast", "parallel", "host", "alive", "discover"],
        notes="Install: apt install fping. Use: fping -a -g 192.168.1.0/24",
    ),

    KaliTool(
        name="zenmap",
        category=Category.SCANNING,
        subcategory="port_scanning",
        description="Official Nmap GUI — visual network scanning and topology mapping",
        syntax="zenmap  (GUI application)",
        common_flags={
            "Intense scan":         "nmap -T4 -A -v",
            "Quick scan":           "nmap -T4 -F",
            "Ping scan":            "nmap -sn",
            "Quick traceroute":     "nmap -sn --traceroute",
            "Slow comprehensive":   "nmap -sS -sU -T4 -A -v -PE -PP -PS80 -PA3389 -PU40125",
        },
        use_cases=[
            "Visual nmap scanning for beginners",
            "Network topology visualization",
            "Save and compare scan results",
            "Profile-based scanning",
        ],
        output_formats=["gui", "xml", "nmap"],
        avg_time_seconds=0,
        risk_level=RiskLevel.MEDIUM,
        keywords=["nmap", "gui", "visual", "topology", "map", "scan"],
        notes="Install: apt install zenmap. GUI wrapper around nmap.",
    ),

    KaliTool(
        name="unicornscan",
        category=Category.SCANNING,
        subcategory="port_scanning",
        description="Stateless TCP/UDP scanner — asynchronous scanning faster than nmap for large networks",
        syntax="unicornscan [options] <target>:<ports>",
        common_flags={
            "-mT":          "TCP scan mode",
            "-mU":          "UDP scan mode",
            "-mTsf":        "TCP SYN/FIN scan",
            "-Iv":          "Verbose with interface info",
            "-r <pps>":     "Packets per second rate",
            "-R <n>":       "Retries",
            "<target>:a":   "All ports",
            "<target>:p":   "Common ports",
            "-l <file>":    "Log to file",
            "-w <file>":    "Write PCAP",
            "-b <size>":    "Receive buffer size",
        },
        use_cases=[
            "Fast TCP/UDP port scanning of large networks",
            "Asynchronous stateless scanning",
            "Banner grabbing",
            "OS and application fingerprinting",
            "PCAP logging during scan",
        ],
        output_formats=["text", "pcap", "database"],
        avg_time_seconds=15,
        risk_level=RiskLevel.MEDIUM,
        keywords=["stateless", "fast", "async", "tcp", "udp", "scan", "large", "network"],
        notes="Install: apt install unicornscan. Faster than nmap on large IP ranges.",
    ),

    # ══════════════════════════════════════════
    # SERVICE ENUMERATION
    # ══════════════════════════════════════════

    KaliTool(
        name="enum4linux",
        category=Category.SCANNING,
        subcategory="smb_enumeration",
        description="Enumerate Windows/Samba systems — users, shares, groups, OS info via SMB/RPC",
        syntax="enum4linux [options] <target>",
        common_flags={
            "-a":           "All simple enumeration (recommended)",
            "-U":           "Get user list",
            "-M":           "Get machine list",
            "-S":           "Get share list",
            "-P":           "Get password policy",
            "-G":           "Get group and member list",
            "-d":           "Detailed output",
            "-u <user>":    "Username (default: none)",
            "-p <pass>":    "Password (default: none)",
            "-r":           "Enumerate users via RID cycling",
            "-R <range>":   "RID range (default: 500-550,1000-1050)",
            "-o":           "Get OS information",
            "-i":           "Get printer info",
            "-n":           "Do nmblookup",
        },
        use_cases=[
            "SMB/Samba user enumeration",
            "Windows share discovery",
            "Password policy extraction",
            "RID cycling for username enumeration",
            "OS information gathering",
        ],
        output_formats=["text"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["smb", "samba", "windows", "enum", "users", "shares", "groups", "policy", "rid"],
        notes="Install: apt install enum4linux. Use -a for full enumeration. Pair with smbclient.",
    ),

    KaliTool(
        name="enum4linux-ng",
        category=Category.SCANNING,
        subcategory="smb_enumeration",
        description="Next-gen enum4linux — faster, JSON/YAML output, LDAP support, better error handling",
        syntax="enum4linux-ng [options] <target>",
        common_flags={
            "-A":           "All simple enumeration",
            "-As":          "All simple + LDAP",
            "-U":           "User enumeration",
            "-G":           "Group enumeration",
            "-S":           "Share enumeration",
            "-P":           "Password policy",
            "-O":           "OS info",
            "-u <user>":    "Username",
            "-p <pass>":    "Password",
            "-H <hash>":    "NTLM hash auth",
            "-oJ <file>":   "JSON output",
            "-oY <file>":   "YAML output",
            "-oA <file>":   "All formats",
            "-v":           "Verbose",
        },
        use_cases=[
            "Modern SMB/Samba enumeration",
            "LDAP-integrated enumeration",
            "Structured JSON output for automation",
            "Kerberos-authenticated enumeration",
        ],
        output_formats=["text", "json", "yaml"],
        avg_time_seconds=25,
        risk_level=RiskLevel.MEDIUM,
        keywords=["smb", "samba", "enum", "modern", "json", "ldap", "kerberos", "next-gen"],
        notes="Install: apt install enum4linux-ng. Preferred over enum4linux for automation.",
    ),

    KaliTool(
        name="smbmap",
        category=Category.SCANNING,
        subcategory="smb_enumeration",
        description="SMB share mapper — enumerate shares, permissions, and execute commands via SMB",
        syntax="smbmap -H <host> [options]",
        common_flags={
            "-H <host>":        "Target host",
            "-u <user>":        "Username",
            "-p <pass>":        "Password",
            "-d <domain>":      "Domain",
            "-s <share>":       "Specific share",
            "-r <path>":        "Recursively list directory",
            "-A <pattern>":     "Download files matching pattern",
            "--download <f>":   "Download a file",
            "--upload <f>":     "Upload a file",
            "-x <cmd>":         "Execute command",
            "-q":               "Quiet mode",
            "--no-banner":      "No banner",
            "-R":               "Recursive directory listing",
        },
        use_cases=[
            "Enumerate SMB shares and permissions",
            "Find readable/writable shares",
            "Download files from SMB shares",
            "Remote command execution via SMB",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.MEDIUM,
        keywords=["smb", "share", "map", "permissions", "read", "write", "enumerate", "download"],
        notes="Install: apt install smbmap. Use null session: smbmap -H <ip> -u '' -p ''",
    ),

    KaliTool(
        name="smbclient",
        category=Category.SCANNING,
        subcategory="smb_enumeration",
        description="SMB/CIFS client — connect to shares, browse files, transfer data",
        syntax="smbclient //<host>/<share> [options]",
        common_flags={
            "-L <host>":        "List shares on host",
            "-U <user>":        "Username",
            "-N":               "Null session (no password)",
            "-W <domain>":      "Domain/workgroup",
            "get <file>":       "Download file",
            "put <file>":       "Upload file",
            "ls":               "List directory",
            "cd <dir>":         "Change directory",
            "mget <pattern>":   "Download multiple files",
            "-c <cmd>":         "Run command non-interactively",
            "--option='client min protocol=NT1'": "Force older protocol",
        },
        use_cases=[
            "Browse SMB shares interactively",
            "Download files from accessible shares",
            "Test null session access",
            "Enumerate shares on Windows/Samba hosts",
        ],
        output_formats=["interactive", "text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.MEDIUM,
        keywords=["smb", "share", "browse", "client", "file", "transfer", "null", "session"],
        notes="Install: apt install smbclient. Null session: smbclient -L //<ip> -N",
    ),

    KaliTool(
        name="rpcclient",
        category=Category.SCANNING,
        subcategory="smb_enumeration",
        description="Execute RPC commands on Windows systems — user/group/domain enumeration",
        syntax="rpcclient -U <user> <target>",
        common_flags={
            "-U <user>%<pass>":     "Authenticate with credentials",
            "-N":                   "Null session",
            "enumdomusers":         "Enumerate domain users",
            "enumdomgroups":        "Enumerate domain groups",
            "queryuser <rid>":      "Query user by RID",
            "querygroup <rid>":     "Query group by RID",
            "getdompwinfo":         "Get domain password info",
            "lookupnames <name>":   "Look up SID for name",
            "lookupsids <sid>":     "Look up name for SID",
            "netshareenum":         "Enumerate shares",
            "querydominfo":         "Domain info",
            "enumprinters":         "Enumerate printers",
        },
        use_cases=[
            "Domain user and group enumeration",
            "SID/RID-based user discovery",
            "Domain password policy extraction",
            "Printer and share enumeration",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.MEDIUM,
        keywords=["rpc", "smb", "windows", "users", "groups", "sid", "rid", "domain", "enum"],
        notes="Install: apt install samba-common-bin. Null session: rpcclient -U '' -N <ip>",
    ),

    KaliTool(
        name="nbtscan",
        category=Category.SCANNING,
        subcategory="smb_enumeration",
        description="Scan networks for NetBIOS name information",
        syntax="nbtscan [options] <target>",
        common_flags={
            "-r":           "Use local port 137 (requires root)",
            "-v":           "Verbose",
            "-s <sep>":     "Separator character",
            "-m":           "Include MAC addresses",
            "-f <file>":    "Read targets from file",
            "<ip/range>":   "Target or range (e.g. 192.168.1.1/24)",
        },
        use_cases=[
            "NetBIOS name resolution on local network",
            "Identify Windows workstation/server names",
            "Discover domain controllers",
            "Enumerate NetBIOS name table",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["netbios", "nbts", "windows", "name", "discover", "domain", "workgroup"],
        notes="Install: apt install nbtscan. Use: nbtscan -r 192.168.1.0/24",
    ),

    # ══════════════════════════════════════════
    # SNMP ENUMERATION
    # ══════════════════════════════════════════

    KaliTool(
        name="snmpwalk",
        category=Category.SCANNING,
        subcategory="snmp_enumeration",
        description="Walk SNMP MIB tree — extract system info, running processes, network interfaces",
        syntax="snmpwalk -v <version> -c <community> <target> [OID]",
        common_flags={
            "-v 1":             "SNMP version 1",
            "-v 2c":            "SNMP version 2c",
            "-v 3":             "SNMP version 3",
            "-c <community>":   "Community string (default: public)",
            "-O e":             "Suppress MIB object errors",
            "1.3.6.1.2.1.1":   "System MIB (sysDescr, etc.)",
            "1.3.6.1.2.1.25.4":"Running processes",
            "1.3.6.1.2.1.25.6":"Installed software",
            "1.3.6.1.4.1.77":  "Windows user accounts",
            "1.3.6.1.2.1.6.13":"TCP connections",
        },
        use_cases=[
            "Extract system description and OS version",
            "Enumerate running processes",
            "List installed software",
            "Enumerate network interfaces",
            "Extract Windows user accounts via SNMP",
        ],
        output_formats=["text"],
        avg_time_seconds=15,
        risk_level=RiskLevel.MEDIUM,
        keywords=["snmp", "mib", "walk", "community", "processes", "software", "enum"],
        notes="Install: apt install snmp snmp-mibs-downloader. Common community strings: public, private, manager",
    ),

    KaliTool(
        name="onesixtyone",
        category=Category.SCANNING,
        subcategory="snmp_enumeration",
        description="Fast SNMP scanner — brute force community strings across multiple hosts",
        syntax="onesixtyone [options] <targets> <communities>",
        common_flags={
            "-c <file>":    "Community strings file",
            "-i <file>":    "Hosts file",
            "-o <file>":    "Output file",
            "-d":           "Debug mode",
            "-q":           "Quiet mode",
            "-w <ms>":      "Wait time between requests (ms)",
            "<target>":     "Single target IP",
        },
        use_cases=[
            "Brute force SNMP community strings",
            "Fast SNMP discovery across subnets",
            "Find devices with default 'public' community",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.MEDIUM,
        keywords=["snmp", "community", "brute", "fast", "discover", "scan"],
        notes="Install: apt install onesixtyone. Community wordlist: /usr/share/doc/onesixtyone/dict.txt",
    ),

    KaliTool(
        name="snmp-check",
        category=Category.SCANNING,
        subcategory="snmp_enumeration",
        description="SNMP enumerator — extract detailed info from SNMP-enabled devices",
        syntax="snmp-check [options] <target>",
        common_flags={
            "-c <community>":   "Community string (default: public)",
            "-v <1|2c>":        "SNMP version",
            "-p <port>":        "Port (default: 161)",
            "-t <n>":           "Timeout",
            "-r <n>":           "Retries",
            "-w":               "Write community check",
            "-d":               "Disable TCP check",
        },
        use_cases=[
            "Comprehensive SNMP enumeration",
            "Extract device info, interfaces, routing tables",
            "User account enumeration via SNMP",
            "Network topology discovery",
        ],
        output_formats=["text"],
        avg_time_seconds=15,
        risk_level=RiskLevel.MEDIUM,
        keywords=["snmp", "enum", "device", "interface", "routing", "user", "community"],
        notes="Install: apt install snmp. More readable output than snmpwalk.",
    ),

    # ══════════════════════════════════════════
    # SMTP ENUMERATION
    # ══════════════════════════════════════════

    KaliTool(
        name="smtp-user-enum",
        category=Category.SCANNING,
        subcategory="smtp_enumeration",
        description="Enumerate valid SMTP usernames via VRFY, EXPN, and RCPT TO commands",
        syntax="smtp-user-enum -M <mode> -U <userlist> -t <target>",
        common_flags={
            "-M VRFY":          "Use VRFY command",
            "-M EXPN":          "Use EXPN command",
            "-M RCPT":          "Use RCPT TO command",
            "-U <file>":        "Username list",
            "-u <user>":        "Single username",
            "-t <target>":      "Target SMTP server",
            "-p <port>":        "Port (default: 25)",
            "-f <from>":        "From address for RCPT mode",
            "-D <domain>":      "Domain to append to usernames",
            "-T <n>":           "Threads",
            "-v":               "Verbose",
        },
        use_cases=[
            "Enumerate valid email accounts on SMTP server",
            "Username harvesting for credential attacks",
            "Verify if user accounts exist on a mail server",
        ],
        output_formats=["text"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["smtp", "email", "user", "enum", "vrfy", "expn", "rcpt", "mail"],
        notes="Install: apt install smtp-user-enum. Best method depends on server: try VRFY first.",
    ),

    KaliTool(
        name="swaks",
        category=Category.SCANNING,
        subcategory="smtp_enumeration",
        description="Swiss Army Knife for SMTP — test and probe SMTP servers",
        syntax="swaks --to <email> --server <smtp>",
        common_flags={
            "--to <email>":         "Recipient",
            "--from <email>":       "Sender",
            "--server <host>":      "SMTP server",
            "--port <n>":           "Port",
            "--tls":                "Use STARTTLS",
            "--tls-on-connect":     "Use SSL/TLS on connect",
            "--auth <type>":        "Auth type (LOGIN, PLAIN, etc.)",
            "--auth-user <u>":      "Auth username",
            "--auth-password <p>":  "Auth password",
            "--body <text>":        "Email body",
            "--attach <file>":      "Attachment",
            "--header <h>":         "Add header",
        },
        use_cases=[
            "Test SMTP server configuration",
            "Send test emails for phishing simulation",
            "Test SMTP auth mechanisms",
            "Open relay testing",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.MEDIUM,
        keywords=["smtp", "email", "test", "relay", "auth", "send", "probe"],
        notes="Install: apt install swaks. Test open relay: swaks --to victim@target.com --server target.com",
    ),

    # ══════════════════════════════════════════
    # SSL/TLS ANALYSIS
    # ══════════════════════════════════════════

    KaliTool(
        name="sslscan",
        category=Category.SCANNING,
        subcategory="ssl_analysis",
        description="SSL/TLS scanner — detect cipher suites, protocols, certificates, vulnerabilities",
        syntax="sslscan [options] <host>:<port>",
        common_flags={
            "--no-failed":      "Only show accepted ciphers",
            "--tls10":          "Only check TLS 1.0",
            "--tls11":          "Only check TLS 1.1",
            "--tls12":          "Only check TLS 1.2",
            "--tls13":          "Only check TLS 1.3",
            "--show-certificate":"Show certificate details",
            "--xml=<file>":     "XML output",
            "--ipv4":           "IPv4 only",
            "--ipv6":           "IPv6 only",
            "--starttls-smtp":  "Use STARTTLS for SMTP",
            "--starttls-ftp":   "Use STARTTLS for FTP",
        },
        use_cases=[
            "Find weak cipher suites (RC4, DES, 3DES)",
            "Detect SSLv2/SSLv3/TLS 1.0/1.1 support",
            "Check for Heartbleed, POODLE, BEAST",
            "Certificate expiry and validity checking",
            "STARTTLS support testing",
        ],
        output_formats=["text", "xml"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["ssl", "tls", "cipher", "certificate", "heartbleed", "poodle", "weak", "scan"],
        notes="Install: apt install sslscan.",
    ),

    KaliTool(
        name="sslyze",
        category=Category.SCANNING,
        subcategory="ssl_analysis",
        description="Fast SSL/TLS configuration analyzer — more detailed than sslscan",
        syntax="sslyze <target>",
        common_flags={
            "--regular":        "Regular scan (most checks)",
            "--heartbleed":     "Check Heartbleed",
            "--robot":          "Check ROBOT attack",
            "--reneg":          "Check renegotiation",
            "--resum":          "Check session resumption",
            "--certinfo":       "Certificate info",
            "--http_headers":   "Check HTTP headers",
            "--json_out <f>":   "JSON output",
            "--targets_in <f>": "Read targets from file",
            "--slow_connection":"Slower but more accurate",
        },
        use_cases=[
            "Comprehensive TLS configuration analysis",
            "ROBOT attack detection",
            "Session resumption and renegotiation testing",
            "Certificate chain validation",
            "Bulk SSL scanning",
        ],
        output_formats=["text", "json", "xml"],
        avg_time_seconds=15,
        risk_level=RiskLevel.LOW,
        keywords=["ssl", "tls", "analyze", "robot", "heartbleed", "cert", "cipher", "detailed"],
        notes="Install: pip install sslyze. More thorough than sslscan.",
    ),

    KaliTool(
        name="testssl",
        category=Category.SCANNING,
        subcategory="ssl_analysis",
        description="Thorough SSL/TLS testing — checks all known vulnerabilities and misconfigs",
        syntax="testssl.sh [options] <host>:<port>",
        common_flags={
            "-e":               "Check cipher per protocol",
            "-E":               "Check ciphers (per strength)",
            "-f":               "Check forward secrecy",
            "-p":               "Check protocols",
            "-y":               "Check all TLS extensions",
            "-U":               "Check vulnerabilities",
            "-S":               "Server defaults",
            "-P":               "Server preferences",
            "--html <file>":    "HTML report",
            "--json <file>":    "JSON report",
            "--csv <file>":     "CSV report",
            "--severity <sev>": "Minimum severity (LOW/MEDIUM/HIGH/CRITICAL)",
        },
        use_cases=[
            "Full TLS/SSL vulnerability assessment",
            "Check BEAST, CRIME, BREACH, POODLE, Heartbleed",
            "Check DROWN, LOGJAM, FREAK, ROBOT",
            "TLS 1.3 support verification",
            "Compliance checking (PCI, HIPAA)",
        ],
        output_formats=["text", "html", "json", "csv"],
        avg_time_seconds=60,
        risk_level=RiskLevel.LOW,
        keywords=["ssl", "tls", "vuln", "beast", "crime", "heartbleed", "drown", "compliance", "full"],
        notes="git clone https://github.com/drwetter/testssl.sh. Most comprehensive SSL tester.",
    ),

    # ══════════════════════════════════════════
    # NFS/RPC ENUMERATION
    # ══════════════════════════════════════════

    KaliTool(
        name="showmount",
        category=Category.SCANNING,
        subcategory="nfs_enumeration",
        description="Show NFS mount points exported by a server",
        syntax="showmount [options] <host>",
        common_flags={
            "-e <host>":    "Show exported file systems",
            "-a <host>":    "Show all mount points",
            "-d <host>":    "Show directories mounted by clients",
        },
        use_cases=[
            "Enumerate NFS exports on target",
            "Find world-readable NFS shares",
            "Identify mountable network directories",
        ],
        output_formats=["text"],
        avg_time_seconds=3,
        risk_level=RiskLevel.LOW,
        keywords=["nfs", "mount", "export", "share", "network", "filesystem"],
        notes="Install: apt install nfs-common. Mount share: mount -t nfs <ip>:<share> /mnt/",
    ),

    KaliTool(
        name="rpcinfo",
        category=Category.SCANNING,
        subcategory="nfs_enumeration",
        description="Report RPC information — list programs registered with portmapper",
        syntax="rpcinfo [options] <host>",
        common_flags={
            "-p <host>":    "List all RPC programs on host",
            "-s <host>":    "Concise list",
            "-T <proto>":   "Use TCP",
            "-U":           "Use UDP",
            "-n <port>":    "Use specific port",
        },
        use_cases=[
            "Enumerate RPC services on target",
            "Discover NFS, NIS, and other RPC services",
            "Port mapper enumeration",
        ],
        output_formats=["text"],
        avg_time_seconds=3,
        risk_level=RiskLevel.LOW,
        keywords=["rpc", "portmapper", "nfs", "nis", "services", "enum"],
        notes="Install: apt install rpcbind. Use: rpcinfo -p <target>",
    ),

    # ══════════════════════════════════════════
    # DATABASE ENUMERATION
    # ══════════════════════════════════════════

    KaliTool(
        name="oscanner",
        category=Category.SCANNING,
        subcategory="database_enumeration",
        description="Oracle database scanner — enumerate Oracle SIDs, accounts, and version info",
        syntax="oscanner -s <host> -P <port>",
        common_flags={
            "-s <host>":    "Target host",
            "-P <port>":    "Port (default: 1521)",
            "-v":           "Verbose",
        },
        use_cases=[
            "Oracle database SID enumeration",
            "Oracle account discovery",
            "Oracle version fingerprinting",
        ],
        output_formats=["text"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["oracle", "database", "sid", "enum", "scan", "db"],
        notes="Install: apt install oscanner.",
    ),

    KaliTool(
        name="tnscmd10g",
        category=Category.SCANNING,
        subcategory="database_enumeration",
        description="Query Oracle TNS listener — extract version and SID info",
        syntax="tnscmd10g <command> -h <host>",
        common_flags={
            "version -h <ip>":  "Get TNS listener version",
            "status -h <ip>":   "Get listener status",
            "ping -h <ip>":     "Ping listener",
            "-p <port>":        "Port (default: 1521)",
        },
        use_cases=[
            "Oracle TNS listener version disclosure",
            "Oracle database reconnaissance",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["oracle", "tns", "listener", "version", "database"],
        notes="Install: apt install tnscmd10g.",
    ),

    KaliTool(
        name="redis-cli",
        category=Category.SCANNING,
        subcategory="database_enumeration",
        description="Redis command-line interface — connect to and enumerate Redis databases",
        syntax="redis-cli -h <host> -p <port> [command]",
        common_flags={
            "-h <host>":        "Target host",
            "-p <port>":        "Port (default: 6379)",
            "-a <password>":    "Auth password",
            "INFO":             "Server information",
            "KEYS *":           "List all keys",
            "CONFIG GET *":     "Get all config",
            "SLAVEOF <ip> <p>": "Make server a slave (exploit)",
            "CONFIG SET dir":   "Set working directory",
            "CONFIG SET dbfilename": "Set dump filename",
            "SAVE":             "Save DB to disk",
        },
        use_cases=[
            "Enumerate unauthenticated Redis instances",
            "Extract data from exposed Redis",
            "Redis RCE via config set (write SSH keys)",
            "Cache data exfiltration",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.HIGH,
        keywords=["redis", "database", "cache", "enum", "unauthenticated", "keys", "rce"],
        notes="Install: apt install redis-tools. Unauthenticated Redis is critical — check port 6379.",
    ),

    # ══════════════════════════════════════════
    # AUTOMATED ENUMERATION FRAMEWORKS
    # ══════════════════════════════════════════

    KaliTool(
        name="autorecon",
        category=Category.SCANNING,
        subcategory="automated_enumeration",
        description="Multi-threaded automated reconnaissance — runs all relevant enum tools based on open ports",
        syntax="autorecon [options] <target>",
        common_flags={
            "<target>":             "Single target IP or hostname",
            "-t <file>":            "Targets file",
            "-o <dir>":             "Output directory",
            "--single-target":      "Single target mode",
            "--only-scans-dir":     "Only create scans directory",
            "--dirbuster.wordlist": "Custom wordlist for dir busting",
            "--dirbuster.ext":      "Extensions to fuzz",
            "--dirbuster.recursive":"Recursive directory scanning",
            "-v":                   "Verbose",
            "--heartbeat <n>":      "Heartbeat interval seconds",
        },
        use_cases=[
            "Automated full host enumeration (OSCP-style)",
            "Run all relevant tools based on discovered ports",
            "CTF host enumeration",
            "Time-saving recon for multiple hosts",
        ],
        output_formats=["directory tree", "text files per service"],
        avg_time_seconds=300,
        risk_level=RiskLevel.MEDIUM,
        keywords=["automated", "recon", "enum", "oscp", "ctf", "multi", "service", "comprehensive"],
        notes="Install: apt install autorecon. Creates organized output per target/service. OSCP essential.",
    ),

    KaliTool(
        name="legion",
        category=Category.SCANNING,
        subcategory="automated_enumeration",
        description="GUI-based network penetration testing framework — automated scanning and enumeration",
        syntax="legion  (GUI application)",
        common_flags={
            "Add host/range":   "Add scan target",
            "Auto":             "Automated scan mode",
            "Services":         "View discovered services",
            "Hosts":            "View discovered hosts",
            "Brute":            "Brute force credentials",
        },
        use_cases=[
            "GUI-based automated network scanning",
            "Visual service enumeration",
            "Integrated brute forcing",
            "Beginner-friendly pentesting framework",
        ],
        output_formats=["gui", "xml"],
        avg_time_seconds=0,
        risk_level=RiskLevel.MEDIUM,
        keywords=["gui", "automated", "scan", "framework", "visual", "enum", "beginner"],
        notes="Install: apt install legion. Fork of SPARTA. GUI-only.",
    ),

    # ══════════════════════════════════════════
    # BANNER GRABBING
    # ══════════════════════════════════════════

    KaliTool(
        name="amap",
        category=Category.SCANNING,
        subcategory="banner_grabbing",
        description="Application mapper — identify services by sending probes and analyzing responses",
        syntax="amap [options] <target> <port>",
        common_flags={
            "-b":           "Print ASCII banner",
            "-q":           "Quiet mode",
            "-1":           "Stop after first match",
            "-A":           "Application fingerprinting",
            "-P":           "No ping before connect",
            "-p <port>":    "Port range",
        },
        use_cases=[
            "Identify services running on non-standard ports",
            "Banner grabbing on unknown services",
            "Complement nmap service detection",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["banner", "grab", "service", "identify", "fingerprint", "non-standard", "port"],
        notes="Install: apt install amap.",
    ),

    KaliTool(
        name="dmitry",
        category=Category.SCANNING,
        subcategory="banner_grabbing",
        description="Deepmagic Information Gathering Tool — whois, subdomains, email, port scan, banner grab",
        syntax="dmitry [options] <host>",
        common_flags={
            "-w":           "Whois lookup",
            "-i":           "Whois for IP",
            "-n":           "Netcraft info",
            "-s":           "Subdomains search",
            "-e":           "Email addresses search",
            "-p":           "Port scan",
            "-f":           "Filter results",
            "-b":           "Banner grab on ports",
            "-t <1-9>":     "TTL for TCP scan",
            "-o <file>":    "Output file",
        },
        use_cases=[
            "All-in-one information gathering",
            "Subdomain and email enumeration",
            "Port scanning with banner grabbing",
            "Quick target profiling",
        ],
        output_formats=["text", "file"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["info", "gather", "whois", "subdomain", "email", "port", "banner", "all-in-one"],
        notes="Install: apt install dmitry. Covers multiple recon steps in one command.",
    ),

    # ══════════════════════════════════════════
    # FIREWALL & IDS EVASION
    # ══════════════════════════════════════════

    KaliTool(
        name="fragroute",
        category=Category.SCANNING,
        subcategory="firewall_evasion",
        description="Intercept and modify outgoing packets — fragment, delay, duplicate to evade IDS/firewall",
        syntax="fragroute -f <config_file> <target>",
        common_flags={
            "-f <file>":    "Configuration file with rules",
            "ip_frag 8":    "Fragment IP packets every 8 bytes",
            "tcp_seg 8":    "Segment TCP packets every 8 bytes",
            "ip_ttl 1":     "Set IP TTL",
            "order random": "Randomize fragment order",
            "dup 1":        "Duplicate packets",
            "delay 10":     "Delay packets 10ms",
        },
        use_cases=[
            "Evade IDS/IPS via packet fragmentation",
            "Test IDS effectiveness against fragmentation attacks",
            "Firewall rule evasion research",
        ],
        output_formats=["packets"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["fragment", "evasion", "ids", "ips", "firewall", "bypass", "packet"],
        notes="Install: apt install fragroute. Use with caution — may disrupt connections.",
    ),

    KaliTool(
        name="proxychains4",
        category=Category.SCANNING,
        subcategory="firewall_evasion",
        description="Proxy chains for any TCP tool — route scans through SOCKS/HTTP proxies",
        syntax="proxychains4 <command> [args]",
        common_flags={
            "proxychains4 nmap -sT <target>":   "Scan through proxy",
            "proxychains4 sqlmap -u <url>":     "SQLmap through proxy",
            "strict_chain":                     "Config: strict chain mode",
            "dynamic_chain":                    "Config: dynamic chain mode",
            "random_chain":                     "Config: random chain mode",
        },
        use_cases=[
            "Anonymize scanning traffic",
            "Route tools through Tor",
            "Pivot through compromised SOCKS proxy",
            "Bypass geo-blocking",
        ],
        output_formats=["piped"],
        avg_time_seconds=2,
        risk_level=RiskLevel.MEDIUM,
        keywords=["proxy", "chain", "anonymize", "tor", "socks", "route", "bypass"],
        notes="Install: apt install proxychains4. Config: /etc/proxychains4.conf",
    ),
]


# ── Quick stats ───────────────────────────────
if __name__ == "__main__":
    print(f"Scanning & Enumeration expansion: {len(SCANNING_TOOLS)} tools")

    subcats = {}
    for t in SCANNING_TOOLS:
        subcats[t.subcategory] = subcats.get(t.subcategory, 0) + 1

    print("\nBy subcategory:")
    for sub, count in sorted(subcats.items()):
        print(f"  {sub:<30} {count} tools")

    print("\nIntegrate with knowledge base:")
    print("  from nova_kali_kb_scanning import SCANNING_TOOLS")
    print("  from nova_kali_knowledge_base import KALI_TOOLS")
    print("  KALI_TOOLS.extend(SCANNING_TOOLS)")
