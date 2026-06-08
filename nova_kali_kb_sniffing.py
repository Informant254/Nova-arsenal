"""
NOVA KALI KNOWLEDGE BASE — SNIFFING & SPOOFING EXPANSION
==========================================================
Full expansion of the Sniffing & Spoofing category.
Add this to nova_kali_knowledge_base.py by importing and extending KALI_TOOLS.

Subcategories covered:
- ARP Spoofing & Poisoning
- DNS Spoofing
- SSL/TLS Stripping & Interception
- MITM Frameworks
- Packet Sniffing
- MAC Spoofing
- Network Traffic Manipulation
- Credential Sniffing
- VLAN & Switch Attacks
- Rogue Access Points

Usage:
    from nova_kali_kb_sniffing import SNIFFING_TOOLS
    from nova_kali_knowledge_base import KALI_TOOLS, KaliKnowledgeBase

    KALI_TOOLS.extend(SNIFFING_TOOLS)
    kb = KaliKnowledgeBase()
"""

from nova_kali_knowledge_base import KaliTool, Category, RiskLevel

SNIFFING_TOOLS = [

    # ══════════════════════════════════════════
    # MITM FRAMEWORKS
    # ══════════════════════════════════════════

    KaliTool(
        name="bettercap",
        category=Category.SNIFFING,
        subcategory="mitm_framework",
        description="Powerful MITM framework — ARP spoofing, DNS spoofing, SSL stripping, credential sniffing, WiFi attacks",
        syntax="bettercap -iface <interface>",
        common_flags={
            "-iface <iface>":           "Network interface",
            "-caplet <file>":           "Run caplet script",
            "net.probe on":             "Probe network for hosts",
            "net.recon on":             "Network recon",
            "arp.spoof on":             "Enable ARP spoofing",
            "arp.spoof.targets <ip>":   "Set ARP spoof targets",
            "dns.spoof on":             "Enable DNS spoofing",
            "dns.spoof.domains <d>":    "Domains to spoof",
            "http.proxy on":            "HTTP proxy/sniffer",
            "https.proxy on":           "HTTPS proxy (with cert)",
            "net.sniff on":             "Network sniffer",
            "net.sniff.verbose true":   "Verbose sniffing",
            "wifi.recon on":            "WiFi reconnaissance",
            "wifi.deauth <bssid>":      "Deauth WiFi clients",
            "hid.inject":               "HID injection attacks",
            "caplets":                  "List available caplets",
            "help":                     "Show all modules",
        },
        use_cases=[
            "Full MITM attack on local network",
            "ARP + DNS spoofing combined",
            "Credential harvesting from HTTP/HTTPS",
            "WiFi network attacks",
            "Network reconnaissance",
            "SSL stripping",
            "Script-based automated attacks via caplets",
        ],
        output_formats=["interactive console", "log files"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["mitm", "arp", "dns", "spoof", "ssl", "strip", "wifi", "credential", "sniff", "bettercap"],
        notes="Install: apt install bettercap. Modern replacement for ettercap. Use caplets for automation.",
    ),

    KaliTool(
        name="ettercap-full",
        category=Category.SNIFFING,
        subcategory="mitm_framework",
        description="Comprehensive MITM suite — ARP poisoning, protocol dissection, plugin support",
        syntax="ettercap -T -M arp //<target1>// //<target2>//",
        common_flags={
            "-T":                   "Text mode",
            "-G":                   "GTK GUI mode",
            "-C":                   "Curses UI mode",
            "-M arp":               "ARP poisoning MITM",
            "-M arp:remote":        "ARP remote poisoning",
            "-M dhcp":              "DHCP spoofing MITM",
            "-M icmp":              "ICMP redirect MITM",
            "-i <iface>":           "Interface",
            "-w <file>":            "Write PCAP",
            "-r <file>":            "Read PCAP",
            "-P <plugin>":          "Load plugin",
            "-F <filter>":          "Load filter",
            "-L <logfile>":         "Log all traffic",
            "-l <logfile>":         "Log only user messages",
            "//<ip>//":             "Target specification",
            "//":                   "All hosts on subnet",
            "--plugin list":        "List available plugins",
        },
        use_cases=[
            "ARP poisoning between specific hosts",
            "Full subnet MITM",
            "Protocol dissection (HTTP, FTP, SSH, etc.)",
            "Plugin-based credential sniffing",
            "Custom packet filtering with etterfilter",
            "DHCP spoofing",
        ],
        output_formats=["text", "pcap", "log"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["mitm", "arp", "poison", "ettercap", "plugin", "dissect", "credential", "dhcp"],
        notes="Install: apt install ettercap-text-only. Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward",
    ),

    # ══════════════════════════════════════════
    # ARP SPOOFING
    # ══════════════════════════════════════════

    KaliTool(
        name="arpspoof",
        category=Category.SNIFFING,
        subcategory="arp_spoofing",
        description="ARP spoofing tool — send forged ARP replies to redirect network traffic",
        syntax="arpspoof -i <iface> -t <target> <gateway>",
        common_flags={
            "-i <iface>":       "Network interface",
            "-t <target>":      "Target IP to spoof",
            "-r":               "Poison both target and gateway (bidirectional)",
            "-c own|host|both": "MAC address to use in reply",
            "<gateway>":        "Gateway IP",
        },
        use_cases=[
            "Redirect target traffic through attacker",
            "Bidirectional ARP poisoning",
            "Intercept traffic between host and gateway",
            "Prerequisite for sslstrip attacks",
        ],
        output_formats=["text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["arp", "spoof", "poison", "redirect", "traffic", "gateway", "intercept"],
        notes="Install: apt install dsniff (includes arpspoof). Enable forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward",
    ),

    KaliTool(
        name="arping",
        category=Category.SNIFFING,
        subcategory="arp_spoofing",
        description="Send ARP requests/replies — detect duplicate IPs, check MAC addresses",
        syntax="arping [options] <host>",
        common_flags={
            "-I <iface>":       "Interface",
            "-c <n>":           "Count",
            "-D":               "Duplicate IP detection mode",
            "-s <ip>":          "Spoof source IP",
            "-t <mac>":         "Target MAC address",
            "-S <mac>":         "Spoof source MAC",
            "-U":               "Unsolicited ARP (update neighbors)",
            "-A":               "ARP reply mode",
        },
        use_cases=[
            "Detect duplicate IP addresses",
            "Verify MAC address of a host",
            "Send gratuitous ARP packets",
            "Network host discovery at Layer 2",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["arp", "ping", "mac", "duplicate", "ip", "layer2", "discover"],
        notes="Install: apt install arping.",
    ),

    # ══════════════════════════════════════════
    # DNS SPOOFING
    # ══════════════════════════════════════════

    KaliTool(
        name="dnsspoof",
        category=Category.SNIFFING,
        subcategory="dns_spoofing",
        description="Forge DNS replies on LAN — redirect domain lookups to attacker-controlled IPs",
        syntax="dnsspoof -i <iface> [-f hostsfile] [expression]",
        common_flags={
            "-i <iface>":       "Network interface",
            "-f <hostsfile>":   "Hosts file with spoofed entries",
            "[expression]":     "BPF filter expression",
        },
        use_cases=[
            "Redirect domain lookups to rogue server",
            "Phishing via DNS spoofing",
            "Redirect updates/connections to attacker host",
            "Combined with ARP spoofing for full MITM",
        ],
        output_formats=["text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["dns", "spoof", "redirect", "domain", "phishing", "mitm", "fake"],
        notes="Install: apt install dsniff. Hosts file format: <ip> <domain> e.g. 192.168.1.1 google.com",
    ),

    KaliTool(
        name="dnschef",
        category=Category.SNIFFING,
        subcategory="dns_spoofing",
        description="Highly configurable DNS proxy — fake DNS responses for malware analysis and pentesting",
        syntax="dnschef [options]",
        common_flags={
            "--fakeip <ip>":        "IP to return for faked domains",
            "--fakedomains <d>":    "Comma-separated domains to fake",
            "--truedomains <d>":    "Domains to resolve normally",
            "--fakeipv6 <ip>":      "IPv6 address for faked domains",
            "--interface <ip>":     "Bind interface",
            "--port <n>":           "DNS port (default 53)",
            "--logfile <f>":        "Log file",
            "--quiet":              "Quiet mode",
        },
        use_cases=[
            "Fake DNS server for malware analysis",
            "Redirect specific domains during pentest",
            "Mobile app traffic interception via DNS",
            "Rogue DNS for captive portal attacks",
        ],
        output_formats=["text", "log"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["dns", "fake", "proxy", "redirect", "malware", "analysis", "rogue", "domain"],
        notes="Install: apt install dnschef. Set target's DNS to attacker IP to route queries.",
    ),

    # ══════════════════════════════════════════
    # SSL/TLS STRIPPING
    # ══════════════════════════════════════════

    KaliTool(
        name="sslstrip",
        category=Category.SNIFFING,
        subcategory="ssl_stripping",
        description="SSL stripping tool — downgrade HTTPS connections to HTTP to capture credentials",
        syntax="sslstrip [options]",
        common_flags={
            "-l <port>":        "Listen port (default 10000)",
            "-w <file>":        "Write log to file",
            "-p":               "Post-only mode (only log POST data)",
            "-s":               "Log to SSL traffic as well",
            "-a":               "Log all SSL traffic",
            "-f":               "Favicon replacement to lock icon",
            "-k":               "Kill sessions in proxy",
        },
        use_cases=[
            "Downgrade HTTPS to HTTP in MITM position",
            "Capture credentials from HTTPS sites",
            "Combined with ARP spoofing and iptables redirect",
            "Bypass SSL on older sites without HSTS",
        ],
        output_formats=["log file", "text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["ssl", "strip", "https", "downgrade", "credential", "http", "mitm", "hsts"],
        notes="Install: apt install sslstrip. Redirect traffic: iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000",
    ),

    KaliTool(
        name="sslsplit",
        category=Category.SNIFFING,
        subcategory="ssl_stripping",
        description="Transparent SSL/TLS interception proxy — decrypt and re-encrypt SSL traffic",
        syntax="sslsplit [options] <proxyspec>",
        common_flags={
            "-D":               "Debug mode",
            "-l <logfile>":     "Connect log file",
            "-L <logfile>":     "Content log file",
            "-S <dir>":         "Log connections to directory",
            "-k <key>":         "CA private key",
            "-c <cert>":        "CA certificate",
            "-t <dir>":         "Certificate cache directory",
            "-P":               "Passthrough unknown SSL",
            "ssl 0.0.0.0 8443 up:127.0.0.1:443": "SSL proxy spec example",
            "tcp 0.0.0.0 8080 up:127.0.0.1:80":  "TCP proxy spec",
        },
        use_cases=[
            "Transparent SSL/TLS interception",
            "Decrypt HTTPS traffic in MITM position",
            "Log decrypted SSL content",
            "Mobile app SSL traffic analysis",
        ],
        output_formats=["log files", "pcap"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["ssl", "tls", "intercept", "decrypt", "proxy", "transparent", "https", "mitm"],
        notes="Install: apt install sslsplit. Requires own CA cert to re-sign intercepted certs.",
    ),

    # ══════════════════════════════════════════
    # CREDENTIAL SNIFFING
    # ══════════════════════════════════════════

    KaliTool(
        name="dsniff",
        category=Category.SNIFFING,
        subcategory="credential_sniffing",
        description="Network password sniffer — capture plaintext passwords from FTP, HTTP, SMTP, IMAP, etc.",
        syntax="dsniff [options]",
        common_flags={
            "-i <iface>":       "Interface",
            "-n":               "No DNS resolution",
            "-d":               "Enable debug",
            "-m":               "Enable automatic protocol detection",
            "-c":               "Perform half-duplex TCP reassembly",
            "-f <services>":    "Services file",
            "-p <pcapfile>":    "Read from PCAP file",
        },
        use_cases=[
            "Capture FTP/HTTP/SMTP/IMAP/POP3 credentials",
            "Sniff plaintext protocol passwords",
            "Post-ARP-poisoning credential capture",
            "Network protocol auditing",
        ],
        output_formats=["text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["credential", "sniff", "password", "ftp", "smtp", "imap", "plaintext", "capture"],
        notes="Install: apt install dsniff. Package includes: arpspoof, dnsspoof, urlsnarf, webspy, mailsnarf.",
    ),

    KaliTool(
        name="urlsnarf",
        category=Category.SNIFFING,
        subcategory="credential_sniffing",
        description="Sniff HTTP URLs from network traffic — log all web requests in CLF format",
        syntax="urlsnarf [-n] [-i <iface>] [expression]",
        common_flags={
            "-i <iface>":       "Interface",
            "-n":               "No DNS resolution",
            "[expression]":     "BPF filter",
        },
        use_cases=[
            "Log all HTTP URLs visited on network",
            "Web activity monitoring",
            "Combined with ARP spoofing for full visibility",
        ],
        output_formats=["CLF log format"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["url", "sniff", "http", "web", "log", "monitor", "activity", "request"],
        notes="Install: apt install dsniff. Output compatible with web log analyzers.",
    ),

    KaliTool(
        name="mailsnarf",
        category=Category.SNIFFING,
        subcategory="credential_sniffing",
        description="Sniff email messages from SMTP and POP3 traffic",
        syntax="mailsnarf [-n] [-i <iface>] [expression]",
        common_flags={
            "-i <iface>":       "Interface",
            "-n":               "No DNS resolution",
            "[expression]":     "BPF filter",
        },
        use_cases=[
            "Capture emails from plaintext SMTP/POP3",
            "Email content interception",
            "Network email audit",
        ],
        output_formats=["mbox format"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["email", "smtp", "pop3", "sniff", "capture", "mail", "intercept"],
        notes="Install: apt install dsniff. Only captures unencrypted SMTP/POP3.",
    ),

    KaliTool(
        name="webspy",
        category=Category.SNIFFING,
        subcategory="credential_sniffing",
        description="Mirror target's web browsing in real-time — see what they browse as they browse it",
        syntax="webspy -i <iface> <target_ip>",
        common_flags={
            "-i <iface>":       "Interface",
            "<target_ip>":      "Target host to spy on",
        },
        use_cases=[
            "Real-time web browsing mirror",
            "See target's HTTP browsing live",
            "Demonstration of MITM risks",
        ],
        output_formats=["browser display"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["web", "spy", "browse", "mirror", "live", "monitor", "http"],
        notes="Install: apt install dsniff. Opens target URLs in local browser in real-time.",
    ),

    # ══════════════════════════════════════════
    # MAC SPOOFING
    # ══════════════════════════════════════════

    KaliTool(
        name="macchanger",
        category=Category.SNIFFING,
        subcategory="mac_spoofing",
        description="GNU MAC changer — change network interface MAC address temporarily",
        syntax="macchanger [options] <interface>",
        common_flags={
            "-r":               "Set random MAC address",
            "-A":               "Set random vendor MAC",
            "-p":               "Reset to permanent/original MAC",
            "-s":               "Print current MAC address",
            "-l":               "List known vendors",
            "-m <mac>":         "Set specific MAC address",
            "-e":               "Don't change vendor bytes",
            "-a":               "Set random same-kind vendor MAC",
        },
        use_cases=[
            "Bypass MAC address filtering on networks",
            "Anonymize identity on wireless networks",
            "Impersonate another device's MAC",
            "Bypass captive portals tied to MAC",
            "Prerequisite for wireless pentesting",
        ],
        output_formats=["text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.MEDIUM,
        keywords=["mac", "spoof", "change", "address", "bypass", "filter", "anonymous", "wireless"],
        notes="Install: apt install macchanger. Interface must be down first: ip link set <iface> down",
    ),

    # ══════════════════════════════════════════
    # NETWORK TRAFFIC MANIPULATION
    # ══════════════════════════════════════════

    KaliTool(
        name="scapy",
        category=Category.SNIFFING,
        subcategory="packet_manipulation",
        description="Powerful Python packet manipulation — craft, send, sniff, and dissect any network packet",
        syntax="scapy  (interactive Python shell)  |  python3 -c 'from scapy.all import *'",
        common_flags={
            "IP(dst='<ip>')/TCP(dport=80)": "Craft TCP packet",
            "send(<packet>)":               "Send packet (L3)",
            "sendp(<packet>)":              "Send packet (L2)",
            "sr1(<packet>)":                "Send and receive one reply",
            "sniff(iface='<i>', count=<n>)":"Sniff packets",
            "wrpcap('<file>', <packets>)":  "Write to PCAP",
            "rdpcap('<file>')":             "Read PCAP",
            "ls(<protocol>)":              "List protocol fields",
            "Ether()/ARP()":               "Craft ARP packet",
            "hexdump(<packet>)":           "Hex dump packet",
            "packet.show()":               "Display packet layers",
        },
        use_cases=[
            "Custom packet crafting for any protocol",
            "ARP/DNS/IP spoofing via code",
            "Network fuzzing",
            "Protocol research and testing",
            "Custom exploit development",
            "Network scanning and probing",
        ],
        output_formats=["interactive", "pcap", "text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.HIGH,
        keywords=["packet", "craft", "custom", "send", "sniff", "python", "arp", "spoof", "fuzz"],
        notes="Install: apt install python3-scapy. Most powerful and flexible packet tool available.",
    ),

    KaliTool(
        name="nemesis",
        category=Category.SNIFFING,
        subcategory="packet_manipulation",
        description="Command-line packet injection tool — inject ARP, DNS, ICMP, TCP, UDP packets",
        syntax="nemesis <protocol> [options]",
        common_flags={
            "arp":              "ARP packet injection",
            "dns":              "DNS packet injection",
            "ethernet":         "Ethernet frame injection",
            "icmp":             "ICMP packet injection",
            "igmp":             "IGMP packet injection",
            "ip":               "IP packet injection",
            "ospf":             "OSPF packet injection",
            "rip":              "RIP packet injection",
            "tcp":              "TCP packet injection",
            "udp":              "UDP packet injection",
            "-S <ip>":          "Source IP",
            "-D <ip>":          "Destination IP",
            "-H <mac>":         "Source MAC",
            "-M <mac>":         "Destination MAC",
        },
        use_cases=[
            "Inject crafted ARP/DNS/TCP/UDP packets",
            "Test firewall and IDS rules",
            "Protocol-level network testing",
            "Spoof network protocol packets",
        ],
        output_formats=["injected packets"],
        avg_time_seconds=2,
        risk_level=RiskLevel.HIGH,
        keywords=["inject", "packet", "arp", "dns", "tcp", "udp", "spoof", "craft", "icmp"],
        notes="Install: apt install nemesis.",
    ),

    KaliTool(
        name="packit",
        category=Category.SNIFFING,
        subcategory="packet_manipulation",
        description="Network packet generator and capture tool — craft and inject custom packets",
        syntax="packit [options]",
        common_flags={
            "-m <mode>":        "Mode: inject or capture",
            "-t <type>":        "Packet type (TCP/UDP/ICMP/ARP/RARP)",
            "-s <ip>":          "Source IP",
            "-d <ip>":          "Destination IP",
            "-S <port>":        "Source port",
            "-D <port>":        "Destination port",
            "-F <flags>":       "TCP flags",
            "-i <iface>":       "Interface",
            "-c <n>":           "Count",
            "-f <filter>":      "BPF capture filter",
        },
        use_cases=[
            "Custom packet injection",
            "Network testing and probing",
            "Firewall rule testing",
            "DoS simulation in lab",
        ],
        output_formats=["text", "pcap"],
        avg_time_seconds=2,
        risk_level=RiskLevel.MEDIUM,
        keywords=["packet", "inject", "custom", "tcp", "udp", "icmp", "craft", "test"],
        notes="Install: apt install packit.",
    ),

    # ══════════════════════════════════════════
    # VLAN & SWITCH ATTACKS
    # ══════════════════════════════════════════

    KaliTool(
        name="yersinia",
        category=Category.SNIFFING,
        subcategory="switch_attacks",
        description="Layer 2 network attack tool — STP, CDP, DTP, DHCP, 802.1Q/ISL attacks",
        syntax="yersinia -G  (GUI)  |  yersinia -I  (interactive)  |  yersinia <protocol> -attack <n>",
        common_flags={
            "-G":               "GTK GUI mode",
            "-I":               "Interactive ncurses mode",
            "dhcp":             "DHCP attacks",
            "stp":              "Spanning Tree Protocol attacks",
            "cdp":              "Cisco Discovery Protocol attacks",
            "dtp":              "Dynamic Trunking Protocol attacks",
            "dot1q":            "802.1Q VLAN attacks",
            "hsrp":             "Hot Standby Router Protocol attacks",
            "isl":              "ISL encapsulation attacks",
            "-attack <n>":      "Specific attack number",
            "--list-attacks":   "List available attacks",
        },
        use_cases=[
            "DHCP starvation attacks",
            "Spanning tree root bridge takeover",
            "VLAN hopping via 802.1Q",
            "DTP trunk negotiation abuse",
            "CDP information disclosure",
            "HSRP gateway hijacking",
        ],
        output_formats=["gui", "interactive", "text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["layer2", "vlan", "dhcp", "stp", "cdp", "dtp", "switch", "trunk", "hopping"],
        notes="Install: apt install yersinia. Requires root and correct interface.",
    ),

    KaliTool(
        name="frogger",
        category=Category.SNIFFING,
        subcategory="switch_attacks",
        description="VLAN hopping tool — jump between VLANs using 802.1Q double tagging",
        syntax="python3 frogger.py [options]",
        common_flags={
            "-i <iface>":       "Interface",
            "-t <vlan>":        "Target VLAN",
            "-n <vlan>":        "Native VLAN",
            "-p <ip>":          "Target IP in destination VLAN",
        },
        use_cases=[
            "VLAN hopping via double 802.1Q tagging",
            "Access restricted VLANs",
            "Test VLAN segmentation controls",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.HIGH,
        keywords=["vlan", "hop", "double", "tag", "802.1q", "switch", "segmentation"],
        notes="git clone https://github.com/nccgroup/vlan-hopping. Requires trunk port access.",
    ),

    # ══════════════════════════════════════════
    # ROGUE ACCESS POINTS
    # ══════════════════════════════════════════

    KaliTool(
        name="hostapd-wpe",
        category=Category.SNIFFING,
        subcategory="rogue_ap",
        description="Rogue AP with WPA Enterprise — capture RADIUS credentials from 802.1X clients",
        syntax="hostapd-wpe <config_file>",
        common_flags={
            "interface=<iface>":    "Wireless interface (in config)",
            "ssid=<name>":          "SSID to broadcast",
            "channel=<n>":          "WiFi channel",
            "eap_user_file=<f>":    "EAP users file",
            "ca_cert=<f>":          "CA certificate",
            "server_cert=<f>":      "Server certificate",
        },
        use_cases=[
            "Capture WPA Enterprise (802.1X) credentials",
            "Rogue RADIUS server for credential harvesting",
            "Test enterprise WiFi security",
            "Capture MSCHAPv2 challenge/response for offline cracking",
        ],
        output_formats=["text logs", "captured credentials"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["rogue", "ap", "wpa", "enterprise", "radius", "802.1x", "credential", "eap", "mschapv2"],
        notes="Install: apt install hostapd-wpe. Crack captured hashes with: asleap or hashcat -m 5500",
    ),

    KaliTool(
        name="mana-toolkit",
        category=Category.SNIFFING,
        subcategory="rogue_ap",
        description="Rogue AP toolkit — KARMA attacks, hostapd-wpe, sslstrip, traffic interception",
        syntax="start-noupstream.sh  |  start-nat-simple.sh  |  start-nat-full.sh",
        common_flags={
            "start-noupstream.sh":  "Rogue AP without internet",
            "start-nat-simple.sh":  "Rogue AP with NAT (internet access)",
            "start-nat-full.sh":    "Full rogue AP with all attacks",
            "start-nat-ppp.sh":     "Rogue AP with PPP upstream",
        },
        use_cases=[
            "KARMA attack — respond to all probe requests",
            "Rogue AP with internet (convincing to victims)",
            "Captive portal credential capture",
            "Combined SSL stripping and credential harvesting",
        ],
        output_formats=["logs", "captured credentials"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["karma", "rogue", "ap", "evil", "twin", "captive", "portal", "wireless", "credential"],
        notes="Install: apt install mana-toolkit. Configure: /etc/mana-toolkit/hostapd-karma.conf",
    ),

    KaliTool(
        name="eaphammer",
        category=Category.SNIFFING,
        subcategory="rogue_ap",
        description="Targeted evil twin attacks for WPA2-Enterprise networks with KARMA support",
        syntax="python3 eaphammer.py [options]",
        common_flags={
            "--interface <i>":          "Wireless interface",
            "--essid <name>":           "Target SSID",
            "--channel <n>":            "Channel",
            "--wpa":                    "WPA/WPA2 mode",
            "--auth peap":              "PEAP authentication",
            "--auth ttls":              "TTLS authentication",
            "--cred-out <file>":        "Credential output file",
            "--karma":                  "Enable KARMA attack",
            "--loud":                   "Respond to all probes",
            "--bootstrap":              "Generate certificates",
        },
        use_cases=[
            "WPA2-Enterprise evil twin attacks",
            "KARMA attack with EAP support",
            "PEAP/TTLS credential harvesting",
            "Certificate generation for rogue AP",
        ],
        output_formats=["text", "credential files"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["eap", "peap", "ttls", "enterprise", "evil", "twin", "karma", "credential", "wpa2"],
        notes="git clone https://github.com/s0lst1c3/eaphammer.",
    ),

    # ══════════════════════════════════════════
    # ADVANCED SNIFFING
    # ══════════════════════════════════════════

    KaliTool(
        name="p0f",
        category=Category.SNIFFING,
        subcategory="passive_sniffing",
        description="Passive OS fingerprinting — identify OS and app info from network traffic without sending packets",
        syntax="p0f [options]",
        common_flags={
            "-i <iface>":       "Interface",
            "-r <pcap>":        "Read from PCAP file",
            "-o <logfile>":     "Log file",
            "-s <socket>":      "API socket path",
            "-u <user>":        "Drop privileges to user",
            "-d":               "Daemon mode",
            "-f <fingerprints>":"Fingerprint database",
            "-q":               "Quiet mode",
        },
        use_cases=[
            "Passive OS fingerprinting without sending packets",
            "Identify connected devices silently",
            "Application version detection",
            "Network traffic analysis",
            "IDS/firewall bypass (completely passive)",
        ],
        output_formats=["text", "log"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["passive", "fingerprint", "os", "detect", "silent", "traffic", "identify"],
        notes="Install: apt install p0f. Completely passive — no packets sent, undetectable.",
    ),

    KaliTool(
        name="netsniff-ng",
        category=Category.SNIFFING,
        subcategory="packet_sniffing",
        description="High-performance Linux network sniffer — zero-copy packet capture toolkit",
        syntax="netsniff-ng [options]",
        common_flags={
            "--in <iface>":     "Input interface",
            "--out <file>":     "Output PCAP file",
            "--filter <bpf>":   "BPF filter expression",
            "--type host":      "Only host packets",
            "--interval <n>":   "PCAP file rotation interval",
            "--verbose":        "Verbose output",
            "trafgen":          "Traffic generator component",
            "ifpps":            "Interface stats component",
            "bpfc":             "BPF compiler component",
        },
        use_cases=[
            "High-speed packet capture",
            "Zero-copy kernel-level sniffing",
            "Traffic generation with trafgen",
            "Real-time interface statistics",
        ],
        output_formats=["pcap", "text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.MEDIUM,
        keywords=["sniff", "capture", "packet", "fast", "zero-copy", "high-performance", "kernel"],
        notes="Install: apt install netsniff-ng. Faster than tcpdump for high-traffic environments.",
    ),

    KaliTool(
        name="darkstat",
        category=Category.SNIFFING,
        subcategory="packet_sniffing",
        description="Network statistics gatherer — real-time traffic analysis via web interface",
        syntax="darkstat -i <interface> [options]",
        common_flags={
            "-i <iface>":       "Capture interface",
            "-p <port>":        "Web interface port (default 667)",
            "-b <ip>":          "Bind address",
            "--base <path>":    "Base URL path",
            "--local-only":     "Only capture local traffic",
            "-f <filter>":      "BPF filter",
            "-l <network>":     "Local network definition",
        },
        use_cases=[
            "Real-time network traffic statistics",
            "Identify top bandwidth users",
            "Network monitoring via web UI",
            "Traffic pattern analysis",
        ],
        output_formats=["web interface", "text"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["statistics", "traffic", "monitor", "bandwidth", "web", "realtime", "network"],
        notes="Install: apt install darkstat. Web UI at http://localhost:667",
    ),
]


# ── Quick stats ───────────────────────────────
if __name__ == "__main__":
    print(f"Sniffing & Spoofing expansion: {len(SNIFFING_TOOLS)} tools")

    subcats = {}
    for t in SNIFFING_TOOLS:
        subcats[t.subcategory] = subcats.get(t.subcategory, 0) + 1

    print("\nBy subcategory:")
    for sub, count in sorted(subcats.items()):
        print(f"  {sub:<30} {count} tools")

    print("\nIntegrate with knowledge base:")
    print("  from nova_kali_kb_sniffing import SNIFFING_TOOLS")
    print("  from nova_kali_knowledge_base import KALI_TOOLS")
    print("  KALI_TOOLS.extend(SNIFFING_TOOLS)")
