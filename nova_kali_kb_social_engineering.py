"""
NOVA KALI KNOWLEDGE BASE — SOCIAL ENGINEERING EXPANSION
=========================================================
Full expansion of the Social Engineering category.
Add this to nova_kali_knowledge_base.py by importing and extending KALI_TOOLS.

Subcategories covered:
- Phishing Frameworks
- Credential Harvesting
- Pretexting & Spoofing
- USB & Physical Attacks
- Vishing & SMS
- Awareness Training Platforms
- Payload Delivery

Usage:
    from nova_kali_kb_social_engineering import SOCIAL_ENGINEERING_TOOLS
    from nova_kali_knowledge_base import KALI_TOOLS, KaliKnowledgeBase

    KALI_TOOLS.extend(SOCIAL_ENGINEERING_TOOLS)
    kb = KaliKnowledgeBase()
"""

from nova_kali_knowledge_base import KaliTool, Category, RiskLevel

SOCIAL_ENGINEERING_TOOLS = [

    # ══════════════════════════════════════════
    # PHISHING FRAMEWORKS
    # ══════════════════════════════════════════

    KaliTool(
        name="gophish",
        category=Category.SOCIAL_ENG,
        subcategory="phishing_framework",
        description="Open-source phishing toolkit — create, launch, and track phishing campaigns with web UI",
        syntax="gophish-start  (web UI at https://127.0.0.1:3333)",
        common_flags={
            "gophish-start":            "Start Gophish service",
            "gophish-stop":             "Stop Gophish service",
            "Campaigns":                "Create and manage phishing campaigns",
            "Templates":                "Create email templates",
            "Landing Pages":            "Create fake login pages",
            "Sending Profiles":         "Configure SMTP settings",
            "Users & Groups":           "Manage target lists",
            "Dashboard":                "View campaign results",
            "--config <file>":          "Custom config file",
        },
        use_cases=[
            "Phishing campaign simulation",
            "Security awareness training",
            "Track who clicks, submits credentials",
            "Clone login pages for credential harvesting",
            "Spear phishing engagements",
            "Generate detailed click/submission reports",
        ],
        output_formats=["web UI", "json API", "csv reports"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["phishing", "campaign", "email", "credential", "harvest", "track", "awareness", "training"],
        notes="Install: apt install gophish. Default creds: admin/kali-gophish. Web UI: https://127.0.0.1:3333",
    ),

    KaliTool(
        name="king-phisher",
        category=Category.SOCIAL_ENG,
        subcategory="phishing_framework",
        description="Advanced phishing campaign tool — real-time metrics, email and web hosting, activity tracking",
        syntax="king-phisher  (GUI client)  |  king-phisher-server (server component)",
        common_flags={
            "New Campaign":         "Create phishing campaign",
            "Import Targets":       "Import target email list",
            "Email Templates":      "Create/edit email templates",
            "Landing Pages":        "Create credential harvesting pages",
            "Campaign Dashboard":   "View real-time campaign stats",
            "Geolocation":          "Track victim locations on map",
            "TOTP":                 "Two-factor auth for server",
        },
        use_cases=[
            "Advanced phishing campaign management",
            "Real-time victim tracking",
            "Geolocation mapping of victims",
            "Security awareness assessments",
            "Credential harvesting campaigns",
        ],
        output_formats=["gui", "reports", "csv"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["phishing", "campaign", "king", "real-time", "track", "geolocation", "credential", "awareness"],
        notes="Install: apt install king-phisher. Requires separate server and client components.",
    ),

    KaliTool(
        name="evilginx2",
        category=Category.SOCIAL_ENG,
        subcategory="phishing_framework",
        description="Advanced phishing framework — bypass 2FA via reverse proxy, steal session cookies",
        syntax="evilginx2",
        common_flags={
            "phishlets":                "List available phishlets",
            "phishlets enable <name>":  "Enable phishlet (gmail, linkedin, etc.)",
            "lures create <phishlet>":  "Create phishing lure URL",
            "lures get-url <id>":       "Get phishing URL",
            "sessions":                 "List captured sessions",
            "sessions <id>":            "View session details (tokens/creds)",
            "config domain <domain>":   "Set your phishing domain",
            "config ip <ip>":           "Set your server IP",
        },
        use_cases=[
            "Bypass two-factor authentication",
            "Steal session cookies via reverse proxy",
            "Phish Google, LinkedIn, Microsoft accounts",
            "OAuth token theft",
            "Targeted spear phishing with 2FA bypass",
        ],
        output_formats=["interactive console", "session logs"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["2fa", "bypass", "reverse", "proxy", "session", "cookie", "steal", "oauth", "phish"],
        notes="Install: apt install evilginx2. Requires own domain + DNS control. Most dangerous phishing tool.",
    ),

    KaliTool(
        name="modlishka",
        category=Category.SOCIAL_ENG,
        subcategory="phishing_framework",
        description="Reverse proxy phishing tool — intercept and steal credentials and 2FA tokens",
        syntax="./modlishka -config <config.json>",
        common_flags={
            "-target <url>":        "Target website to proxy",
            "-phishingDomain <d>":  "Your phishing domain",
            "-listeningPort <p>":   "Listening port",
            "-tls":                 "Enable TLS",
            "-cert <file>":         "TLS certificate",
            "-key <file>":          "TLS key",
            "-credParams <params>": "Parameters to capture as credentials",
            "-log <file>":          "Log file",
        },
        use_cases=[
            "2FA bypass via reverse proxy",
            "Real-time credential interception",
            "Session hijacking",
            "Proxy any website transparently",
        ],
        output_formats=["log files", "credential files"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["reverse", "proxy", "2fa", "bypass", "intercept", "credential", "session", "hijack"],
        notes="git clone https://github.com/drk1wi/Modlishka. Alternative to Evilginx2.",
    ),

    # ══════════════════════════════════════════
    # CREDENTIAL HARVESTING
    # ══════════════════════════════════════════

    KaliTool(
        name="blackeye",
        category=Category.SOCIAL_ENG,
        subcategory="credential_harvesting",
        description="Phishing tool with 38+ pre-built login page templates — Facebook, Google, Netflix, etc.",
        syntax="bash blackeye.sh",
        common_flags={
            "1":    "Facebook phishing page",
            "2":    "Twitter phishing page",
            "3":    "Instagram phishing page",
            "4":    "Google phishing page",
            "5":    "Netflix phishing page",
            "6":    "LinkedIn phishing page",
            "7":    "GitHub phishing page",
            "8":    "Dropbox phishing page",
            "Custom": "Custom phishing page option",
        },
        use_cases=[
            "Quick phishing page deployment",
            "Social media credential harvesting",
            "Pre-built templates for common sites",
            "Combined with ngrok for public access",
        ],
        output_formats=["terminal", "credential log"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["phishing", "page", "facebook", "google", "template", "credential", "harvest", "login"],
        notes="git clone https://github.com/An0nUD4Y/blackeye. Use with ngrok for public URL.",
    ),

    KaliTool(
        name="hiddeneye",
        category=Category.SOCIAL_ENG,
        subcategory="credential_harvesting",
        description="Modern phishing tool — 30+ templates, keylogger, live feed, ngrok integration",
        syntax="python3 HiddenEye.py",
        common_flags={
            "1-30":             "Select phishing template",
            "Keylogger":        "Enable keylogger on page",
            "Live Feed":        "View victims in real-time",
            "Ngrok":            "Auto-integrate with ngrok",
            "Custom":           "Custom phishing page",
            "Survey":           "Survey-based phishing",
            "Information":      "Device info capture",
        },
        use_cases=[
            "Advanced phishing with keylogger",
            "Real-time victim monitoring",
            "Device information capture",
            "30+ site templates",
            "Integrated ngrok deployment",
        ],
        output_formats=["terminal", "credential files", "keylog files"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["phishing", "keylogger", "template", "live", "ngrok", "credential", "device", "info"],
        notes="git clone https://github.com/DarkSecDevelopers/HiddenEye-Legacy",
    ),

    KaliTool(
        name="zphisher",
        category=Category.SOCIAL_ENG,
        subcategory="credential_harvesting",
        description="Automated phishing tool — 30+ templates with cloudflared/ngrok tunneling",
        syntax="bash zphisher.sh",
        common_flags={
            "1-30":                 "Select template",
            "Cloudflared":          "Use Cloudflare tunnel",
            "Ngrok":                "Use ngrok tunnel",
            "Localhost":            "Local only",
            "Custom Port":          "Custom port option",
        },
        use_cases=[
            "Quick phishing deployment",
            "Cloudflare tunnel integration (harder to block)",
            "30+ social media templates",
            "Automated URL generation",
        ],
        output_formats=["terminal", "credential log"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["phishing", "cloudflare", "tunnel", "template", "automated", "credential", "ngrok"],
        notes="git clone https://github.com/htr-tech/zphisher. Uses cloudflared for stable URLs.",
    ),

    # ══════════════════════════════════════════
    # PRETEXTING & SPOOFING
    # ══════════════════════════════════════════

    KaliTool(
        name="spooftel",
        category=Category.SOCIAL_ENG,
        subcategory="vishing_spoofing",
        description="Caller ID spoofing — make phone calls appear to come from any number",
        syntax="# Web-based service or SIP configuration",
        common_flags={
            "SIP trunk":        "Configure SIP provider",
            "Asterisk":         "Use Asterisk PBX for spoofing",
            "CallerID":         "Set spoofed caller ID",
        },
        use_cases=[
            "Vishing (voice phishing) attacks",
            "Impersonate trusted organizations",
            "Test employee awareness of vishing",
            "Social engineering via phone calls",
        ],
        output_formats=["voice calls"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["vishing", "caller", "id", "spoof", "phone", "call", "impersonate", "voice"],
        notes="Use Asterisk + SIP trunk. Many VoIP providers offer CallerID spoofing APIs.",
    ),

    KaliTool(
        name="email-spoofing",
        category=Category.SOCIAL_ENG,
        subcategory="vishing_spoofing",
        description="Email spoofing techniques — send emails appearing to come from trusted domains",
        syntax="sendmail -f <spoofed@domain.com> -t <target@email.com>  |  swaks --from <spoofed>",
        common_flags={
            "swaks --from <spoofed> --to <target> --server <smtp>":  "Spoof via open relay",
            "sendmail -f <from> <to>":                               "Send via sendmail",
            "python3 smtp_spoof.py":                                 "Python SMTP spoofing",
            "Check SPF/DMARC first":                                 "Verify domain has weak SPF/DMARC",
        },
        use_cases=[
            "Test email spoofing defenses (SPF/DKIM/DMARC)",
            "Spear phishing via email spoofing",
            "Internal phishing simulations",
            "Test open mail relay servers",
        ],
        output_formats=["email"],
        avg_time_seconds=5,
        risk_level=RiskLevel.CRITICAL,
        keywords=["email", "spoof", "spf", "dmarc", "dkim", "relay", "phishing", "impersonate"],
        notes="Check domain SPF/DMARC: dig TXT domain.com. Domains without SPF/DMARC are spoofable.",
    ),

    # ══════════════════════════════════════════
    # USB & PHYSICAL ATTACKS
    # ══════════════════════════════════════════

    KaliTool(
        name="usb-rubber-ducky",
        category=Category.SOCIAL_ENG,
        subcategory="physical_attacks",
        description="USB HID attack tool — keystroke injection device that appears as keyboard",
        syntax="# Write DuckyScript payloads, compile with duckencoder",
        common_flags={
            "DELAY <ms>":           "Wait milliseconds",
            "STRING <text>":        "Type string",
            "ENTER":                "Press Enter",
            "GUI r":                "Windows+R (Run dialog)",
            "CTRL ALT t":          "Open terminal (Linux)",
            "ALT F2":               "Open run dialog (Linux)",
            "duckencoder -i <script> -o inject.bin": "Compile DuckyScript",
        },
        use_cases=[
            "Physical access keyboard injection attacks",
            "Bypass locked screens with auto-type",
            "Deploy payloads via USB in seconds",
            "Test physical security controls",
            "Red team physical intrusion simulation",
        ],
        output_formats=["compiled bin file"],
        avg_time_seconds=5,
        risk_level=RiskLevel.CRITICAL,
        keywords=["usb", "rubber", "ducky", "hid", "keystroke", "inject", "physical", "keyboard"],
        notes="Hardware: Hak5 Rubber Ducky. Use duckencoder to compile payloads.",
    ),

    KaliTool(
        name="bash-bunny",
        category=Category.SOCIAL_ENG,
        subcategory="physical_attacks",
        description="Multi-function USB attack platform — HID, network, storage attacks in one device",
        syntax="# Write payloads in /payloads/switch1/ or /payloads/switch2/",
        common_flags={
            "ATTACKMODE HID":               "Keyboard injection mode",
            "ATTACKMODE RNDIS_ETHERNET":    "Network adapter mode",
            "ATTACKMODE STORAGE":           "Mass storage mode",
            "ATTACKMODE HID STORAGE":       "Combined HID + storage",
            "Q STRING <text>":              "Type string (QuackScript)",
            "Q ENTER":                      "Press Enter",
            "LED <color>":                  "Set LED color",
        },
        use_cases=[
            "Advanced USB physical attacks",
            "Combine HID + network attacks",
            "Credential harvesting via USB network adapter",
            "Multi-stage payload delivery",
        ],
        output_formats=["loot directory"],
        avg_time_seconds=5,
        risk_level=RiskLevel.CRITICAL,
        keywords=["bash", "bunny", "usb", "hid", "network", "physical", "payload", "credential"],
        notes="Hardware: Hak5 Bash Bunny. More powerful than Rubber Ducky.",
    ),

    KaliTool(
        name="o-mg-cable",
        category=Category.SOCIAL_ENG,
        subcategory="physical_attacks",
        description="Malicious USB-C/Lightning cable — looks normal but contains HID attack payload",
        syntax="# Configure via OMG server web interface",
        common_flags={
            "Keylogger mode":   "Log all keystrokes",
            "Payload mode":     "Execute DuckyScript payloads",
            "WiFi trigger":     "Trigger payload via WiFi",
            "Geofencing":       "Trigger based on location",
        },
        use_cases=[
            "Covert physical attack via charging cable",
            "Keylogging via seemingly normal cable",
            "Remote payload triggering",
            "Red team physical security testing",
        ],
        output_formats=["web interface", "keylog files"],
        avg_time_seconds=0,
        risk_level=RiskLevel.CRITICAL,
        keywords=["cable", "usb", "hid", "covert", "keylogger", "physical", "charging", "omg"],
        notes="Hardware: Hak5 O.MG Cable. Most covert physical attack vector.",
    ),

    # ══════════════════════════════════════════
    # SMS PHISHING
    # ══════════════════════════════════════════

    KaliTool(
        name="smishing-tools",
        category=Category.SOCIAL_ENG,
        subcategory="smishing",
        description="SMS phishing (smishing) — send spoofed SMS messages for credential harvesting",
        syntax="# Use Twilio API or SMS spoofing services",
        common_flags={
            "Twilio API":       "Programmatic SMS via Twilio",
            "TextBelt API":     "Free SMS API for testing",
            "SET SMS Spoofing": "SET menu option 7",
            "--from <number>":  "Spoofed sender number",
            "--to <number>":    "Target phone number",
            "--message <text>": "SMS message content",
        },
        use_cases=[
            "SMS phishing campaign simulation",
            "Mobile credential harvesting",
            "Test employee smishing awareness",
            "Combined with phishing pages",
        ],
        output_formats=["SMS messages"],
        avg_time_seconds=2,
        risk_level=RiskLevel.CRITICAL,
        keywords=["sms", "smishing", "phishing", "mobile", "text", "spoof", "credential", "awareness"],
        notes="Use SET > SMS Spoofing Attack Vector or Twilio API for legitimate testing.",
    ),

    # ══════════════════════════════════════════
    # INFORMATION GATHERING FOR SE
    # ══════════════════════════════════════════

    KaliTool(
        name="osint-se",
        category=Category.SOCIAL_ENG,
        subcategory="se_recon",
        description="OSINT for social engineering — gather personal info to craft convincing pretexts",
        syntax="# Combine: theHarvester + Sherlock + LinkedIn + SpiderFoot",
        common_flags={
            "theHarvester -d <domain> -b all":  "Harvest emails and names",
            "sherlock <username>":              "Find social profiles",
            "linkedin2username -c <company>":   "Get employee usernames",
            "spiderfoot -s <target>":           "Full OSINT on target",
            "h8mail -t <email>":                "Find breached passwords",
        },
        use_cases=[
            "Build detailed target profiles for SE attacks",
            "Find personal info for pretexting",
            "Identify security questions answers",
            "Map organizational hierarchy for spear phishing",
        ],
        output_formats=["combined reports"],
        avg_time_seconds=120,
        risk_level=RiskLevel.MEDIUM,
        keywords=["osint", "recon", "profile", "pretext", "spear", "phishing", "employee", "personal"],
        notes="Combine multiple OSINT tools for comprehensive target profiling before SE attack.",
    ),

    KaliTool(
        name="maltego-se",
        category=Category.SOCIAL_ENG,
        subcategory="se_recon",
        description="Maltego for social engineering — map target relationships and attack surface visually",
        syntax="maltego  (GUI — use Person/Organization entity types)",
        common_flags={
            "Person entity":            "Start with target person",
            "To Email Address":         "Find email addresses",
            "To Phone Numbers":         "Find phone numbers",
            "To Social Networks":       "Find social profiles",
            "To Organization":          "Find employer",
            "To Website":               "Find associated websites",
            "Run all transforms":       "Comprehensive data gathering",
        },
        use_cases=[
            "Map target's social connections",
            "Identify relationships for spear phishing",
            "Find personal information for pretexting",
            "Organizational chart reconstruction",
        ],
        output_formats=["visual graph", "report"],
        avg_time_seconds=0,
        risk_level=RiskLevel.MEDIUM,
        keywords=["maltego", "graph", "social", "engineer", "map", "relationship", "spear", "phishing"],
        notes="Use Maltego Person entity as starting point. Run transforms to find emails, phones, social profiles.",
    ),
]


# ── Quick stats ───────────────────────────────
if __name__ == "__main__":
    print(f"Social Engineering expansion: {len(SOCIAL_ENGINEERING_TOOLS)} tools")

    subcats = {}
    for t in SOCIAL_ENGINEERING_TOOLS:
        subcats[t.subcategory] = subcats.get(t.subcategory, 0) + 1

    print("\nBy subcategory:")
    for sub, count in sorted(subcats.items()):
        print(f"  {sub:<30} {count} tools")

    print("\nIntegrate with knowledge base:")
    print("  from nova_kali_kb_social_engineering import SOCIAL_ENGINEERING_TOOLS")
    print("  from nova_kali_knowledge_base import KALI_TOOLS")
    print("  KALI_TOOLS.extend(SOCIAL_ENGINEERING_TOOLS)")
