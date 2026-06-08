"""
NOVA KALI KNOWLEDGE BASE — REPORTING EXPANSION
================================================
Full expansion of the Reporting category.
Add this to nova_kali_knowledge_base.py by importing and extending KALI_TOOLS.

Subcategories covered:
- Pentest Collaboration Platforms
- Report Generation
- Note Taking & Documentation
- Data Aggregation & Visualization
- Evidence Management
- Template-Based Reporting
- Automated Report Generation

Usage:
    from nova_kali_kb_reporting import REPORTING_TOOLS
    from nova_kali_knowledge_base import KALI_TOOLS, KaliKnowledgeBase

    KALI_TOOLS.extend(REPORTING_TOOLS)
    kb = KaliKnowledgeBase()
"""

from nova_kali_knowledge_base import KaliTool, Category, RiskLevel

REPORTING_TOOLS = [

    # ══════════════════════════════════════════
    # PENTEST COLLABORATION PLATFORMS
    # ══════════════════════════════════════════

    KaliTool(
        name="dradis",
        category=Category.REPORTING,
        subcategory="collaboration_platform",
        description="Open-source pentest collaboration and reporting platform — import tool results and generate client reports",
        syntax="service dradis start  |  dradis (web UI at https://127.0.0.1:3004)",
        common_flags={
            "service dradis start":         "Start Dradis service",
            "service dradis stop":          "Stop Dradis service",
            "https://127.0.0.1:3004":       "Web UI URL",
            "Import > Nmap":                "Import Nmap XML results",
            "Import > Nessus":              "Import Nessus .nessus file",
            "Import > Burp":                "Import Burp Suite XML",
            "Import > Nexpose":             "Import Nexpose XML",
            "Notes > New Note":             "Add finding note",
            "Evidence > Add Evidence":      "Add screenshot/evidence",
            "Reports > Export":             "Generate Word/HTML report",
            "Projects > New Project":       "Create new engagement",
        },
        use_cases=[
            "Team collaboration during pentest engagements",
            "Import and consolidate tool outputs (Nmap, Nessus, Burp)",
            "Generate client-ready reports from templates",
            "Track findings with severity and evidence",
            "Multi-user pentest project management",
            "PCI-DSS and NIST report templates",
        ],
        output_formats=["web UI", "word (.docx)", "html", "excel"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["report", "collaborate", "pentest", "import", "nmap", "nessus", "burp", "template", "findings"],
        notes="Install: apt install dradis. Web UI: https://127.0.0.1:3004. Import nmap: -oX output.xml",
    ),

    KaliTool(
        name="faraday",
        category=Category.REPORTING,
        subcategory="collaboration_platform",
        description="Integrated Pentest Environment (IPE) — multi-user IDE for collaborative penetration testing and reporting",
        syntax="faraday-server  |  faraday-client  (web UI at http://localhost:5985)",
        common_flags={
            "faraday-server":               "Start Faraday server",
            "faraday-client":               "Start Faraday client",
            "http://localhost:5985":        "Web UI URL",
            "Workspaces > New":             "Create workspace per engagement",
            "Hosts > Add Host":             "Add discovered host",
            "Vulns > New Vuln":             "Add vulnerability finding",
            "Reports > Generate":           "Generate pentest report",
            "--pipeline":                   "Enable tool pipeline integration",
            "fplugin nmap -xml <file>":     "Import Nmap via plugin",
            "fplugin burp -xml <file>":     "Import Burp via plugin",
        },
        use_cases=[
            "Multi-user collaborative penetration testing",
            "Real-time tool output aggregation",
            "Vulnerability database per engagement",
            "Integration with 70+ security tools",
            "Generate executive and technical reports",
            "Manage multiple client engagements",
        ],
        output_formats=["web UI", "pdf", "html", "xml", "csv"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["faraday", "ipe", "collaborative", "multi-user", "aggregate", "pipeline", "engagement", "report"],
        notes="Install: apt install faraday-server faraday-client. Integrates with Nmap, Metasploit, Burp, Nessus, etc.",
    ),

    KaliTool(
        name="serpico",
        category=Category.REPORTING,
        subcategory="collaboration_platform",
        description="Pentest report generation tool — template-based collaborative reporting with Metasploit integration",
        syntax="ruby serpico.rb  (web UI at https://localhost:8443)",
        common_flags={
            "https://localhost:8443":       "Web UI URL",
            "Reports > New Report":         "Create new report",
            "Add Finding":                  "Add vulnerability finding",
            "Templates > New Template":     "Create custom report template",
            "Metasploit > Sync":            "Import from Metasploit DB",
            "Screenshots > Upload":         "Add evidence screenshots",
            "Export > Word":                "Export as Word document",
            "--bind <ip>":                  "Bind address",
            "--port <n>":                   "Port number",
        },
        use_cases=[
            "Template-based pentest report generation",
            "Metasploit database integration",
            "Screenshot and evidence management",
            "Collaborative report writing",
            "Custom report templates",
        ],
        output_formats=["web UI", "word (.docx)"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["report", "template", "metasploit", "screenshot", "evidence", "collaborate", "word"],
        notes="Install: apt install serpico. Note: Largely unmaintained. Consider PwnDoc or Dradis instead.",
    ),

    KaliTool(
        name="ghostwriter",
        category=Category.REPORTING,
        subcategory="collaboration_platform",
        description="Reporting and engagement management platform — track findings, manage clients, generate reports",
        syntax="# Docker-based deployment: docker-compose up",
        common_flags={
            "Engagements > New":            "Create new pentest engagement",
            "Findings > Add Finding":       "Document vulnerability",
            "Reports > Generate":           "Generate report",
            "Clients > New Client":         "Add client",
            "Evidence > Upload":            "Upload screenshots",
            "Templates > Manage":           "Custom report templates",
            "Calendar > Schedule":          "Track project timeline",
            "Activity Log":                 "Audit trail of actions",
        },
        use_cases=[
            "Full engagement lifecycle management",
            "Multi-client pentest firm management",
            "Custom branded report generation",
            "Team collaboration and task assignment",
            "Evidence and artifact management",
            "Calendar and project timeline tracking",
        ],
        output_formats=["web UI", "word (.docx)", "pdf"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["ghostwriter", "engagement", "management", "report", "client", "team", "collaborate", "timeline"],
        notes="git clone https://github.com/GhostManager/Ghostwriter. Docker required. Most feature-rich option.",
    ),

    KaliTool(
        name="pwndoc",
        category=Category.REPORTING,
        subcategory="report_generation",
        description="Self-hosted pentest report generation — modern web UI with customizable templates and findings database",
        syntax="# Docker: docker-compose up  |  Access: https://localhost:8443",
        common_flags={
            "Audits > New Audit":           "Create new pentest report",
            "Findings > Add":               "Add vulnerability finding",
            "Templates > New Template":     "Create Word template",
            "Data > Custom Fields":         "Add custom finding fields",
            "Export > Word":                "Export as Word document",
            "Vulnerabilities > Library":    "Reusable finding library",
            "Users > Manage":               "Multi-user management",
        },
        use_cases=[
            "Modern pentest report generation",
            "Reusable vulnerability library",
            "Custom Word report templates",
            "Team-based report writing",
            "CVSS scoring integration",
        ],
        output_formats=["web UI", "word (.docx)"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["pwndoc", "report", "word", "template", "findings", "library", "cvss", "modern"],
        notes="git clone https://github.com/pwndoc/pwndoc. Active development. Good Dradis/Serpico alternative.",
    ),

    KaliTool(
        name="sysreptor",
        category=Category.REPORTING,
        subcategory="report_generation",
        description="Pentest report writing platform — popular for OSCP and HTB certification reports",
        syntax="# Docker: docker-compose up  |  Access: http://localhost:8000",
        common_flags={
            "Projects > New":               "Create new report project",
            "Sections > Edit":              "Edit report sections",
            "Findings > Add":               "Add vulnerability finding",
            "Designs > Templates":          "Manage report designs",
            "Export > PDF":                 "Export as PDF",
            "--design <id>":                "Use specific report design",
        },
        use_cases=[
            "OSCP exam report writing",
            "HackTheBox certification reports",
            "Professional pentest report generation",
            "Custom PDF report templates",
            "Team-based report collaboration",
        ],
        output_formats=["web UI", "pdf"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["sysreptor", "oscp", "htb", "report", "pdf", "certification", "pentest", "template"],
        notes="git clone https://github.com/Syslifters/sysreptor. Popular for OSCP reports. PDF-only output.",
    ),

    # ══════════════════════════════════════════
    # NOTE TAKING & DOCUMENTATION
    # ══════════════════════════════════════════

    KaliTool(
        name="cherrytree",
        category=Category.REPORTING,
        subcategory="note_taking",
        description="Hierarchical note-taking application — organize pentest findings, commands, and evidence",
        syntax="cherrytree  (GUI application)",
        common_flags={
            "Node > Add Node":          "Add new section/node",
            "Node > Add Child Node":    "Add child section",
            "Format > Code Box":        "Insert code block",
            "Insert > Image":           "Add screenshot",
            "Insert > Table":           "Add table",
            "File > Export > PDF":      "Export notes as PDF",
            "File > Password":          "Encrypt notebook",
            "Search > Find in Nodes":   "Search all notes",
        },
        use_cases=[
            "Organize pentest notes hierarchically",
            "Document commands and outputs during engagement",
            "Store screenshots and evidence",
            "Encrypted note storage for sensitive data",
            "Export findings to PDF",
            "Template-based note structure for engagements",
        ],
        output_formats=["cherrytree file (.ctd/.ctb)", "pdf", "html", "txt"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["notes", "organize", "hierarchy", "screenshot", "evidence", "encrypt", "pentest", "document"],
        notes="Install: apt install cherrytree. Essential daily-driver for pentesters. Supports encrypted .ctb files.",
    ),

    KaliTool(
        name="obsidian",
        category=Category.REPORTING,
        subcategory="note_taking",
        description="Markdown-based knowledge base — link notes together for comprehensive pentest documentation",
        syntax="obsidian  (GUI — download from obsidian.md)",
        common_flags={
            "[[link]]":                 "Create note link",
            "Graph View":               "Visualize note connections",
            "Templates":                "Use note templates",
            "Tags":                     "Tag notes for organization",
            "Canvas":                   "Visual mind mapping",
            "Community Plugins":        "Extend functionality",
            "Ctrl+P":                   "Command palette",
            "Ctrl+Shift+F":             "Search all notes",
        },
        use_cases=[
            "Interconnected pentest note-taking",
            "Visual knowledge graph of findings",
            "Markdown-based report drafting",
            "Long-term knowledge management",
            "Team knowledge sharing via vaults",
        ],
        output_formats=["markdown files", "pdf (via plugin)", "html"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["obsidian", "markdown", "notes", "knowledge", "graph", "link", "template", "pentest"],
        notes="Download: obsidian.md. Free for personal use. Popular among CTF players and pentesters.",
    ),

    # ══════════════════════════════════════════
    # DATA AGGREGATION & VISUALIZATION
    # ══════════════════════════════════════════

    KaliTool(
        name="magictree",
        category=Category.REPORTING,
        subcategory="data_aggregation",
        description="Pentest data aggregation tool — consolidate, query, and report data from multiple tools",
        syntax="magictree  (GUI — Java application)",
        common_flags={
            "Import > Nmap XML":        "Import Nmap results",
            "Import > Nessus":          "Import Nessus results",
            "Query > XQuery":           "Query imported data",
            "Report > Generate":        "Generate report",
            "Tree View":                "View hierarchical data",
            "Task > New Task":          "Create pentest task",
        },
        use_cases=[
            "Aggregate data from multiple scanning tools",
            "Query findings using XQuery",
            "Generate reports from consolidated data",
            "Pentest project management",
            "Track findings across multiple hosts",
        ],
        output_formats=["gui", "html", "xml"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["aggregate", "consolidate", "nmap", "nessus", "query", "report", "tree", "data"],
        notes="Install: apt install magictree. Java-based. Good for consolidating multiple tool outputs.",
    ),

    KaliTool(
        name="maltego-report",
        category=Category.REPORTING,
        subcategory="data_visualization",
        description="Maltego graph export — export visual OSINT relationship graphs for reports",
        syntax="maltego  (GUI — File > Export Graph)",
        common_flags={
            "File > Export Graph":          "Export as image/PDF",
            "View > Screenshot":            "Take graph screenshot",
            "Report > Generate Report":     "Auto-generate report",
            "Export as PNG/PDF/SVG":        "Image formats",
            "Share > Collaborate":          "Share investigation",
        },
        use_cases=[
            "Export OSINT relationship graphs for reports",
            "Visual evidence of attack surface",
            "Client-facing infrastructure maps",
            "Social engineering target relationship maps",
        ],
        output_formats=["png", "pdf", "svg", "maltego graph"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["maltego", "graph", "export", "visual", "osint", "relationship", "map", "report"],
        notes="Export graphs from Maltego for inclusion in pentest reports as visual evidence.",
    ),

    # ══════════════════════════════════════════
    # EVIDENCE MANAGEMENT
    # ══════════════════════════════════════════

    KaliTool(
        name="flameshot",
        category=Category.REPORTING,
        subcategory="evidence_management",
        description="Screenshot tool with annotation — capture and annotate screenshots for pentest reports",
        syntax="flameshot gui  |  flameshot full -p <path>  |  flameshot screen",
        common_flags={
            "gui":                      "Interactive screenshot with annotation",
            "full -p <path>":           "Full screen capture to path",
            "screen -n <n>":            "Capture specific screen",
            "-d <ms>":                  "Delay before capture",
            "Annotation tools":         "Arrow, rectangle, text, blur",
            "Copy to clipboard":        "Copy for pasting into reports",
            "Upload":                   "Upload to Imgur",
        },
        use_cases=[
            "Annotate proof-of-concept screenshots",
            "Add arrows and text to highlight findings",
            "Blur sensitive information in screenshots",
            "Capture evidence for pentest reports",
            "Quick screenshot workflow during engagements",
        ],
        output_formats=["png", "jpg", "clipboard"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["screenshot", "annotate", "evidence", "arrow", "blur", "capture", "report", "poc"],
        notes="Install: apt install flameshot. Best screenshot tool for pentest evidence collection.",
    ),

    KaliTool(
        name="recordmydesktop-report",
        category=Category.REPORTING,
        subcategory="evidence_management",
        description="Screen recording for pentest evidence — record exploitation demos for reports",
        syntax="recordmydesktop [options] -o <output.ogv>",
        common_flags={
            "-o <file>":            "Output file",
            "--no-sound":           "Disable audio recording",
            "--fps <n>":            "Frames per second",
            "--width <n>":          "Recording width",
            "--height <n>":         "Recording height",
            "--x <n> --y <n>":      "Recording position",
            "--windowid <id>":      "Record specific window",
            "--pause-shortcut":     "Keyboard shortcut to pause",
        },
        use_cases=[
            "Record exploitation proof-of-concept videos",
            "Document attack chain for reports",
            "Create client demo recordings",
            "Evidence of time-sensitive findings",
        ],
        output_formats=["ogv video"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["record", "screen", "video", "evidence", "poc", "demo", "exploitation", "report"],
        notes="Install: apt install recordmydesktop. Convert ogv to mp4: ffmpeg -i output.ogv output.mp4",
    ),

    # ══════════════════════════════════════════
    # AUTOMATED REPORT GENERATION
    # ══════════════════════════════════════════

    KaliTool(
        name="pipal-report",
        category=Category.REPORTING,
        subcategory="automated_reporting",
        description="Password statistics analyzer — generate password analysis reports from cracked password lists",
        syntax="ruby pipal.rb <password_file> --output <report>",
        common_flags={
            "<password_file>":      "Cracked password list",
            "--top <n>":            "Top N results per category",
            "--output <file>":      "Output report file",
            "--external <file>":    "External comparison wordlist",
        },
        use_cases=[
            "Generate password strength analysis reports",
            "Show password policy compliance stats",
            "Identify most common password patterns",
            "Include in client security awareness sections",
        ],
        output_formats=["text report"],
        avg_time_seconds=15,
        risk_level=RiskLevel.LOW,
        keywords=["password", "analysis", "statistics", "report", "patterns", "compliance", "awareness"],
        notes="Install: apt install pipal. Include password analysis in pentest reports to show impact.",
    ),

    KaliTool(
        name="msf-report",
        category=Category.REPORTING,
        subcategory="automated_reporting",
        description="Metasploit reporting — export findings from Metasploit database to reports",
        syntax="db_export -f <format> -o <output>  (inside msfconsole)",
        common_flags={
            "db_export -f xml -o <file>":   "Export XML report",
            "db_export -f pwdump <file>":   "Export password hashes",
            "hosts -o <file>":              "Export hosts to CSV",
            "vulns -o <file>":              "Export vulnerabilities to CSV",
            "services -o <file>":           "Export services to CSV",
            "creds -o <file>":              "Export credentials to CSV",
            "notes -o <file>":              "Export notes to CSV",
            "loot -o <file>":               "Export loot to CSV",
        },
        use_cases=[
            "Export Metasploit findings for reports",
            "Generate vulnerability lists from MSF database",
            "Export compromised credentials for evidence",
            "Create asset inventory from scan results",
        ],
        output_formats=["xml", "csv", "pwdump"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["metasploit", "export", "report", "database", "findings", "hosts", "vulns", "creds"],
        notes="Run inside msfconsole. Requires postgresql DB: msfdb init",
    ),

    KaliTool(
        name="nmap-report",
        category=Category.REPORTING,
        subcategory="automated_reporting",
        description="Nmap report generation — convert Nmap XML to readable HTML/CSV reports",
        syntax="xsltproc <nmap.xsl> <scan.xml> -o <report.html>  |  python3 nmap-report.py",
        common_flags={
            "nmap -oX <file>":                          "Save Nmap XML output",
            "nmap -oA <basename>":                      "Save all formats",
            "xsltproc nmap.xsl scan.xml -o report.html":"Convert XML to HTML",
            "nmap-parse-output <file>":                 "Parse Nmap output",
            "--json":                                   "JSON output",
            "--markdown":                               "Markdown output",
        },
        use_cases=[
            "Convert Nmap XML scans to readable HTML reports",
            "Generate port/service inventory for clients",
            "Include network discovery data in reports",
            "Batch process multiple Nmap scans",
        ],
        output_formats=["html", "csv", "json", "markdown"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["nmap", "xml", "html", "convert", "report", "port", "service", "inventory"],
        notes="nmap-xsl: /usr/share/nmap/nmap.xsl. Tool: pip install nmap-parse-output",
    ),
]


# ── Quick stats ───────────────────────────────
if __name__ == "__main__":
    print(f"Reporting expansion: {len(REPORTING_TOOLS)} tools")

    subcats = {}
    for t in REPORTING_TOOLS:
        subcats[t.subcategory] = subcats.get(t.subcategory, 0) + 1

    print("\nBy subcategory:")
    for sub, count in sorted(subcats.items()):
        print(f"  {sub:<30} {count} tools")

    print("\nIntegrate with knowledge base:")
    print("  from nova_kali_kb_reporting import REPORTING_TOOLS")
    print("  from nova_kali_knowledge_base import KALI_TOOLS")
    print("  KALI_TOOLS.extend(REPORTING_TOOLS)")
