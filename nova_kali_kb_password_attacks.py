"""
NOVA KALI KNOWLEDGE BASE — PASSWORD ATTACKS EXPANSION
=======================================================
Full expansion of the Password Attacks category.
Add this to nova_kali_knowledge_base.py by importing and extending KALI_TOOLS.

Subcategories covered:
- Online Brute Force
- Offline Hash Cracking
- Rainbow Table Attacks
- Wordlist Generation & Mutation
- Hash Identification & Analysis
- Protocol-Specific Attacks
- Windows Password Attacks
- Password Policy Auditing
- GPU-Accelerated Cracking

Usage:
    from nova_kali_kb_password_attacks import PASSWORD_ATTACK_TOOLS
    from nova_kali_knowledge_base import KALI_TOOLS, KaliKnowledgeBase

    KALI_TOOLS.extend(PASSWORD_ATTACK_TOOLS)
    kb = KaliKnowledgeBase()
"""

from nova_kali_knowledge_base import KaliTool, Category, RiskLevel

PASSWORD_ATTACK_TOOLS = [

    # ══════════════════════════════════════════
    # ONLINE BRUTE FORCE
    # ══════════════════════════════════════════

    KaliTool(
        name="patator",
        category=Category.PASSWORD,
        subcategory="online_brute_force",
        description="Multi-purpose brute forcer with modular design — more flexible than Hydra",
        syntax="patator <module> <options>",
        common_flags={
            "ssh_login host=<ip> user=<u> password=FILE0 0=<wordlist>": "SSH brute force",
            "ftp_login host=<ip> user=<u> password=FILE0 0=<wordlist>": "FTP brute force",
            "http_fuzz url=<url> method=POST body='user=<u>&pass=FILE0' 0=<wordlist>": "HTTP form",
            "smtp_login host=<ip> user=<u> password=FILE0 0=<wordlist>": "SMTP brute force",
            "-x ignore:code=401":   "Ignore 401 responses",
            "-x ignore:fgrep=<s>":  "Ignore responses containing string",
            "--threads=<n>":        "Number of threads",
            "--timeout=<n>":        "Connection timeout",
            "-o <file>":            "Output file",
        },
        use_cases=[
            "SSH/FTP/SMTP/HTTP brute force",
            "Custom HTTP form attacks",
            "DNS brute force",
            "LDAP/SMB authentication testing",
            "More granular control than Hydra",
        ],
        output_formats=["text", "csv"],
        avg_time_seconds=120,
        risk_level=RiskLevel.HIGH,
        keywords=["brute", "force", "online", "modular", "ssh", "ftp", "http", "flexible"],
        notes="Install: apt install patator. Supports: ssh, ftp, telnet, smtp, ldap, snmp, dns, http, smb, and more.",
    ),

    KaliTool(
        name="ncrack",
        category=Category.PASSWORD,
        subcategory="online_brute_force",
        description="High-speed network authentication cracker — designed for large-scale audits",
        syntax="ncrack [options] [target]",
        common_flags={
            "-U <file>":            "Username list",
            "-P <file>":            "Password list",
            "-u <user>":            "Single username",
            "-p <pass>":            "Single password",
            "--user <u>":           "Username",
            "-T <0-5>":             "Timing template (0=paranoid, 5=insane)",
            "-v":                   "Verbose",
            "-oN <file>":           "Normal output",
            "-oX <file>":           "XML output",
            "ssh://<ip>":           "Target SSH",
            "rdp://<ip>":           "Target RDP",
            "ftp://<ip>":           "Target FTP",
            "telnet://<ip>":        "Target Telnet",
            "-CL <file>":           "Credential combo list (user:pass)",
        },
        use_cases=[
            "Large-scale network auth cracking",
            "RDP brute force",
            "SSH/FTP/Telnet cracking",
            "VNC authentication testing",
            "WordPress/HTTP auth testing",
        ],
        output_formats=["text", "xml", "gnmap"],
        avg_time_seconds=120,
        risk_level=RiskLevel.HIGH,
        keywords=["brute", "force", "network", "rdp", "ssh", "large", "scale", "ncrack"],
        notes="Install: apt install ncrack. Supports: ssh, rdp, ftp, telnet, http, pop3, imap, smb, vnc, wordpress.",
    ),

    KaliTool(
        name="spray",
        category=Category.PASSWORD,
        subcategory="online_brute_force",
        description="Password spraying tool for various protocols — avoid account lockouts",
        syntax="spray.sh -smb <dc_ip> <user_file> <password> <attempts> <lockout_mins> <domain>",
        common_flags={
            "-smb":    "SMB protocol",
            "-owa":    "Outlook Web Access",
            "-lync":   "Lync/Skype for Business",
            "-imap":   "IMAP email",
        },
        use_cases=[
            "Password spraying against AD (avoid lockouts)",
            "OWA/Exchange spraying",
            "Careful credential testing with delay control",
        ],
        output_formats=["text"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["spray", "password", "smb", "ad", "lockout", "owa", "exchange"],
        notes="git clone https://github.com/Greenwolf/Spray. Always check lockout policy first.",
    ),

    KaliTool(
        name="brutespray",
        category=Category.PASSWORD,
        subcategory="online_brute_force",
        description="Automatically brute force services found by nmap scans",
        syntax="brutespray -f <nmap.xml> [options]",
        common_flags={
            "-f <nmap.xml>":    "Nmap XML output file",
            "-u <user>":        "Single username",
            "-p <pass>":        "Single password",
            "-U <file>":        "Username list",
            "-P <file>":        "Password list",
            "-t <n>":           "Threads per service",
            "-o <dir>":         "Output directory",
            "--only-default":   "Only try default credentials",
        },
        use_cases=[
            "Auto-attack all services found in nmap scan",
            "Default credential testing across network",
            "Mass service credential auditing",
        ],
        output_formats=["text", "directory of results"],
        avg_time_seconds=120,
        risk_level=RiskLevel.HIGH,
        keywords=["brute", "nmap", "auto", "services", "credentials", "default", "spray"],
        notes="Install: apt install brutespray. Works directly from nmap -oX output.",
    ),

    # ══════════════════════════════════════════
    # OFFLINE HASH CRACKING
    # ══════════════════════════════════════════

    KaliTool(
        name="john-jumbo",
        category=Category.PASSWORD,
        subcategory="offline_cracking",
        description="John the Ripper Jumbo — community-enhanced version with more hash formats",
        syntax="john [options] <hashfile>",
        common_flags={
            "--wordlist=<f>":        "Dictionary attack",
            "--rules":               "Apply default mangling rules",
            "--rules=<ruleset>":     "Apply specific ruleset (e.g. KoreLogic)",
            "--incremental":         "Brute force all combinations",
            "--incremental=<mode>":  "Specific charset (Alpha, Digits, ASCII)",
            "--format=<fmt>":        "Hash format (auto-detect if omitted)",
            "--list=formats":        "List all supported formats",
            "--show":                "Show cracked passwords",
            "--session=<name>":      "Name this session",
            "--restore=<name>":      "Restore session",
            "--fork=<n>":            "Fork N processes",
            "--pot=<file>":          "Custom pot file",
            "--mask=<mask>":         "Mask attack (e.g. ?u?l?l?l?d?d)",
            "--markov":              "Markov mode",
            "--external=<mode>":     "External mode (custom logic)",
        },
        use_cases=[
            "Crack /etc/shadow hashes",
            "Crack NTLM/NTLMv2 hashes",
            "Dictionary + rules attacks",
            "Brute force unknown passwords",
            "Crack ZIP/RAR/PDF/Office passwords",
            "Crack Kerberos hashes (AS-REP, TGS)",
        ],
        output_formats=["text", "pot file"],
        avg_time_seconds=300,
        risk_level=RiskLevel.HIGH,
        keywords=["hash", "crack", "offline", "dictionary", "rules", "brute", "shadow", "ntlm"],
        notes="Jumbo version supports 400+ formats. Install: apt install john. Pot file: ~/.john/john.pot",
    ),

    KaliTool(
        name="hashcat-advanced",
        category=Category.PASSWORD,
        subcategory="offline_cracking",
        description="Hashcat advanced usage — rules, masks, hybrid attacks, brain feature",
        syntax="hashcat -m <type> -a <mode> <hashfile> <wordlist/mask> [options]",
        common_flags={
            "-m 0":              "MD5",
            "-m 100":            "SHA1",
            "-m 1000":           "NTLM",
            "-m 1800":           "sha512crypt (Linux shadow)",
            "-m 2500":           "WPA/WPA2 (use hcxtools to convert)",
            "-m 5600":           "NTLMv2",
            "-m 13100":          "Kerberos TGS-REP (Kerberoasting)",
            "-m 18200":          "Kerberos AS-REP (ASREPRoasting)",
            "-a 0":              "Dictionary attack",
            "-a 1":              "Combination attack",
            "-a 3":              "Brute force/mask attack",
            "-a 6":              "Hybrid wordlist + mask",
            "-a 7":              "Hybrid mask + wordlist",
            "-r <rules>":        "Rules file",
            "--increment":       "Increment mask length",
            "--brain-server":    "Enable brain deduplication server",
            "--brain-client":    "Connect to brain server",
            "--loopback":        "Add cracked hashes back to wordlist",
            "-S":                "Slow candidates (for complex rules)",
            "--status":          "Show live status",
            "-O":                "Optimized kernel (shorter passwords)",
            "--stdout":          "Print candidates to stdout",
        },
        use_cases=[
            "GPU-accelerated hash cracking",
            "Kerberoasting hash cracking",
            "WPA2 handshake cracking",
            "NTLM/NTLMv2 cracking",
            "Rule-based mutations",
            "Mask attacks for known password patterns",
        ],
        output_formats=["text", "potfile"],
        avg_time_seconds=300,
        risk_level=RiskLevel.HIGH,
        keywords=["hashcat", "gpu", "crack", "mask", "rules", "kerberos", "ntlm", "wpa2", "hybrid"],
        notes="Use --force on Termux/VM. Hash mode list: hashcat --help | grep -i <type>",
    ),

    KaliTool(
        name="ophcrack",
        category=Category.PASSWORD,
        subcategory="windows_password",
        description="Windows password cracker using rainbow tables — cracks LM and NTLM hashes",
        syntax="ophcrack  (GUI)  |  ophcrack -g -d <tables_dir> -t <hashes_file>",
        common_flags={
            "-g":               "GUI mode",
            "-d <dir>":         "Rainbow tables directory",
            "-t <file>":        "Hash file",
            "-f <file>":        "SAM file",
            "-n <n>":           "Number of threads",
            "-o <file>":        "Output file",
            "-s":               "Statistics only",
        },
        use_cases=[
            "Crack Windows LM/NTLM hashes with rainbow tables",
            "Fast Windows password recovery",
            "Offline SAM database cracking",
            "No wordlist needed — uses precomputed tables",
        ],
        output_formats=["text", "gui"],
        avg_time_seconds=3600,
        risk_level=RiskLevel.HIGH,
        keywords=["windows", "rainbow", "ntlm", "lm", "sam", "crack", "ophcrack"],
        notes="Install: apt install ophcrack. Download free tables from: https://ophcrack.sourceforge.io/tables.php",
    ),

    # ══════════════════════════════════════════
    # RAINBOW TABLE ATTACKS
    # ══════════════════════════════════════════

    KaliTool(
        name="rainbowcrack",
        category=Category.PASSWORD,
        subcategory="rainbow_tables",
        description="Hash cracker using precomputed rainbow tables — time-memory tradeoff",
        syntax="rcrack <table_dir> -h <hash>  |  rcrack <table_dir> -l <hash_file>",
        common_flags={
            "-h <hash>":        "Single hash to crack",
            "-l <file>":        "File with hashes",
            "-f <file>":        "Hash file",
            "rtgen":            "Generate rainbow tables",
            "rtsort":           "Sort rainbow tables (required before cracking)",
        },
        use_cases=[
            "Crack MD5/SHA1/LM/NTLM with precomputed tables",
            "Faster than brute force for common passwords",
            "Offline hash cracking without GPU",
        ],
        output_formats=["text"],
        avg_time_seconds=600,
        risk_level=RiskLevel.HIGH,
        keywords=["rainbow", "table", "crack", "hash", "precomputed", "md5", "sha1", "lm", "ntlm"],
        notes="Install: apt install rainbowcrack. Generate tables: rtgen md5 loweralpha 1 7 0 2400 8000000 0",
    ),

    KaliTool(
        name="rcracki-mt",
        category=Category.PASSWORD,
        subcategory="rainbow_tables",
        description="Multi-threaded rainbow table cracker — faster than standard rainbowcrack",
        syntax="rcracki_mt <table_dir> -h <hash>",
        common_flags={
            "-h <hash>":    "Single hash",
            "-l <file>":    "Hash list file",
            "-t <n>":       "Threads",
            "-o <file>":    "Output file",
        },
        use_cases=[
            "Multi-threaded rainbow table cracking",
            "LM/NTLM/MD5 hash cracking",
            "Faster alternative to rainbowcrack",
        ],
        output_formats=["text"],
        avg_time_seconds=300,
        risk_level=RiskLevel.HIGH,
        keywords=["rainbow", "table", "multi", "thread", "crack", "hash", "fast"],
        notes="Install: apt install rcracki-mt",
    ),

    # ══════════════════════════════════════════
    # WORDLIST GENERATION & MUTATION
    # ══════════════════════════════════════════

    KaliTool(
        name="rsmangler",
        category=Category.PASSWORD,
        subcategory="wordlist_generation",
        description="Wordlist mangler — generates permutations, acronyms, and mutations from input words",
        syntax="rsmangler --file <wordlist> [options]",
        common_flags={
            "--file <f>":       "Input wordlist",
            "--output <f>":     "Output file",
            "--min <n>":        "Minimum word length",
            "--max <n>":        "Maximum word length",
            "--perm":           "Generate permutations",
            "--acro":           "Generate acronyms",
            "--leet":           "Apply leet speak substitutions",
            "--capital":        "Capitalize first letter",
            "--upper":          "All uppercase",
            "--lower":          "All lowercase",
            "--reverse":        "Reverse words",
            "--ed":             "Add common suffixes",
            "--full":           "Apply all mangles",
        },
        use_cases=[
            "Generate targeted wordlists from company/person names",
            "Apply leet speak and common password patterns",
            "Create permutations for targeted attacks",
        ],
        output_formats=["text"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["wordlist", "mangle", "mutate", "permutation", "leet", "generate", "targeted"],
        notes="Install: apt install rsmangler. Pair with theHarvester output for targeted attacks.",
    ),

    KaliTool(
        name="wordlistctl",
        category=Category.PASSWORD,
        subcategory="wordlist_generation",
        description="Fetch, install and search wordlist archives from online repositories",
        syntax="wordlistctl <command> [options]",
        common_flags={
            "fetch -l <name>":    "Download a wordlist by name",
            "search <term>":      "Search available wordlists",
            "list":               "List all available wordlists",
            "list -g <group>":    "List by group (passwords, usernames, etc.)",
            "-d <dir>":           "Download directory",
            "-X":                 "Extract after download",
        },
        use_cases=[
            "Download rockyou, SecLists, and other wordlists",
            "Search for domain-specific wordlists",
            "Manage local wordlist library",
        ],
        output_formats=["text", "downloaded files"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["wordlist", "download", "rockyou", "seclists", "fetch", "manage"],
        notes="Install: apt install wordlistctl. Downloads to /usr/share/wordlists/ by default.",
    ),

    KaliTool(
        name="mentalist",
        category=Category.PASSWORD,
        subcategory="wordlist_generation",
        description="GUI wordlist generator — build custom wordlists with rules and patterns",
        syntax="mentalist  (GUI application)",
        common_flags={
            "Base Words":   "Input base words",
            "Rules":        "Add transformation rules",
            "Generate":     "Generate wordlist",
            "Export":       "Export to file",
        },
        use_cases=[
            "Visual wordlist creation",
            "Rule-based password generation",
            "Targeted wordlist building",
        ],
        output_formats=["text", "gui"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["wordlist", "gui", "generate", "rules", "targeted", "visual"],
        notes="Install: apt install mentalist. GUI-only tool.",
    ),

    KaliTool(
        name="pack",
        category=Category.PASSWORD,
        subcategory="wordlist_generation",
        description="Password Analysis and Cracking Kit — analyze password lists and generate optimized masks",
        syntax="python3 statsgen.py <wordlist>  |  python3 maskgen.py <stats>",
        common_flags={
            "statsgen.py <file>":          "Analyze password list statistics",
            "maskgen.py <stats>":          "Generate hashcat masks from stats",
            "policygen.py":                "Generate masks from password policy",
            "--minlength=<n>":             "Minimum password length",
            "--maxlength=<n>":             "Maximum password length",
            "--mindigit=<n>":              "Minimum digit count",
            "--minupper=<n>":              "Minimum uppercase count",
            "--minspecial=<n>":            "Minimum special char count",
            "-o <file>":                   "Output mask file",
            "--target-time=<seconds>":     "Target crack time",
        },
        use_cases=[
            "Analyze cracked password patterns",
            "Generate optimized hashcat masks",
            "Build masks from known password policies",
            "Improve cracking efficiency",
        ],
        output_formats=["text", "mask files"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["mask", "analysis", "statistics", "hashcat", "policy", "optimize", "pattern"],
        notes="git clone https://github.com/iphelix/pack. Use statsgen output as maskgen input.",
    ),

    KaliTool(
        name="cupp",
        category=Category.PASSWORD,
        subcategory="wordlist_generation",
        description="Common User Passwords Profiler — generate targeted wordlists from personal info",
        syntax="python3 cupp.py [options]",
        common_flags={
            "-i":           "Interactive mode (enter target info)",
            "-w <file>":    "Improve existing wordlist",
            "-l":           "Download huge wordlist from repository",
            "-a":           "Parse default usernames and passwords",
            "-v":           "Verbose",
        },
        use_cases=[
            "Generate passwords from target's personal info (name, DOB, pet, etc.)",
            "Social engineering-based wordlist creation",
            "Targeted spear-phishing password guessing",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.MEDIUM,
        keywords=["targeted", "wordlist", "personal", "profile", "social", "engineering", "cupp"],
        notes="Install: apt install cupp. Pairs well with LinkedIn/Facebook OSINT.",
    ),

    KaliTool(
        name="princeprocessor",
        category=Category.PASSWORD,
        subcategory="wordlist_generation",
        description="PRINCE wordlist generator — generates password candidates from input words",
        syntax="pp64.bin [options] < <wordlist>",
        common_flags={
            "--pw-min=<n>":         "Minimum password length",
            "--pw-max=<n>":         "Maximum password length",
            "--elem-cnt-min=<n>":   "Minimum elements per candidate",
            "--elem-cnt-max=<n>":   "Maximum elements per candidate",
            "--wl-dist-len":        "Calculate length distribution",
            "--keyspace":           "Show total keyspace",
            "--output-file=<f>":    "Output file",
        },
        use_cases=[
            "Generate complex password candidates",
            "Combine words intelligently for cracking",
            "Better than simple dictionary for complex passwords",
        ],
        output_formats=["text", "piped to hashcat"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["wordlist", "prince", "generate", "combine", "candidates", "complex"],
        notes="Install: apt install princeprocessor. Pipe to hashcat: pp64.bin < words.txt | hashcat -m 0",
    ),

    # ══════════════════════════════════════════
    # HASH IDENTIFICATION & ANALYSIS
    # ══════════════════════════════════════════

    KaliTool(
        name="hash-identifier",
        category=Category.PASSWORD,
        subcategory="hash_identification",
        description="Identify hash types — older tool, broader format detection than hashid",
        syntax="hash-identifier  (interactive)  |  hash-identifier <hash>",
        common_flags={},
        use_cases=[
            "Identify unknown hash format",
            "Differentiate between similar hash types",
        ],
        output_formats=["text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["hash", "identify", "type", "format", "unknown"],
        notes="Install: apt install hash-identifier. Use hashid for more accurate identification.",
    ),

    KaliTool(
        name="name-that-hash",
        category=Category.PASSWORD,
        subcategory="hash_identification",
        description="Modern hash identifier — faster and more accurate than hash-identifier",
        syntax="nth --text '<hash>'  |  nth --file <hashfile>",
        common_flags={
            "--text '<hash>'":  "Identify single hash",
            "--file <file>":    "Identify hashes in file",
            "--output <file>":  "Output file",
            "-g":               "Grep-able output",
            "-a":               "Show all possible hashes",
            "--hashcat":        "Show hashcat mode",
            "--john":           "Show john format",
        },
        use_cases=[
            "Quickly identify hash type before cracking",
            "Get hashcat mode and john format in one command",
            "Process multiple hashes at once",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["hash", "identify", "nth", "modern", "hashcat", "mode", "format"],
        notes="Install: pip install name-that-hash. Modern replacement for hash-identifier.",
    ),

    # ══════════════════════════════════════════
    # PROTOCOL-SPECIFIC ATTACKS
    # ══════════════════════════════════════════

    KaliTool(
        name="polenum",
        category=Category.PASSWORD,
        subcategory="password_policy",
        description="Extract Windows password policy from a domain/host via SMB",
        syntax="polenum <domain>/<user>:<pass>@<ip>",
        common_flags={
            "<domain>/<user>:<pass>@<ip>": "Standard auth format",
            "--username <u>":              "Username",
            "--password <p>":              "Password",
            "--domain <d>":                "Domain",
        },
        use_cases=[
            "Extract password policy before brute forcing",
            "Check lockout threshold and duration",
            "Inform spray timing to avoid lockouts",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["policy", "lockout", "windows", "smb", "domain", "spray", "threshold"],
        notes="Install: apt install polenum. Always check policy before brute forcing Windows accounts.",
    ),

    KaliTool(
        name="sipcrack",
        category=Category.PASSWORD,
        subcategory="protocol_specific",
        description="SIP protocol login sniffer and cracker — capture and crack SIP digest auth",
        syntax="sipdump -i <iface> -p <pcap>  |  sipcrack -w <wordlist> <dumpfile>",
        common_flags={
            "sipdump -i <iface>":   "Capture SIP auth from interface",
            "sipdump -p <pcap>":    "Parse SIP auth from pcap",
            "sipcrack -w <list>":   "Crack captured SIP hashes",
            "-f <file>":            "Dump file to crack",
        },
        use_cases=[
            "VoIP/SIP authentication cracking",
            "Capture SIP digest authentication",
            "Test SIP server password strength",
        ],
        output_formats=["text", "dump file"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["sip", "voip", "digest", "crack", "capture", "authentication"],
        notes="Install: apt install sipcrack. Requires SIP traffic capture first with sipdump.",
    ),

    KaliTool(
        name="gpp-decrypt",
        category=Category.PASSWORD,
        subcategory="protocol_specific",
        description="Decrypt Group Policy Preferences (GPP) passwords from XML files",
        syntax="gpp-decrypt <encrypted_password>",
        common_flags={},
        use_cases=[
            "Decrypt GPP passwords from SYSVOL",
            "Extract cpassword values from Groups.xml",
            "MS14-025 vulnerability exploitation",
        ],
        output_formats=["text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.HIGH,
        keywords=["gpp", "group policy", "cpassword", "xml", "decrypt", "windows", "sysvol"],
        notes="Install: apt install gpp-decrypt. Find GPP files: find //<dc>/SYSVOL -name Groups.xml",
    ),

    KaliTool(
        name="truecrack",
        category=Category.PASSWORD,
        subcategory="volume_cracking",
        description="Brute force password cracker for TrueCrypt/VeraCrypt volumes",
        syntax="truecrack -t <volume> -w <wordlist>",
        common_flags={
            "-t <volume>":      "TrueCrypt/VeraCrypt volume file",
            "-w <wordlist>":    "Wordlist",
            "-k <keyfile>":     "Keyfile",
            "-n <n>":           "Number of threads",
            "-v":               "Verbose",
        },
        use_cases=[
            "Brute force encrypted TrueCrypt volumes",
            "VeraCrypt password recovery",
            "Forensic volume password recovery",
        ],
        output_formats=["text"],
        avg_time_seconds=600,
        risk_level=RiskLevel.HIGH,
        keywords=["truecrypt", "veracrypt", "volume", "encrypt", "crack", "brute", "forensic"],
        notes="Install: apt install truecrack. GPU-optimized for NVIDIA CUDA.",
    ),

    KaliTool(
        name="fcrackzip",
        category=Category.PASSWORD,
        subcategory="archive_cracking",
        description="Fast ZIP password cracker — dictionary and brute force attacks on ZIP files",
        syntax="fcrackzip [options] <zipfile>",
        common_flags={
            "-u":               "Use unzip to filter false positives",
            "-D":               "Dictionary attack",
            "-p <wordlist>":    "Wordlist for dictionary attack",
            "-b":               "Brute force mode",
            "-c <charset>":     "Charset (a=lower, A=upper, 1=digits, !=special)",
            "-l <min-max>":     "Password length range",
            "-v":               "Verbose",
        },
        use_cases=[
            "Crack password-protected ZIP files",
            "CTF challenge ZIP cracking",
            "Forensic ZIP password recovery",
        ],
        output_formats=["text"],
        avg_time_seconds=60,
        risk_level=RiskLevel.MEDIUM,
        keywords=["zip", "crack", "archive", "password", "dictionary", "brute", "ctf"],
        notes="Install: apt install fcrackzip. For RAR files use: rarcrack",
    ),

    KaliTool(
        name="rarcrack",
        category=Category.PASSWORD,
        subcategory="archive_cracking",
        description="Crack password-protected RAR, ZIP, and 7z archives",
        syntax="rarcrack <archive> --threads <n> --type <rar|zip|7z>",
        common_flags={
            "--threads <n>":    "Number of threads",
            "--type rar":       "RAR archive",
            "--type zip":       "ZIP archive",
            "--type 7z":        "7z archive",
        },
        use_cases=[
            "Crack password-protected RAR/ZIP/7z files",
            "CTF archive password recovery",
            "Forensic archive cracking",
        ],
        output_formats=["text"],
        avg_time_seconds=120,
        risk_level=RiskLevel.MEDIUM,
        keywords=["rar", "zip", "7z", "archive", "crack", "password", "ctf"],
        notes="Install: apt install rarcrack.",
    ),

    KaliTool(
        name="pdf2john",
        category=Category.PASSWORD,
        subcategory="archive_cracking",
        description="Extract hash from password-protected PDF for cracking with John or Hashcat",
        syntax="pdf2john <file.pdf> > hash.txt",
        common_flags={},
        use_cases=[
            "Extract PDF password hash",
            "Crack PDF passwords via john/hashcat",
            "CTF PDF challenge solving",
        ],
        output_formats=["hash text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.MEDIUM,
        keywords=["pdf", "hash", "extract", "crack", "john", "hashcat", "ctf"],
        notes="Part of john package. Also: zip2john, rar2john, office2john, ssh2john for other formats.",
    ),

    # ══════════════════════════════════════════
    # WINDOWS PASSWORD ATTACKS
    # ══════════════════════════════════════════

    KaliTool(
        name="mimipenguin",
        category=Category.PASSWORD,
        subcategory="credential_dumping",
        description="Dump login credentials from Linux memory — like Mimikatz but for Linux",
        syntax="python3 mimipenguin.py  |  sudo bash mimipenguin.sh",
        common_flags={
            "--help":   "Show help",
        },
        use_cases=[
            "Dump plaintext credentials from Linux memory",
            "Extract passwords from gnome-keyring, VSFTPd, Apache, SSH",
            "Post-exploitation Linux credential harvesting",
        ],
        output_formats=["text"],
        avg_time_seconds=5,
        risk_level=RiskLevel.CRITICAL,
        keywords=["linux", "credentials", "dump", "memory", "plaintext", "gnome", "keyring"],
        notes="git clone https://github.com/huntergregal/mimipenguin. Requires root.",
    ),

    KaliTool(
        name="acccheck",
        category=Category.PASSWORD,
        subcategory="windows_password",
        description="Password dictionary attack tool against Windows via SMB/NetBIOS",
        syntax="acccheck -t <ip> -u <user> -P <wordlist>",
        common_flags={
            "-t <ip>":      "Target IP",
            "-u <user>":    "Username",
            "-U <file>":    "Username file",
            "-p <pass>":    "Single password",
            "-P <file>":    "Password file",
            "-v":           "Verbose",
        },
        use_cases=[
            "SMB/NetBIOS password dictionary attack",
            "Windows share credential testing",
            "Network authentication auditing",
        ],
        output_formats=["text"],
        avg_time_seconds=60,
        risk_level=RiskLevel.HIGH,
        keywords=["smb", "windows", "netbios", "dictionary", "attack", "share", "credentials"],
        notes="Install: apt install acccheck.",
    ),

    # ══════════════════════════════════════════
    # PASSWORD ANALYSIS & AUDITING
    # ══════════════════════════════════════════

    KaliTool(
        name="pipal-advanced",
        category=Category.PASSWORD,
        subcategory="password_analysis",
        description="Advanced password analyzer — detailed statistics from cracked password lists",
        syntax="ruby pipal.rb <password_file>",
        common_flags={
            "--top <n>":        "Show top N results per category",
            "--output <f>":     "Output file",
            "--external <f>":   "External word list for comparison",
        },
        use_cases=[
            "Analyze password patterns after cracking",
            "Generate stats for security reports",
            "Identify most common base words and patterns",
            "Password policy compliance checking",
        ],
        output_formats=["text"],
        avg_time_seconds=15,
        risk_level=RiskLevel.LOW,
        keywords=["analyze", "statistics", "pattern", "report", "policy", "compliance", "crack"],
        notes="Install: apt install pipal. Great for post-engagement reporting.",
    ),

    KaliTool(
        name="chntpw",
        category=Category.PASSWORD,
        subcategory="windows_password",
        description="Offline Windows password and registry editor — reset Windows passwords",
        syntax="chntpw -u <username> <SAM_file>",
        common_flags={
            "-u <user>":    "Select user to modify",
            "-l":           "List users in SAM",
            "-i":           "Interactive mode",
            "-e":           "Registry editor mode",
            "SAM":          "Path to SAM file (e.g. /mnt/windows/Windows/System32/config/SAM)",
            "SYSTEM":       "Path to SYSTEM file",
        },
        use_cases=[
            "Reset Windows local admin password offline",
            "Unlock Windows accounts without knowing password",
            "Forensic Windows account analysis",
            "Physical access privilege escalation",
        ],
        output_formats=["text", "modified SAM"],
        avg_time_seconds=10,
        risk_level=RiskLevel.CRITICAL,
        keywords=["windows", "reset", "password", "sam", "offline", "registry", "admin"],
        notes="Install: apt install chntpw. Boot from Kali live USB, mount Windows drive, run against SAM file.",
    ),

    KaliTool(
        name="samdump2",
        category=Category.PASSWORD,
        subcategory="windows_password",
        description="Dump Windows SAM database hashes offline from mounted Windows partition",
        syntax="samdump2 <SYSTEM_file> <SAM_file>",
        common_flags={},
        use_cases=[
            "Extract NTLM hashes from offline Windows SAM",
            "Forensic Windows hash extraction",
            "Pre-cracking hash collection",
        ],
        output_formats=["text", "hashes"],
        avg_time_seconds=5,
        risk_level=RiskLevel.CRITICAL,
        keywords=["sam", "windows", "hash", "ntlm", "dump", "offline", "forensic"],
        notes="Install: apt install samdump2. Requires SYSTEM and SAM files from Windows/System32/config/",
    ),
]


# ── Quick stats ───────────────────────────────
if __name__ == "__main__":
    print(f"Password Attacks expansion: {len(PASSWORD_ATTACK_TOOLS)} tools")

    subcats = {}
    for t in PASSWORD_ATTACK_TOOLS:
        subcats[t.subcategory] = subcats.get(t.subcategory, 0) + 1

    print("\nBy subcategory:")
    for sub, count in sorted(subcats.items()):
        print(f"  {sub:<30} {count} tools")

    print("\nIntegrate with knowledge base:")
    print("  from nova_kali_kb_password_attacks import PASSWORD_ATTACK_TOOLS")
    print("  from nova_kali_knowledge_base import KALI_TOOLS")
    print("  KALI_TOOLS.extend(PASSWORD_ATTACK_TOOLS)")
