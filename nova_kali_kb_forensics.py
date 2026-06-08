"""
NOVA KALI KNOWLEDGE BASE — FORENSICS EXPANSION
================================================
Full expansion of the Forensics category.
Add this to nova_kali_knowledge_base.py by importing and extending KALI_TOOLS.

Subcategories covered:
- Disk Imaging & Acquisition
- Data Carving & File Recovery
- Memory Forensics
- Network Forensics
- Mobile Forensics
- Browser & Artifact Analysis
- Steganography
- Hash & Integrity Verification
- Log Analysis
- Anti-Forensics Detection
- Metadata Analysis
- Timeline Analysis

Usage:
    from nova_kali_kb_forensics import FORENSICS_TOOLS
    from nova_kali_knowledge_base import KALI_TOOLS, KaliKnowledgeBase

    KALI_TOOLS.extend(FORENSICS_TOOLS)
    kb = KaliKnowledgeBase()
"""

from nova_kali_knowledge_base import KaliTool, Category, RiskLevel

FORENSICS_TOOLS = [

    # ══════════════════════════════════════════
    # DISK IMAGING & ACQUISITION
    # ══════════════════════════════════════════

    KaliTool(
        name="dc3dd",
        category=Category.FORENSICS,
        subcategory="disk_imaging",
        description="Forensic DD — patched GNU dd with hashing, progress, pattern writing for forensic imaging",
        syntax="dc3dd if=<source> of=<destination> [options]",
        common_flags={
            "if=<source>":          "Input device/file",
            "of=<destination>":     "Output file",
            "hash=md5":             "Hash during imaging (md5/sha1/sha256/sha512)",
            "hof=<hashfile>":       "Write hash to file",
            "log=<logfile>":        "Write log to file",
            "bs=<size>":            "Block size (e.g. bs=512)",
            "cnt=<n>":              "Block count",
            "skip=<n>":             "Skip N blocks from input",
            "pat=<hex>":            "Fill unreadable sectors with pattern",
            "verb=on":              "Verbose progress",
            "split=<size>":         "Split output into chunks",
            "ssz=<size>":           "Segment size for split",
        },
        use_cases=[
            "Forensic disk imaging with integrity verification",
            "Hash verification during acquisition",
            "Image failing drives sector by sector",
            "Write-protected evidence acquisition",
            "Multi-hash imaging (MD5 + SHA256 simultaneously)",
        ],
        output_formats=["raw image", "hash file", "log file"],
        avg_time_seconds=600,
        risk_level=RiskLevel.LOW,
        keywords=["disk", "image", "forensic", "hash", "acquire", "dd", "integrity", "evidence"],
        notes="Install: apt install dc3dd. Always image to a different drive than the source.",
    ),

    KaliTool(
        name="guymager",
        category=Category.FORENSICS,
        subcategory="disk_imaging",
        description="GUI forensic disk imager — create forensic images with built-in hex editor",
        syntax="guymager  (GUI application)",
        common_flags={
            "Acquire image":    "Start imaging wizard",
            "EWF format":       "Expert Witness Format (E01)",
            "AFF format":       "Advanced Forensic Format",
            "dd format":        "Raw DD image",
            "Split size":       "Split image into chunks",
            "Hash verification":"MD5/SHA1/SHA256",
            "Hex editor":       "Built-in hex editor for headers",
        },
        use_cases=[
            "GUI-based forensic disk imaging",
            "Create EWF/AFF/DD forensic images",
            "Multi-threaded fast imaging",
            "Simultaneous source verification",
            "Evidence integrity documentation",
        ],
        output_formats=["E01 (EWF)", "AFF", "raw DD", "split images"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["disk", "image", "gui", "ewf", "aff", "forensic", "acquire", "evidence"],
        notes="Install: apt install guymager. Supports EWF format used by EnCase.",
    ),

    KaliTool(
        name="ddrescue",
        category=Category.FORENSICS,
        subcategory="disk_imaging",
        description="Data recovery tool — recover data from failing drives, minimizing data loss",
        syntax="ddrescue [options] <input> <output> <mapfile>",
        common_flags={
            "-d":               "Direct disc access (no kernel cache)",
            "-r <n>":           "Retry failed blocks N times",
            "-R":               "Reverse direction",
            "-T <time>":        "Max time between successful reads",
            "-C":               "Verify copy",
            "-v":               "Verbose",
            "-n":               "No scrape (skip failed blocks on first pass)",
            "-f":               "Force overwrite output",
            "<mapfile>":        "Log file for resuming interrupted recovery",
        },
        use_cases=[
            "Recover data from failing/damaged drives",
            "Resume interrupted imaging sessions",
            "Bad sector imaging",
            "Forensic recovery of damaged evidence drives",
        ],
        output_formats=["raw image", "map file"],
        avg_time_seconds=1800,
        risk_level=RiskLevel.LOW,
        keywords=["recover", "failing", "drive", "bad", "sector", "data", "rescue", "resume"],
        notes="Install: apt install gddrescue. Always use mapfile to allow resuming: ddrescue /dev/sdb image.dd map.log",
    ),

    KaliTool(
        name="ewftools",
        category=Category.FORENSICS,
        subcategory="disk_imaging",
        description="Expert Witness Format tools — acquire, verify, export and info on EWF/E01 images",
        syntax="ewfacquire <device>  |  ewfverify <image>  |  ewfinfo <image>",
        common_flags={
            "ewfacquire <dev>":     "Acquire image in EWF format",
            "ewfverify <image>":    "Verify EWF image integrity",
            "ewfinfo <image>":      "Display EWF image information",
            "ewfexport <image>":    "Export EWF to raw DD",
            "ewfmount <image> <mp>":"Mount EWF image as filesystem",
            "-t <target>":          "Target filename (without extension)",
            "-S <size>":            "Segment file size",
            "-c <compression>":     "Compression level",
            "-m <media_type>":      "Media type (fixed/removable/optical)",
        },
        use_cases=[
            "Create and verify EWF/E01 forensic images",
            "Mount EWF images for analysis",
            "Convert between image formats",
            "Verify image integrity with hash comparison",
        ],
        output_formats=["E01/EWF", "raw"],
        avg_time_seconds=300,
        risk_level=RiskLevel.LOW,
        keywords=["ewf", "e01", "encase", "image", "verify", "mount", "forensic", "format"],
        notes="Install: apt install ewf-tools. Industry-standard forensic image format.",
    ),

    # ══════════════════════════════════════════
    # DATA CARVING & FILE RECOVERY
    # ══════════════════════════════════════════

    KaliTool(
        name="foremost",
        category=Category.FORENSICS,
        subcategory="data_carving",
        description="File recovery tool — recover deleted files based on headers, footers and data structures",
        syntax="foremost [options] -i <image>",
        common_flags={
            "-i <image>":       "Input file/device",
            "-o <dir>":         "Output directory",
            "-t <types>":       "File types (jpg,pdf,doc,xls,zip,all)",
            "-c <config>":      "Custom config file",
            "-v":               "Verbose",
            "-q":               "Quick mode (faster, less thorough)",
            "-T":               "Set output directory timestamp",
            "-b <size>":        "Block size",
            "-k <size>":        "Chunk size",
        },
        use_cases=[
            "Recover deleted JPG, PDF, DOC, ZIP files",
            "Data carving from disk images",
            "Unallocated space analysis",
            "Flash drive and SD card recovery",
        ],
        output_formats=["recovered files", "audit.txt"],
        avg_time_seconds=120,
        risk_level=RiskLevel.LOW,
        keywords=["carve", "recover", "deleted", "file", "header", "footer", "unallocated"],
        notes="Install: apt install foremost. Config: /etc/foremost.conf for custom file types.",
    ),

    KaliTool(
        name="scalpel",
        category=Category.FORENSICS,
        subcategory="data_carving",
        description="High-performance file carver — faster than foremost with configurable file types",
        syntax="scalpel [options] <image>",
        common_flags={
            "-c <config>":      "Configuration file",
            "-o <dir>":         "Output directory",
            "-b":               "Carve with no size limits",
            "-r":               "Find overlapping headers",
            "-O":               "Don't organize files by type",
            "-v":               "Verbose",
            "-i <file>":        "Input list of files",
        },
        use_cases=[
            "High-speed file carving from disk images",
            "Custom file type recovery",
            "Recover files from damaged filesystems",
            "Evidence recovery in forensic investigations",
        ],
        output_formats=["recovered files", "scalpel.log"],
        avg_time_seconds=90,
        risk_level=RiskLevel.LOW,
        keywords=["carve", "recover", "fast", "file", "config", "custom", "disk", "image"],
        notes="Install: apt install scalpel. Edit /etc/scalpel/scalpel.conf to enable file types.",
    ),

    KaliTool(
        name="bulk-extractor",
        category=Category.FORENSICS,
        subcategory="data_carving",
        description="Extract features from disk images without parsing filesystem — emails, URLs, credit cards",
        syntax="bulk_extractor [options] -o <output_dir> <image>",
        common_flags={
            "-o <dir>":         "Output directory",
            "-E <scanner>":     "Enable specific scanner",
            "-x <scanner>":     "Disable specific scanner",
            "-e email":         "Extract email addresses",
            "-e url":           "Extract URLs",
            "-e ccn":           "Extract credit card numbers",
            "-e pdf":           "Extract PDF content",
            "-j <n>":           "Threads",
            "-S <opt>=<val>":   "Set scanner option",
            "-R":               "Recursive scan of directory",
            "-r <file>":        "Alert list file",
            "-w <file>":        "Stop list file",
        },
        use_cases=[
            "Extract emails, URLs, and IPs from disk images",
            "Credit card number detection",
            "Domain and URL extraction",
            "Phone number extraction",
            "Social media artifact extraction",
            "EXIF data extraction",
        ],
        output_formats=["feature files", "histogram files", "json"],
        avg_time_seconds=180,
        risk_level=RiskLevel.LOW,
        keywords=["extract", "email", "url", "credit", "card", "phone", "feature", "scan", "disk"],
        notes="Install: apt install bulk-extractor. Outputs feature files readable by BEVIEWER.",
    ),

    KaliTool(
        name="photorec",
        category=Category.FORENSICS,
        subcategory="data_carving",
        description="File recovery software — recover lost photos and documents from storage media",
        syntax="photorec [options] <device>",
        common_flags={
            "/log":             "Enable logging",
            "/d <dir>":         "Output directory",
            "/cmd <device>":    "Non-interactive mode",
            "fileopt":          "Select file types to recover",
            "search":           "Start recovery",
        },
        use_cases=[
            "Photo and document recovery from SD cards",
            "File recovery from formatted drives",
            "Camera card forensics",
            "USB drive recovery",
        ],
        output_formats=["recovered files"],
        avg_time_seconds=180,
        risk_level=RiskLevel.LOW,
        keywords=["photo", "recover", "sd", "card", "camera", "deleted", "file", "format"],
        notes="Install: apt install testdisk (includes photorec). Part of TestDisk suite.",
    ),

    KaliTool(
        name="testdisk",
        category=Category.FORENSICS,
        subcategory="data_carving",
        description="Disk partition recovery — fix partition tables, recover deleted partitions, repair boot sectors",
        syntax="testdisk [/log] [/debug] [<device>]",
        common_flags={
            "Analyse":          "Search for partitions",
            "Advanced":         "Filesystem utilities",
            "Geometry":         "Change disk geometry",
            "Options":          "Change options",
            "Rebuild BS":       "Rebuild boot sector",
            "List":             "List files in partition",
            "Copy":             "Copy files from partition",
        },
        use_cases=[
            "Recover deleted partitions",
            "Repair corrupted partition tables",
            "Recover files from damaged filesystems",
            "Fix MBR and boot sectors",
            "NTFS/FAT/ext2-4 recovery",
        ],
        output_formats=["restored partitions", "recovered files"],
        avg_time_seconds=120,
        risk_level=RiskLevel.LOW,
        keywords=["partition", "recover", "boot", "sector", "mbr", "table", "ntfs", "fat", "ext"],
        notes="Install: apt install testdisk. Includes PhotoRec. Supports NTFS, FAT, ext2/3/4, HFS+.",
    ),

    # ══════════════════════════════════════════
    # MEMORY FORENSICS
    # ══════════════════════════════════════════

    KaliTool(
        name="volatility3",
        category=Category.FORENSICS,
        subcategory="memory_forensics",
        description="Next-generation memory forensics framework — Python 3, no profile needed for Win10+",
        syntax="python3 vol.py -f <memory_dump> <plugin>",
        common_flags={
            "-f <file>":                    "Memory dump file",
            "windows.pslist":               "List Windows processes",
            "windows.pstree":               "Process tree",
            "windows.cmdline":              "Command line args",
            "windows.netscan":              "Network connections",
            "windows.filescan":             "Scan for file objects",
            "windows.dumpfiles":            "Extract files from memory",
            "windows.hashdump":             "Extract password hashes",
            "windows.malfind":              "Find injected code",
            "windows.dlllist":              "List DLLs per process",
            "windows.handles":              "List open handles",
            "windows.registry.hivelist":    "List registry hives",
            "windows.registry.printkey":    "Print registry key",
            "linux.pslist":                 "Linux process list",
            "linux.bash":                   "Bash history from memory",
            "-o <dir>":                     "Output directory",
        },
        use_cases=[
            "Windows/Linux memory dump analysis",
            "Malware detection in memory",
            "Credential extraction from RAM",
            "Network connection analysis",
            "Process injection detection",
            "Registry analysis from memory",
        ],
        output_formats=["text", "json"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["memory", "forensics", "volatility", "dump", "process", "malware", "inject", "ram"],
        notes="Install: apt install volatility3. No profile needed for Win8+. Profiles needed for older Windows.",
    ),

    KaliTool(
        name="lime",
        category=Category.FORENSICS,
        subcategory="memory_forensics",
        description="Linux Memory Extractor — loadable kernel module to acquire Linux memory",
        syntax="insmod lime.ko 'path=<output> format=<fmt>'",
        common_flags={
            "path=<file>":      "Output file path",
            "path=tcp:<port>":  "Stream over TCP",
            "format=raw":       "Raw memory format",
            "format=lime":      "LiME format (recommended)",
            "format=padded":    "Padded format",
            "dio=1":            "Direct IO (bypass page cache)",
        },
        use_cases=[
            "Live Linux memory acquisition",
            "Acquire memory from running Linux system",
            "Remote memory acquisition over TCP",
            "Volatile data preservation",
        ],
        output_formats=["raw", "lime", "padded"],
        avg_time_seconds=60,
        risk_level=RiskLevel.LOW,
        keywords=["linux", "memory", "acquire", "live", "kernel", "module", "ram", "volatile"],
        notes="git clone https://github.com/504ensicsLabs/LiME. Compile for target kernel version.",
    ),

    KaliTool(
        name="rekall",
        category=Category.FORENSICS,
        subcategory="memory_forensics",
        description="Memory forensics framework — fork of Volatility with live memory analysis",
        syntax="rekall -f <memory_dump> <plugin>",
        common_flags={
            "-f <file>":        "Memory image file",
            "pslist":           "Process list",
            "pstree":           "Process tree",
            "netscan":          "Network connections",
            "malfind":          "Find injected code",
            "dlllist":          "DLL list",
            "hashdump":         "Password hashes",
            "live":             "Live memory analysis mode",
            "--output json":    "JSON output",
        },
        use_cases=[
            "Memory forensics analysis",
            "Live system memory analysis",
            "Malware investigation",
            "Incident response",
        ],
        output_formats=["text", "json", "html"],
        avg_time_seconds=20,
        risk_level=RiskLevel.LOW,
        keywords=["memory", "forensics", "rekall", "live", "malware", "process", "analysis"],
        notes="Install: pip install rekall. Supports live analysis without memory dump.",
    ),

    # ══════════════════════════════════════════
    # NETWORK FORENSICS
    # ══════════════════════════════════════════

    KaliTool(
        name="xplico",
        category=Category.FORENSICS,
        subcategory="network_forensics",
        description="Network forensic analysis tool — reconstruct application data from PCAP captures",
        syntax="xplico  (web interface at http://localhost:9876)",
        common_flags={
            "New Case":         "Create forensic case",
            "New Session":      "Create capture session",
            "Upload PCAP":      "Import capture file",
            "HTTP":             "Reconstructed HTTP traffic",
            "Email":            "Reconstructed emails",
            "VoIP":             "Reconstructed VoIP calls",
            "FTP":              "Reconstructed FTP transfers",
        },
        use_cases=[
            "Reconstruct HTTP sessions from PCAP",
            "Extract emails from network captures",
            "VoIP call reconstruction",
            "FTP file transfer reconstruction",
            "Network traffic timeline analysis",
        ],
        output_formats=["web interface", "extracted files"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["pcap", "reconstruct", "http", "email", "voip", "ftp", "network", "traffic"],
        notes="Install: apt install xplico. Start: service apache2 start && service xplico start",
    ),

    KaliTool(
        name="networkminer",
        category=Category.FORENSICS,
        subcategory="network_forensics",
        description="Network forensic analyzer — passive sniffer and PCAP parser for host info extraction",
        syntax="mono NetworkMiner.exe  (runs via Mono on Linux)",
        common_flags={
            "Open PCAP":        "Load capture file",
            "Hosts":            "View discovered hosts",
            "Files":            "Extracted files from traffic",
            "Messages":         "Extracted messages",
            "Credentials":      "Extracted credentials",
            "Sessions":         "Network sessions",
            "DNS":              "DNS queries",
        },
        use_cases=[
            "Extract files from network captures",
            "Passive host discovery",
            "Credential extraction from PCAP",
            "OS fingerprinting from traffic",
            "Email extraction from captures",
        ],
        output_formats=["gui", "extracted files"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["pcap", "network", "extract", "file", "credential", "passive", "host", "forensics"],
        notes="Install: apt install mono-complete. Download NetworkMiner from netresec.com",
    ),

    KaliTool(
        name="chaosreader",
        category=Category.FORENSICS,
        subcategory="network_forensics",
        description="Trace TCP/UDP sessions from tcpdump/snoop files and reassemble data",
        syntax="chaosreader <pcap_file>",
        common_flags={
            "-D <dir>":         "Output directory",
            "-b <size>":        "Buffer size",
            "-v":               "Verbose",
            "-n":               "No DNS resolution",
        },
        use_cases=[
            "Reconstruct TCP sessions from PCAP",
            "Extract HTTP, FTP, SMTP content",
            "Session replay analysis",
        ],
        output_formats=["html", "extracted session files"],
        avg_time_seconds=15,
        risk_level=RiskLevel.LOW,
        keywords=["pcap", "session", "reconstruct", "tcp", "udp", "replay", "extract"],
        notes="Install: apt install chaosreader.",
    ),

    # ══════════════════════════════════════════
    # MOBILE FORENSICS
    # ══════════════════════════════════════════

    KaliTool(
        name="android-sdk-tools",
        category=Category.FORENSICS,
        subcategory="mobile_forensics",
        description="Android Debug Bridge (ADB) — interface with Android devices for forensic extraction",
        syntax="adb [options] <command>",
        common_flags={
            "devices":              "List connected devices",
            "shell":                "Open device shell",
            "pull <remote> <local>":"Pull file from device",
            "push <local> <remote>":"Push file to device",
            "backup -all -f <f>":  "Full device backup",
            "logcat":               "View device logs",
            "shell dumpsys":        "Dump system services info",
            "shell pm list packages":"List installed apps",
            "shell settings get":   "Get device settings",
            "shell getprop":        "Get device properties",
            "-d":                   "USB device",
            "-e":                   "Emulator",
            "-s <serial>":          "Specific device",
        },
        use_cases=[
            "Android device forensic data extraction",
            "App data extraction via ADB",
            "Android device backup",
            "Log analysis from Android devices",
            "Installed package enumeration",
        ],
        output_formats=["files", "text", "backup"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["android", "adb", "mobile", "forensics", "extract", "backup", "app", "device"],
        notes="Install: apt install android-tools-adb. Device must have USB debugging enabled.",
    ),

    KaliTool(
        name="iphone-backup-analyzer",
        category=Category.FORENSICS,
        subcategory="mobile_forensics",
        description="Analyze iPhone backups — extract messages, contacts, calls, app data",
        syntax="python3 iphone-backup-analyzer.py [options]",
        common_flags={
            "-d <backup_dir>":  "iTunes backup directory",
            "-o <output>":      "Output directory",
            "--sms":            "Extract SMS messages",
            "--contacts":       "Extract contacts",
            "--calls":          "Extract call history",
            "--notes":          "Extract notes",
            "--apps":           "Extract app data",
        },
        use_cases=[
            "Extract data from iTunes iPhone backups",
            "SMS and iMessage extraction",
            "Call log analysis",
            "App data forensic analysis",
        ],
        output_formats=["text", "csv", "html"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["iphone", "ios", "backup", "sms", "contacts", "call", "forensics", "mobile"],
        notes="git clone https://github.com/PicciMario/iPhone-Backup-Analyzer-2",
    ),

    # ══════════════════════════════════════════
    # BROWSER & ARTIFACT ANALYSIS
    # ══════════════════════════════════════════

    KaliTool(
        name="galleta",
        category=Category.FORENSICS,
        subcategory="artifact_analysis",
        description="Internet Explorer cookie analyzer — extract and analyze IE cookie files",
        syntax="galleta [options] <cookie_file>",
        common_flags={
            "-d <sep>":         "Field separator character",
        },
        use_cases=[
            "Extract IE cookie data for forensics",
            "Reconstruct browsing sessions from cookies",
            "User activity timeline from IE cookies",
        ],
        output_formats=["text", "csv"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["ie", "internet", "explorer", "cookie", "browser", "artifact", "analyze"],
        notes="Install: apt install galleta.",
    ),

    KaliTool(
        name="pasco",
        category=Category.FORENSICS,
        subcategory="artifact_analysis",
        description="Internet Explorer history analyzer — parse IE index.dat files",
        syntax="pasco [options] <index.dat>",
        common_flags={
            "-d <sep>":         "Output delimiter",
            "-t":               "Output tab-delimited",
        },
        use_cases=[
            "Extract IE browsing history",
            "Parse index.dat files",
            "User web activity timeline reconstruction",
        ],
        output_formats=["text", "csv"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["ie", "history", "browser", "index.dat", "activity", "timeline", "artifact"],
        notes="Install: apt install pasco.",
    ),

    KaliTool(
        name="dff",
        category=Category.FORENSICS,
        subcategory="artifact_analysis",
        description="Digital Forensics Framework — modular open-source forensic analysis platform",
        syntax="dff  (GUI)  |  dff --nogui (CLI)",
        common_flags={
            "local":            "Access local filesystem",
            "open <file>":      "Open evidence file",
            "ls":               "List files",
            "find":             "Search for files",
            "export":           "Export artifacts",
        },
        use_cases=[
            "Comprehensive digital forensic investigation",
            "Disk image analysis",
            "Registry and artifact analysis",
            "Timeline generation",
            "Report generation",
        ],
        output_formats=["gui", "html report"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["forensics", "framework", "analysis", "modular", "gui", "investigation", "platform"],
        notes="Install: apt install dff.",
    ),

    # ══════════════════════════════════════════
    # STEGANOGRAPHY
    # ══════════════════════════════════════════

    KaliTool(
        name="steghide",
        category=Category.FORENSICS,
        subcategory="steganography",
        description="Steganography tool — embed and extract hidden data in image and audio files",
        syntax="steghide <command> -sf <file> [options]",
        common_flags={
            "embed -cf <cover> -sf <secret>":   "Embed file into cover file",
            "extract -sf <stego_file>":          "Extract hidden data",
            "info <file>":                       "Display info about file",
            "-p <password>":                     "Passphrase",
            "-e <algo>":                         "Encryption algorithm",
            "-z <level>":                        "Compression level",
            "-f":                                "Force overwrite",
        },
        use_cases=[
            "Hide files inside JPEG/BMP/WAV/AU files",
            "Extract hidden files from stego images",
            "CTF steganography challenges",
            "Covert data exfiltration detection",
        ],
        output_formats=["embedded files", "extracted files"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["stego", "hidden", "image", "embed", "extract", "jpeg", "wav", "ctf", "covert"],
        notes="Install: apt install steghide. Supports JPEG, BMP, WAV, AU formats.",
    ),

    KaliTool(
        name="stegcracker",
        category=Category.FORENSICS,
        subcategory="steganography",
        description="Steganography brute force tool — crack steghide-protected files with wordlists",
        syntax="stegcracker <file> [wordlist]",
        common_flags={
            "<file>":           "Steganographic file",
            "<wordlist>":       "Password wordlist (default: rockyou.txt)",
            "--threads <n>":    "Threads",
            "--wordlist <f>":   "Custom wordlist",
        },
        use_cases=[
            "Crack steghide password-protected files",
            "CTF steganography challenges",
            "Forensic hidden data extraction",
        ],
        output_formats=["extracted file", "cracked password"],
        avg_time_seconds=60,
        risk_level=RiskLevel.LOW,
        keywords=["stego", "crack", "brute", "force", "hidden", "password", "ctf", "steghide"],
        notes="Install: pip install stegcracker. Only works with steghide-protected files.",
    ),

    KaliTool(
        name="zsteg",
        category=Category.FORENSICS,
        subcategory="steganography",
        description="Detect hidden data in PNG and BMP files — LSB steganography detection",
        syntax="zsteg [options] <image>",
        common_flags={
            "-a":               "Try all detection methods",
            "-b <n>":           "Number of bits",
            "-o <order>":       "Bit order (msb/lsb)",
            "-v":               "Verbose",
            "--lsb":            "LSB first",
            "--msb":            "MSB first",
            "-E <name>":        "Extract specified channel",
            "--all-channels":   "Try all channels",
        },
        use_cases=[
            "LSB steganography detection in PNG/BMP",
            "CTF image challenge solving",
            "Hidden message detection",
            "Multiple channel analysis",
        ],
        output_formats=["text", "extracted data"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["lsb", "stego", "png", "bmp", "hidden", "detect", "ctf", "channel"],
        notes="Install: gem install zsteg. Ruby-based tool.",
    ),

    KaliTool(
        name="outguess",
        category=Category.FORENSICS,
        subcategory="steganography",
        description="Universal steganography tool — hide data in JPEG redundant bits",
        syntax="outguess [options] <input> <output>",
        common_flags={
            "-d <file>":        "Data file to embed",
            "-r":               "Retrieve hidden data",
            "-k <key>":         "Key/passphrase",
            "-t":               "Run statistical tests",
        },
        use_cases=[
            "Embed data in JPEG files",
            "Extract data from outguess-encoded images",
            "CTF steganography",
        ],
        output_formats=["stego image", "extracted data"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["stego", "jpeg", "hidden", "embed", "extract", "ctf", "redundant"],
        notes="Install: apt install outguess.",
    ),

    # ══════════════════════════════════════════
    # HASH & INTEGRITY VERIFICATION
    # ══════════════════════════════════════════

    KaliTool(
        name="md5deep",
        category=Category.FORENSICS,
        subcategory="hash_verification",
        description="Compute and audit MD5/SHA hashes recursively — forensic hash verification",
        syntax="md5deep [options] <files>  |  sha256deep [options] <files>",
        common_flags={
            "-r":               "Recursive",
            "-e":               "Estimate completion time",
            "-s":               "Silent — no warnings",
            "-z":               "Display file size",
            "-m <hashfile>":    "Match against known hash list",
            "-x <hashfile>":    "Exclude files matching hash list",
            "-w <hashfile>":    "Alert on hash list matches",
            "-p <size>":        "Piecewise hashing (chunk size)",
            "-o <types>":       "File types (regular/directory/etc.)",
        },
        use_cases=[
            "Generate forensic hash manifests",
            "Verify evidence integrity",
            "Match files against known malware hash lists",
            "NSRL hash set matching",
            "Piecewise hashing for large files",
        ],
        output_formats=["text", "hashdeep format"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["hash", "md5", "sha256", "integrity", "verify", "forensic", "manifest", "nsrl"],
        notes="Install: apt install hashdeep (includes md5deep, sha1deep, sha256deep, tigerdeep).",
    ),

    KaliTool(
        name="ssdeep",
        category=Category.FORENSICS,
        subcategory="hash_verification",
        description="Fuzzy hashing — compute context-triggered piecewise hashes for similarity matching",
        syntax="ssdeep [options] <files>",
        common_flags={
            "-r":               "Recursive",
            "-m <file>":        "Match against hash file",
            "-b":               "Basename only in output",
            "-l":               "Relative paths",
            "-c":               "CSV output",
            "-s":               "Silent mode",
        },
        use_cases=[
            "Find similar files (even if modified)",
            "Malware variant detection",
            "Identify file modifications",
            "Duplicate document detection",
        ],
        output_formats=["text", "csv"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["fuzzy", "hash", "similar", "malware", "variant", "compare", "match"],
        notes="Install: apt install ssdeep. Compare: ssdeep -m known_hashes.txt suspicious_file",
    ),

    # ══════════════════════════════════════════
    # TIMELINE ANALYSIS
    # ══════════════════════════════════════════

    KaliTool(
        name="log2timeline",
        category=Category.FORENSICS,
        subcategory="timeline_analysis",
        description="Plaso/log2timeline — create super timelines from forensic artifacts",
        syntax="log2timeline.py [options] <storage_file> <source>",
        common_flags={
            "<storage_file>":       "Output Plaso storage file (.plaso)",
            "<source>":             "Source (disk image, directory, etc.)",
            "--parsers <list>":     "Specific parsers to use",
            "--filter_file <f>":    "Filter file for artifacts",
            "--storage-file <f>":   "Storage output file",
            "-z <timezone>":        "Timezone",
            "--workers <n>":        "Worker processes",
            "psort.py <file>":      "Sort and filter timeline",
            "pinfo.py <file>":      "Info about storage file",
        },
        use_cases=[
            "Create comprehensive forensic timelines",
            "Correlate events across multiple artifact types",
            "Windows Event Log timeline",
            "Registry and filesystem timeline",
            "Browser history timeline",
        ],
        output_formats=["plaso storage", "CSV", "json", "l2tcsv", "xlsx"],
        avg_time_seconds=600,
        risk_level=RiskLevel.LOW,
        keywords=["timeline", "plaso", "forensic", "log", "event", "artifact", "correlate", "super"],
        notes="Install: apt install plaso. Use psort.py to filter/output: psort.py -o l2tcsv storage.plaso",
    ),

    KaliTool(
        name="mactime",
        category=Category.FORENSICS,
        subcategory="timeline_analysis",
        description="Part of Sleuth Kit — create timeline from filesystem MAC times (Modified/Accessed/Changed)",
        syntax="mactime [options] -b <bodyfile> -d",
        common_flags={
            "-b <bodyfile>":    "Body file from fls/ils",
            "-d":               "Comma delimited output",
            "-z <timezone>":    "Timezone",
            "-g <groupfile>":   "User/group mapping file",
            "-y":               "Year 2000 output format",
            "<start>-<end>":    "Date range filter",
        },
        use_cases=[
            "Filesystem timeline creation",
            "MAC time analysis",
            "Identify file access patterns",
            "Correlate events with known time of compromise",
        ],
        output_formats=["text", "csv"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["mac", "time", "timeline", "filesystem", "modified", "accessed", "created", "sleuth"],
        notes="Install: apt install sleuthkit. Generate bodyfile first: fls -r -m / <image> > bodyfile",
    ),

    # ══════════════════════════════════════════
    # ANTI-FORENSICS DETECTION
    # ══════════════════════════════════════════

    KaliTool(
        name="chkrootkit",
        category=Category.FORENSICS,
        subcategory="anti_forensics",
        description="Rootkit detector — check for signs of rootkits on Linux systems",
        syntax="chkrootkit [options]",
        common_flags={
            "-n":               "Skip NFS mounted dirs",
            "-r <dir>":         "Use as root directory",
            "-p <dir>":         "Use dir as external command path",
            "-q":               "Quiet mode (only problems)",
            "-x":               "Expert mode",
            "-l":               "Link libraries",
            "<test>":           "Run specific test only",
        },
        use_cases=[
            "Detect rootkits on live Linux systems",
            "Check for modified system binaries",
            "Detect hidden processes and files",
            "Post-compromise integrity checking",
        ],
        output_formats=["text"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["rootkit", "detect", "linux", "hidden", "binary", "integrity", "compromise"],
        notes="Install: apt install chkrootkit. Complement with rkhunter.",
    ),

    KaliTool(
        name="rkhunter",
        category=Category.FORENSICS,
        subcategory="anti_forensics",
        description="Rootkit Hunter — scan for rootkits, backdoors, and local exploits",
        syntax="rkhunter [options]",
        common_flags={
            "--check":          "Perform system check",
            "--update":         "Update database",
            "--propupd":        "Update file properties",
            "--list":           "List enabled tests",
            "--enable <test>":  "Enable specific test",
            "--disable <test>": "Disable specific test",
            "--report-warnings-only": "Report warnings only",
            "--logfile <f>":    "Log file",
            "--quiet":          "Quiet mode",
        },
        use_cases=[
            "Rootkit and backdoor detection",
            "System binary integrity verification",
            "Network interface promiscuous mode detection",
            "Scheduled integrity checking",
        ],
        output_formats=["text", "log file"],
        avg_time_seconds=60,
        risk_level=RiskLevel.LOW,
        keywords=["rootkit", "backdoor", "detect", "integrity", "binary", "system", "scan"],
        notes="Install: apt install rkhunter. Run --propupd after system updates to reset baseline.",
    ),

    # ══════════════════════════════════════════
    # SLEUTH KIT
    # ══════════════════════════════════════════

    KaliTool(
        name="sleuthkit",
        category=Category.FORENSICS,
        subcategory="disk_forensics",
        description="The Sleuth Kit — collection of CLI tools for filesystem and volume forensic analysis",
        syntax="<tool> [options] <image>",
        common_flags={
            "mmls <image>":         "Display partition layout",
            "fsstat <image>":       "Filesystem statistics",
            "fls <image>":          "List files (including deleted)",
            "icat <image> <inode>": "Output file by inode",
            "ils <image>":          "List inodes",
            "blkcat <image> <blk>": "Display block contents",
            "blkls <image>":        "List unallocated blocks",
            "dcat <image> <blk>":   "Data unit display",
            "ifind <image> -d <blk>":"Find inode using block",
            "ffind <image> <inode>":"Find filename for inode",
            "jls <image>":          "List journal entries",
            "tsk_recover <image> <dir>": "Recover deleted files",
        },
        use_cases=[
            "Filesystem analysis and forensics",
            "Recover deleted files by inode",
            "Analyze partition structure",
            "Journal analysis",
            "Unallocated space analysis",
            "Timeline creation with mactime",
        ],
        output_formats=["text", "body file"],
        avg_time_seconds=30,
        risk_level=RiskLevel.LOW,
        keywords=["filesystem", "inode", "deleted", "recover", "partition", "journal", "sleuth", "forensics"],
        notes="Install: apt install sleuthkit. Foundation of Autopsy GUI. Supports NTFS, FAT, ext, HFS+.",
    ),
]


# ── Quick stats ───────────────────────────────
if __name__ == "__main__":
    print(f"Forensics expansion: {len(FORENSICS_TOOLS)} tools")

    subcats = {}
    for t in FORENSICS_TOOLS:
        subcats[t.subcategory] = subcats.get(t.subcategory, 0) + 1

    print("\nBy subcategory:")
    for sub, count in sorted(subcats.items()):
        print(f"  {sub:<30} {count} tools")

    print("\nIntegrate with knowledge base:")
    print("  from nova_kali_kb_forensics import FORENSICS_TOOLS")
    print("  from nova_kali_knowledge_base import KALI_TOOLS")
    print("  KALI_TOOLS.extend(FORENSICS_TOOLS)")
