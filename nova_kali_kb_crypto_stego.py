"""
NOVA KALI KNOWLEDGE BASE — CRYPTO & STEGANOGRAPHY EXPANSION
=============================================================
Full expansion of the Crypto & Steganography category.
Add this to nova_kali_knowledge_base.py by importing and extending KALI_TOOLS.

Subcategories covered:
- Steganography (Image, Audio, Text, Video)
- Steganalysis (Detection)
- Cryptography Tools
- Encryption & Decryption
- Covert Channels
- Hash Tools
- Encoding & Decoding
- Certificate & PKI Tools

Usage:
    from nova_kali_kb_crypto_stego import CRYPTO_STEGO_TOOLS
    from nova_kali_knowledge_base import KALI_TOOLS, KaliKnowledgeBase

    KALI_TOOLS.extend(CRYPTO_STEGO_TOOLS)
    kb = KaliKnowledgeBase()
"""

from nova_kali_knowledge_base import KaliTool, Category, RiskLevel


# Add CRYPTO category since it's not in the base Category enum
# We reuse FORENSICS for crypto tools since they share the category space
# You can extend the Category enum in nova_kali_knowledge_base.py if needed

CRYPTO_STEGO_TOOLS = [

    # ══════════════════════════════════════════
    # STEGANOGRAPHY — IMAGE
    # ══════════════════════════════════════════

    KaliTool(
        name="stegosuite",
        category=Category.FORENSICS,
        subcategory="steganography_image",
        description="GUI steganography tool — hide text and files in BMP, GIF, JPG, PNG with AES encryption",
        syntax="stegosuite  (GUI)  |  stegosuite embed -k <pass> -i <image> -d <data> -o <out>",
        common_flags={
            "embed -k <pass> -i <img> -d <data> -o <out>": "Embed data into image",
            "extract -k <pass> -i <stego_img>":            "Extract hidden data",
            "-k <passphrase>":  "Passphrase for AES encryption",
            "-i <image>":       "Input image file",
            "-d <data>":        "Data file to embed",
            "-o <output>":      "Output stego image",
        },
        use_cases=[
            "Hide files inside BMP/GIF/JPG/PNG images",
            "AES-encrypted steganography",
            "GUI-based stego for beginners",
            "CTF steganography challenges",
            "Covert data embedding with encryption",
        ],
        output_formats=["stego image", "extracted file"],
        avg_time_seconds=3,
        risk_level=RiskLevel.LOW,
        keywords=["stego", "image", "hide", "embed", "aes", "encrypt", "gui", "bmp", "jpg", "png", "ctf"],
        notes="Install: apt install stegosuite. Java-based GUI. Supports BMP, GIF, JPG, PNG.",
    ),

    KaliTool(
        name="openstego",
        category=Category.FORENSICS,
        subcategory="steganography_image",
        description="Open source steganography tool — hide data in images and digital watermarking",
        syntax="openstego  (GUI)  |  java -jar openstego.jar <command>",
        common_flags={
            "embed -mf <msg> -cf <cover> -p <pass> -sf <stego>":  "Embed message",
            "extract -sf <stego> -p <pass> -xf <output>":         "Extract message",
            "genwatermark -mf <wmk> -cf <cover> -sf <output>":    "Generate watermark",
            "checkwatermark -sf <stego> -waf <wmk>":              "Check watermark",
            "-p <password>":    "Password",
            "-a <algorithm>":   "Algorithm (RandomLSB default)",
        },
        use_cases=[
            "Steganography with multiple algorithms",
            "Digital watermarking for copyright protection",
            "Hidden data embedding in images",
            "CTF steganography",
        ],
        output_formats=["stego image", "extracted file"],
        avg_time_seconds=3,
        risk_level=RiskLevel.LOW,
        keywords=["stego", "image", "watermark", "hide", "embed", "copyright", "lsb", "ctf"],
        notes="Install: apt install openstego. Also supports watermarking for copyright.",
    ),

    KaliTool(
        name="jphide",
        category=Category.FORENSICS,
        subcategory="steganography_image",
        description="Hide data in JPEG files — uses DCT coefficient manipulation",
        syntax="jphide <cover.jpg> <stego.jpg> <data_file>  |  jpseek <stego.jpg> <output>",
        common_flags={
            "jphide <cover> <stego> <file>":    "Hide file in JPEG",
            "jpseek <stego> <output>":          "Extract hidden data",
        },
        use_cases=[
            "Hide data in JPEG DCT coefficients",
            "More resistant to detection than LSB",
            "CTF JPEG steganography",
        ],
        output_formats=["stego jpeg", "extracted file"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["jpeg", "jpg", "dct", "hide", "stego", "coefficient", "ctf"],
        notes="Install: apt install jphide. Part of JPHSWIN package.",
    ),

    KaliTool(
        name="gifshuffle",
        category=Category.FORENSICS,
        subcategory="steganography_image",
        description="Conceal messages in GIF images by shuffling colormap entries",
        syntax="gifshuffle [options] [infile] [outfile]",
        common_flags={
            "-c":               "Compress data before hiding",
            "-C":               "Decompress on extraction",
            "-e <passphrase>":  "Encrypt with passphrase",
            "-m <message>":     "Message to embed",
            "-f <file>":        "File to embed",
            "-p <passphrase>":  "Extract with passphrase",
            "-x":               "Extract hidden data",
            "-Q":               "Quiet mode",
        },
        use_cases=[
            "Hide messages in GIF images",
            "Encrypted message embedding in GIFs",
            "CTF GIF steganography",
        ],
        output_formats=["stego gif", "extracted text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["gif", "stego", "colormap", "shuffle", "hide", "message", "ctf"],
        notes="Install: apt install gifshuffle.",
    ),

    # ══════════════════════════════════════════
    # STEGANOGRAPHY — AUDIO
    # ══════════════════════════════════════════

    KaliTool(
        name="mp3stego",
        category=Category.FORENSICS,
        subcategory="steganography_audio",
        description="Hide information in MP3 files during compression process",
        syntax="encode -E <hidden_file> -P <password> <cover.wav> <stego.mp3>",
        common_flags={
            "encode -E <file> -P <pass> <wav> <mp3>":  "Encode hidden file into MP3",
            "decode -X -P <pass> <stego.mp3>":         "Decode hidden file from MP3",
            "-E <file>":        "File to hide",
            "-P <password>":    "Password",
            "-X":               "Extract hidden data",
        },
        use_cases=[
            "Hide data in MP3 during encoding",
            "Covert audio steganography",
            "CTF audio challenges",
        ],
        output_formats=["stego mp3", "extracted file"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["mp3", "audio", "stego", "hide", "encode", "compress", "ctf"],
        notes="Install: apt install mp3stego.",
    ),

    KaliTool(
        name="audacity",
        category=Category.FORENSICS,
        subcategory="steganography_audio",
        description="Audio editor — analyze spectrograms to find hidden messages in audio files",
        syntax="audacity <file>  (GUI)",
        common_flags={
            "Spectrogram view":     "View frequency spectrum (reveals hidden images)",
            "Effect > Reverse":     "Reverse audio",
            "Analyze > Plot Spectrum": "Frequency analysis",
            "View > Show Clipping": "Show clipped samples",
        },
        use_cases=[
            "Spectrogram steganography analysis",
            "Find hidden images in audio spectrograms",
            "CTF audio challenge analysis",
            "Audio forensics and manipulation",
        ],
        output_formats=["gui", "audio files"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["audio", "spectrogram", "hidden", "frequency", "ctf", "analyze", "forensics"],
        notes="Install: apt install audacity. Change view to Spectrogram to reveal hidden images.",
    ),

    KaliTool(
        name="sonic-visualiser",
        category=Category.FORENSICS,
        subcategory="steganography_audio",
        description="Audio visualization tool — advanced spectrogram and waveform analysis",
        syntax="sonic-visualiser <file>  (GUI)",
        common_flags={
            "Layer > Add Spectrogram":  "Add spectrogram layer",
            "Layer > Add Waveform":     "Add waveform layer",
            "View > Show All Layers":   "Show all analysis layers",
            "Transform > Analysis":     "Run analysis plugins",
        },
        use_cases=[
            "Advanced audio spectrogram analysis",
            "CTF audio steganography",
            "Find hidden messages in audio",
            "Frequency-based data extraction",
        ],
        output_formats=["gui"],
        avg_time_seconds=0,
        risk_level=RiskLevel.LOW,
        keywords=["audio", "spectrogram", "visualize", "ctf", "hidden", "frequency", "wave"],
        notes="Install: apt install sonic-visualiser. Better spectrogram than Audacity for CTFs.",
    ),

    # ══════════════════════════════════════════
    # STEGANOGRAPHY — TEXT
    # ══════════════════════════════════════════

    KaliTool(
        name="snow",
        category=Category.FORENSICS,
        subcategory="steganography_text",
        description="Whitespace steganography — hide messages in ASCII text using tabs and spaces",
        syntax="snow [options] [infile] [outfile]",
        common_flags={
            "-C":               "Compress message",
            "-Q":               "Quiet mode",
            "-S":               "Report statistics",
            "-p <passphrase>":  "Encrypt with ICE",
            "-l <line_len>":    "Line length limit",
            "-m <message>":     "Message to hide",
            "-f <file>":        "File message to hide",
            "-x":               "Extract hidden message",
        },
        use_cases=[
            "Hide messages in text using invisible whitespace",
            "CTF text steganography",
            "Covert text communication",
        ],
        output_formats=["text file with hidden whitespace"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["whitespace", "text", "stego", "tabs", "spaces", "invisible", "ctf", "hide"],
        notes="Install: apt install snow. Hidden data invisible to naked eye in text files.",
    ),

    # ══════════════════════════════════════════
    # STEGANALYSIS (DETECTION)
    # ══════════════════════════════════════════

    KaliTool(
        name="stegdetect",
        category=Category.FORENSICS,
        subcategory="steganalysis",
        description="Detect steganographic content in JPEG images — identify JSteg, JPHide, OutGuess, Steghide",
        syntax="stegdetect [options] <file(s)>",
        common_flags={
            "-t <tools>":       "Tools to detect (j=jsteg, o=outguess, p=jphide, i=invisible secrets)",
            "-s <float>":       "Sensitivity (default 1.0, higher = more sensitive)",
            "-q":               "Quiet mode",
            "-n":               "Print only detected files",
            "-V":               "Verbose",
        },
        use_cases=[
            "Detect steganography in JPEG images",
            "Forensic stego analysis",
            "CTF image analysis",
            "Batch detection across multiple images",
        ],
        output_formats=["text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["detect", "stego", "jpeg", "analysis", "forensic", "ctf", "jsteg", "outguess"],
        notes="Install: apt install stegdetect.",
    ),

    KaliTool(
        name="foremost-stego",
        category=Category.FORENSICS,
        subcategory="steganalysis",
        description="Use foremost to extract files hidden inside other files (file-in-file steganography)",
        syntax="foremost -i <stego_file> -o <output_dir>",
        common_flags={
            "-i <file>":        "Input stego file",
            "-o <dir>":         "Output directory",
            "-t all":           "Extract all file types",
            "-v":               "Verbose",
        },
        use_cases=[
            "Detect files hidden inside other files",
            "CTF file-in-file challenges",
            "Extract embedded archives from images",
        ],
        output_formats=["extracted files"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["file", "in", "file", "extract", "hidden", "ctf", "embedded", "archive"],
        notes="Use foremost on stego files to find embedded ZIPs, PDFs, images inside images.",
    ),

    # ══════════════════════════════════════════
    # CRYPTOGRAPHY TOOLS
    # ══════════════════════════════════════════

    KaliTool(
        name="cryptcat",
        category=Category.FORENSICS,
        subcategory="encryption",
        description="Netcat with built-in Twofish encryption — encrypted reverse shells and file transfer",
        syntax="cryptcat -k <key> -l -p <port>  |  cryptcat -k <key> <host> <port>",
        common_flags={
            "-k <key>":         "Encryption key",
            "-l":               "Listen mode",
            "-p <port>":        "Port",
            "-e <program>":     "Execute program on connect",
            "-v":               "Verbose",
            "-n":               "No DNS resolution",
        },
        use_cases=[
            "Encrypted reverse shells",
            "Encrypted file transfer",
            "Bypass IDS that looks for plaintext netcat",
            "Encrypted covert channels",
        ],
        output_formats=["encrypted stream"],
        avg_time_seconds=2,
        risk_level=RiskLevel.HIGH,
        keywords=["encrypt", "netcat", "twofish", "reverse", "shell", "covert", "ids", "bypass"],
        notes="Install: apt install cryptcat. Drop-in replacement for netcat with Twofish encryption.",
    ),

    KaliTool(
        name="gpg",
        category=Category.FORENSICS,
        subcategory="encryption",
        description="GNU Privacy Guard — encrypt, decrypt, sign, and verify files using public key cryptography",
        syntax="gpg [options] <file>",
        common_flags={
            "--gen-key":                    "Generate new key pair",
            "--list-keys":                  "List public keys",
            "--list-secret-keys":           "List private keys",
            "--encrypt -r <recipient>":     "Encrypt file for recipient",
            "--decrypt <file>":             "Decrypt file",
            "--sign <file>":                "Sign file",
            "--verify <sig> <file>":        "Verify signature",
            "--symmetric":                  "Symmetric encryption (passphrase)",
            "--armor":                      "ASCII armored output",
            "--export <keyid>":             "Export public key",
            "--import <keyfile>":           "Import public key",
            "--fingerprint":                "Show key fingerprints",
        },
        use_cases=[
            "Encrypt files with public key cryptography",
            "Sign and verify file integrity",
            "Symmetric file encryption",
            "Key management",
            "Secure communication",
        ],
        output_formats=["encrypted file", "signature file", "armored text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["gpg", "pgp", "encrypt", "decrypt", "sign", "verify", "public", "key", "symmetric"],
        notes="Install: apt install gnupg. Industry standard for file encryption and signing.",
    ),

    KaliTool(
        name="openssl",
        category=Category.FORENSICS,
        subcategory="encryption",
        description="Cryptography toolkit — encrypt/decrypt files, generate keys and certificates, test SSL/TLS",
        syntax="openssl <command> [options]",
        common_flags={
            "enc -aes-256-cbc -in <f> -out <f>":    "AES-256 encrypt file",
            "enc -d -aes-256-cbc -in <f> -out <f>": "AES-256 decrypt file",
            "genrsa -out <key> 4096":               "Generate RSA private key",
            "req -new -x509 -key <key> -out <cert>":"Generate self-signed cert",
            "s_client -connect <host>:443":         "Test SSL/TLS connection",
            "x509 -in <cert> -text":                "View certificate details",
            "dgst -sha256 <file>":                  "Hash file with SHA256",
            "rand -hex 32":                         "Generate random hex",
            "pkcs12 -export":                       "Export to PKCS12 format",
            "verify -CAfile <ca> <cert>":           "Verify certificate chain",
        },
        use_cases=[
            "File encryption/decryption",
            "SSL/TLS certificate generation",
            "Key generation (RSA, ECDSA)",
            "Hash calculation",
            "Certificate analysis",
            "SSL/TLS connection testing",
        ],
        output_formats=["encrypted file", "key file", "certificate", "hash"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["openssl", "aes", "rsa", "encrypt", "decrypt", "cert", "key", "hash", "ssl", "tls"],
        notes="Install: apt install openssl. Swiss army knife of cryptography.",
    ),

    KaliTool(
        name="veracrypt",
        category=Category.FORENSICS,
        subcategory="encryption",
        description="Disk encryption — create encrypted containers and full disk encryption",
        syntax="veracrypt  (GUI)  |  veracrypt [options] <volume> <mountpoint>",
        common_flags={
            "-c":                           "Create new volume",
            "-m <mountpoint>":              "Mount volume",
            "--dismount <volume>":          "Dismount volume",
            "-l":                           "List mounted volumes",
            "--encryption <algo>":          "Encryption algorithm",
            "--hash <algo>":                "Hash algorithm",
            "--volume-type <normal|hidden>":"Volume type",
            "--size <size>":                "Volume size",
            "--password <pass>":            "Password",
            "--pim <n>":                    "Personal Iterations Multiplier",
            "--keyfiles <file>":            "Keyfiles",
            "--filesystem <type>":          "Filesystem type",
        },
        use_cases=[
            "Create encrypted file containers",
            "Full disk/partition encryption",
            "Hidden volume (plausible deniability)",
            "Forensic evidence encryption",
            "Secure portable drives",
        ],
        output_formats=["encrypted volume", "mounted filesystem"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["encrypt", "disk", "volume", "container", "hidden", "deniability", "full", "partition"],
        notes="Install: apt install veracrypt. Successor to TrueCrypt. Supports hidden volumes.",
    ),

    # ══════════════════════════════════════════
    # ENCODING & DECODING
    # ══════════════════════════════════════════

    KaliTool(
        name="cyberchef",
        category=Category.FORENSICS,
        subcategory="encoding_decoding",
        description="The Cyber Swiss Army Knife — encode, decode, encrypt, decrypt, transform data",
        syntax="# Web tool: https://gchq.github.io/CyberChef/  |  cyberchef (local install)",
        common_flags={
            "From Base64":          "Decode Base64",
            "To Base64":            "Encode to Base64",
            "From Hex":             "Decode hexadecimal",
            "ROT13":                "ROT13 cipher",
            "XOR":                  "XOR with key",
            "AES Decrypt":          "AES decryption",
            "Magic":                "Auto-detect encoding",
            "URL Decode":           "URL decode",
            "JWT Decode":           "Decode JWT token",
            "Entropy":              "Calculate data entropy",
            "Strings":              "Extract strings",
        },
        use_cases=[
            "Decode Base64/Hex/URL encoded data",
            "CTF challenge solving",
            "JWT token analysis",
            "Multi-step encoding chains",
            "Cipher text analysis",
            "Hash identification and cracking",
        ],
        output_formats=["web interface", "text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["encode", "decode", "base64", "hex", "rot13", "xor", "ctf", "cipher", "jwt", "magic"],
        notes="Web: https://gchq.github.io/CyberChef/ — Essential CTF tool. Use 'Magic' for auto-detection.",
    ),

    KaliTool(
        name="base64",
        category=Category.FORENSICS,
        subcategory="encoding_decoding",
        description="Base64 encode and decode — built-in Linux tool",
        syntax="base64 [options] [file]  |  echo '<data>' | base64",
        common_flags={
            "-d":               "Decode",
            "-w <n>":           "Wrap at N characters (0=no wrap)",
            "-i <file>":        "Input file",
            "-o <file>":        "Output file",
        },
        use_cases=[
            "Encode binary data to text",
            "Decode Base64 encoded strings",
            "CTF encoding challenges",
            "Encode payloads for transport",
        ],
        output_formats=["text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["base64", "encode", "decode", "binary", "text", "ctf", "payload"],
        notes="Built into Linux. Decode: echo '<base64>' | base64 -d",
    ),

    KaliTool(
        name="xxd",
        category=Category.FORENSICS,
        subcategory="encoding_decoding",
        description="Hex dump and reverse hex dump — convert files to hex and back",
        syntax="xxd [options] [file]",
        common_flags={
            "-r":               "Reverse (hex to binary)",
            "-p":               "Plain hex dump (no address/ASCII)",
            "-c <n>":           "Bytes per line",
            "-l <n>":           "Stop after N bytes",
            "-s <offset>":      "Start at offset",
            "-u":               "Uppercase hex",
            "-i":               "Output as C include file",
            "-b":               "Binary dump",
        },
        use_cases=[
            "View binary files as hex",
            "Convert hex strings back to binary",
            "Binary file analysis",
            "CTF binary/hex challenges",
            "Patch binary files",
        ],
        output_formats=["hex text", "binary"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["hex", "dump", "binary", "convert", "ctf", "patch", "reverse"],
        notes="Built into Linux. Patch file: xxd file | sed 's/old/new/' | xxd -r > patched_file",
    ),

    # ══════════════════════════════════════════
    # HASH TOOLS
    # ══════════════════════════════════════════

    KaliTool(
        name="hashdeep",
        category=Category.FORENSICS,
        subcategory="hash_tools",
        description="Compute and audit multiple hashes simultaneously — MD5, SHA1, SHA256, Tiger, Whirlpool",
        syntax="hashdeep [options] <files>",
        common_flags={
            "-r":               "Recursive",
            "-l":               "Relative paths",
            "-a":               "Audit mode (compare against known hashes)",
            "-m":               "Match mode",
            "-x":               "Negative match",
            "-e":               "Estimate completion",
            "-c <algo>":        "Hash algorithm (md5/sha1/sha256/tiger/whirlpool)",
            "-k <hashfile>":    "Known hash file for audit",
            "-o <types>":       "File types to hash",
        },
        use_cases=[
            "Compute multiple hashes simultaneously",
            "Forensic hash manifests",
            "File integrity auditing",
            "NSRL matching",
        ],
        output_formats=["text", "hashdeep format"],
        avg_time_seconds=15,
        risk_level=RiskLevel.LOW,
        keywords=["hash", "md5", "sha1", "sha256", "audit", "integrity", "forensic", "multiple"],
        notes="Install: apt install hashdeep.",
    ),

    KaliTool(
        name="haiti",
        category=Category.FORENSICS,
        subcategory="hash_tools",
        description="Hash type identifier — identify hash algorithms with color-coded output",
        syntax="haiti <hash>",
        common_flags={
            "-e":               "Extended mode",
            "--no-color":       "No color output",
            "--short":          "Short output",
        },
        use_cases=[
            "Identify unknown hash types",
            "Get hashcat and john modes simultaneously",
            "CTF hash identification",
        ],
        output_formats=["text"],
        avg_time_seconds=1,
        risk_level=RiskLevel.LOW,
        keywords=["hash", "identify", "type", "hashcat", "john", "ctf", "color"],
        notes="Install: gem install haiti-hash. Modern hash identifier with color output.",
    ),

    # ══════════════════════════════════════════
    # COVERT CHANNELS
    # ══════════════════════════════════════════

    KaliTool(
        name="covert-tcp",
        category=Category.FORENSICS,
        subcategory="covert_channels",
        description="Covert TCP channel — hide data in TCP/IP header fields (sequence numbers, etc.)",
        syntax="covert_tcp -dest <ip> -source <ip> -source_port <p> -dest_port <p> -server/-file <f>",
        common_flags={
            "-dest <ip>":           "Destination IP",
            "-source <ip>":         "Source IP",
            "-source_port <port>":  "Source port",
            "-dest_port <port>":    "Destination port",
            "-server":              "Server mode (receive)",
            "-file <file>":         "File to send",
            "-ipid":                "Use IP ID field",
            "-seq":                 "Use sequence number field",
            "-ack":                 "Use ACK field",
        },
        use_cases=[
            "Hide data in TCP/IP packet headers",
            "Bypass DLP and content filters",
            "Covert exfiltration channel",
            "Research and education on covert channels",
        ],
        output_formats=["covert channel packets"],
        avg_time_seconds=5,
        risk_level=RiskLevel.HIGH,
        keywords=["covert", "channel", "tcp", "ip", "header", "hide", "exfil", "bypass", "dlp"],
        notes="Compile from source. For research/CTF use. Requires raw socket access (root).",
    ),

    KaliTool(
        name="dns2tcp",
        category=Category.FORENSICS,
        subcategory="covert_channels",
        description="DNS tunneling tool — tunnel TCP connections through DNS queries",
        syntax="dns2tcpd -f <config>  |  dns2tcpc -r <resource> -z <domain> <host>",
        common_flags={
            "dns2tcpd -f <conf>":           "Start server",
            "dns2tcpc -r ssh -z <domain>":  "Connect SSH through DNS",
            "-z <domain>":                  "Domain to use for DNS tunnel",
            "-r <resource>":                "Resource to access",
            "-l <port>":                    "Local port",
            "-d <level>":                   "Debug level",
            "-k <key>":                     "Shared key",
        },
        use_cases=[
            "Bypass firewalls using DNS port 53",
            "Exfiltrate data via DNS",
            "SSH through DNS tunnel",
            "C2 over DNS",
        ],
        output_formats=["tunnel"],
        avg_time_seconds=5,
        risk_level=RiskLevel.HIGH,
        keywords=["dns", "tunnel", "bypass", "firewall", "exfil", "covert", "ssh", "c2"],
        notes="Install: apt install dns2tcp. Requires own DNS domain for server setup.",
    ),

    # ══════════════════════════════════════════
    # CERTIFICATE & PKI TOOLS
    # ══════════════════════════════════════════

    KaliTool(
        name="certutil",
        category=Category.FORENSICS,
        subcategory="certificate_tools",
        description="Certificate utility — manage certificates, CRLs, and cryptographic keys",
        syntax="certutil [options]",
        common_flags={
            "-d <dir>":         "NSS database directory",
            "-L":               "List certificates",
            "-A -n <name> -t <trust> -i <cert>": "Add certificate",
            "-D -n <name>":     "Delete certificate",
            "-V -n <name>":     "Verify certificate",
            "-K":               "List keys",
            "-G -s <subject>":  "Generate key and certificate",
            "-H":               "Hash a file",
        },
        use_cases=[
            "Manage certificate stores",
            "Verify certificate chains",
            "Generate self-signed certificates",
            "Hash files for verification",
        ],
        output_formats=["text"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["certificate", "cert", "pki", "key", "trust", "verify", "nss"],
        notes="Install: apt install libnss3-tools.",
    ),

    KaliTool(
        name="keytool",
        category=Category.FORENSICS,
        subcategory="certificate_tools",
        description="Java keystore management — manage certificates and key pairs for Java apps",
        syntax="keytool [options]",
        common_flags={
            "-genkeypair -alias <a> -keyalg RSA":   "Generate key pair",
            "-list -keystore <ks>":                 "List keystore entries",
            "-import -alias <a> -file <cert>":      "Import certificate",
            "-export -alias <a> -file <cert>":      "Export certificate",
            "-delete -alias <a>":                   "Delete entry",
            "-printcert -file <cert>":              "Print certificate info",
            "-storepass <pass>":                    "Keystore password",
        },
        use_cases=[
            "Manage Java keystores",
            "Import/export certificates",
            "Generate key pairs for Java apps",
            "Android APK certificate analysis",
        ],
        output_formats=["text", "keystore file"],
        avg_time_seconds=2,
        risk_level=RiskLevel.LOW,
        keywords=["java", "keystore", "certificate", "key", "android", "apk", "trust"],
        notes="Install: apt install default-jdk. Used for Android app certificate analysis.",
    ),

    # ══════════════════════════════════════════
    # CTF CRYPTO TOOLS
    # ══════════════════════════════════════════

    KaliTool(
        name="rsactftool",
        category=Category.FORENSICS,
        subcategory="ctf_crypto",
        description="RSA attack tool for CTFs — factor weak RSA keys and decrypt ciphertext",
        syntax="python3 RsaCtfTool.py [options]",
        common_flags={
            "--publickey <pem>":    "Public key file",
            "--private":           "Recover private key",
            "--uncipher <file>":   "Decrypt ciphertext file",
            "--attack all":        "Try all attacks",
            "--attack factordb":   "Use FactorDB",
            "--attack wiener":     "Wiener's attack (small d)",
            "--attack hastads":    "Hastad's broadcast attack",
            "--attack common_factors": "Common prime factors",
            "-n <n>":              "Modulus",
            "-e <e>":              "Public exponent",
        },
        use_cases=[
            "CTF RSA challenge solving",
            "Factor weak RSA moduli",
            "Recover RSA private key from weak params",
            "Multiple RSA attacks in one tool",
        ],
        output_formats=["text", "private key", "plaintext"],
        avg_time_seconds=30,
        risk_level=RiskLevel.MEDIUM,
        keywords=["rsa", "ctf", "factor", "weak", "attack", "decrypt", "private", "key", "wiener"],
        notes="git clone https://github.com/RsaCtfTool/RsaCtfTool. Essential for CTF crypto challenges.",
    ),

    KaliTool(
        name="xortool",
        category=Category.FORENSICS,
        subcategory="ctf_crypto",
        description="XOR cipher analysis tool — find XOR key length and key from ciphertext",
        syntax="xortool [options] <file>",
        common_flags={
            "-l <len>":         "Known key length",
            "-c <char>":        "Most common plaintext char (e.g. 0x20 for space)",
            "-x":               "Input is hex encoded",
            "-b":               "Brute force key length",
            "--output-dir <d>": "Output directory for decoded files",
        },
        use_cases=[
            "Break XOR ciphers in CTF challenges",
            "Find XOR key length via Index of Coincidence",
            "Recover XOR key from ciphertext",
        ],
        output_formats=["text", "decoded files"],
        avg_time_seconds=5,
        risk_level=RiskLevel.LOW,
        keywords=["xor", "cipher", "key", "ctf", "analysis", "break", "decode"],
        notes="Install: pip install xortool. Essential CTF crypto tool.",
    ),

    KaliTool(
        name="factordb",
        category=Category.FORENSICS,
        subcategory="ctf_crypto",
        description="Factor integers using the FactorDB online database — find RSA prime factors",
        syntax="python3 -c \"from factordb.factordb import FactorDB; f=FactorDB(<n>); f.connect(); print(f.get_factor_list())\"",
        common_flags={
            "FactorDB(<n>)":    "Initialize with number to factor",
            ".connect()":       "Query FactorDB",
            ".get_factor_list()":"Get list of factors",
            ".get_status()":    "Check if fully factored",
        },
        use_cases=[
            "Factor RSA moduli for CTF challenges",
            "Check if a number has known factors",
            "RSA private key recovery",
        ],
        output_formats=["factors list"],
        avg_time_seconds=3,
        risk_level=RiskLevel.LOW,
        keywords=["factor", "rsa", "prime", "ctf", "modulus", "integer", "database"],
        notes="Install: pip install factordb-pycli. Database at factordb.com",
    ),

    KaliTool(
        name="featherduster",
        category=Category.FORENSICS,
        subcategory="ctf_crypto",
        description="Automated cryptanalysis tool — identify and exploit weak cryptographic systems",
        syntax="python3 featherduster.py",
        common_flags={
            "analyze":          "Analyze ciphertext",
            "crack":            "Attempt to crack cipher",
            "--samples <n>":    "Number of ciphertext samples",
        },
        use_cases=[
            "Automated cipher identification",
            "CTF cryptanalysis",
            "Break classical ciphers",
            "Detect reused keys/nonces",
        ],
        output_formats=["text", "plaintext"],
        avg_time_seconds=10,
        risk_level=RiskLevel.LOW,
        keywords=["cryptanalysis", "cipher", "automated", "ctf", "break", "classical", "weak"],
        notes="git clone https://github.com/nccgroup/featherduster.",
    ),
]


# ── Quick stats ───────────────────────────────
if __name__ == "__main__":
    print(f"Crypto & Steganography expansion: {len(CRYPTO_STEGO_TOOLS)} tools")

    subcats = {}
    for t in CRYPTO_STEGO_TOOLS:
        subcats[t.subcategory] = subcats.get(t.subcategory, 0) + 1

    print("\nBy subcategory:")
    for sub, count in sorted(subcats.items()):
        print(f"  {sub:<30} {count} tools")

    print("\nIntegrate with knowledge base:")
    print("  from nova_kali_kb_crypto_stego import CRYPTO_STEGO_TOOLS")
    print("  from nova_kali_knowledge_base import KALI_TOOLS")
    print("  KALI_TOOLS.extend(CRYPTO_STEGO_TOOLS)")
