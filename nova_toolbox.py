"""
Nova Toolbox Module - Comprehensive collection of 100+ security tools.
"""

from typing import Any, Dict, List


class NovaToolbox:
    """Registry of 100+ security tools organized by category."""

    def __init__(self) -> None:
        self.tools: Dict[str, List[str]] = {
            "recon": [
                "nmap", "masscan", "zmap", "subfinder", "amass", "assetfinder",
                "knockpy", "dnsrecon", "dnsenum", "fierce", " sublist3r",
                "crt.sh", "github-subdomains", "dnsx", "uncover", "httpx",
                "waybackurls", "gau", "katana", "hakrawler", "gospider",
                "theHarvester", "sherlock", "mulrecon", "recon-ng",
                "spiderfoot", "maltego", "reconftw", "osrframework",
            ],
            "web_exploit": [
                "sqlmap", "nuclei", "nikto", "wpscan", "joomscan",
                "drupalscan", "droopescan", "cmseek", "xsstrike",
                "dalfox", " XSStrike", "commix", "tplmap", "ffuf",
                "gobuster", "dirb", "dirsearch", "feroxbuster",
                "wfuzz", "wfuzz", "arjun", "paramspider", "x8",
                "katana", "linkfinder", "secretfinder", "jsfinder",
                "retire.js", "semgrep", "bandit", "grype", "trivy",
                "zaproxy", "burpsuite", "arachni", "whatweb",
                "wafw00f", "http-put", "curl", "wget",
            ],
            "network": [
                "netcat", "socat", "ncat", "hping3", "masscan",
                "zmap", "unicornscan", "rustscan", "nmap", "angry-ip-scanner",
                "wireshark", "tcpdump", "tshark", "ettercap", "bettercap",
                "mitmproxy", "sslstrip", "sslsniff", "responder",
                "ntlmrelayx", "smbclient", "rpcclient", "enum4linux",
                "smbmap", "nbtscan", "onesixtyone", "snmpwalk",
                "braa", "hydra", "medusa", "ncrack", "patator",
                "slowloris", "hulk", "goldeneye", "memcrashed",
            ],
            "binary": [
                "gdb", "pwndbg", "peda", "gef", "radare2",
                "r2", "ghidra", "ida", "binary-ninja", "hopper",
                "objdump", "readelf", "strings", "file", "xxd",
                "hexdump", "binwalk", "firmware-mod-kit", "unblob",
                "checksec", "ROPgadget", "ropper", "one_gadget",
                "pwntools", "capstone", "keystone", "unicorn",
                "angr", "claripy", "manticore", "qemu",
            ],
            "cloud": [
                "aws-cli", "awscurl", "pacu", "enumerate-iam",
                "cloud_enum", "ScoutSuite", "Prowler", "CloudSploit",
                "prowler", "cloudfox", "roadtools", "AADInternals",
                "MicroBurst", "AzureCLI", "gcloud", " ScoutSuite",
                "Steampipe", "cloudquery", "cartography", "PMapper",
                "aws_consoler", "IAMinator", "weirdAAL", ".cloudfox",
            ],
            "forensics": [
                "volatility", "volatility3", "autopsy", "sleuthkit",
                "bulk-extractor", "foremost", "binwalk", "scalpel",
                "PhotoRec", "dd", "dc3dd", "guymager", "log2timeline",
                "plaso", "mactime", "mftparser", "NTFSLogTracker",
                "bstrings", "yara", "clamav", "hashdeep", "md5deep",
                "ssdeep", "capstone", "rekall", "d Response",
            ],
            "password": [
                "hashcat", "john", "hydra", "medusa", "ncrack",
                "patator", "crunch", "maskprocessor", "hashprocessor",
                "ntlm-crack", "ophcrack", "rainbowcrack", "mdcrack",
                "hash-buster", "brutespray", "crowbar", "legion",
                "thc-pptp-bruter", "wordlists", "seclists", "rockyou",
                "cewl", "crunch", "mentalist", "pipal",
            ],
            "ai_security": [
                "garak", "inspect", "pyrit", "llm-fuzzer", "vigil",
                "prompt-injection-bench", "rebuff", "giskard",
            ],
            "hardware": [
                "rtl_433", "hackrf_transfer", "flashrom", "openocd",
                "sigrok", "pulseview", "ubertooth-btle", "killerbee",
            ],
            "vehicle": [
                "cansniffer", "cansend", "candump", "kayak",
                "caringcaribou", "uds-scan", "icat",
            ],
            "mobile_advanced": [
                "drozer", "frida", "objection", "apkleaks", "apkx",
                "mobsf", "apkid", "dex2jar", "qark",
            ],
            "cloud_advanced": [
                "cloud_enum", "pacu", "scoutsuite", "cloudsploit",
                "s3scanner", "bucket-finder", "prowler", "cloudfox",
            ],
        }

        self.target_mapping: Dict[str, List[str]] = {
            "linux": ["nmap", "enum4linux", "smbclient", "ssh-audit", "lynis"],
            "windows": ["nmap", "enum4linux", "smbclient", "bloodhound", "crackmapexec"],
            "web": ["nuclei", "nikto", "wpscan", "sqlmap", "ffuf"],
            "android": ["adb", "apktool", "jadx", "frida", "objection"],
            "ios": ["frida", "objection", "iproxy", "libimobiledevice"],
            "cloud": ["pacu", " ScoutSuite", "Prowler", "cloudfox"],
            "network": ["nmap", "masscan", "wireshark", "bettercap", "responder"],
            "database": ["sqlmap", "nmap", "medusa", "hydra", "pgcli"],
            "iot": ["nmap", "binwalk", "firmware-mod-kit", "binwalk"],
        }

        self.attack_mapping: Dict[str, List[str]] = {
            "sql_injection": ["sqlmap", "bbqsql", "jsql"],
            "xss": ["xsstrike", "dalfox", "XSStrike"],
            "ssrf": ["ssrf-queen", "gopherus"],
            "xxe": ["xxeinjector", "oxmlparser"],
            "command_injection": ["commix", "shellnoob"],
            "path_traversal": ["dotdotpwn", "fimap"],
            "lfi": ["dotdotpwn", "fimap", "liffy"],
            "rfi": ["fimap"],
            "deserialization": ["ysoserial", "jexboss"],
            "buffer_overflow": ["pwntools", "ropper", "ROPgadget"],
            "brute_force": ["hydra", "medusa", "ncrack", "patator"],
            "credential_stuffing": ["snipr", "SentryMBA"],
            "privilege_escalation": ["linpeas", "winpeas", "linux-exploit-suggester"],
            "lateral_movement": ["crackmapexec", "evil-winrm", "psexec"],
            "persistence": ["empire", "meterpreter", "sliver"],
            "exfiltration": ["nc", "socat", "dnscat2", "iodine"],
            "recon": ["nmap", "masscan", "subfinder", "amass"],
            "web_scan": ["nuclei", "nikto", "wpscan", "whatweb"],
            "directory_bruteforce": ["ffuf", "gobuster", "dirb", "dirsearch"],
            "subdomain_enum": ["subfinder", "amass", "assetfinder", "knockpy"],
            "vulnerability_scan": ["nuclei", "nmap", "nikto"],
            "exploitation": ["metasploit", "sqlmap", "commix"],
            "post_exploitation": ["empire", "meterpreter", "bloodhound"],
        }

    def get_tools_for_target(self, target_type: str) -> List[str]:
        """Get recommended tools for a target type."""
        return self.target_mapping.get(target_type, ["nmap", "nuclei"])

    def get_tools_for_attack(self, attack_type: str) -> List[str]:
        """Get tools for a specific attack type."""
        return self.attack_mapping.get(attack_type, [])

    def count_all(self) -> int:
        """Count total number of tools across all categories."""
        all_tools = set()
        for tools in self.tools.values():
            all_tools.update(tools)
        return len(all_tools)

    def list_all_tools(self) -> Dict[str, List[str]]:
        """Return all tools grouped by category."""
        return dict(self.tools)

    def get_top_tools(self, n: int = 10) -> List[str]:
        """Get the top N most commonly used tools."""
        priority = [
            "nmap", "nuclei", "sqlmap", "ffuf", "subfinder",
            "nikto", "masscan", "hydra", "gobuster", "wpscan",
            "amass", "httpx", "dirsearch", "feroxbuster", "whatweb",
            "nmap", "wfuzz", "arjun", "katana", "hakrawler",
        ]
        seen = set()
        result = []
        for tool in priority:
            if tool not in seen:
                seen.add(tool)
                result.append(tool)
                if len(result) >= n:
                    break
        return result
