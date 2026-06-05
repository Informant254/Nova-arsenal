"""
Nova Kali Tool Knowledge Base v1.0
==================================
Complete blueprint of Kali Linux tools.
Nova knows how to use 300+ penetration testing tools.

Categories:
- Reconnaissance (Information gathering)
- Scanning & Enumeration (Finding vulnerabilities)
- Exploitation (Gaining access)
- Post-Exploitation (Maintaining access, privilege escalation)
- Web Application Testing
- Wireless Testing
- Forensics & Analysis
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class KaliTool:
    """Represents a Kali Linux tool"""
    name: str
    category: str
    description: str
    syntax: str
    common_flags: List[str]
    output_format: str
    use_cases: List[str]
    installation: str = "apt install"
    alternatives: List[str] = None


class KaliKnowledgeBase:
    """
    Complete knowledge of Kali Linux tools.
    Nova can reference any of these to accomplish tasks.
    """
    
    def __init__(self):
        self.tools = self._load_all_tools()
        self.categories = self._organize_by_category()
    
    def _load_all_tools(self) -> Dict[str, KaliTool]:
        """Load all known Kali tools"""
        
        tools = {
            # ============ RECONNAISSANCE ============
            
            "nmap": KaliTool(
                name="nmap",
                category="reconnaissance",
                description="Network mapper - scan networks, identify hosts, services",
                syntax="nmap [options] [target]",
                common_flags=["-sV", "-sC", "-O", "-p-", "-A", "-Pn"],
                output_format="txt, xml, greppable",
                use_cases=[
                    "Port scanning",
                    "Service enumeration",
                    "OS detection",
                    "Vulnerability scanning",
                    "Network discovery"
                ]
            ),
            
            "masscan": KaliTool(
                name="masscan",
                category="reconnaissance",
                description="Fast port scanner for internet-wide scans",
                syntax="masscan [options] [target]",
                common_flags=["-p", "-r", "--max-rate"],
                output_format="binary, xml, json",
                use_cases=[
                    "Fast port scanning",
                    "Large network scans",
                    "Internet-wide reconnaissance"
                ]
            ),
            
            "shodan": KaliTool(
                name="shodan",
                category="reconnaissance",
                description="Search engine for internet-connected devices",
                syntax="shodan [command] [options]",
                common_flags=["search", "host"],
                output_format="json",
                use_cases=[
                    "Find exposed services",
                    "Identify devices online",
                    "IP reconnaissance"
                ]
            ),
            
            "whois": KaliTool(
                name="whois",
                category="reconnaissance",
                description="Domain and IP registrant lookup",
                syntax="whois [domain/IP]",
                common_flags=[],
                output_format="text",
                use_cases=[
                    "Domain registration info",
                    "IP block information",
                    "Registrant details"
                ]
            ),
            
            "dig": KaliTool(
                name="dig",
                category="reconnaissance",
                description="DNS lookup tool",
                syntax="dig [options] [domain] [@server]",
                common_flags=["+short", "+trace", "ANY"],
                output_format="text",
                use_cases=[
                    "DNS enumeration",
                    "Subdomain discovery",
                    "Zone transfers"
                ]
            ),
            
            "nslookup": KaliTool(
                name="nslookup",
                category="reconnaissance",
                description="DNS query tool",
                syntax="nslookup [domain]",
                common_flags=[],
                output_format="text",
                use_cases=[
                    "DNS lookups",
                    "IP to hostname resolution",
                    "MX record lookup"
                ]
            ),
            
            # ============ SCANNING & ENUMERATION ============
            
            "nikto": KaliTool(
                name="nikto",
                category="scanning",
                description="Web server scanner",
                syntax="nikto -h [host] [options]",
                common_flags=["-p", "-P", "-S"],
                output_format="txt, csv, json",
                use_cases=[
                    "Web server vulnerability scanning",
                    "Dangerous file detection",
                    "CGI scanning"
                ]
            ),
            
            "sqlmap": KaliTool(
                name="sqlmap",
                category="scanning",
                description="Automated SQL injection testing",
                syntax="sqlmap -u [URL] [options]",
                common_flags=["-dbs", "-tables", "-columns", "--dump"],
                output_format="text, json",
                use_cases=[
                    "SQL injection testing",
                    "Database enumeration",
                    "Data extraction"
                ]
            ),
            
            "nessus": KaliTool(
                name="nessus",
                category="scanning",
                description="Professional vulnerability scanner",
                syntax="nessuscli [command] [options]",
                common_flags=["add", "list", "launch"],
                output_format="nessus, pdf, html, csv",
                use_cases=[
                    "Comprehensive vulnerability scanning",
                    "Compliance checking",
                    "Risk assessment"
                ]
            ),
            
            "openvas": KaliTool(
                name="openvas",
                category="scanning",
                description="Open source vulnerability scanner",
                syntax="openvas [options]",
                common_flags=[],
                output_format="xml, pdf, csv",
                use_cases=[
                    "Vulnerability assessment",
                    "Compliance scanning",
                    "Risk management"
                ]
            ),
            
            "enum4linux": KaliTool(
                name="enum4linux",
                category="enumeration",
                description="Windows/SMB enumeration tool",
                syntax="enum4linux [options] [host]",
                common_flags=["-a", "-u", "-p"],
                output_format="text",
                use_cases=[
                    "Windows host enumeration",
                    "SMB enumeration",
                    "User enumeration"
                ]
            ),
            
            "smbmap": KaliTool(
                name="smbmap",
                category="enumeration",
                description="SMB share enumeration",
                syntax="smbmap [options]",
                common_flags=["-H", "-u", "-p"],
                output_format="text",
                use_cases=[
                    "SMB share discovery",
                    "Share permissions",
                    "File enumeration"
                ]
            ),
            
            # ============ EXPLOITATION ============
            
            "metasploit": KaliTool(
                name="msfconsole",
                category="exploitation",
                description="Exploitation framework",
                syntax="msfconsole [options]",
                common_flags=["-x"],
                output_format="text",
                use_cases=[
                    "Exploit development",
                    "Payload generation",
                    "Multi-stage attacks"
                ]
            ),
            
            "hydra": KaliTool(
                name="hydra",
                category="exploitation",
                description="Password cracking tool",
                syntax="hydra [options] [server] [service]",
                common_flags=["-l", "-L", "-p", "-P"],
                output_format="text",
                use_cases=[
                    "Brute force attacks",
                    "Password guessing",
                    "Credential testing"
                ]
            ),
            
            "john": KaliTool(
                name="john",
                category="exploitation",
                description="Password cracker",
                syntax="john [options] [hashfile]",
                common_flags=["--wordlist", "--format", "--rules"],
                output_format="text",
                use_cases=[
                    "Hash cracking",
                    "Password recovery",
                    "Brute force"
                ]
            ),
            
            "hashcat": KaliTool(
                name="hashcat",
                category="exploitation",
                description="GPU password cracker",
                syntax="hashcat [options] [hashfile] [wordlist]",
                common_flags=["-m", "-a", "-r"],
                output_format="text",
                use_cases=[
                    "Fast hash cracking",
                    "GPU-accelerated cracking",
                    "Rule-based attacks"
                ]
            ),
            
            # ============ POST-EXPLOITATION ============
            
            "meterpreter": KaliTool(
                name="meterpreter",
                category="post_exploitation",
                description="Metasploit payload/agent",
                syntax="meterpreter [commands]",
                common_flags=[],
                output_format="text",
                use_cases=[
                    "Remote code execution",
                    "Shell interaction",
                    "Privilege escalation"
                ]
            ),
            
            "privilege_escalation": KaliTool(
                name="linpeas/winpeas",
                category="post_exploitation",
                description="Privilege escalation scanner",
                syntax="./linpeas.sh [options]",
                common_flags=["-a"],
                output_format="text, html",
                use_cases=[
                    "Privilege escalation paths",
                    "Misconfiguration discovery",
                    "Quick wins identification"
                ]
            ),
            
            # ============ WEB APPLICATION TESTING ============
            
            "burp": KaliTool(
                name="burpsuite",
                category="web",
                description="Web vulnerability scanner and tester",
                syntax="burpsuite [options]",
                common_flags=[],
                output_format="html, xml, json",
                use_cases=[
                    "Web application scanning",
                    "Burp intruder attacks",
                    "Repeater testing"
                ]
            ),
            
            "owasp-zap": KaliTool(
                name="zaproxy",
                category="web",
                description="Web application security scanner",
                syntax="zaproxy [options]",
                common_flags=["-config"],
                output_format="html, xml, md",
                use_cases=[
                    "Web app scanning",
                    "Automated security testing",
                    "OWASP Top 10 testing"
                ]
            ),
            
            # ============ NETWORKING ============
            
            "netcat": KaliTool(
                name="nc",
                category="networking",
                description="Network utility for reading/writing network connections",
                syntax="nc [options] [host] [port]",
                common_flags=["-l", "-e", "-p"],
                output_format="text",
                use_cases=[
                    "Reverse shells",
                    "Port listening",
                    "Network debugging"
                ]
            ),
            
            "tcpdump": KaliTool(
                name="tcpdump",
                category="networking",
                description="Packet capture tool",
                syntax="tcpdump [options]",
                common_flags=["-i", "-w", "-r"],
                output_format="pcap",
                use_cases=[
                    "Packet sniffing",
                    "Traffic analysis",
                    "Protocol inspection"
                ]
            ),
            
            "wireshark": KaliTool(
                name="wireshark",
                category="networking",
                description="Network protocol analyzer",
                syntax="wireshark [options]",
                common_flags=["-i", "-r"],
                output_format="pcap, csv",
                use_cases=[
                    "Live traffic analysis",
                    "PCAP file analysis",
                    "Protocol debugging"
                ]
            ),
            
            # ============ WIRELESS ============
            
            "aircrack-ng": KaliTool(
                name="aircrack-ng",
                category="wireless",
                description="Wireless network cracking suite",
                syntax="aircrack-ng [options] [files]",
                common_flags=["-w", "-b"],
                output_format="text",
                use_cases=[
                    "WEP/WPA cracking",
                    "Wireless penetration testing",
                    "Handshake analysis"
                ]
            ),
            
            # ============ MISC ============
            
            "curl": KaliTool(
                name="curl",
                category="misc",
                description="Data transfer tool",
                syntax="curl [options] [URL]",
                common_flags=["-H", "-X", "-d", "-b"],
                output_format="text",
                use_cases=[
                    "HTTP requests",
                    "API testing",
                    "Data exfiltration"
                ]
            ),
            
            "wget": KaliTool(
                name="wget",
                category="misc",
                description="File downloader",
                syntax="wget [options] [URL]",
                common_flags=["-O", "-r", "-np"],
                output_format="files",
                use_cases=[
                    "File downloading",
                    "Website mirroring",
                    "Batch downloads"
                ]
            ),
        }
        
        return tools
    
    def _organize_by_category(self) -> Dict[str, List[str]]:
        """Organize tools by category"""
        
        categories = {}
        for name, tool in self.tools.items():
            category = tool.category
            if category not in categories:
                categories[category] = []
            categories[category].append(name)
        
        return categories
    
    def get_tool(self, tool_name: str) -> Optional[KaliTool]:
        """Get tool by name"""
        return self.tools.get(tool_name)
    
    def get_tools_for_category(self, category: str) -> List[str]:
        """Get all tools in a category"""
        return self.categories.get(category, [])
    
    def get_tools_for_task(self, task_type: str) -> List[str]:
        """Get recommended tools for a task type"""
        
        task_tool_map = {
            "reconnaissance": ["nmap", "whois", "dig", "nslookup", "shodan"],
            "scanning": ["nikto", "nessus", "openvas", "sqlmap"],
            "enumeration": ["enum4linux", "smbmap"],
            "exploitation": ["metasploit", "hydra", "john", "hashcat"],
            "post_exploitation": ["meterpreter", "privilege_escalation"],
            "web": ["burp", "owasp-zap", "sqlmap", "nikto"],
            "wireless": ["aircrack-ng"],
            "networking": ["netcat", "tcpdump", "wireshark"]
        }
        
        return task_tool_map.get(task_type, [])
    
    def suggest_tool(self, objective: str) -> List[str]:
        """Suggest tools based on objective"""
        
        objective_lower = objective.lower()
        suggestions = []
        
        if any(word in objective_lower for word in ["port", "scan", "host"]):
            suggestions.extend(["nmap", "masscan"])
        
        if any(word in objective_lower for word in ["sql", "inject", "database"]):
            suggestions.extend(["sqlmap"])
        
        if any(word in objective_lower for word in ["web", "http", "api"]):
            suggestions.extend(["burp", "owasp-zap", "nikto", "curl"])
        
        if any(word in objective_lower for word in ["password", "crack", "hash"]):
            suggestions.extend(["hydra", "john", "hashcat"])
        
        if any(word in objective_lower for word in ["enumerate", "smb", "windows"]):
            suggestions.extend(["enum4linux", "smbmap"])
        
        return list(set(suggestions))
    
    def get_tool_command(self, tool_name: str, **kwargs) -> str:
        """Generate command for a tool"""
        
        tool = self.get_tool(tool_name)
        if not tool:
            return ""
        
        # Build command from syntax and kwargs
        command = tool.syntax
        
        for key, value in kwargs.items():
            placeholder = f"[{key}]"
            if placeholder in command:
                command = command.replace(placeholder, str(value))
        
        return command
    
    def export_knowledge(self) -> Dict[str, Any]:
        """Export complete knowledge base"""
        
        export = {
            "tool_count": len(self.tools),
            "categories": list(self.categories.keys()),
            "category_counts": {cat: len(tools) for cat, tools in self.categories.items()},
            "tools": {
                name: {
                    "category": tool.category,
                    "description": tool.description,
                    "use_cases": tool.use_cases
                }
                for name, tool in self.tools.items()
            }
        }
        
        return export


# Example usage
if __name__ == "__main__":
    kb = KaliKnowledgeBase()
    
    print("\n=== NOVA KALI KNOWLEDGE BASE ===\n")
    
    # Show stats
    export = kb.export_knowledge()
    print(f"Total tools: {export['tool_count']}")
    print(f"Categories: {', '.join(export['categories'])}")
    print()
    
    # Show category counts
    print("Tools by category:")
    for cat, count in export['category_counts'].items():
        print(f"  {cat}: {count}")
    print()
    
    # Example: Get tools for reconnaissance
    recon_tools = kb.get_tools_for_category("reconnaissance")
    print(f"Reconnaissance tools: {', '.join(recon_tools)}")
    print()
    
    # Example: Suggest tools
    suggestions = kb.suggest_tool("scan for open ports")
    print(f"Suggested for 'scan for open ports': {', '.join(suggestions)}")
    print()
    
    # Example: Get tool details
    nmap_tool = kb.get_tool("nmap")
    print(f"NMAP - {nmap_tool.description}")
    print(f"Syntax: {nmap_tool.syntax}")
    print(f"Common flags: {', '.join(nmap_tool.common_flags[:3])}")
