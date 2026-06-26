"""
Nova-Arsenal Tool Integrations.

Native API/RPC clients for external security tools:
- Metasploit (msfrpcd REST API)
- Burp Suite (REST API)
- Nmap (XML output parser)
- SQLmap (API mode)
"""

from .msf_rpc import MetasploitRPC
from .burp_api import BurpAPI
from .nmap_parser import NmapParser
from .sqlmap_api import SQLmapAPI

__all__ = ["MetasploitRPC", "BurpAPI", "NmapParser", "SQLmapAPI"]
