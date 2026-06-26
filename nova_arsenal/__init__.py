"""
Nova-Arsenal: Autonomous Security Research Platform

A comprehensive security agent platform with 70+ modules covering
reconnaissance, exploitation, and analysis.

Sub-packages:
- integrations: Native API/RPC clients for Metasploit, Burp, Nmap, SQLmap
- intelligence: Tool-selection reasoning engine
- correlation: Cross-tool result correlation engine
"""

__version__ = "1.0.0"
__author__ = "Informant254"

from nova_arsenal.integrations import MetasploitRPC, BurpAPI, NmapParser, SQLmapAPI
from nova_arsenal.intelligence import ToolSelector
from nova_arsenal.correlation import Correlator

__all__ = [
    "MetasploitRPC", "BurpAPI", "NmapParser", "SQLmapAPI",
    "ToolSelector", "Correlator",
]
