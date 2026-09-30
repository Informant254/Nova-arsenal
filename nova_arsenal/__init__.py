"""
Nova-Arsenal: Autonomous Security Research Platform

A comprehensive security agent platform with 70+ modules covering
reconnaissance, exploitation, analysis, intelligence, CTF solving,
MCP integration, E2E encryption, and zero-day candidate research.

Sub-packages:
- integrations: Native API/RPC clients for Metasploit, Burp, Nmap, SQLmap
- intelligence: Tool-selection reasoning engine, CVE research, OSINT chain
- correlation: Cross-tool result correlation engine
- compliance: PCI DSS / SOC 2 / ISO 27001 / NIST mapping
- swarm: Multi-agent parallel orchestration with weighted voting
- crypto: E2E encryption with RSA key exchange + AES-GCM
- mcp: Model Context Protocol server for AI agent interoperability
- zeroday: High-speed zero-day *candidate* discovery pipeline
"""

__version__ = "1.3.0"
__author__ = "Informant254"

from nova_arsenal.compliance import ComplianceMapper, ComplianceResult
from nova_arsenal.correlation import Correlator
from nova_arsenal.crypto import (
    Cipher,
    EncryptionError,
    KeyManager,
    KeyPair,
    KeySize,
    SecureEnvelope,
)
from nova_arsenal.ctf_solver import ChallengeType, CtfChallenge, CtfFlag, CtfSolver
from nova_arsenal.integrations import BurpAPI, MetasploitRPC, NmapParser, SQLmapAPI
from nova_arsenal.intelligence import (
    CveResearch,
    OsintChain,
    OsintChainResult,
    OsintPhase,
    ToolSelector,
)
from nova_arsenal.mcp import NovaMcpServer
from nova_arsenal.mcp import run_server as run_mcp_server
from nova_arsenal.payload_generator import PayloadGenerator, PayloadLanguage, PayloadType
from nova_arsenal.persona_manager import PersonaManager
from nova_arsenal.prompt_builder import (
    BASE_PRIORITY,
    COT_INSTRUCTION,
    ChainOfThought,
    ChatMessage,
    Empty,
    First,
    Isolate,
    PromptBuilder,
    PromptNode,
    RenderResult,
    Scope,
    Text,
    ToolDefinition,
    assistant_message,
    compute_priority_levels,
    cot_block,
    render,
    system_message,
    tool_result,
    user_message,
)
from nova_arsenal.scheduler import CronExpression, NovaScheduler, ScheduleEntry
from nova_arsenal.sessions import (
    SessionManager,
    SessionStatus,
    SubAgentResult,
    SubAgentRole,
    TaskSession,
    get_session_manager,
)
from nova_arsenal.swarm import SwarmAgentRole, SwarmOrchestrator, SwarmResult
from nova_arsenal.tool_definitions import (
    ALL_TOOLS,
    CURSOR_BUILTIN_TOOLS,
    NOVA_SECURITY_TOOLS,
    ToolSchema,
    get_tool_by_name,
    tools_to_anthropic_format,
    tools_to_openai_format,
)
from nova_arsenal.zeroday import (
    AttackSurfaceMapper,
    CrashTriageEngine,
    FuzzOrchestrator,
    LiveFuzzWorker,
    NoveltyScorer,
    StaticBugScanner,
    VariantAnalyzer,
    ZeroDayCandidate,
    ZeroDayHuntConfig,
    ZeroDayHunter,
    ZeroDayHuntResult,
    findings_to_services,
)

__all__ = [
    "MetasploitRPC",
    "BurpAPI",
    "NmapParser",
    "SQLmapAPI",
    "ToolSelector",
    "Correlator",
    "PersonaManager",
    "PayloadGenerator",
    "PayloadType",
    "PayloadLanguage",
    "NovaScheduler",
    "ScheduleEntry",
    "CronExpression",
    "ComplianceMapper",
    "ComplianceResult",
    "SwarmOrchestrator",
    "SwarmAgentRole",
    "SwarmResult",
    "CveResearch",
    "OsintChain",
    "OsintChainResult",
    "OsintPhase",
    "CtfSolver",
    "CtfFlag",
    "CtfChallenge",
    "ChallengeType",
    "KeyManager",
    "KeyPair",
    "KeySize",
    "Cipher",
    "SecureEnvelope",
    "EncryptionError",
    "NovaMcpServer",
    "run_mcp_server",
    "Scope",
    "First",
    "Empty",
    "Isolate",
    "Text",
    "ChatMessage",
    "ToolDefinition",
    "ChainOfThought",
    "PromptBuilder",
    "PromptNode",
    "RenderResult",
    "BASE_PRIORITY",
    "render",
    "compute_priority_levels",
    "system_message",
    "user_message",
    "assistant_message",
    "tool_result",
    "cot_block",
    "COT_INSTRUCTION",
    "ToolSchema",
    "CURSOR_BUILTIN_TOOLS",
    "NOVA_SECURITY_TOOLS",
    "ALL_TOOLS",
    "get_tool_by_name",
    "tools_to_openai_format",
    "tools_to_anthropic_format",
    "ZeroDayHunter",
    "ZeroDayHuntConfig",
    "ZeroDayHuntResult",
    "ZeroDayCandidate",
    "AttackSurfaceMapper",
    "VariantAnalyzer",
    "FuzzOrchestrator",
    "LiveFuzzWorker",
    "CrashTriageEngine",
    "StaticBugScanner",
    "NoveltyScorer",
    "findings_to_services",
    "SessionManager",
    "get_session_manager",
    "TaskSession",
    "SubAgentRole",
    "SessionStatus",
    "SubAgentResult",
]
