"""
Cursor-Inspired Structured Tool Definitions.

Ports Cursor's 19 BuiltinTool enums and JSON Schema definitions
into Python, plus Nova-Arsenal-specific security research tools.

Tools can be rendered into prompt_builder Scope nodes for
priority-based prompt assembly.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolSchema:
    """A tool definition with JSON Schema parameters."""
    name: str
    description: str
    parameters: Dict[str, Any]


# ── Cursor Builtin Tools (from aiserver.proto BuiltinTool enum) ────────────


CURSOR_BUILTIN_TOOLS: List[ToolSchema] = [
    ToolSchema(
        name="search",
        description="Semantic code search across the codebase. Returns relevant file paths and code snippets matching the query.",
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query (supports regex and fuzzy matching)",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return",
                    "default": 10,
                },
            },
            "required": ["query"],
        },
    ),
    ToolSchema(
        name="read_chunk",
        description="Read a specific chunk/lines from a file. Use to inspect file contents without loading the entire file.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to read",
                },
                "start_line": {
                    "type": "integer",
                    "description": "Starting line number (1-indexed)",
                },
                "end_line": {
                    "type": "integer",
                    "description": "Ending line number (inclusive)",
                },
            },
            "required": ["file_path", "start_line", "end_line"],
        },
    ),
    ToolSchema(
        name="gotodef",
        description="Navigate to the definition of a symbol (function, class, variable) in the codebase.",
        parameters={
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "Symbol name to find the definition of",
                },
                "file_path": {
                    "type": "string",
                    "description": "Optional file path to scope the search",
                },
            },
            "required": ["symbol"],
        },
    ),
    ToolSchema(
        name="edit",
        description="Apply an edit to a file. Specify the old and new content for exact replacements.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to edit",
                },
                "old_string": {
                    "type": "string",
                    "description": "Exact text to replace",
                },
                "new_string": {
                    "type": "string",
                    "description": "New text to insert",
                },
            },
            "required": ["file_path", "old_string", "new_string"],
        },
    ),
    ToolSchema(
        name="undo_edit",
        description="Undo the last edit made to a file.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to undo edits on",
                },
            },
            "required": ["file_path"],
        },
    ),
    ToolSchema(
        name="end",
        description="Signal that the current task is complete and no further actions are needed.",
        parameters={
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Summary of what was accomplished",
                },
            },
            "required": ["summary"],
        },
    ),
    ToolSchema(
        name="new_file",
        description="Create a new file in the project with the specified content.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path where the new file should be created",
                },
                "content": {
                    "type": "string",
                    "description": "Content of the new file",
                },
            },
            "required": ["file_path", "content"],
        },
    ),
    ToolSchema(
        name="add_test",
        description="Add a test for a specified function or file.",
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name or file path to test",
                },
                "test_code": {
                    "type": "string",
                    "description": "Test code content",
                },
            },
            "required": ["target", "test_code"],
        },
    ),
    ToolSchema(
        name="run_test",
        description="Run a specific test file or test function.",
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Test file path or test function name",
                },
                "framework": {
                    "type": "string",
                    "description": "Test framework (pytest, unittest, etc.)",
                    "default": "pytest",
                },
            },
            "required": ["target"],
        },
    ),
    ToolSchema(
        name="delete_test",
        description="Delete a test file or specific test function.",
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Test file path or test function name to delete",
                },
            },
            "required": ["target"],
        },
    ),
    ToolSchema(
        name="save_file",
        description="Save the current state of a file to disk.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to save",
                },
            },
            "required": ["file_path"],
        },
    ),
    ToolSchema(
        name="get_tests",
        description="List all test files and test functions in the project.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Optional path to scope the search",
                },
            },
        },
    ),
    ToolSchema(
        name="get_symbols",
        description="Get all symbols (functions, classes, variables) defined in a file or project.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to get symbols from",
                },
                "include_dependencies": {
                    "type": "boolean",
                    "description": "Whether to include symbols from imported modules",
                    "default": False,
                },
            },
            "required": ["file_path"],
        },
    ),
    ToolSchema(
        name="semantic_search",
        description="Perform a semantic/code-aware search using embedding-based retrieval.",
        parameters={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language query describing what to find",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return",
                    "default": 10,
                },
            },
            "required": ["query"],
        },
    ),
    ToolSchema(
        name="get_project_structure",
        description="Get the tree structure of the project, showing directories and key files.",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root path to examine",
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum directory depth",
                    "default": 3,
                },
            },
            "required": [],
        },
    ),
    ToolSchema(
        name="create_rm_files",
        description="Create or remove multiple files in batch.",
        parameters={
            "type": "object",
            "properties": {
                "create": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"},
                        },
                    },
                    "description": "Files to create",
                },
                "delete": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Paths to delete",
                },
            },
            "required": [],
        },
    ),
    ToolSchema(
        name="run_terminal_commands",
        description="Run one or more terminal commands and get their output.",
        parameters={
            "type": "object",
            "properties": {
                "commands": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Commands to execute sequentially",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds per command",
                    "default": 30,
                },
                "workdir": {
                    "type": "string",
                    "description": "Working directory for commands",
                },
            },
            "required": ["commands"],
        },
    ),
    ToolSchema(
        name="new_edit",
        description="Create a new edit with structured diff semantics.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to edit",
                },
                "operations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "op": {
                                "type": "string",
                                "enum": ["replace", "insert", "delete"],
                            },
                            "old_text": {"type": "string"},
                            "new_text": {"type": "string"},
                            "line": {"type": "integer"},
                        },
                    },
                },
            },
            "required": ["file_path", "operations"],
        },
    ),
    ToolSchema(
        name="read_with_linter",
        description="Read a file and run the linter on it, returning both content and linting results.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to read and lint",
                },
            },
            "required": ["file_path"],
        },
    ),
]


# ── Nova-Arsenal Security Tools ─────────────────────────────────────────────


NOVA_SECURITY_TOOLS: List[ToolSchema] = [
    ToolSchema(
        name="nmap_scan",
        description="Run an Nmap scan against a target. Supports full port scans, service detection, and NSE scripts.",
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address, hostname, or CIDR range",
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g., '80', '1-1000', '80,443,8080')",
                    "default": "top-1000",
                },
                "flags": {
                    "type": "string",
                    "description": "Additional Nmap flags (e.g., '-sV -sC -O')",
                    "default": "-sV",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["xml", "normal", "grepable"],
                    "default": "xml",
                },
            },
            "required": ["target"],
        },
    ),
    ToolSchema(
        name="burp_scan",
        description="Trigger a Burp Suite active scan against a web target.",
        parameters={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to scan",
                },
                "scope": {
                    "type": "object",
                    "properties": {
                        "include": {"type": "array", "items": {"type": "string"}},
                        "exclude": {"type": "array", "items": {"type": "string"}},
                    },
                    "description": "Scope configuration for the scan",
                },
            },
            "required": ["url"],
        },
    ),
    ToolSchema(
        name="sqlmap_scan",
        description="Automated SQL injection detection and exploitation using SQLmap.",
        parameters={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with potentially injectable parameters",
                },
                "data": {
                    "type": "string",
                    "description": "POST data string",
                },
                "level": {
                    "type": "integer",
                    "description": "Test level (1-5, higher = more thorough)",
                    "default": 1,
                },
                "risk": {
                    "type": "integer",
                    "description": "Risk level (1-3, higher = riskier tests)",
                    "default": 1,
                },
                "technique": {
                    "type": "string",
                    "description": "SQL injection technique (B: Boolean, E: Error, U: Union, Q: Query, S: Stacked, T: Time)",
                    "default": "BEUSTQ",
                },
            },
            "required": ["url"],
        },
    ),
    ToolSchema(
        name="osint_investigate",
        description="Perform an OSINT investigation chain against a target domain or identity.",
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain name, username, or email to investigate",
                },
                "phases": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "domain_discovery", "subdomain_enum", "tech_detection",
                            "email_harvest", "social_discovery", "breach_search",
                        ],
                    },
                    "description": "OSINT phases to execute",
                    "default": ["domain_discovery", "subdomain_enum", "tech_detection"],
                },
            },
            "required": ["target"],
        },
    ),
    ToolSchema(
        name="cve_lookup",
        description="Look up CVEs and known exploits for a given service and version.",
        parameters={
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name (e.g., 'http', 'smb', 'ssh', 'mysql')",
                },
                "version": {
                    "type": "string",
                    "description": "Service version string",
                },
                "port": {
                    "type": "integer",
                    "description": "Port the service is running on",
                },
            },
            "required": ["service"],
        },
    ),
    ToolSchema(
        name="payload_generate",
        description="Generate a reverse shell or other payload for exploitation.",
        parameters={
            "type": "object",
            "properties": {
                "lhost": {
                    "type": "string",
                    "description": "Listener IP address",
                },
                "lport": {
                    "type": "integer",
                    "description": "Listener port",
                },
                "payload_type": {
                    "type": "string",
                    "enum": ["reverse_shell", "bind_shell", "webshell", "download_exec"],
                    "default": "reverse_shell",
                },
                "language": {
                    "type": "string",
                    "enum": ["bash", "python", "perl", "ruby", "powershell", "netcat"],
                    "default": "python",
                },
            },
            "required": ["lhost", "lport"],
        },
    ),
    ToolSchema(
        name="compliance_check",
        description="Map findings to compliance frameworks (PCI DSS, SOC 2, ISO 27001, NIST).",
        parameters={
            "type": "object",
            "properties": {
                "finding_type": {
                    "type": "string",
                    "description": "Type of finding (e.g., 'sql_injection', 'xss', 'rce')",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "description": {
                    "type": "string",
                    "description": "Description of the finding",
                },
            },
            "required": ["finding_type", "severity"],
        },
    ),
    ToolSchema(
        name="ctf_solve",
        description="Attempt to solve a CTF challenge automatically.",
        parameters={
            "type": "object",
            "properties": {
                "challenge_type": {
                    "type": "string",
                    "enum": [
                        "web", "crypto", "stego", "forensics",
                        "reversing", "pwn", "osint", "recon", "misc",
                    ],
                    "description": "Type of CTF challenge",
                },
                "target": {
                    "type": "string",
                    "description": "Challenge target URL, file path, or description",
                },
                "hints": {
                    "type": "string",
                    "description": "Optional hints or additional context",
                },
            },
            "required": ["challenge_type", "target"],
        },
    ),
    ToolSchema(
        name="swarm_scan",
        description="Launch a multi-agent swarm scan with parallel recon, web, exploit, and OSINT agents.",
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target to scan",
                },
                "roles": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["recon", "web", "exploit", "osint"],
                    },
                    "description": "Agent roles to include",
                    "default": ["recon", "web", "exploit", "osint"],
                },
                "max_steps_per_agent": {
                    "type": "integer",
                    "description": "Maximum steps per agent",
                    "default": 10,
                },
            },
            "required": ["target"],
        },
    ),
    ToolSchema(
        name="metasploit_run",
        description="Execute a Metasploit module against a target.",
        parameters={
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "description": "Full module path (e.g., 'exploit/multi/handler')",
                },
                "options": {
                    "type": "object",
                    "description": "Module options as key-value pairs",
                    "additionalProperties": {"type": "string"},
                },
                "module_type": {
                    "type": "string",
                    "enum": ["exploit", "auxiliary", "post", "payload"],
                    "default": "auxiliary",
                },
            },
            "required": ["module"],
        },
    ),
]


# ── Combined Tool Registry ──────────────────────────────────────────────────


ALL_TOOLS: List[ToolSchema] = CURSOR_BUILTIN_TOOLS + NOVA_SECURITY_TOOLS


def get_tool_by_name(name: str) -> Optional[ToolSchema]:
    """Look up a tool by name across all registries."""
    for tool in ALL_TOOLS:
        if tool.name == name:
            return tool
    return None


def tools_to_openai_format(tools: List[ToolSchema]) -> List[Dict[str, Any]]:
    """Convert tool schemas to OpenAI-compatible tool definitions."""
    result = []
    for tool in tools:
        result.append({
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            },
        })
    return result


def tools_to_anthropic_format(tools: List[ToolSchema]) -> List[Dict[str, Any]]:
    """Convert tool schemas to Anthropic-compatible tool definitions."""
    result = []
    for tool in tools:
        result.append({
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.parameters,
        })
    return result


def tools_to_nexn2_xml_format(tools: List[ToolSchema]) -> str:
    """Convert tool schemas to Nex-N2 XML tool call format.

    Generates the <tools> block for Nex-N2 style chat templates:
    <tools>
    {"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}
    ...
    </tools>

    With instruction to use <tool_call><function=name><parameter=key>value</parameter></function></tool_call>
    """
    import json

    lines = ["<tools>"]
    for tool in tools:
        entry = {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            },
        }
        lines.append(json.dumps(entry, ensure_ascii=False))
    lines.append("</tools>")

    instruction = """
If you choose to call a function ONLY reply in the following format with NO suffix:

<tool_call>
<function=function_name>
<parameter=parameter_name>
value
</parameter>
</function>
</tool_call>

<IMPORTANT>
- Function calls MUST follow the <tool_call><function=...></function></tool_call> format
- Required parameters MUST be specified
- You may provide optional reasoning in natural language BEFORE the function call, but NOT after
- If there is no function call available, answer the question like normal
</IMPORTANT>"""

    return "\n".join(lines) + instruction


def tools_to_deepseek_xml_format(tools: List[ToolSchema]) -> str:
    """Convert tool schemas to DeepSeek V4 Pro DSML tool format.

    Uses <|DSML|tool_calls> markers and XML format.
    """
    import json

    lines = ["<|DSML|tool_calls>"]
    for tool in tools:
        entry = {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            },
        }
        lines.append(json.dumps(entry, ensure_ascii=False))
    lines.append("</|DSML|tool_calls>")
    return "\n".join(lines)
