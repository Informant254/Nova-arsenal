"""
Nova Tool Kit Module - Governed security tools with permission profiles and scope guards.
"""

import re
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class PermissionProfile(Enum):
    """Permission profiles controlling tool access levels."""

    READ_ONLY = "read_only"
    SCOPED = "scoped"
    FULL = "full"


BLOCKED_HOSTS = {
    "google.com",
    "facebook.com",
    "twitter.com",
    "x.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "googleapis.com",
    "cloudflare.com",
}

SENSITIVE_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/",
    "/proc/self",
    "/sys/",
]


class ScopeGuard:
    """Guards tool execution against scope boundaries."""

    def __init__(self, scope: List[str], strict: bool = False) -> None:
        self._scope = scope
        self._strict = strict

    def check_url(self, url: str) -> Tuple[bool, str]:
        """Check if a URL is within scope."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        except Exception:
            return False, "Invalid URL"

        if not self._scope:
            if self._strict:
                return False, "No scope defined and strict mode is on"
            return True, "No scope defined, allowing"

        for scope_entry in self._scope:
            if scope_entry.startswith("*."):
                base = scope_entry[2:]
                if host == base or host.endswith("." + base):
                    return True, f"{host} matches wildcard {scope_entry} (in scope)"
            elif host == scope_entry:
                return True, f"{host} matches scope {scope_entry} (in scope)"
            elif host.endswith("." + scope_entry):
                return True, f"{host} is subdomain of {scope_entry} (in scope)"

        for blocked in BLOCKED_HOSTS:
            if host == blocked or host.endswith("." + blocked):
                return False, f"{host} is a blocked host"

        return False, f"{host} is not in scope"

    def check_path(self, path: str) -> Tuple[bool, str]:
        """Check if a file path is safe to access."""
        for sensitive in SENSITIVE_PATHS:
            if path.startswith(sensitive):
                return False, f"Path {path} matches blocked sensitive path {sensitive}"
        return True, f"Path {path} is safe"


class GovernedTool:
    """A tool with permission governance and schema."""

    def __init__(
        self,
        name: str,
        description: str,
        handler: Callable[..., str],
        schema: Optional[Dict[str, Any]] = None,
        allowed_profiles: Optional[List[PermissionProfile]] = None,
    ) -> None:
        self.name = name
        self.description = description
        self._handler = handler
        self.schema = schema or {
            "type": "object",
            "properties": {},
            "required": [],
        }
        self._allowed_profiles = allowed_profiles or list(PermissionProfile)

    def schema_str(self) -> str:
        """Return schema as JSON string."""
        import json
        return json.dumps(self.schema, indent=2)

    def call(self, args: Dict[str, Any], profile: PermissionProfile = PermissionProfile.FULL) -> str:
        """Execute the tool with given arguments and permission profile."""
        if profile not in self._allowed_profiles:
            return f"BLOCKED: Tool '{self.name}' is not allowed under {profile.value} profile"
        try:
            return self._handler(**args)
        except Exception as e:
            return f"ERROR: {e}"


def _http_probe_handler(url: str = "", **kwargs: Any) -> str:
    """Probe an HTTP endpoint."""
    return f"HTTP_PROBE: Probing {url} - Status: 200 OK"


def _shell_handler(command: str = "", **kwargs: Any) -> str:
    """Execute a shell command."""
    return f"SHELL: Executed '{command}' - Output simulated"


def _read_file_handler(path: str = "", **kwargs: Any) -> str:
    """Read a file."""
    return f"READ_FILE: Contents of {path}"


def _grep_code_handler(pattern: str = "", path: str = ".", **kwargs: Any) -> str:
    """Search code with regex."""
    return f"GREP: Searching '{pattern}' in {path}"


def _write_file_handler(path: str = "", content: str = "", **kwargs: Any) -> str:
    """Write content to a file."""
    return f"WRITE: Wrote to {path}"


class NovaToolKit:
    """Toolkit providing governed security tools with permission profiles."""

    def __init__(
        self,
        profile: PermissionProfile = PermissionProfile.SCOPED,
        scope: Optional[List[str]] = None,
    ) -> None:
        self._profile = profile
        self._scope = scope or []
        self._guard = ScopeGuard(self._scope)

    def build(self) -> List[GovernedTool]:
        """Build and return the list of governed tools."""
        tools = [
            GovernedTool(
                name="http_probe",
                description="Probe HTTP endpoints for status, headers, and response data",
                handler=_http_probe_handler,
                schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                    },
                    "required": ["url"],
                },
                allowed_profiles=[PermissionProfile.SCOPED, PermissionProfile.FULL],
            ),
            GovernedTool(
                name="shell",
                description="Execute shell commands on the local system",
                handler=_shell_handler,
                schema={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Shell command"},
                    },
                    "required": ["command"],
                },
                allowed_profiles=[PermissionProfile.FULL],
            ),
            GovernedTool(
                name="read_file",
                description="Read contents of a file",
                handler=_read_file_handler,
                schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path"},
                    },
                    "required": ["path"],
                },
                allowed_profiles=[PermissionProfile.READ_ONLY, PermissionProfile.SCOPED, PermissionProfile.FULL],
            ),
            GovernedTool(
                name="grep_code",
                description="Search file contents using regex patterns",
                handler=_grep_code_handler,
                schema={
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Regex pattern"},
                        "path": {"type": "string", "description": "Search path"},
                    },
                    "required": ["pattern"],
                },
                allowed_profiles=[PermissionProfile.READ_ONLY, PermissionProfile.SCOPED, PermissionProfile.FULL],
            ),
            GovernedTool(
                name="write_file",
                description="Write content to a file",
                handler=_write_file_handler,
                schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path"},
                        "content": {"type": "string", "description": "Content to write"},
                    },
                    "required": ["path", "content"],
                },
                allowed_profiles=[PermissionProfile.SCOPED, PermissionProfile.FULL],
            ),
        ]
        return tools
