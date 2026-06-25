"""
Secure Executor - Command validation, scope enforcement, and safety checks.

Every command goes through this before reaching the sandbox.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class SecurityPolicy:
    """Security policy for command execution."""
    blocked_commands: List[str] = field(default_factory=lambda: [
        "rm -rf /",
        "rm -rf /*",
        "mkfs",
        "dd if=/dev/zero",
        ":(){:|:&};:",
        "fork bomb",
        "shutdown",
        "reboot",
        "halt",
        "init 0",
        "init 6",
    ])

    blocked_patterns: List[str] = field(default_factory=lambda: [
        r"rm\s+-rf\s+/",
        r"curl\s+.*\|\s*(ba)?sh",
        r"wget\s+.*\|\s*(ba)?sh",
        r"chmod\s+777\s+/",
        r"chown\s+.*\s+/",
        r"DROP\s+TABLE",
        r"DROP\s+DATABASE",
        r"DELETE\s+FROM.*WHERE\s+1",
        r"TRUNCATE\s+TABLE",
        r"shutdown\s+-h\s+now",
        r"reboot",
        r"halt\s+-p",
    ])

    blocked_hosts: List[str] = field(default_factory=lambda: [
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
    ])

    sensitive_paths: List[str] = field(default_factory=lambda: [
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh",
        "/proc/self",
        "/sys/",
    ])

    max_command_length: int = 4096
    max_concurrent_commands: int = 5


@dataclass
class ValidationResult:
    """Result of command validation."""
    allowed: bool
    reason: str = ""
    sanitized_command: str = ""
    warnings: List[str] = field(default_factory=list)


class SecureExecutor:
    """Validates and sanitizes commands before execution."""

    def __init__(self, policy: Optional[SecurityPolicy] = None) -> None:
        self._policy = policy or SecurityPolicy()
        self._active_commands = 0

    def validate_command(self, command: str, scope: Optional[List[str]] = None) -> ValidationResult:
        """Validate a command against security policy."""
        if len(command) > self._policy.max_command_length:
            return ValidationResult(
                allowed=False,
                reason=f"Command exceeds maximum length ({self._policy.max_command_length})",
            )

        if self._active_commands >= self._policy.max_concurrent_commands:
            return ValidationResult(
                allowed=False,
                reason="Maximum concurrent commands reached",
            )

        # Check blocked commands
        for blocked in self._policy.blocked_commands:
            if blocked in command:
                return ValidationResult(
                    allowed=False,
                    reason=f"Command contains blocked string: {blocked}",
                )

        # Check blocked patterns
        for pattern in self._policy.blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return ValidationResult(
                    allowed=False,
                    reason=f"Command matches blocked pattern: {pattern}",
                )

        # Check for URL access to blocked hosts
        urls = re.findall(r'https?://[^\s"\']+', command)
        for url in urls:
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                for blocked_host in self._policy.blocked_hosts:
                    if host == blocked_host or host.endswith("." + blocked_host):
                        return ValidationResult(
                            allowed=False,
                            reason=f"URL accesses blocked host: {host}",
                        )
            except Exception:
                pass

        # Check sensitive paths
        for sensitive in self._policy.sensitive_paths:
            if sensitive in command:
                return ValidationResult(
                    allowed=False,
                    reason=f"Command accesses sensitive path: {sensitive}",
                )

        # Check scope
        if scope:
            scope_result = self._check_scope(command, scope)
            if not scope_result[0]:
                return ValidationResult(
                    allowed=False,
                    reason=scope_result[1],
                )

        # Generate warnings
        warnings = []
        if "sudo" in command:
            warnings.append("Command uses sudo")
        if any(x in command for x in ["/etc/passwd", "/etc/shadow"]):
            warnings.append("Command accesses system auth files")
        if "python" in command and "-c" in command:
            warnings.append("Command runs inline Python code")
        if "bash" in command and "-c" in command:
            warnings.append("Command runs inline bash code")

        return ValidationResult(
            allowed=True,
            sanitized_command=command.strip(),
            warnings=warnings,
        )

    def validate_script(self, script: str, scope: Optional[List[str]] = None) -> ValidationResult:
        """Validate a complete script."""
        # Split into individual commands and validate each
        commands = [c.strip() for c in script.split("\n") if c.strip() and not c.strip().startswith("#")]

        for cmd in commands:
            result = self.validate_command(cmd, scope)
            if not result.allowed:
                return result

        return ValidationResult(
            allowed=True,
            sanitized_command=script,
        )

    def _check_scope(self, command: str, scope: List[str]) -> Tuple[bool, str]:
        """Check if command targets are within scope."""
        # Extract hosts/domains from command
        hosts = set()

        # Check URLs
        urls = re.findall(r'https?://([^/\s"\']+)', command)
        for url in urls:
            host = url.split(":")[0].split("/")[0]
            hosts.add(host)

        # Check IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', command)
        for ip in ips:
            if not ip.startswith("127.") and ip != "0.0.0.0":
                hosts.add(ip)

        # Check domain names in common flags
        domain_flags = re.findall(r'(?:target|host|domain|url|site)\s*[=:]\s*[^\s]+', command)
        for flag in domain_flags:
            parts = flag.split("=")
            if len(parts) > 1:
                hosts.add(parts[1].strip().strip("'\""))

        # Also extract bare domain-like arguments (e.g., "nmap other.com")
        # Look for words that contain dots and look like domains
        words = command.split()
        for word in words:
            word = word.strip("'\"")
            if "." in word and not word.startswith("-"):
                # Looks like a domain
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', word):
                    hosts.add(word)

        if not hosts:
            return True, "No specific hosts found in command"

        for host in hosts:
            in_scope = False
            for scope_entry in scope:
                if scope_entry.startswith("*."):
                    base = scope_entry[2:]
                    if host == base or host.endswith("." + base):
                        in_scope = True
                        break
                elif host == scope_entry:
                    in_scope = True
                    break
                elif scope_entry.replace("*", "").replace(".", "") in host:
                    in_scope = True
                    break

            # Always allow localhost/private IPs for local operations
            if host in ("localhost", "127.0.0.1", "0.0.0.0") or host.startswith("192.168.") or host.startswith("10."):
                in_scope = True

            if not in_scope:
                return False, f"Host {host} is not in scope"

        return True, "All hosts are in scope"

    def acquire(self) -> bool:
        """Acquire a command slot."""
        if self._active_commands >= self._policy.max_concurrent_commands:
            return False
        self._active_commands += 1
        return True

    def release(self) -> None:
        """Release a command slot."""
        self._active_commands = max(0, self._active_commands - 1)
