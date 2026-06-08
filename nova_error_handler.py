"""
Nova Error Handler v1.0
========================
Comprehensive error handling and recovery.

Instead of crashing silently, Nova:
- Explains what went wrong clearly
- Suggests alternatives
- Recovers gracefully
- Logs everything
- Never leaves user confused

Error categories:
- Tool errors (tool not found, wrong flags)
- Network errors (timeout, no connection)
- LLM errors (API down, quota exceeded)
- Permission errors (not root, no access)
- Parse errors (unexpected output format)
- Memory errors (database issues)
"""

import logging
import traceback
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """How serious is this error"""
    INFO = "info"           # Minor, can continue
    WARNING = "warning"     # Something wrong but can continue
    ERROR = "error"         # Significant, needs attention
    CRITICAL = "critical"   # Cannot continue


class ErrorCategory(Enum):
    """What type of error"""
    TOOL_NOT_FOUND = "tool_not_found"
    TOOL_FAILED = "tool_failed"
    NETWORK_TIMEOUT = "network_timeout"
    NETWORK_UNREACHABLE = "network_unreachable"
    LLM_UNAVAILABLE = "llm_unavailable"
    LLM_QUOTA_EXCEEDED = "llm_quota_exceeded"
    PERMISSION_DENIED = "permission_denied"
    PARSE_ERROR = "parse_error"
    MEMORY_ERROR = "memory_error"
    AUTHENTICATION_ERROR = "auth_error"
    UNKNOWN = "unknown"


@dataclass
class NovaError:
    """Structured error with context"""
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    technical_detail: str = ""
    suggestion: str = ""
    alternative: str = ""
    timestamp: str = ""
    recoverable: bool = True
    context: Dict[str, Any] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if self.context is None:
            self.context = {}

    def to_user_message(self) -> str:
        """Format error as user-friendly message"""

        icon = {
            ErrorSeverity.INFO: "ℹ️",
            ErrorSeverity.WARNING: "⚠️",
            ErrorSeverity.ERROR: "❌",
            ErrorSeverity.CRITICAL: "🚨"
        }.get(self.severity, "❌")

        msg = f"{icon} {self.message}"

        if self.suggestion:
            msg += f"\n\n💡 {self.suggestion}"

        if self.alternative:
            msg += f"\n\n🔄 Alternative: {self.alternative}"

        return msg

    def to_log_message(self) -> str:
        """Format for logging"""
        return (
            f"[{self.category.value}] {self.severity.value.upper()}: "
            f"{self.message} | {self.technical_detail}"
        )


class NovaErrorHandler:
    """
    Handles all errors gracefully.

    Goal: Nova never crashes silently.
    Always explains what went wrong and what to do next.
    """

    def __init__(self, memory=None, notification_handler=None):
        """
        Initialize error handler.

        Args:
            memory: Nova memory system for storing errors
            notification_handler: For critical error alerts
        """
        self.memory = memory
        self.notifications = notification_handler
        self.error_history = []
        self.recovery_strategies = self._register_recovery_strategies()

    def _register_recovery_strategies(self) -> Dict[ErrorCategory, Callable]:
        """Register recovery strategy for each error type"""

        return {
            ErrorCategory.TOOL_NOT_FOUND: self._recover_tool_not_found,
            ErrorCategory.TOOL_FAILED: self._recover_tool_failed,
            ErrorCategory.NETWORK_TIMEOUT: self._recover_network_timeout,
            ErrorCategory.NETWORK_UNREACHABLE: self._recover_network_unreachable,
            ErrorCategory.LLM_UNAVAILABLE: self._recover_llm_unavailable,
            ErrorCategory.LLM_QUOTA_EXCEEDED: self._recover_llm_quota,
            ErrorCategory.PERMISSION_DENIED: self._recover_permission_denied,
            ErrorCategory.PARSE_ERROR: self._recover_parse_error,
            ErrorCategory.MEMORY_ERROR: self._recover_memory_error,
        }

    def handle(self, error: NovaError) -> str:
        """
        Handle an error.

        Args:
            error: NovaError to handle

        Returns:
            User-friendly response
        """

        # Log it
        logger.log(
            logging.ERROR if error.severity == ErrorSeverity.ERROR else logging.WARNING,
            error.to_log_message()
        )

        # Store in history
        self.error_history.append(error)

        # Try recovery
        if error.recoverable and error.category in self.recovery_strategies:
            recovery_message = self.recovery_strategies[error.category](error)
            if recovery_message:
                return recovery_message

        # Return user message
        return error.to_user_message()

    def wrap(self, func: Callable, *args, **kwargs) -> Any:
        """
        Wrap any function call with error handling.

        Usage:
            result = handler.wrap(nova.scan, target)
        """

        try:
            return func(*args, **kwargs)
        except FileNotFoundError as e:
            error = self._parse_tool_not_found(str(e))
            self.handle(error)
            return None
        except PermissionError as e:
            error = self._parse_permission_error(str(e))
            self.handle(error)
            return None
        except TimeoutError as e:
            error = self._parse_timeout_error(str(e))
            self.handle(error)
            return None
        except ConnectionError as e:
            error = self._parse_connection_error(str(e))
            self.handle(error)
            return None
        except Exception as e:
            error = self._parse_unknown_error(e)
            return self.handle(error)

    # ─────────────────────────────────────────
    # ERROR PARSERS
    # ─────────────────────────────────────────

    def tool_not_found(self, tool_name: str) -> NovaError:
        """Create tool not found error"""

        alternatives = self._get_tool_alternatives(tool_name)

        return NovaError(
            category=ErrorCategory.TOOL_NOT_FOUND,
            severity=ErrorSeverity.WARNING,
            message=f"Tool '{tool_name}' is not installed.",
            technical_detail=f"shutil.which('{tool_name}') returned None",
            suggestion=f"Install it with: apt install {tool_name}",
            alternative=f"Try: {alternatives}" if alternatives else "",
            recoverable=True,
            context={"tool": tool_name}
        )

    def tool_failed(self, tool_name: str, return_code: int, stderr: str) -> NovaError:
        """Create tool execution failed error"""

        suggestion = self._suggest_fix_for_tool_error(tool_name, stderr)

        return NovaError(
            category=ErrorCategory.TOOL_FAILED,
            severity=ErrorSeverity.ERROR,
            message=f"'{tool_name}' failed with error code {return_code}.",
            technical_detail=stderr[:200],
            suggestion=suggestion,
            recoverable=True,
            context={"tool": tool_name, "return_code": return_code}
        )

    def network_timeout(self, target: str, timeout: int) -> NovaError:
        """Create network timeout error"""

        return NovaError(
            category=ErrorCategory.NETWORK_TIMEOUT,
            severity=ErrorSeverity.WARNING,
            message=f"Connection to {target} timed out after {timeout}s.",
            technical_detail=f"Timeout: {timeout}s",
            suggestion="Check if the target is online. Try increasing timeout.",
            alternative="Try: ping target first to verify connectivity",
            recoverable=True,
            context={"target": target, "timeout": timeout}
        )

    def network_unreachable(self, target: str) -> NovaError:
        """Create network unreachable error"""

        return NovaError(
            category=ErrorCategory.NETWORK_UNREACHABLE,
            severity=ErrorSeverity.ERROR,
            message=f"Cannot reach {target}.",
            suggestion="Check your internet connection. Verify the target exists.",
            alternative="Try: curl -I " + target,
            recoverable=False,
            context={"target": target}
        )

    def llm_unavailable(self, provider: str) -> NovaError:
        """Create LLM unavailable error"""

        return NovaError(
            category=ErrorCategory.LLM_UNAVAILABLE,
            severity=ErrorSeverity.WARNING,
            message=f"AI model ({provider}) is not available.",
            suggestion="Check your API key or internet connection.",
            alternative="Nova will use local reasoning (less powerful but works offline)",
            recoverable=True,
            context={"provider": provider}
        )

    def llm_quota_exceeded(self, provider: str) -> NovaError:
        """Create quota exceeded error"""

        return NovaError(
            category=ErrorCategory.LLM_QUOTA_EXCEEDED,
            severity=ErrorSeverity.WARNING,
            message=f"API quota exceeded for {provider}.",
            suggestion="Wait for quota reset or switch to a different provider.",
            alternative="Nova will switch to local Ollama model",
            recoverable=True,
            context={"provider": provider}
        )

    def permission_denied(self, action: str) -> NovaError:
        """Create permission denied error"""

        return NovaError(
            category=ErrorCategory.PERMISSION_DENIED,
            severity=ErrorSeverity.ERROR,
            message=f"Permission denied: {action}",
            suggestion="Some tools require root. Try: sudo nova or run as root.",
            alternative="Check if you're running in the right environment",
            recoverable=True,
            context={"action": action}
        )

    def parse_error(self, tool: str, output: str) -> NovaError:
        """Create parse error"""

        return NovaError(
            category=ErrorCategory.PARSE_ERROR,
            severity=ErrorSeverity.INFO,
            message=f"Couldn't parse output from {tool}.",
            technical_detail=f"Output: {output[:100]}",
            suggestion="Nova will show you the raw output instead.",
            recoverable=True,
            context={"tool": tool}
        )

    # ─────────────────────────────────────────
    # RECOVERY STRATEGIES
    # ─────────────────────────────────────────

    def _recover_tool_not_found(self, error: NovaError) -> str:
        """Recovery: Tool not found"""

        tool = error.context.get("tool", "")
        alternatives = self._get_tool_alternatives(tool)

        msg = error.to_user_message()
        msg += f"\n\n🔧 To install: apt install {tool}"

        if alternatives:
            msg += f"\n📦 Or use instead: {alternatives}"

        return msg

    def _recover_tool_failed(self, error: NovaError) -> str:
        """Recovery: Tool failed"""

        return (
            f"{error.to_user_message()}\n\n"
            f"🔄 Nova will try an alternative approach."
        )

    def _recover_network_timeout(self, error: NovaError) -> str:
        """Recovery: Network timeout"""

        target = error.context.get("target", "")

        return (
            f"{error.to_user_message()}\n\n"
            f"🔄 Retrying with longer timeout...\n"
            f"💡 Also check: ping {target}"
        )

    def _recover_network_unreachable(self, error: NovaError) -> str:
        """Recovery: Network unreachable"""

        return (
            f"{error.to_user_message()}\n\n"
            f"📡 Check your connection and try again."
        )

    def _recover_llm_unavailable(self, error: NovaError) -> str:
        """Recovery: LLM unavailable - switch to fallback"""

        provider = error.context.get("provider", "")

        return (
            f"⚠️ {provider} is unavailable.\n"
            f"🔄 Switching to local Ollama model...\n"
            f"💡 Performance may be reduced but Nova will continue."
        )

    def _recover_llm_quota(self, error: NovaError) -> str:
        """Recovery: Quota exceeded"""

        return (
            f"⚠️ API quota exceeded.\n"
            f"🔄 Switching to Ollama (local model)...\n"
            f"💡 Nova will continue with local reasoning."
        )

    def _recover_permission_denied(self, error: NovaError) -> str:
        """Recovery: Permission denied"""

        return (
            f"{error.to_user_message()}\n\n"
            f"🔑 Try running Nova with elevated permissions."
        )

    def _recover_parse_error(self, error: NovaError) -> str:
        """Recovery: Parse error - show raw output"""

        return (
            f"ℹ️ Couldn't parse structured output.\n"
            f"📄 Showing raw output instead.\n"
            f"Nova will continue analyzing."
        )

    def _recover_memory_error(self, error: NovaError) -> str:
        """Recovery: Memory error"""

        return (
            f"⚠️ Memory system issue.\n"
            f"🔄 Nova will continue without saving this session.\n"
            f"💡 Check disk space: df -h"
        )

    # ─────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────

    def _get_tool_alternatives(self, tool: str) -> str:
        """Suggest alternative tools"""

        alternatives = {
            "nmap": "masscan",
            "masscan": "nmap",
            "nikto": "whatweb, wfuzz",
            "sqlmap": "manual testing",
            "hydra": "medusa",
            "john": "hashcat",
            "hashcat": "john",
            "gobuster": "ffuf, dirb, wfuzz",
            "ffuf": "gobuster, dirb",
            "dirb": "gobuster, ffuf",
            "wireshark": "tcpdump",
            "tcpdump": "wireshark",
            "netcat": "socat",
            "socat": "netcat"
        }

        return alternatives.get(tool, "")

    def _suggest_fix_for_tool_error(self, tool: str, stderr: str) -> str:
        """Suggest fix based on tool error"""

        stderr_lower = stderr.lower()

        if "permission denied" in stderr_lower:
            return f"Run with sudo: sudo {tool}"
        elif "connection refused" in stderr_lower:
            return "Target is not accepting connections on that port"
        elif "no route to host" in stderr_lower:
            return "Target is unreachable. Check network connectivity"
        elif "invalid option" in stderr_lower:
            return f"Wrong flags used. Check: man {tool}"
        elif "not found" in stderr_lower:
            return f"Install first: apt install {tool}"

        return f"Check the command syntax: man {tool}"

    def _parse_tool_not_found(self, error_str: str) -> NovaError:
        """Parse FileNotFoundError"""

        tool = error_str.split("'")[1] if "'" in error_str else "unknown"
        return self.tool_not_found(tool)

    def _parse_permission_error(self, error_str: str) -> NovaError:
        """Parse PermissionError"""
        return self.permission_denied(error_str)

    def _parse_timeout_error(self, error_str: str) -> NovaError:
        """Parse TimeoutError"""
        return self.network_timeout("target", 30)

    def _parse_connection_error(self, error_str: str) -> NovaError:
        """Parse ConnectionError"""
        return self.network_unreachable("target")

    def _parse_unknown_error(self, exception: Exception) -> NovaError:
        """Parse unknown exception"""

        return NovaError(
            category=ErrorCategory.UNKNOWN,
            severity=ErrorSeverity.ERROR,
            message=f"Unexpected error: {str(exception)[:100]}",
            technical_detail=traceback.format_exc()[:300],
            suggestion="This is unexpected. Please report this to the Nova team.",
            recoverable=False
        )

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of all errors in this session"""

        by_category = {}
        by_severity = {}

        for error in self.error_history:
            cat = error.category.value
            sev = error.severity.value

            by_category[cat] = by_category.get(cat, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total_errors": len(self.error_history),
            "by_category": by_category,
            "by_severity": by_severity,
            "recoverable": sum(1 for e in self.error_history if e.recoverable),
            "unrecoverable": sum(1 for e in self.error_history if not e.recoverable)
        }


# ─────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────

if __name__ == "__main__":
    handler = NovaErrorHandler()

    print("\n=== NOVA ERROR HANDLER ===\n")

    # Tool not found
    error = handler.tool_not_found("gobuster")
    print(handler.handle(error))
    print()

    # Network timeout
    error = handler.network_timeout("target.com", 30)
    print(handler.handle(error))
    print()

    # LLM unavailable
    error = handler.llm_unavailable("Claude")
    print(handler.handle(error))
    print()

    # Permission denied
    error = handler.permission_denied("run nmap SYN scan")
    print(handler.handle(error))
    print()

    # Summary
    summary = handler.get_error_summary()
    print(f"\nError Summary: {summary}")
