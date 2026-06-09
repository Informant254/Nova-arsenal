"""
Nova CLI v1.0
=============
Command line interface for Nova.

Usage:
    nova chat                         Start conversational mode
    nova scan target.com              Quick scan
    nova sessions list                List all sessions
    nova sessions resume <id>         Resume session
    nova memory show target.com       Show target memory
    nova report --session <id>        Generate report
    nova config setup                 Run setup wizard
    nova config show                  Show configuration
    nova status                       System status

Nova is smart enough to understand natural commands too:
    nova "scan target.com for SQLi"
    nova "what do you know about target.com"
    nova "generate report for last session"
"""

import os
import sys
import logging
import argparse
from typing import Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

NOVA_VERSION = "1.0.0"
NOVA_BANNER = f"""
 ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
 ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║███████║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
 
 Security Intelligence Platform v{NOVA_VERSION}
 github.com/Informant254/Nova-arsenal
 ─────────────────────────────────────
"""


class NovaCLI:
    """
    Nova command line interface.
    Entry point for all Nova interactions.
    """

    def __init__(self):
        """Initialize CLI"""

        self.config = None
        self.memory = None
        self.session_manager = None
        self.conversational_agent = None

        self._initialize_components()

    def _initialize_components(self):
        """Initialize Nova components"""

        try:
            from nova_config_manager import NovaConfig
            self.config = NovaConfig()
        except ImportError:
            logger.warning("Config manager not available")

        try:
            from nova_memory import NovaMemory
            db_path = "~/.nova/memory.db"
            if self.config:
                db_path = self.config.get("memory.db_path", db_path)
            self.memory = NovaMemory(os.path.expanduser(db_path))
        except ImportError:
            logger.warning("Memory system not available")

        try:
            from nova_session_manager import NovaSessionManager
            session_dir = "~/.nova/sessions"
            if self.config:
                session_dir = self.config.get("sessions.dir", session_dir)
            self.session_manager = NovaSessionManager(os.path.expanduser(session_dir))
        except ImportError:
            logger.warning("Session manager not available")

    def run(self, args: Optional[List[str]] = None):
        """
        Main entry point.

        Args:
            args: Command line arguments (defaults to sys.argv)
        """

        parser = self._build_parser()

        # If no args, show banner and start chat
        if not args and len(sys.argv) == 1:
            self._print_banner()
            self._start_chat()
            return

        parsed = parser.parse_args(args)

        if hasattr(parsed, "func"):
            parsed.func(parsed)
        else:
            # Try to interpret as natural language
            if args:
                natural_input = " ".join(args)
                self._handle_natural_input(natural_input)
            else:
                parser.print_help()

    def _build_parser(self) -> argparse.ArgumentParser:
        """Build argument parser"""

        parser = argparse.ArgumentParser(
            prog="nova",
            description="Nova Security Intelligence Platform",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  nova chat                        Start interactive chat
  nova scan target.com             Quick reconnaissance scan
  nova sessions list               Show all sessions
  nova memory show target.com      What Nova knows about target
  nova report --session abc123     Generate report
  nova config setup                First-time setup
  nova status                      Check system status
  nova "scan target.com for SQLi"  Natural language command
            """
        )

        parser.add_argument(
            "--version", "-v",
            action="version",
            version=f"Nova {NOVA_VERSION}"
        )

        parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug output"
        )

        subparsers = parser.add_subparsers(title="commands")

        # ─── CHAT ───
        chat_parser = subparsers.add_parser(
            "chat",
            help="Start interactive conversation with Nova"
        )
        chat_parser.set_defaults(func=self._cmd_chat)

        # ─── SCAN ───
        scan_parser = subparsers.add_parser(
            "scan",
            help="Scan a target"
        )
        scan_parser.add_argument("target", help="Target to scan")
        scan_parser.add_argument(
            "--risk", "-r",
            choices=["low", "medium", "high"],
            default="medium",
            help="Risk level (default: medium)"
        )
        scan_parser.add_argument(
            "--scope", "-s",
            help="Scope of scan"
        )
        scan_parser.set_defaults(func=self._cmd_scan)

        # ─── SESSIONS ───
        sessions_parser = subparsers.add_parser(
            "sessions",
            help="Manage sessions"
        )
        sessions_sub = sessions_parser.add_subparsers()

        sessions_list = sessions_sub.add_parser("list", help="List sessions")
        sessions_list.add_argument("--target", help="Filter by target")
        sessions_list.set_defaults(func=self._cmd_sessions_list)

        sessions_resume = sessions_sub.add_parser("resume", help="Resume session")
        sessions_resume.add_argument("session_id", help="Session ID to resume")
        sessions_resume.set_defaults(func=self._cmd_sessions_resume)

        sessions_show = sessions_sub.add_parser("show", help="Show session details")
        sessions_show.add_argument("session_id", help="Session ID")
        sessions_show.set_defaults(func=self._cmd_sessions_show)

        # ─── MEMORY ───
        memory_parser = subparsers.add_parser(
            "memory",
            help="Access Nova's memory"
        )
        memory_sub = memory_parser.add_subparsers()

        memory_show = memory_sub.add_parser("show", help="Show target memory")
        memory_show.add_argument("target", help="Target to show")
        memory_show.set_defaults(func=self._cmd_memory_show)

        memory_list = memory_sub.add_parser("list", help="List all targets")
        memory_list.set_defaults(func=self._cmd_memory_list)

        memory_stats = memory_sub.add_parser("stats", help="Memory statistics")
        memory_stats.set_defaults(func=self._cmd_memory_stats)

        # ─── REPORT ───
        report_parser = subparsers.add_parser(
            "report",
            help="Generate report"
        )
        report_parser.add_argument(
            "--session", "-s",
            help="Session ID"
        )
        report_parser.add_argument(
            "--format", "-f",
            choices=["html", "markdown", "json"],
            default="html",
            help="Report format (default: html)"
        )
        report_parser.add_argument(
            "--output", "-o",
            help="Output file path"
        )
        report_parser.set_defaults(func=self._cmd_report)

        # ─── CONFIG ───
        config_parser = subparsers.add_parser(
            "config",
            help="Manage configuration"
        )
        config_sub = config_parser.add_subparsers()

        config_setup = config_sub.add_parser("setup", help="Run setup wizard")
        config_setup.set_defaults(func=self._cmd_config_setup)

        config_show = config_sub.add_parser("show", help="Show configuration")
        config_show.add_argument("--section", help="Config section to show")
        config_show.set_defaults(func=self._cmd_config_show)

        config_set = config_sub.add_parser("set", help="Set config value")
        config_set.add_argument("key", help="Config key (e.g. llm.primary)")
        config_set.add_argument("value", help="Value to set")
        config_set.set_defaults(func=self._cmd_config_set)

        # ─── STATUS ───
        status_parser = subparsers.add_parser(
            "status",
            help="Show Nova system status"
        )
        status_parser.set_defaults(func=self._cmd_status)

        return parser

    # ─────────────────────────────────────────
    # COMMANDS
    # ─────────────────────────────────────────

    def _cmd_chat(self, args):
        """Start interactive chat"""
        self._print_banner()
        self._start_chat()

    def _cmd_scan(self, args):
        """Quick scan command"""

        print(f"\n[Nova] Starting scan: {args.target}")
        print(f"[Nova] Risk level: {args.risk}")

        if self.session_manager:
            session = self.session_manager.new_session(
                target=args.target,
                scope=args.scope or "",
                risk_level=args.risk
            )
            print(f"[Nova] Session: {session.session_id}")

        if self.memory:
            knowledge = self.memory.what_do_i_know_about(args.target)
            if knowledge.get("known"):
                print(f"\n[Nova] I've seen this target before:")
                print(f"  {knowledge['summary']}")

        print(f"\n[Nova] Use 'nova chat' for full interaction with {args.target}")

    def _cmd_sessions_list(self, args):
        """List sessions"""

        if not self.session_manager:
            print("[Nova] Session manager not available")
            return

        sessions = self.session_manager.list_sessions(
            target=getattr(args, "target", None)
        )

        if not sessions:
            print("[Nova] No sessions found")
            return

        print(f"\n[Nova] Found {len(sessions)} session(s):\n")
        self.session_manager.print_session_list(sessions)

    def _cmd_sessions_resume(self, args):
        """Resume a session"""

        if not self.session_manager:
            print("[Nova] Session manager not available")
            return

        session = self.session_manager.resume_session(args.session_id)

        if session:
            print(f"\n[Nova] Resuming session {args.session_id}")
            print("[Nova] Starting chat mode...\n")
            self._start_chat(session=session)

    def _cmd_sessions_show(self, args):
        """Show session details"""

        if not self.session_manager:
            print("[Nova] Session manager not available")
            return

        sessions = self.session_manager.list_sessions()
        session = next((s for s in sessions if s.session_id == args.session_id), None)

        if session:
            self.session_manager.print_session_detail(session)
        else:
            print(f"[Nova] Session {args.session_id} not found")

    def _cmd_memory_show(self, args):
        """Show target memory"""

        if not self.memory:
            print("[Nova] Memory system not available")
            return

        knowledge = self.memory.what_do_i_know_about(args.target)

        if not knowledge.get("known"):
            print(f"\n[Nova] I haven't tested {args.target} before.")
            return

        print(f"\n[Nova] What I know about {args.target}:\n")
        print(f"  First seen:     {knowledge['first_seen'][:10]}")
        print(f"  Last seen:      {knowledge['last_seen'][:10]}")
        print(f"  Total scans:    {knowledge['total_scans']}")
        print(f"  Total findings: {knowledge['total_findings']}")
        print(f"  Open findings:  {knowledge['open_findings']}")
        print(f"  Critical:       {knowledge['critical_findings']}")

        if knowledge.get("summary"):
            print(f"\n  Summary: {knowledge['summary']}")

        # Show findings
        findings = self.memory.get_findings_for_target(args.target)
        if findings:
            print(f"\n  Recent findings:")
            for f in findings[:5]:
                status = "✓" if f.status == "fixed" else "●"
                print(f"  {status} [{f.severity}] {f.title}")

    def _cmd_memory_list(self, args):
        """List all targets in memory"""

        if not self.memory:
            print("[Nova] Memory system not available")
            return

        targets = self.memory.get_all_targets()

        if not targets:
            print("[Nova] No targets in memory yet")
            return

        print(f"\n[Nova] Remembered targets ({len(targets)}):\n")
        print(f"{'TARGET':<30} {'SCANS':<8} {'FINDINGS':<10} {'LAST SEEN'}")
        print("─" * 65)

        for t in targets:
            print(
                f"{t.target[:29]:<30} "
                f"{t.total_scans:<8} "
                f"{t.findings_count:<10} "
                f"{t.last_seen[:10]}"
            )

        print()

    def _cmd_memory_stats(self, args):
        """Show memory statistics"""

        if not self.memory:
            print("[Nova] Memory system not available")
            return

        stats = self.memory.get_stats()
        print("\n[Nova] Memory Statistics:\n")
        for k, v in stats.items():
            print(f"  {k}: {v}")
        print()

    def _cmd_report(self, args):
        """Generate report"""

        print(f"\n[Nova] Generating {args.format} report...")

        if args.session:
            print(f"[Nova] Session: {args.session}")

        output = args.output or f"nova_report_{datetime.now().strftime('%Y%m%d_%H%M')}.{args.format}"
        print(f"[Nova] Output: {output}")
        print("[Nova] Report generation requires nova_report_generator.py")

    def _cmd_config_setup(self, args):
        """Run setup wizard"""

        if self.config:
            self.config.setup_wizard()
        else:
            print("[Nova] Config manager not available")

    def _cmd_config_show(self, args):
        """Show configuration"""

        if self.config:
            self.config.show(getattr(args, "section", None))
        else:
            print("[Nova] Config manager not available")

    def _cmd_config_set(self, args):
        """Set config value"""

        if self.config:
            self.config.set(args.key, args.value, save=True)
            print(f"[Nova] Set {args.key} = {args.value}")
        else:
            print("[Nova] Config manager not available")

    def _cmd_status(self, args):
        """Show system status"""

        print("\n[Nova] System Status\n")
        print("─" * 40)

        # Config
        config_status = "✓" if self.config else "✗"
        print(f"{config_status} Config Manager")

        # Memory
        memory_status = "✓" if self.memory else "✗"
        print(f"{memory_status} Memory System")

        # Sessions
        session_status = "✓" if self.session_manager else "✗"
        print(f"{session_status} Session Manager")

        # LLM
        if self.config:
            primary_llm = self.config.get("llm.primary", "unknown")
            print(f"  LLM: {primary_llm}")

        # Memory stats
        if self.memory:
            stats = self.memory.get_stats()
            print(f"\n Memory:")
            print(f"   Targets: {stats['targets_remembered']}")
            print(f"   Findings: {stats['total_findings']}")
            print(f"   Sessions: {stats['total_sessions']}")

        print("─" * 40)
        print(f"\n  Nova v{NOVA_VERSION} — Ready\n")

    # ─────────────────────────────────────────
    # CHAT MODE
    # ─────────────────────────────────────────

    def _start_chat(self, session=None):
        """Start interactive chat mode"""

        print("Nova is ready. Type your request or 'exit' to quit.\n")
        print("Examples:")
        print("  scan target.com")
        print("  what do you know about target.com")
        print("  show my sessions")
        print("  help\n")

        while True:
            try:
                user_input = input("You: ").strip()

                if not user_input:
                    continue

                if user_input.lower() in ["exit", "quit", "bye"]:
                    print("\nNova: Goodbye. Stay sharp. 🦅\n")
                    break

                if user_input.lower() == "help":
                    self._show_chat_help()
                    continue

                # Handle input
                response = self._handle_chat_input(user_input, session)
                print(f"\nNova: {response}\n")

            except KeyboardInterrupt:
                print("\n\nNova: Session interrupted. Goodbye. 🦅\n")
                break
            except EOFError:
                break

    def _handle_chat_input(self, user_input: str, session=None) -> str:
        """Handle chat input"""

        input_lower = user_input.lower()

        # Quick commands
        if "sessions" in input_lower or "session list" in input_lower:
            if self.session_manager:
                sessions = self.session_manager.get_recent_sessions()
                if sessions:
                    lines = [f"Your recent sessions:"]
                    for s in sessions[:5]:
                        lines.append(f"  {s.session_id} | {s.target} | {s.status.value}")
                    return "\n".join(lines)
            return "No sessions found."

        elif "know about" in input_lower or "remember" in input_lower:
            # Extract target
            import re
            target_match = re.search(r'(?:about|remember)\s+(\S+)', input_lower)
            if target_match and self.memory:
                target = target_match.group(1)
                knowledge = self.memory.what_do_i_know_about(target)
                if knowledge.get("known"):
                    return knowledge["summary"]
                return f"I haven't tested {target} before."
            return "Which target do you want to know about?"

        elif "status" in input_lower:
            self._cmd_status(None)
            return ""

        elif "scan" in input_lower:
            import re
            target_match = re.search(r'scan\s+(\S+)', input_lower)
            if target_match:
                target = target_match.group(1)
                return (
                    f"I'll plan a scan for {target}.\n"
                    f"Use: nova scan {target}\n"
                    f"Or tell me more about what you want to find."
                )
            return "What target do you want to scan?"

        else:
            # Try conversational agent if available
            try:
                from nova_conversational_agent import NovaConversationalAgent
                # Would use conversational agent here
                pass
            except ImportError:
                pass

            return (
                f"I understand you want to: {user_input}\n"
                f"Tell me the target and I'll help you plan the assessment."
            )

    def _handle_natural_input(self, text: str):
        """Handle natural language command"""

        print(f"\n[Nova] Processing: {text}")

        text_lower = text.lower()

        if "scan" in text_lower:
            import re
            target = re.search(r'scan\s+(\S+)', text_lower)
            if target:
                print(f"[Nova] Scanning {target.group(1)}...")
                print(f"[Nova] Use: nova scan {target.group(1)}")
                return

        print("[Nova] Use 'nova chat' for natural conversation")
        print("[Nova] Or use: nova --help")

    def _show_chat_help(self):
        """Show help in chat mode"""

        print("""
Nova commands:
  scan <target>         Scan a target
  sessions              Show recent sessions
  memory <target>       What I know about a target
  status                System status
  exit                  Exit Nova
  help                  Show this help
        """)

    def _print_banner(self):
        """Print Nova banner"""
        print(NOVA_BANNER)


# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────

def main():
    """Main entry point"""

    cli = NovaCLI()

    if len(sys.argv) > 1:
        cli.run(sys.argv[1:])
    else:
        cli.run()


if __name__ == "__main__":
    main()
