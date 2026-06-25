"""
Nova-Arsenal CLI Entry Point

Usage:
    nova-agent --target <target> [options]
    nova-agent --target <target> --auto       # Full autonomous mode
"""

import argparse
import asyncio
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="nova-agent",
        description="Nova-Arsenal Autonomous Security Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nova-agent --target example.com
  nova-agent --target example.com --auto
  nova-agent --target example.com --objective "Find SQL injection"
  nova-agent --target example.com --scope example.com api.example.com
  nova-agent --config settings.yaml --target example.com
        """,
    )
    parser.add_argument("--target", required=True, help="Target to scan")
    parser.add_argument(
        "--objective",
        default="Find and exploit all critical vulnerabilities",
        help="Objective for the agent",
    )
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--max-steps", type=int, default=40, help="Maximum steps")
    parser.add_argument("--scope", nargs="+", help="Target scope")
    parser.add_argument("--auto", action="store_true", help="Run in fully autonomous mode")
    parser.add_argument("--sandbox", choices=["docker", "ssh", "local"], help="Sandbox mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", "-V", action="version", version="%(prog)s 1.0.0")

    args = parser.parse_args()

    # Add parent directory to path for module imports
    sys.path.insert(0, str(Path(__file__).parent.parent))

    try:
        from nova_agent_core import NovaAgent

        print(f"Nova-Arsenal Agent v1.0.0")
        print(f"=" * 50)
        print(f"Target: {args.target}")
        print(f"Objective: {args.objective}")
        print(f"Max Steps: {args.max_steps}")
        if args.scope:
            print(f"Scope: {', '.join(args.scope)}")
        if args.auto:
            print(f"Mode: FULLY AUTONOMOUS")
        print(f"=" * 50)

        agent = NovaAgent(
            target=args.target,
            objective=args.objective,
            max_steps=args.max_steps,
        )

        if args.auto:
            # Full autonomous mode
            async def run():
                async def print_event(event_type, data):
                    if event_type == "step_completed":
                        step = data.get("step", "?")
                        cmd = data.get("command", "")[:80]
                        print(f"  [Step {step}] {cmd}")
                    elif event_type == "finding_discovered":
                        title = data.get("title", "Unknown")
                        severity = data.get("severity", "?")
                        print(f"  [FINDING] {severity.upper()}: {title}")
                    elif event_type == "phase_changed":
                        phase = data.get("to", "?")
                        print(f"\n--- Phase: {phase.upper()} ---")
                    elif event_type == "agent_completed":
                        findings = data.get("findings", 0)
                        elapsed = data.get("elapsed_seconds", 0)
                        print(f"\n{'='*50}")
                        print(f"COMPLETED in {elapsed:.1f}s | Findings: {findings}")
                    elif event_type == "agent_error":
                        error = data.get("error", "?")
                        print(f"\n[ERROR] {error}")

                result = await agent.run_autonomous(
                    scope=args.scope,
                    on_event=print_event,
                    sandbox_mode=args.sandbox,
                )

                if args.verbose:
                    print(f"\nFull result:")
                    print(f"  Status: {result.get('status')}")
                    print(f"  Steps: {result.get('steps_taken', 0)}")
                    for f in result.get("findings", []):
                        print(f"  Finding: {f.get('title')} ({f.get('severity')})")

            asyncio.run(run())
        else:
            # Basic mode (backward compatible)
            try:
                from nova_tool_kit import NovaToolKit, PermissionProfile
                kit = NovaToolKit(
                    profile=PermissionProfile.SCOPED,
                    scope=args.scope or [args.target],
                )
                tools = kit.build()
                print(f"Loaded {len(tools)} tools")
            except ImportError:
                print("Note: nova_tool_kit not found, running without tool kit")

            print(f"\nAgent initialized.")
            print(f"Use --auto for fully autonomous mode")
            print(f"Or start the API server: python -m nova_arsenal.api")

    except ImportError as e:
        print(f"Error: Missing dependency - {e}")
        print("Run: pip install -e '.[dev]'")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
