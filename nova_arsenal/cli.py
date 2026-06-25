"""
Nova-Arsenal CLI Entry Point

Usage:
    nova-agent --target <target> [options]
"""

import argparse
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
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Add parent directory to path for module imports
    sys.path.insert(0, str(Path(__file__).parent.parent))

    try:
        from nova_agent_core import NovaAgent
        from nova_tool_kit import NovaToolKit, PermissionProfile

        print(f"Nova-Arsenal Agent v{__version__}")
        print(f"=" * 50)
        print(f"Target: {args.target}")
        print(f"Objective: {args.objective}")
        print(f"Max Steps: {args.max_steps}")
        if args.scope:
            print(f"Scope: {', '.join(args.scope)}")
        print(f"=" * 50)

        # Initialize tool kit
        kit = NovaToolKit(
            profile=PermissionProfile.SCOPED,
            scope=args.scope or [args.target],
        )
        tools = kit.build()
        print(f"Loaded {len(tools)} tools")

        # Initialize and run agent
        agent = NovaAgent(
            target=args.target,
            objective=args.objective,
            max_steps=args.max_steps,
        )

        print(f"\nAgent initialized. Starting hunt...")
        # Note: Actual execution requires LLM connection
        print(f"To run with Docker: docker compose up -d")
        print(f"For web UI: cd clients/web && npm run dev")

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
