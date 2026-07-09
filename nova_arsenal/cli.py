"""
Nova-Arsenal CLI Entry Point

Usage:
    nova-agent --target <target> [options]
    nova-agent --target <target> --auto       # Full autonomous mode
    nova-agent --target <target> --zeroday --authorized --auth-ref ENG-1
"""

import argparse
import asyncio
import json
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
  nova-agent --target lab.local --zeroday --authorized --auth-ref ENG-42
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
    parser.add_argument(
        "--zeroday",
        action="store_true",
        help="Run high-speed zero-day candidate pipeline (research leads, not confirmed 0-days)",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm written authorization for the target (required for --zeroday)",
    )
    parser.add_argument(
        "--auth-ref",
        default="",
        help="Engagement / RoE / ticket ID for audit trail",
    )
    parser.add_argument(
        "--services-json",
        default="",
        help="Optional JSON service map for zeroday hunt",
    )
    parser.add_argument(
        "--live-fuzz",
        action="store_true",
        help="Execute live fuzz engines when installed (requires --authorized)",
    )
    parser.add_argument(
        "--swarm",
        action="store_true",
        help="Run multi-agent swarm (recon → zeroday researcher → deep scan)",
    )
    parser.add_argument("--sandbox", choices=["docker", "ssh", "local"], help="Sandbox mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", "-V", action="version", version="%(prog)s 1.3.0")

    args = parser.parse_args()

    # Add parent directory to path for module imports
    sys.path.insert(0, str(Path(__file__).parent.parent))

    try:
        if args.swarm:
            from nova_arsenal.swarm import SwarmOrchestrator

            print("Nova-Arsenal Swarm v1.3.0 (recon → zeroday → deep scan)")
            print("=" * 50)
            print(f"Target: {args.target}")
            print(f"Authorized: {args.authorized}")
            print(f"Live fuzz: {bool(args.live_fuzz and args.authorized)}")
            print("=" * 50)

            swarm = SwarmOrchestrator(
                target=args.target,
                enable_zeroday=True,
                zeroday_authorized=bool(args.authorized),
                zeroday_auth_ref=args.auth_ref or f"cli-swarm:{args.target}",
                execute_live_fuzz=bool(args.live_fuzz and args.authorized),
                dry_run_fuzz=not bool(args.live_fuzz and args.authorized),
            )
            result = asyncio.run(swarm.run_swarm())
            print(f"\n{result.summary}")
            print(f"Phases: {result.phases}")
            print(f"Findings: {len(result.findings)} | Consensus: {len(result.consensus_findings)}")
            if result.zeroday_hunt:
                print(
                    f"Zero-day candidates: {result.zeroday_hunt.get('candidate_count', 0)} "
                    f"in {result.zeroday_hunt.get('elapsed_ms', 0):.0f}ms"
                )
            for f in result.consensus_findings[:15]:
                print(f"  [{f.severity}] ({f.agent_role.value}) {f.title}")
            if args.verbose:
                print(json.dumps(result.to_dict(), indent=2)[:10000])
            return

        if args.zeroday:
            from nova_arsenal.zeroday import ZeroDayHunter, ZeroDayHuntConfig

            services = {}
            if args.services_json:
                services = json.loads(args.services_json)

            print("Nova-Arsenal Zero-Day Candidate Pipeline v1.3.0")
            print("=" * 50)
            print(f"Target: {args.target}")
            print(f"Authorized: {args.authorized}")
            print(f"Auth ref: {args.auth_ref or '(none)'}")
            print(f"Live fuzz: {bool(args.live_fuzz and args.authorized)}")
            print("=" * 50)
            print(
                "NOTE: This finds ranked *candidates* fast. "
                "Confirmed zero-days still need human validation."
            )

            hunter = ZeroDayHunter()
            live = bool(args.live_fuzz and args.authorized)

            async def run_zeroday():
                return await hunter.hunt(
                    target=args.target,
                    services=services,
                    config=ZeroDayHuntConfig(
                        authorized=bool(args.authorized),
                        authorization_ref=args.auth_ref,
                        execute_fuzz=live,
                        dry_run_fuzz=not live,
                        live_fuzz=True,
                    ),
                )

            result = asyncio.run(run_zeroday())
            print(f"\nStatus: {result.status}")
            print(f"Elapsed: {result.elapsed_ms:.1f}ms")
            if result.warnings:
                for w in result.warnings:
                    print(f"  [warn] {w}")
            if result.fuzz_campaign:
                print(f"Fuzz jobs planned: {result.fuzz_campaign.get('job_count', 0)}")
                exec_meta = result.fuzz_campaign.get("execution") or []
                live_meta = next(
                    (x for x in exec_meta if isinstance(x, dict) and x.get("_meta") == "live_campaign"),
                    None,
                )
                if live_meta:
                    print(
                        f"Live engines: ran={live_meta.get('ran_count')} "
                        f"skipped={live_meta.get('skipped_count')} "
                        f"crashes={live_meta.get('crash_count')}"
                    )
            print(f"Candidates: {len(result.candidates)}")
            for c in result.candidates[:20]:
                print(
                    f"  [{c.severity.upper()}] novelty={c.novelty:.2f} "
                    f"conf={c.confidence:.2f} ({c.source_stage}) {c.title}"
                )
            if args.verbose:
                print(json.dumps(result.to_dict(), indent=2)[:8000])
            if result.status == "blocked_unauthorized":
                sys.exit(2)
            return

        from nova_agent_core import NovaAgent

        print(f"Nova-Arsenal Agent v1.3.0")
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
