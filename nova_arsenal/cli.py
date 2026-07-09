"""
Nova-Arsenal CLI Entry Point

Usage:
    nova-agent login --import-existing
    nova-agent login --provider anthropic --token <token>
    nova-agent login --provider gemini --oauth
    nova-agent accounts
    nova-agent llm-status
    nova-agent --target <target> [options]
    nova-agent --target <target> --auto
    nova-agent --target <target> --zeroday --authorized --auth-ref ENG-1
    nova-agent --target <target> --swarm --authorized
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path


def main() -> None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

    # Account / status commands don't need --target
    if len(sys.argv) > 1 and sys.argv[1] in {
        "login",
        "logout",
        "accounts",
        "llm-status",
        "help-login",
    }:
        _account_main(sys.argv[1:])
        return

    parser = argparse.ArgumentParser(
        prog="nova-agent",
        description="Nova-Arsenal Autonomous Security Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Account login (like Codex / Claude Code — no API key required if you have a subscription session)
  nova-agent login --import-existing
  nova-agent login --provider anthropic --token "$CLAUDE_CODE_OAUTH_TOKEN"
  nova-agent login --provider openai --token <codex-or-openai-token>
  nova-agent login --provider gemini --oauth
  nova-agent accounts
  nova-agent llm-status

  # Agent runs
  nova-agent --target example.com
  nova-agent --target example.com --auto
  nova-agent --target lab.local --zeroday --authorized --auth-ref ENG-42
  nova-agent --target lab.local --swarm --authorized --auth-ref ENG-42
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
        help="Run high-speed zero-day candidate pipeline",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm written authorization for the target",
    )
    parser.add_argument("--auth-ref", default="", help="Engagement / RoE / ticket ID")
    parser.add_argument("--services-json", default="", help="JSON service map for zeroday hunt")
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

    try:
        if args.config:
            from nova_arsenal.config import reload_config

            reload_config(args.config)

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
            from nova_arsenal.zeroday import ZeroDayHuntConfig, ZeroDayHunter

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
            for w in result.warnings:
                print(f"  [warn] {w}")
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

        print("Nova-Arsenal Agent v1.3.0")
        print("=" * 50)
        print(f"Target: {args.target}")
        print(f"Objective: {args.objective}")
        print(f"Max Steps: {args.max_steps}")
        if args.scope:
            print(f"Scope: {', '.join(args.scope)}")
        if args.auto:
            print("Mode: FULLY AUTONOMOUS")
        print("=" * 50)

        agent = NovaAgent(
            target=args.target,
            objective=args.objective,
            max_steps=args.max_steps,
        )

        if args.auto:

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
                        print(f"\n{'=' * 50}")
                        print(f"COMPLETED in {elapsed:.1f}s | Findings: {findings}")
                    elif event_type == "agent_error":
                        print(f"\n[ERROR] {data.get('error', '?')}")

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

            print("\nAgent initialized.")
            print("Use --auto for fully autonomous mode")
            print("Or start the API server: python -m nova_arsenal.api")
            print("Sign in with AI account: nova-agent login --import-existing")

    except ImportError as e:
        print(f"Error: Missing dependency - {e}")
        print("Run: pip install -e '.[dev]'")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if getattr(args, "verbose", False):
            import traceback

            traceback.print_exc()
        sys.exit(1)


def _account_main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="nova-agent",
        description="AI account login (Codex / Claude Code style)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_login = sub.add_parser("login", help="Sign in with AI account, ChatGPT OAuth, or local LLM")
    p_login.add_argument(
        "--provider",
        choices=[
            "openai",
            "anthropic",
            "gemini",
            "openrouter",
            "google",
            "ollama",
            "local",
        ],
        help="Provider: openai (ChatGPT/Codex), ollama/local (offline), etc.",
    )
    p_login.add_argument("--token", default="", help="Session / OAuth / API token to store")
    p_login.add_argument(
        "--oauth",
        action="store_true",
        help="Browser OAuth (openai=ChatGPT/Codex subscription; gemini=Google)",
    )
    p_login.add_argument(
        "--device-code",
        action="store_true",
        help="Use device-code flow for OpenAI Codex (headless/SSH)",
    )
    p_login.add_argument(
        "--import-existing",
        action="store_true",
        help="Import from local Claude Code / Codex / Cursor credentials",
    )
    p_login.add_argument("--url", default="", help="Local LLM base URL (Ollama / LM Studio)")
    p_login.add_argument("--model", default="", help="Model name for local LLM or preferred cloud model")
    p_login.add_argument("--label", default="", help="Friendly label for this account")

    p_logout = sub.add_parser("logout", help="Remove a stored AI account")
    p_logout.add_argument("--provider", required=True)

    sub.add_parser("accounts", help="List signed-in AI accounts (no secrets)")
    sub.add_parser("llm-status", help="Show LLM BYOK + account wiring status")
    sub.add_parser("help-login", help="Print account-login help")

    args = parser.parse_args(argv)

    from nova_arsenal.llm.account_auth import account_status, get_account_store
    from nova_arsenal.llm.router import get_llm_router, reset_llm_router

    if args.cmd == "help-login":
        print(json.dumps(account_status()["how_to"], indent=2))
        return

    if args.cmd == "accounts":
        print(json.dumps(account_status(), indent=2))
        return

    if args.cmd == "llm-status":
        reset_llm_router()
        print(json.dumps(get_llm_router().byok_status(), indent=2))
        return

    if args.cmd == "logout":
        ok = get_account_store().remove(args.provider.lower())
        reset_llm_router()
        print(json.dumps({"logged_out": ok, "provider": args.provider}))
        return

    if args.cmd == "login":
        store = get_account_store()
        if args.import_existing:
            results = store.import_from_tools()
            reset_llm_router()
            print(json.dumps({"imported": results, "accounts": [a.to_public_dict() for a in store.list_accounts()]}, indent=2))
            return

        provider = (args.provider or "").lower()
        if provider == "google":
            provider = "gemini"

        # Local LLM (Ollama / LM Studio) — no cloud account
        if provider in {"ollama", "local"} or (
            not provider and (args.url or args.model) and not args.token and not args.oauth
        ):
            kind = "ollama" if provider in {"ollama", ""} else "openai_compatible"
            print("Registering local LLM…")
            cred = store.login_local_llm(
                url=args.url,
                model=args.model,
                kind=kind,
                label=args.label,
            )
            reset_llm_router()
            print(json.dumps({"status": "ok", "account": cred.to_public_dict()}, indent=2))
            return

        if args.oauth:
            if provider in {"openai", "codex", "chatgpt", ""}:
                print("Starting ChatGPT / Codex OAuth (subscription)…")
                cred = store.login_openai_codex_oauth(
                    open_browser=True,
                    device_code=bool(args.device_code),
                )
                reset_llm_router()
                print(json.dumps({"status": "ok", "account": cred.to_public_dict()}, indent=2))
                return
            if provider in {"gemini", "google"}:
                print("Starting Google OAuth (browser)…")
                print("Ensure GOOGLE_OAUTH_CLIENT_ID is set.")
                cred = store.login_google_oauth(open_browser=True)
                reset_llm_router()
                print(json.dumps({"status": "ok", "account": cred.to_public_dict()}, indent=2))
                return
            print(
                "Error: --oauth supports: openai (ChatGPT/Codex), gemini (Google)",
                file=sys.stderr,
            )
            sys.exit(2)

        if not provider or not args.token:
            print(
                "Usage:\n"
                "  # ChatGPT Plus/Pro subscription (browser OAuth)\n"
                "  nova-agent login --provider openai --oauth\n"
                "  nova-agent login --provider openai --oauth --device-code\n"
                "  # Local LLM (Ollama)\n"
                "  nova-agent login --provider ollama\n"
                "  nova-agent login --provider ollama --model llama3.2\n"
                "  # Import Claude Code / Codex sessions\n"
                "  nova-agent login --import-existing\n"
                "  # Token paste\n"
                "  nova-agent login --provider anthropic --token <token>\n"
                "  nova-agent login --provider gemini --oauth\n",
                file=sys.stderr,
            )
            sys.exit(2)

        cred = store.login_with_token(
            provider,
            args.token,
            label=args.label or f"{provider} account",
            source="cli",
        )
        reset_llm_router()
        print(json.dumps({"status": "ok", "account": cred.to_public_dict()}, indent=2))
        return


if __name__ == "__main__":
    main()
