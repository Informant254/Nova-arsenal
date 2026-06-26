#!/usr/bin/env python3
"""
Nova-Arsenal Quick Test Script

Test Nova against a real target using direct Python API.
No FastAPI or API authentication required.

Usage:
    python test_nova.py <target> <objective>

Examples:
    python test_nova.py localhost:8080 "Identify vulnerabilities"
    python test_nova.py 192.168.1.100 "Full penetration test"
    python test_nova.py example.com "Find exposed services"
"""

import asyncio
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from nova_arsenal.agent_runner import AgentRunner
from nova_arsenal.kali_blueprint import KaliBlueprint
from nova_arsenal.sandbox_executor import SandboxExecutor


async def test_nova(target: str, objective: str, max_steps: int = 20):
    """Test Nova agent directly."""
    print(f"🎯 Target: {target}")
    print(f"🎯 Objective: {objective}")
    print(f"🎯 Max Steps: {max_steps}")
    print("\n" + "="*60)
    print("NOVA-ARSENAL TEST RUN")
    print("="*60 + "\n")
    
    # Initialize blueprint (loads all 230 tools)
    print("📂 Loading Kali Linux knowledge base...")
    blueprint = KaliBlueprint()
    print(f"   ✓ Loaded {len(blueprint.tools)} tools")
    print(f"   ✓ {len(blueprint.attack_chains)} attack chains")
    print(f"   ✓ {len(blueprint.nse_scripts)} NSE scripts")
    print()
    
    # Create agent runner
    print("🤖 Initializing Nova agent runner...")
    executor = SandboxExecutor(mode="local")
    runner = AgentRunner(
        target=target,
        objective=objective,
        max_steps=max_steps,
        executor=executor,
    )
    print("   ✓ Agent runner initialized")
    print()
    
    # Run agent
    print("🚀 Starting autonomous testing...")
    print("-"*60)
    
    result = await runner.run()
    
    print("-"*60)
    print("\n" + "="*60)
    print("TEST RESULTS")
    print("="*60)
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Steps taken: {result.get('steps_taken', 0)}")
    print(f"Findings: {len(result.get('findings', []))}")
    print(f"Duration: {result.get('elapsed_seconds', 0):.2f}s")
    print()
    
    if result.get("findings"):
        print("📊 Findings Summary:")
        for finding in result["findings"][:10]:  # Show first 10
            severity = finding.get("severity", "UNKNOWN")
            description = finding.get("description", "N/A")[:80]
            print(f"   [{severity}] {description}")
        if len(result["findings"]) > 10:
            print(f"   ... and {len(result['findings']) - 10} more")
    print()
    
    if result.get("report"):
        print("📝 Final Report:")
        print(result["report"][:1000] + "..." if len(result["report"]) > 1000 else result["report"])
    
    return result


async def main():
    if len(sys.argv) < 3:
        print("Usage: python test_nova.py <target> <objective> [max_steps]")
        print()
        print("Examples:")
        print("  python test_nova.py localhost:8080 'Find vulnerabilities'")
        print("  python test_nova.py 192.168.1.100 'Full audit'")
        print("  python test_nova.py example.com 'Web app test'")
        sys.exit(1)
    
    target = sys.argv[1]
    objective = sys.argv[2]
    max_steps = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    
    await test_nova(target, objective, max_steps)


if __name__ == "__main__":
    asyncio.run(main())
