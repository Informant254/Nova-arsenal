#!/usr/bin/env python3
from nova_swarm_parallel import *

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║   🦅  NOVA 10-AGENT PARALLEL SWARM DEPLOYMENT  🦅         ║
║   Recon|Exploit|Auth|Code|Race|Config|XSS|IDOR|Exfil|Val   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    kg = ConcurrentKnowledgeGraph()
    base_url = "http://localhost:3000"
    
    agents = [
        ReconAgent(kg, base_url),
        ExploitAgent(kg, base_url),
        AuthAgent(kg, base_url),
        CodeAgent(kg, base_url),
        RaceAgent(kg, base_url),
        ConfigAgent(kg, base_url),
        XSSAgent(kg, base_url),
        IDORAgent(kg, base_url),
        ExfilAgent(kg, base_url),
        ValidateAgent(kg, base_url),
    ]
    
    for agent in agents:
        agent.start()
        print(f"  🚀 {agent.name} launched")
    
    print(f"\n  ⏱️  All 10 agents running in parallel...\n")
    
    # Wait for all to complete
    for agent in agents:
        agent.join(timeout=60)
    
    print("\n  🛑 Swarm shutdown complete.")
