"""
Nova Arsenal Modules
"""

MODULES = {
    "ssrf_scanner":     "modules.recon.ssrf_scanner      - Cloud metadata SSRF verifier (AWS/GCP/Azure/K8s)",
    "scope_validator":  "modules.recon.scope_validator   - Validates targets against program scope maps",
    "cve_monitor":      "modules.cve_watch.cve_monitor   - Local CVE/PoC index search (windows-kernel-exploits)",
    "cka_adapter":      "modules.llm_jailbreak.cka_adapter - CKA-Agent trojan knowledge jailbreak runner",
    "odysseus_adapter": "modules.llm_jailbreak.odysseus_adapter - Odysseus dual-steganography jailbreak",
    "exploit_ref":      "modules.windows.exploit_reference - Reference index for cloned Windows exploit PoCs",
}

def list_modules():
    print("\n[*] Loaded Arsenal Modules:\n")
    for name, desc in MODULES.items():
        print(f"  • {desc}")
    print()
