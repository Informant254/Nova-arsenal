# Nova Arsenal — Module Index

> **Security research toolkit. All tools for authorized testing and academic research only.**
> Verify scope in `targets_scope_map.json` before any active testing.

---

## 🗂️ Module Structure

```
Nova-arsenal/
├── nova_arsenal.py              ← Main CLI entry point
├── targets_scope_map.json       ← Program scope validation map
├── targets_priority.txt         ← Bug bounty priority targets
├── targets.txt                  ← Full target list (Kong + others)
├── verify_ssrf_direct.py        ← SSRF quick verifier (original)
├── modules/
│   ├── recon/
│   │   ├── ssrf_scanner.py      ← Extended SSRF scanner (17 cloud endpoints)
│   │   └── scope_validator.py   ← Target scope validator
│   ├── cve_watch/
│   │   └── cve_monitor.py       ← Local CVE/PoC index search + SARIF export
│   ├── llm_jailbreak/
│   │   ├── cka_adapter.py       ← CKA-Agent trojan knowledge jailbreak
│   │   └── odysseus_adapter.py  ← Odysseus dual-steganography jailbreak
│   └── windows/
│       └── exploit_reference.py ← Indexed PoC reference (10 exploits)
```

---

## ⚡ Quick Start

```bash
# List all loaded modules
python nova_arsenal.py list-modules

# Run SSRF scan (cloud metadata probing)
python nova_arsenal.py ssrf --target https://target.example.com --verbose

# Validate a target against scope map
python nova_arsenal.py scope --target api.shopify.com --program shopify

# Search local exploit/CVE index
python nova_arsenal.py cve

# Full recon pipeline
python nova_arsenal.py recon --target admin.shopify.com --verbose

# LLM jailbreak (interactive)
python nova_arsenal.py jailbreak
```

---

## 🔧 Integrated Tool Reference

| Module | Source | Technique | Status |
|--------|--------|-----------|--------|
| `RoguePlanet` | MSNightmare | Defender TOCTOU → SYSTEM | ⚠️ Unpatched |
| `GreatXML` | MSNightmare | BitLocker/WinRE bypass | ⚠️ Unpatched |
| `ByePg` | can1357 | PatchGuard defeat (all Win10) | ⚡ Active |
| `herpaderping` | jxy-s | AV evasion via file replace | ⚡ Active |
| `KernelForge` | Cr4sh | Kernel payload post-HVCI | ⚡ Active |
| `Certify` | GhostPack | AD CS privilege escalation | ⚡ Active |
| `WubbabooMark` | hfiref0x | Anti-detection benchmark | 🔬 Research |
| `CKA-Agent` | Graph-COM | LLM trojan knowledge bypass | ⚡ Active (>90% ASR) |
| `Odysseus` | S3IC-Lab | Multimodal stego jailbreak | ⚡ Active (>85% ASR) |

---

## 📡 Live CVE Feed
The tracker API polls `@MSNightmare` every 5 minutes and auto-clones new repos.
Keyword alerts: `Defender`, `BitLocker`, `SYSTEM`, `LPE`, `TOCTOU`

---

## ⚖️ Legal
Only test systems you own or have explicit written authorization to test.
Check `targets_scope_map.json` before scanning any external host.
