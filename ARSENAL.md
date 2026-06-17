# Nova Arsenal — Module Index

> **Security research toolkit. All tools for authorized testing and academic research only.**
> Verify scope in `targets_scope_map.json` before any active testing.

---

## 🗂️ Module Structure

```
Nova-arsenal/
├── nova.py                      ← Main autonomous agent (orchestrator)
├── nova_arsenal.py              ← CLI entry point (subcommands)
├── nova_core.py                 ← Unified core v3.0 (9 phases + RAG + swarm)
│
├── ── PROVIDER LAYER (loaded once, shared by all phases) ──────────────
├── nova_llm_router.py           ← LLM abstraction (OpenAI/Anthropic/Gemini/Ollama)
├── nova_hooks.py                ← Hook bus (PreRun/PostRun/FindingAdded)
├── nova_sessions.py             ← Session persistence
├── nova_observability.py        ← Tracer / spans
├── nova_memory_system.py        ← Cross-session brain
├── nova_notifications.py        ← Telegram/email/webhook alerts per finding
├── nova_findings_db.py          ← SQLite findings store
├── nova_weapon_forge.py         ← Exploit writer + CVE lookup
├── nova_auto_exploit_loop.py    ← Autonomous exploitation pipeline
├── nova_truth_engine.py         ← Zero false-positive gate (95% confidence)
│
├── ── INTELLIGENCE MODULES (v3.0, wired to nova.py + nova_core.py) ────
├── nova_payload_engine.py       ← Polymorphic WAF-bypass payload generation
├── nova_payload_library.py      ← Centralized exploit payload store
├── nova_trace_isolator.py       ← Stealth headers + proxy rotation
├── nova_cloud_strike.py         ← S3/Azure/GCP recon + metadata SSRF
├── nova_identity_takeover.py    ← Entra ID / IAM / cloud identity audit
├── nova_zero_day_correlator.py  ← Live CVE feed (NVD/OSV/GHSA) correlation
│
├── ── SCAN MODULES (phases 1-13) ──────────────────────────────────────
├── nova_codebase_mapper.py      ← Phase 0: source intelligence + RAG
├── nova_recon.py                ← Phase 1: subdomain enum + DNS
├── nova_auth_scanner.py         ← Phase 2: auth bypass + session
├── nova_idor_scanner.py         ← Phase 3: IDOR / BOLA
├── nova_csrf_tester.py          ← Phase 3: CSRF token checks
├── nova_sca_scanner.py          ← Phase 5: dependency CVE scan
├── nova_cicd_scanner.py         ← Phase 7: pipeline / workflow injection
├── nova_container_scanner.py    ← Phase 8: Docker/K8s misconfigs
├── nova_business_logic.py       ← Phase 9: price/coupon/workflow abuse
├── nova_threat_model.py         ← Phase 10: STRIDE threat modeling
├── nova_llm_injection.py        ← Phase 11: prompt injection / jailbreak
├── nova_proto_polluter.py       ← Phase 12: prototype pollution
├── nova_race_engine.py          ← Phase 13: race conditions / TOCTOU
├── nova_source_auditor.py       ← SAST: map-aware code audit
├── nova_git_scanner.py          ← Git history + leaked secrets
├── nova_github_scanner.py       ← GitHub API: org/repo scanning
├── nova_jwt_forge.py            ← JWT: alg-none, key confusion, crack
├── nova_graphql_tester.py       ← GraphQL: introspection + injection
├── nova_payload_engine.py       ← Polymorphic payload generator
│
├── targets_scope_map.json       ← Program scope validation map
├── targets_priority.txt         ← Bug bounty priority targets
├── targets.txt                  ← Full target list
│
├── NOVA_ARCHITECTURE.md         ← Full ASCII system architecture diagram
├── INSTALL.md                   ← Installation guide (all platforms)
└── .github/workflows/
    ├── nova-truth-verified.yml  ← Truth-verified CI scan (95% confidence)
    └── nova-cloud-strike.yml    ← Cloud-native recon workflow
```

---

## ⚡ Quick Start

```bash
# Clone and install
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal && pip install -r requirements.txt

# Full autonomous scan (natural language)
python3 nova.py "Hunt https://target.com for all vulnerabilities"

# Cloud recon
python3 nova.py "Cloud strike on https://target.cloud.com"

# Identity audit (Entra ID / IAM)
python3 nova.py "Identity takeover audit on https://login.microsoftonline.com/tenant"

# Zero-day CVE correlation against detected tech stack
python3 nova.py "Zero day correlate ./source-dir"

# CLI subcommands (nova_arsenal.py)
python3 nova_arsenal.py recon   --target https://target.com
python3 nova_arsenal.py exploit --target https://target.com
python3 nova_arsenal.py crack   --hashcat hashes.txt --type ntlm
```

---

## 🧠 Newly Wired Modules (v4.2+)

### `nova_payload_engine.py` — Polymorphic Payload Generator
Generates and mutates attack payloads for all vuln types.
WAF-bypass mutations applied per payload. LLM-augmented variants when `_ROUTER` is available.

```python
from nova_payload_engine import NovaPayloadEngine
engine = NovaPayloadEngine(reasoning=llm_router)
payloads = engine.generate("sql_injection", count=10, waf_mode=True)
```

Supports: `sql_injection`, `xss`, `ssrf`, `ssti`, `xxe`, `prototype_pollution`, `open_redirect`

---

### `nova_payload_library.py` — Centralized Payload Store
Used by `nova_payload_engine.py` and `nova_cloud_strike.py` as a shared payload source.

```python
from nova_payload_library import get_payloads
cloud_ssrf = get_payloads("ssrf", subcategory="aws")
# → ['http://169.254.169.254/latest/meta-data/', ...]
```

---

### `nova_trace_isolator.py` — Stealth HTTP Layer
Rotates User-Agents and proxies on every request. Applied passively to all scan phases.

```python
from nova_trace_isolator import get_isolator
isolator = get_isolator()
resp = isolator.stealth_request("GET", "https://target.com/api/admin")
```

Env: `NOVA_PROXY_LIST` (comma-separated proxy URLs)

---

### `nova_cloud_strike.py` — Cloud Pentest Engine
Audits S3/Azure Blob/GCP Storage for public exposure.
Generates cloud metadata SSRF payloads per cloud provider.
Runs cloud-native recon (IAM roles, serverless functions, metadata endpoints).

**Triggered by:** `cloud`, `ssrf`, `hunt`, `full_stack` modes

```bash
python3 nova.py "Cloud strike on https://app.example.com"
python3 nova.py "AWS recon https://s3.amazonaws.com/target-bucket"
```

---

### `nova_identity_takeover.py` — Cloud Identity Audit
Checks for IAM role trust policy misconfigurations (AWS cross-account assume-role).
Detects managed identity / metadata endpoint exposure (Azure).
Simulates Entra ID actor token hijack patterns (CVE-2025-55241).

**Triggered by:** `identity`, `cloud`, `hunt`, `full_stack` modes

```bash
python3 nova.py "Identity takeover audit on https://login.microsoftonline.com"
python3 nova.py "IAM hijack audit on https://aws.target.com"
```

---

### `nova_zero_day_correlator.py` — Live CVE Feed Correlation
Already wired in Phase 5. Detects tech stack from source or response headers,
queries NVD (NIST), OSV.dev, and GHSA for live CVEs, then correlates against
discovered findings. Weaponizes critical CVEs with PoC links.

**Triggered by:** `zero_day`, `full_stack` modes

```bash
python3 nova.py "Zero day correlate ./source-code-dir"
python3 nova.py "CVE correlation on https://target.com"
```

Env: `NVD_API_KEY` (optional, raises NVD rate limits from 5→50 req/30s)

---

## 🔧 Integrated Tool Reference

| Module | Source | Technique | Status |
|--------|--------|-----------|--------|
| `nova_truth_engine` | Nova v1.1 | 7-method false-positive verification (95% confidence) | ✅ Wired |
| `nova_cloud_strike` | Nova v4.2 | S3/GCP/Azure recon + metadata SSRF | ✅ Wired |
| `nova_identity_takeover` | Nova v4.2 | Entra ID / IAM cloud identity audit | ✅ Wired |
| `nova_trace_isolator` | Nova v4.2 | Stealth UA rotation + proxy chain | ✅ Wired |
| `nova_payload_engine` | Nova v4.2 | Polymorphic WAF-bypass payloads | ✅ Wired |
| `nova_zero_day_correlator` | Nova v4.2 | Live NVD/OSV CVE correlation | ✅ Wired |
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

## 🔌 nova.py Intent Keywords (all modes)

| Say this... | Nova runs... |
|---|---|
| `"Hunt https://target.com"` | Full 13-phase scan + Truth Engine |
| `"Cloud strike on https://target.com"` | Cloud Strike + Identity phases |
| `"Identity takeover audit"` | Entra ID / IAM / cross-tenant check |
| `"Zero day correlate ./src"` | Live CVE feed + tech stack correlation |
| `"SSRF https://target.com"` | SSRF + Cloud metadata vector generation |
| `"Full stack pipeline"` | All phases including cloud + identity |
| `"Recon https://target.com"` | Passive recon only |
| `"SAST ./src"` | Static code audit only |
| `"Bootstrap"` | Health check all modules |

---

## ⚖️ Legal
Only test systems you own or have explicit written authorization to test.
Check `targets_scope_map.json` before scanning any external host.
