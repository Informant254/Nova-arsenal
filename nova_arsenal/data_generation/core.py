"""
Core data generation engine - port of empero-org/taskgen with Nova security focus.

Ported from taskgen/src/main.rs. Key adaptations:
- Security-focused domain taxonomy (recon, exploitation, osint, forensics, etc.)
- Difficulty-aware system prompt adapted from taskgen's DEFAULT_SYSTEM_PROMPT
- Structured chain-of-thought blocks (hypothesis→verification→conclusion)
- Async generation with configurable concurrency
- Qwythos-compatible output format (assistant-only loss ready)
"""

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Difficulty Scale (ported from taskgen) ──────────────────────────────────

class DifficultyScale(Enum):
    VERY_EASY = 1
    EASY = 2
    BASIC = 3
    INTERMEDIATE = 4
    STANDARD = 5
    SKILLED = 6
    PROFICIENT = 7
    ADVANCED = 8
    EXPERT = 9
    POLYMATH = 10


DIFFICULTY_LABELS: Dict[DifficultyScale, str] = {
    DifficultyScale.VERY_EASY: "Very Easy (child-level)",
    DifficultyScale.EASY: "Easy (elementary)",
    DifficultyScale.BASIC: "Basic (middle school)",
    DifficultyScale.INTERMEDIATE: "Intermediate (high school)",
    DifficultyScale.STANDARD: "Standard (undergraduate intro)",
    DifficultyScale.SKILLED: "Skilled (undergraduate advanced)",
    DifficultyScale.PROFICIENT: "Proficient (graduate level)",
    DifficultyScale.ADVANCED: "Advanced (professional/researcher)",
    DifficultyScale.EXPERT: "Expert (top specialist)",
    DifficultyScale.POLYMATH: "Polymath (1-in-a-million genius)",
}


# ── Nex-N2 Style RL Data ───────────────────────────────────────────────────

NEXN2_RL_DATA_FORMAT = "parquet"
NEXN2_RL_COLUMNS = ["prompt", "ground_truth"]

NEXN2_CHAT_TEMPLATE = """{%- if add_generation_prompt %}
    {{- '<|im_start|>assistant\n' }}
    {%- if enable_thinking is defined and enable_thinking is false %}
        {{- '<think>\n\n</think>\n\n' }}
    {%- else %}
        {{- '<think>' }}
    {%- endif %}
{%- endif %}"""

NEXN2_TOOL_FORMAT_INSTRUCTION = """# Tools

You have access to the following functions:

<tools>
{tools_json}
</tools>

If you choose to call a function ONLY reply in the following format with NO suffix:

<tool_call>
<function=function_name>
<parameter=parameter_name>
value
</parameter>
</function>
</tool_call>

<IMPORTANT>
- Function calls MUST follow the <tool_call><function=...></function></tool_call> format
- Required parameters MUST be specified
- You may provide optional reasoning in natural language BEFORE the function call, but NOT after
- If there is no function call available, answer the question like normal
</IMPORTANT>"""


# ── Chain-of-Thought Framework (Qwythos-style) ─────────────────────────────

COT_FRAMEWORK = """You MUST structure your reasoning in the following blocks:

<hypothesis>
What you think is happening and why. State your initial assessment, assumptions, and expected outcome.
</hypothesis>

<verification>
Walk through the evidence. Check each assumption. Test edge cases. Consider alternative explanations.
Include specific commands, code, or logic you would use to verify.
</verification>

<conclusion>
State what you determined, why, and what the implications are. If uncertain, explain what additional
information would resolve the ambiguity.
</conclusion>

Each block must be present and substantive. Empty blocks will be rejected."""


# ── Security Domain Taxonomy ────────────────────────────────────────────────

@dataclass
class SecurityDomainTaxonomy:
    category: str
    name: str
    subdomains: List[str]


SECURITY_DOMAIN_TAXONOMY: List[SecurityDomainTaxonomy] = [
    # Reconnaissance
    SecurityDomainTaxonomy("recon", "Passive Reconnaissance", [
        "dns_enumeration", "subdomain_discovery", "certificate_transparency",
        "whois_lookup", "email_harvesting", "social_media_osint",
    ]),
    SecurityDomainTaxonomy("recon", "Active Reconnaissance", [
        "port_scanning", "service_fingerprinting", "network_mapping",
        "banner_grabbing", "firewall_detection", "cdn_detection",
    ]),
    SecurityDomainTaxonomy("recon", "Web Reconnaissance", [
        "directory_enumeration", "parameter_discovery", "endpoint_mapping",
        "tech_stack_detection", "hidden_files", "api_discovery",
    ]),

    # Exploitation
    SecurityDomainTaxonomy("exploit", "Web Exploitation", [
        "sql_injection", "xss", "csrf", "ssrf", "lfi_rfi",
        "command_injection", "file_upload_bypass", "template_injection",
        "deserialization", "xxe",
    ]),
    SecurityDomainTaxonomy("exploit", "Network Exploitation", [
        "mitm", "arp_spoofing", "dns_spoofing", "sniffing",
        "session_hijacking", "vlan_hopping",
    ]),
    SecurityDomainTaxonomy("exploit", "Authentication Bypass", [
        "oauth_misconfiguration", "jwt_forgery", "session_fixation",
        "brute_force", "credential_stuffing", "mfa_bypass",
    ]),
    SecurityDomainTaxonomy("exploit", "Privilege Escalation", [
        "sudo_abuse", "suid_exploitation", "kernel_exploit",
        "container_escape", "service_abuse", "token_impersonation",
    ]),

    # OSINT
    SecurityDomainTaxonomy("osint", "Technical OSINT", [
        "github_recon", "shodan_search", "censys_search",
        "google_dorking", "pastebin_monitoring", "dark_web_monitoring",
    ]),
    SecurityDomainTaxonomy("osint", "Human OSINT", [
        "social_media_analysis", "relationship_mapping", "identity_correlation",
        "geolocation", "timeline_analysis",
    ]),

    # Cryptography & Security Engineering
    SecurityDomainTaxonomy("crypto", "Cryptography", [
        "symmetric_encryption", "asymmetric_encryption", "hash_analysis",
        "tls_ssl", "key_exchange", "digital_signatures",
    ]),
    SecurityDomainTaxonomy("crypto", "Security Engineering", [
        "secure_architecture", "threat_modeling", "zero_trust",
        "network_segmentation", "iam", "secret_management",
    ]),

    # Malware & Forensics
    SecurityDomainTaxonomy("forensics", "Digital Forensics", [
        "memory_analysis", "disk_forensics", "network_forensics",
        "log_analysis", "timeline_reconstruction", "file_carving",
    ]),
    SecurityDomainTaxonomy("forensics", "Malware Analysis", [
        "static_analysis", "dynamic_analysis", "reverse_engineering",
        "packer_detection", "c2_analysis", "ransomware_analysis",
    ]),

    # AI Security
    SecurityDomainTaxonomy("ai_security", "AI Security", [
        "prompt_injection", "model_extraction", "adversarial_examples",
        "training_data_poisoning", "model_inversion", "llm_safety",
    ]),

    # Cloud & Container
    SecurityDomainTaxonomy("cloud", "Cloud Security", [
        "aws_enumeration", "gcp_enumeration", "azure_enumeration",
        "iam_abuse", "storage_misconfiguration", "serverless_security",
    ]),
    SecurityDomainTaxonomy("cloud", "Container Security", [
        "docker_escape", "k8s_enumeration", "container_vulnerability_scanning",
        "image_analysis", "registry_security",
    ]),

    # Code & Application Security
    SecurityDomainTaxonomy("appsec", "Code Security", [
        "static_analysis", "dynamic_analysis", "dependency_scanning",
        "code_review", "secret_detection", "supply_chain_security",
    ]),
    SecurityDomainTaxonomy("appsec", "Network Security", [
        "firewall_configuration", "ids_ips", "vpn_security",
        "wireless_security", "protocol_analysis",
    ]),

    # Social Engineering
    SecurityDomainTaxonomy("social", "Social Engineering", [
        "phishing", "spear_phishing", "pretexting",
        "baiting", "tailgating", "quid_pro_quo",
    ]),
]

# Category → domains mapping for weighted sampling
CATEGORY_MAP: Dict[str, List[SecurityDomainTaxonomy]] = {}
for d in SECURITY_DOMAIN_TAXONOMY:
    CATEGORY_MAP.setdefault(d.category, []).append(d)

CATEGORIES = list(CATEGORY_MAP.keys())

DEFAULT_CATEGORY_DISTRIBUTION: Dict[str, float] = {
    "recon": 0.15,
    "exploit": 0.25,
    "osint": 0.10,
    "crypto": 0.10,
    "forensics": 0.10,
    "ai_security": 0.10,
    "cloud": 0.10,
    "appsec": 0.10,
    "social": 0.05,
}

DEFAULT_DIFFICULTY_DISTRIBUTION: Dict[int, float] = {
    1: 0.05,
    2: 0.05,
    3: 0.10,
    4: 0.15,
    5: 0.20,
    6: 0.15,
    7: 0.10,
    8: 0.08,
    9: 0.07,
    10: 0.05,
}


# ── Difficulty-Aware System Prompt (adapted from taskgen) ───────────────────

DIFFICULTY_SYSTEM_PROMPT = """Write prompts as if a security professional asked a question on a forum or Stack Overflow. They might be tired or frustrated, but they're competent. They state the problem directly without excessive explanation.

CRITICAL: Difficulty affects both phrasing AND problem complexity/scope:
- Difficulty 1-3: Basic security questions, clear answer. "how do I check if a port is open?" "what's the difference between symmetric and asymmetric encryption?"
- Difficulty 4-5: Competent professional with a real technical problem. Some ambiguity or competing approaches. "I'm setting up WAF rules but keep getting false positives on our API endpoints—what's the right approach to tune ModSecurity without breaking legitimate traffic?" Include what you've tried.
- Difficulty 6-7: Expert-level, use terminology naturally. The problem has inherent tensions or trade-offs. "We're implementing zero-trust network segmentation across 5000+ microservices—deciding between sidecar proxies vs eBPF-based enforcement. Tradeoffs for latency vs security guarantees vs operational complexity?" State them frankly.
- Difficulty 8-10: Cutting-edge security research. Multiple valid framings, uncertain outcomes, synthesis across domains. "Proving constant-time execution against speculative side channels in a formal verification framework—current approach uses BPL but the model checker blows up on cache-line contention patterns across SMT threads. Any decomposition strategies or lemmas that reduce state space without losing semantic soundness?" Expert-to-expert: assume domain knowledge, be honest about where you're stuck.

For difficulty 6+: Include genuine constraint conflicts or design trade-offs—but phrase them as a competent person would. Don't manufacture fake complexity.

Output only the prompt itself. Keep it short but preserve all actual complexity."""  # noqa: E501


# ── Task Entry ──────────────────────────────────────────────────────────────

@dataclass
class TaskEntry:
    prompt: str
    domain: str
    subdomain: str
    difficulty: int
    category: str
    language: str = "en"
    cot_style: bool = False
    taskgen_model: str = "nova-data-gen"
    temperature: float = 0.9
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_nexn2_rl_row(self) -> dict:
        """Convert to Nex-N2 style RL training row (parquet format)."""
        return {
            "prompt": self.prompt,
            "ground_truth": "",
            "domain": f"{self.category}::{self.domain}",
            "subdomain": self.subdomain,
            "difficulty": self.difficulty,
            "category": self.category,
            "language": self.language,
            "cot_style": self.cot_style,
        }

    def to_jsonl(self) -> str:
        d = {
            "prompt": self.prompt,
            "domain": f"{self.category}::{self.domain}",
            "subdomain": self.subdomain,
            "difficulty": self.difficulty,
            "category": self.category,
            "language": self.language,
        }
        if self.cot_style:
            d["cot_instruction"] = COT_FRAMEWORK
        d["taskgen_model"] = self.taskgen_model
        d["temperature"] = self.temperature
        d["created_at"] = self.created_at
        return json.dumps(d, ensure_ascii=False)

    @classmethod
    def from_jsonl(cls, line: str) -> "TaskEntry":
        d = json.loads(line)
        return cls(
            prompt=d["prompt"],
            domain=d["domain"].split("::")[1] if "::" in d["domain"] else d["domain"],
            subdomain=d["subdomain"],
            difficulty=d["difficulty"],
            category=d.get("category", d["domain"].split("::")[0] if "::" in d.get("domain", "") else ""),
            language=d.get("language", "en"),
            cot_style="cot_instruction" in d,
            taskgen_model=d.get("taskgen_model", "unknown"),
            temperature=d.get("temperature", 0.9),
            created_at=d.get("created_at", ""),
        )


# ── Generation Config ──────────────────────────────────────────────────────

@dataclass
class GenerationConfig:
    count: int = 250
    workers: int = 5
    temperature: float = 0.9
    model: str = "gpt-4o-mini"
    system_prompt: Optional[str] = None
    category_distribution: Optional[Dict[str, float]] = None
    difficulty_distribution: Optional[Dict[int, float]] = None
    output_path: Optional[Path] = None
    dedup: bool = True
    dedup_threshold: float = 0.6
    cot_ratio: float = 0.3
    append: bool = False
    budget: Optional[float] = None
    input_price: Optional[float] = None
    output_price: Optional[float] = None


# ── Sampling Logic (ported from taskgen) ────────────────────────────────────

def build_domain_pool(dist: Dict[str, float]) -> List[Tuple[str, str, str, float]]:
    pool = []
    for cat, weight in dist.items():
        domains = CATEGORY_MAP.get(cat, [])
        if not domains:
            continue
        per_domain = weight / len(domains)
        for d in domains:
            per_sub = per_domain / len(d.subdomains)
            for sub in d.subdomains:
                pool.append((cat, d.name, sub, per_sub))
    return pool


def weighted_sample(
    items: List[Tuple[Any, ...]],
    weights: List[float],
    rng: random.Random,
) -> Any:
    total = sum(weights)
    r = rng.random() * total
    cumulative = 0.0
    for item, w in zip(items, weights):
        cumulative += w
        if r <= cumulative:
            return item
    return items[-1] if items else None


def sample_domain(
    rng: random.Random,
    pool: List[Tuple[str, str, str, float]],
) -> Tuple[str, str, str]:
    weights = [w for _, _, _, w in pool]
    return weighted_sample(pool, weights, rng)


def sample_difficulty(
    rng: random.Random,
    dist: Dict[int, float],
) -> int:
    levels = list(dist.keys())
    weights = [dist[l] for l in levels]
    return weighted_sample(levels, weights, rng)


# ── Prompt Builder ──────────────────────────────────────────────────────────

SECURITY_TASK_INSTRUCTION = """Generate a realistic security task/prompt for the following:

Domain: {domain} :: {name}
Subdomain: {subdomain}
Difficulty: {difficulty}/10 ({label})

The task MUST be directly about "{subdomain}" within {name}. Be specific about the subdomain topic — not just a generic {domain} question.

Phrasing rules by difficulty:
- 1-3: Simple question, genuine confusion, clear answer expected
- 4-5: Competent professional with real problem — state what you've tried
- 6-7: Expert discussing trade-offs — include constraint conflicts naturally
- 8-10: Cutting-edge research — assume domain knowledge, be honest about stuck points

Output only the task prompt, nothing else."""


def build_generation_messages(
    system_prompt: str,
    domain: str,
    name: str,
    subdomain: str,
    difficulty: int,
    include_cot: bool,
) -> List[Dict[str, str]]:
    user_msg = SECURITY_TASK_INSTRUCTION.format(
        domain=domain, name=name, subdomain=subdomain,
        difficulty=difficulty, label=DIFFICULTY_LABELS.get(DifficultyScale(difficulty), ""),
    )
    if include_cot:
        user_msg += f"""\n\nAdditionally, include the expected chain-of-thought reasoning format:
{COT_FRAMEWORK}"""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_msg},
    ]


# ── Generator ───────────────────────────────────────────────────────────────

class NovaDataGenerator:
    """
    Generates security-focused SFT training data using any OpenAI-compatible API.

    Ported from empero-org/taskgen with Nova-specific additions:
    - Security domain taxonomy
    - Structured CoT blocks
    - Qwythos-compatible output format
    """

    def __init__(
        self,
        config: GenerationConfig,
        api_key: str,
        api_base: str = "https://api.openai.com/v1",
        llm_call: Optional[Callable] = None,
    ):
        self.config = config
        self.api_key = api_key
        self.api_base = api_base
        self.llm_call = llm_call or self._default_llm_call
        self.rng = random.Random()
        self._stats = {"generated": 0, "errors": 0, "input_tokens": 0, "output_tokens": 0}

    async def _default_llm_call(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int = 2048,
    ) -> Tuple[str, int, int]:
        import httpx
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                f"{self.api_base.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.config.model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]
            text = choice["message"]["content"].strip()
            usage = data.get("usage", {})
            in_tok = usage.get("prompt_tokens", 0)
            out_tok = usage.get("completion_tokens", 0)
            return text, in_tok, out_tok

    async def generate_task(
        self,
        domain: str,
        name: str,
        subdomain: str,
        difficulty: int,
        include_cot: bool,
    ) -> Optional[TaskEntry]:
        system_prompt = self.config.system_prompt or DIFFICULTY_SYSTEM_PROMPT
        messages = build_generation_messages(
            system_prompt, domain, name, subdomain, difficulty, include_cot,
        )
        try:
            text, in_tok, out_tok = await self.llm_call(
                messages, self.config.temperature,
            )
            if not text:
                return None
            self._stats["input_tokens"] += in_tok
            self._stats["output_tokens"] += out_tok
            return TaskEntry(
                prompt=text,
                domain=f"{domain}::{name}",
                subdomain=subdomain,
                difficulty=difficulty,
                category=domain,
                cot_style=include_cot,
                taskgen_model=self.config.model,
                temperature=self.config.temperature,
            )
        except Exception as e:
            self._stats["errors"] += 1
            logger.warning(f"Generation failed for {domain}/{subdomain} d{difficulty}: {e}")
            return None

    async def generate(self) -> List[TaskEntry]:
        pool = build_domain_pool(
            self.config.category_distribution or DEFAULT_CATEGORY_DISTRIBUTION
        )
        diff_dist = self.config.difficulty_distribution or DEFAULT_DIFFICULTY_DISTRIBUTION
        if not pool:
            raise ValueError("No domains matched distribution")

        presampled = []
        for _ in range(self.config.count):
            cat, name, sub = sample_domain(self.rng, pool)
            diff = sample_difficulty(self.rng, diff_dist)
            include_cot = self.rng.random() < self.config.cot_ratio
            presampled.append((cat, name, sub, diff, include_cot))

        semaphore = asyncio.Semaphore(self.config.workers)
        tasks = []

        async def _generate_one(args):
            async with semaphore:
                return await self.generate_task(*args)

        for args in presampled:
            tasks.append(_generate_one(args))

        results = await asyncio.gather(*tasks)
        entries = [e for e in results if e is not None]
        self._stats["generated"] = len(entries)

        if self.config.output_path:
            self._write_output(entries)

        logger.info(
            f"Generated {len(entries)} tasks ({self._stats['errors']} errors, "
            f"{self._stats['input_tokens']} in / {self._stats['output_tokens']} out tokens)"
        )
        return entries

    def _write_output(self, entries: List[TaskEntry]) -> None:
        path = self.config.output_path
        mode = "a" if self.config.append else "w"

        if path and path.suffix == ".parquet":
            self._write_parquet(entries, path)
        else:
            with open(path, mode, encoding="utf-8") as f:
                for entry in entries:
                    f.write(entry.to_jsonl() + "\n")
        logger.info(f"Wrote {len(entries)} tasks to {path}")

    def _write_parquet(self, entries: List[TaskEntry], path: Path) -> None:
        """Write entries in Nex-N2 style parquet format (prompt/ground_truth columns)."""
        try:
            import pandas as pd
            rows = [e.to_nexn2_rl_row() for e in entries]
            df = pd.DataFrame(rows)
            df.to_parquet(path, index=False)
        except ImportError:
            logger.warning("pandas not available, falling back to JSONL")
            with open(path.with_suffix(".jsonl"), "w", encoding="utf-8") as f:
                for entry in entries:
                    f.write(entry.to_jsonl() + "\n")

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)
