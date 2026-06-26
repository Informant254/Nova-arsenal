"""
Nova-Arsenal Data Generation Pipeline.

Port of empero-org/taskgen (Rust) for security-specific SFT data generation.
Generates difficulty-weighted, domain-structured training tasks with structured
chain-of-thought for fine-tuning security agents.

Key concepts ported from taskgen:
- 45+ domains, 200+ subdomains across 6 categories (extended with security focus)
- Weighted difficulty sampling (1-10) with style controlled by difficulty level
- Pre-sampled batches with concurrent async generation
- Two-pass dedup (exact match + trigram Jaccard similarity)
- JSONL output with full metadata per task
- Difficulty-aware system prompt from taskgen's DEFAULT_SYSTEM_PROMPT

Nova-specific additions:
- Security-focused domain taxonomy (recon, exploitation, osint, forensics, etc.)
- Structured chain-of-thought blocks (hypothesis→verification→conclusion)
- Qwythos-style training data format (assistant-only loss ready)
- CLI interface for standalone use
"""

from nova_arsenal.data_generation.core import (
    SecurityDomainTaxonomy,
    DifficultyScale,
    DIFFICULTY_LABELS as DifficultyLabels,
    TaskEntry,
    GenerationConfig,
    NovaDataGenerator,
    SECURITY_DOMAIN_TAXONOMY,
    DEFAULT_DIFFICULTY_DISTRIBUTION,
    DEFAULT_CATEGORY_DISTRIBUTION,
    COT_FRAMEWORK,
)

from nova_arsenal.data_generation.dedup import (
    word_trigrams,
    jaccard_similarity,
    exact_dedup,
    semantic_dedup,
    run_dedup_pipeline,
)

__all__ = [
    "SecurityDomainTaxonomy",
    "DifficultyScale",
    "DifficultyLabels",
    "TaskEntry",
    "GenerationConfig",
    "NovaDataGenerator",
    "SECURITY_DOMAIN_TAXONOMY",
    "DEFAULT_DIFFICULTY_DISTRIBUTION",
    "DEFAULT_CATEGORY_DISTRIBUTION",
    "COT_FRAMEWORK",
    "word_trigrams",
    "jaccard_similarity",
    "exact_dedup",
    "semantic_dedup",
    "run_dedup_pipeline",
]
