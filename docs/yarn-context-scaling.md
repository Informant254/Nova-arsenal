# YaRN Context Scaling for Nova-Arsenal

## Overview

**YaRN** (Yet another RoPE extensioN method) extends a model's native context window by modifying its Rotary Position Embeddings (RoPE). It requires only ~0.1% of original training data and 400 training steps, making it the most compute-efficient long-context method for production use.

- **Paper**: [YaRN: Efficient Context Window Extension of Large Language Models](https://arxiv.org/abs/2309.00071) (ICLR 2024)
- **Code**: [github.com/jquesnelle/yarn](https://github.com/jquesnelle/yarn)
- **Key insight**: NTK-by-parts interpolation — each RoPE dimension is interpolated differently based on its wavelength relative to the original context size

## How Qwythos-9B Uses It

From `config.json`:

```json
"rope_parameters": {
    "rope_type": "yarn",
    "factor": 4.0,
    "original_max_position_embeddings": 262144,
    "rope_theta": 10000000
}
```

- **Base**: Qwen3.5-9B (native 262k context)
- **YaRN factor**: 4.0 → effective **1,048,576 tokens** (1M)
- **Training**: Full-parameter SFT with 128k max seq len during training; YaRN handles extrapolation to 1M at inference
- **Attention**: Hybrid — 3:1 Gated DeltaNet linear-attention to Gated full-attention (not related to YaRN, but relevant for memory at long context)

## Applying to Nova

### 1. Ollama Modelfile

Create a Modelfile for any RoPE-based model (Llama, Mistral, Qwen, etc.):

```dockerfile
FROM model-name

# Set context length to desired extended size
PARAMETER num_ctx 1048576

# YaRN rope scaling
PARAMETER rope_scaling_type yarn
PARAMETER rope_scaling_factor 4.0

# Optional: specify original context length of base model
PARAMETER rope_scaling_original_max_position_embeddings 4096  # or whatever the base uses
```

Build and run:

```bash
ollama create nova-yarn -f Modelfile
ollama run nova-yarn
```

### 2. Existing Nova Ollama Provider

The Ollama provider (`nova_arsenal/llm/ollama.py`) sets `num_ctx` via its HTTP client. If you've created a YaRN-scaled model in Ollama, update the provider config:

```python
# In nova config / environment:
OLLAMA_MODEL="qwythos-9b:1m"  # or your custom YaRN model
# No code changes needed — Ollama handles rope params server-side
```

### 3. Transformers / Training

When fine-tuning your own model with YaRN scaling:

```python
from transformers import AutoConfig, AutoModelForCausalLM

config = AutoConfig.from_pretrained("base-model")
config.max_position_embeddings = 1048576  # target context
config.rope_scaling = {
    "type": "yarn",
    "factor": 4.0,
    "original_max_position_embeddings": 262144,  # base model's native context
}
model = AutoModelForCausalLM.from_pretrained("base-model", config=config)
```

### 4. Key Parameters

| Parameter | Qwythos value | Notes |
|-----------|---------------|-------|
| `factor` | 4.0 | Scale factor: `target_ctx / original_ctx` |
| `original_max_position_embeddings` | 262144 | The model's **native** context, not training max |
| `rope_type` / `type` | `yarn` | Must match the implementation (HF vs custom) |
| `rope_theta` | 10000000 | Base frequency (keep the model's original value) |

### 5. NTK-by-parts Internals

YaRN divides RoPE dimensions into three regimes based on wavelength λ relative to original context L:

1. **Short dimensions** (λ ≪ L): no interpolation — preserved exactly
2. **Long dimensions** (λ ≥ L): full interpolation — prevents unseen positions
3. **Middle dimensions**: blended interpolation (NTK-aware style)

This avoids the two failure modes of simpler methods:
- **Positional Interpolation (PI)**: loses high-frequency detail, degrades short-context performance
- **NTK-aware**: can over-extrapolate long dimensions, causing instability

### 6. Inference-Only Dynamic YaRN

If you can't fine-tune, use **Dynamic YaRN** at inference for 2× extension with zero training:

```python
# Applied at inference in the RoPE computation:
scale = max(1.0, current_seq_len / original_max_position_embeddings)
# This dynamically increases the scale factor as context grows
```

Ollama does not support Dynamic YaRN natively; you would need a custom inference server (vLLM, ExLlama, or custom HF pipeline).

## When YaRN Makes Sense for Nova

- **Security assessments with large codebases**: Scanning 100K+ line repos requires proportional context
- **Multi-stage exploitation chains**: Long agent trajectories with full tool call history
- **Forensic analysis**: Memory dumps, log files, and packet captures can exceed 100K tokens
- **OSINT correlation**: Maintaining full thread context across dozens of lookups

## When It Doesn't

- **Quick recon tasks** (under 8K tokens): YaRN is neutral — no benefit, no penalty
- **Models without RoPE** (e.g., some older architectures): YaRN is RoPE-specific
- **Memory-constrained environments**: 1M context requires proportional VRAM for KV cache (32GB+ for 9B params)

## References

- YaRN paper: https://arxiv.org/abs/2309.00071
- YaRN code: https://github.com/jquesnelle/yarn
- HuggingFace docs on rope_scaling: https://huggingface.co/docs/transformers/main/en/llm_tutorial#rope-scaling
- Ollama Modelfile: https://github.com/ollama/ollama/blob/main/docs/modelfile.md
- Qwythos-9B config: https://huggingface.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M
