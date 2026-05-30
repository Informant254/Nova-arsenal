#!/usr/bin/env python3
"""Local self-improvement memory and planning for Nova.

Nova uses this module to learn from completed runs, turn failures into a local
improvement backlog, and keep all update planning on the user's machine.
"""

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
DEFAULT_MODEL = os.getenv("NOVA_LLM_MODEL", "")
DEFAULT_OLLAMA_URL = os.getenv("NOVA_LLM_URL", "http://localhost:11434")
PLAN_FILE = "nova_self_improvement_plan.json"
MEMORY_FILE = "nova_self_improvement_memory.json"


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _recent_json_files(workspace: Path, prefix: str, limit: int = 8) -> List[Path]:
    if not workspace.exists():
        return []
    files = [path for path in workspace.glob(f"{prefix}*.json") if path.is_file()]
    files.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    return files[:limit]


def collect_run_signals(workspace: str = None, limit: int = 8) -> Dict[str, Any]:
    """Collect compact evidence from recent Nova runs and self-improvement memory."""
    base = Path(os.path.expanduser(workspace)) if workspace else WORKSPACE
    reports = []
    for path in _recent_json_files(base, "agent_report_", limit=limit):
        data = _read_json(path, {})
        reports.append({
            "file": str(path),
            "objective": data.get("objective"),
            "steps": data.get("steps"),
            "findings_count": len(data.get("findings", [])),
            "verification_log": data.get("verification_log", [])[-8:],
            "reflections": data.get("reflections", [])[-4:],
            "plan_tail": data.get("plan", [])[-8:],
        })
    memory = _read_json(base / MEMORY_FILE, {"lessons": [], "outcomes": []})
    plan = _read_json(base / PLAN_FILE, {"proposals": []})
    return {
        "workspace": str(base),
        "reports": reports,
        "memory_tail": memory.get("lessons", [])[-20:],
        "recent_outcomes": memory.get("outcomes", [])[-20:],
        "open_proposals": [p for p in plan.get("proposals", []) if p.get("status") not in {"done", "rejected"}][-20:],
    }


def _fallback_proposals(signals: Dict[str, Any]) -> List[Dict[str, Any]]:
    proposals = []
    reports = signals.get("reports", [])
    failed_commands = []
    for report in reports:
        for item in report.get("verification_log", []):
            if item and item.get("success") is False:
                failed_commands.append(item.get("command"))
    if failed_commands:
        proposals.append({
            "id": f"fix-failing-verification-{int(time.time())}",
            "title": "Improve automatic diagnosis for recurring verification failures",
            "rationale": "Recent Nova runs recorded failing verification commands that should feed targeted repair prompts.",
            "target_files": ["nova_agent_core.py", "nova_tool_kit.py"],
            "verification": sorted({cmd for cmd in failed_commands if cmd}),
            "status": "pending",
        })
    proposals.append({
        "id": f"expand-agent-evals-{int(time.time())}",
        "title": "Add local regression tasks for Nova coding-agent behavior",
        "rationale": "A local benchmark harness would make self-updates measurable instead of subjective.",
        "target_files": ["nova_self_improvement.py", "nova_agent_core.py"],
        "verification": ["python3 -m py_compile nova_agent_core.py nova_tool_kit.py nova_self_improvement.py"],
        "status": "pending",
    })
    return proposals


def _call_ollama(prompt: str, model: str, ollama_url: str, timeout: int = 60) -> Optional[Dict[str, Any]]:
    if not model:
        return None
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are Nova's local self-improvement planner. Output JSON only."},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 900},
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{ollama_url.rstrip('/')}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = json.loads(response.read().decode("utf-8"))
        content = raw.get("message", {}).get("content", "").strip()
        if not content:
            return None
        return json.loads(content)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return None


def generate_improvement_plan(
    root: str = ".",
    workspace: str = None,
    model: str = None,
    ollama_url: str = None,
) -> Dict[str, Any]:
    """Create a local improvement backlog from recent run evidence."""
    base = Path(os.path.expanduser(workspace)) if workspace else WORKSPACE
    signals = collect_run_signals(str(base))
    prompt = json.dumps({
        "task": "Create 3-6 concrete code-improvement proposals for Nova itself. Prefer small, testable updates. Do not suggest cloud APIs.",
        "repo_root": str(Path(root).expanduser().resolve()),
        "signals": signals,
        "schema": {
            "proposals": [{
                "id": "short-stable-id",
                "title": "specific improvement",
                "rationale": "evidence-based reason",
                "target_files": ["relative/path.py"],
                "verification": ["exact command"],
                "status": "pending",
            }]
        },
    }, default=str)[:8000]
    data = _call_ollama(
        prompt,
        model=model if model is not None else DEFAULT_MODEL,
        ollama_url=ollama_url or DEFAULT_OLLAMA_URL,
    )
    proposals = data.get("proposals", []) if isinstance(data, dict) else []
    if not proposals:
        proposals = _fallback_proposals(signals)
    plan = {
        "generated_at": int(time.time()),
        "root": str(Path(root).expanduser().resolve()),
        "workspace": str(base),
        "proposals": proposals,
        "signals": signals,
    }
    _write_json(base / PLAN_FILE, plan)
    return plan


def record_self_update_outcome(
    summary: str,
    changed_files: List[str] = None,
    verification: List[Dict[str, Any]] = None,
    workspace: str = None,
) -> Dict[str, Any]:
    """Persist a lesson after Nova modifies or evaluates its own code."""
    base = Path(os.path.expanduser(workspace)) if workspace else WORKSPACE
    memory_path = base / MEMORY_FILE
    memory = _read_json(memory_path, {"lessons": [], "outcomes": []})
    outcome = {
        "timestamp": int(time.time()),
        "summary": summary,
        "changed_files": changed_files or [],
        "verification": verification or [],
    }
    memory.setdefault("outcomes", []).append(outcome)
    if summary:
        memory.setdefault("lessons", []).append(summary[:500])
    _write_json(memory_path, memory)
    return {"success": True, "memory_file": str(memory_path), "outcome": outcome}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Nova local self-improvement planner")
    parser.add_argument("--root", default=".")
    parser.add_argument("--workspace", default=None)
    parser.add_argument("--model", default=None)
    args = parser.parse_args()
    print(json.dumps(generate_improvement_plan(args.root, args.workspace, args.model), indent=2))
