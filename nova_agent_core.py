#!/usr/bin/env python3
# NOVA AGENT CORE v1.0 - AUTONOMOUS REASONING ENGINE

import json
import os
import sys
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from nova_tool_kit import execute_tool, tools_summary_for_prompt, TOOL_SCHEMAS

try:
    from nova_model_router import get_router
    _ROUTER_AVAILABLE = True
except ImportError:
    _ROUTER_AVAILABLE = False

try:
    from nova_rag_builder import get_rag_context
    _RAG_AVAILABLE = True
except ImportError:
    _RAG_AVAILABLE = False

OLLAMA_URL = os.getenv("NOVA_LLM_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("NOVA_LLM_MODEL", "")
MAX_STEPS = int(os.getenv("NOVA_MAX_STEPS", "30"))
AGENT_TIMEOUT = int(os.getenv("NOVA_LLM_TIMEOUT", "120"))
WORKSPACE = os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace"))
REFLECT_EVERY = int(os.getenv("NOVA_REFLECT_EVERY", "5"))
HISTORY_LIMIT = int(os.getenv("NOVA_HISTORY_LIMIT", "30"))

# === SYSTEM PROMPT ===
AGENT_SYSTEM_PROMPT = """You operate like a senior human researcher: you plan, inspect evidence, use tools deliberately, and adapt your strategy based on observations, and verify conclusions before reporting them.

You work in a ReAct loop:
THINK: reason about what you know and what to try next
ACT: call exactly one tool
OBSERVE: study the result and plan your next step

RULES:
1. Always output valid JSON with "thought", "action", and "args" fields.
2. Never guess -- use tools to observe before concluding.
3. Chain your findings: a leaked JWT enables admin access, admin access enables data exfiltration.
4. Verify every finding before reporting it -- false positives waste bounty budgets.
5. When you find something critical, write it to a findings file.
6. Call mission_complete only when you have exhausted the attack surface or reached the objective.
7. Keep a running plan in thoughts. Update it as you learn.
8. If a tool fails, inspect the error and try a different approach. Do not repeat the exact same command.
11. To improve yourself on Nova's repo, choose one tool or logic on Nova's repo, test it, create git checkpoint, run test, if tests fail, inspect the failure, make the small patch, repeat until tests pass, or revert if change is bad.
12. Self-updates must remain local, auditable, reverted if bad, and never rewritten manually.
"""

OUTPUT_FORMAT = """{
  "thought": "What I know so far and why I'm choosing this action",
  "action": "tool_name",
  "args": {...}
}"""

class NovaAgent:
    """Nova's true agentic execution engine."""
    def __init__(self, target: str, objective: str = "Find and exploit all critical vulnerabilities. Start with recon, then attack the high risk-endpoints, and exfiltrate data.", max_steps: int = 30, session_id: Optional[str] = None):
        self.target = target
        self.objective = objective
        self.max_steps = max_steps
        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.history = []
        self.plan = []
        self.findings = []
        self.start_time = None
        self.is_done = False
        self.self_reflection = False
        self.self_index_built = False
        self.self_verification = []
        self.model = OLLAMA_MODEL
        if not self.model and _ROUTER_AVAILABLE:
            try:
                router = get_router()
                self.model = router.best_model_for("attack_planning")
            except Exception:
                pass
        if not self.model:
            self.model = "llama3"

        if _RAG_AVAILABLE:
            self.self_load_rag = True
        else:
            self.self_load_rag = False

        os.makedirs(WORKSPACE, exist_ok=True)
        self.log_file = os.path.join(WORKSPACE, f"nova_run_{self.session_id}.log")
        self.findings_file = os.path.join(WORKSPACE, f"nova_findings_{self.session_id}.json")
        self.self_plan_file = os.path.join(WORKSPACE, f"nova_plan_{self.session_id}.json")

    def _detect_model(self) -> str:
        """Pick best available model on local system."""
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                preferred = ["deepseek-coder", "deepseek-r1", "qwen2.5-coder", "llama3"]
                for p in preferred:
                    for m in models:
                        if p in m:
                            return m
                if models:
                    return models[0]
        except Exception:
            pass
        return "llama3"

    def _load_rag(self) -> str:
        """Load relevant past findings or repo index context."""
        if not self.self_load_rag:
            return ""
        try:
            entries = query_repo_index(self.target)
            if entries:
                return "\n".join(entries)
        except Exception:
            pass
        return ""

    def _build_system_prompt(self) -> str:
        """Assemble the complete context window prompt."""
        prompt = AGENT_SYSTEM_PROMPT
        rag_context = self._load_rag()
        if rag_context:
            prompt += f"\n\nPAST FINDINGS / REPO INDEX:\n{rag_context}"
        
        prompt += f"\n\nAVAILABLE TOOLS:\n{tools_summary_for_prompt()}"
        prompt += f"\n\nEXPECTED OUTPUT FORMAT:\n{OUTPUT_FORMAT}"
        return prompt

    def _bootstrap_repo_index(self):
        """Build index of the local repository for self-improvement."""
        if self.self_index_built:
            return
        print("[*] Bootstrapping repository intelligence index...")
        try:
            from nova_repo_intelligence import update_index
            update_index()
            self.self_index_built = True
        except Exception as e:
            print(f"[!] Failed to bootstrap index: {e}")

    def _record_self_verification(self, tool_name: str, args: Dict[str, Any], result: Dict[str, Any]):
        """Record execution logs for local feedback loop."""
        self.self_verification.append({
            "tool": tool_name,
            "args": args,
            "success": result.get("success", False),
            "output": result.get("stdout", "") or result.get("error", "")
        })

    def run(self) -> Dict[str, Any]:
        """Execute the complete autonomous agentic loop."""
        self.start_time = time.time()
        print(f"[*] Nova Agent started. Session: {self.session_id}")
        
        self.history.append({
            "role": "user",
            "content": f"TARGET: {self.target}\nOBJECTIVE: {self.objective}"
        })
        
        step = 0
        while step < self.max_steps and not self.is_done:
            step += 1
            print(f"\n[+] STEP {step}/{self.max_steps}")
            
            if "self-improve" in self.objective or "self_improvement" in self.objective:
                self._bootstrap_repo_index()
                
            prompt = self._build_system_prompt()
            messages = [{"role": "system", "content": prompt}] + self.history
            
            response = self._call_ollama(messages)
            if not response:
                print("[!] Empty response from LLM, retrying...")
                time.sleep(2)
                continue
                
            self.history.append({"role": "assistant", "content": response})
            
            parsed = self._parse_action(response)
            if not parsed:
                parsed = self._fallback_parse(response)
                
            if not parsed:
                print("[!] Failed to parse action. Retrying step...")
                self.history.append({
                    "role": "user",
                    "content": "Error: Your previous output was not a valid JSON. Please output EXACTLY a single JSON object."
                })
                continue
                
            thought = parsed.get("thought", "")
            tool_name = parsed.get("action", "")
            args = parsed.get("args", {})
            
            print(f"[THOUGHT] {thought}")
            print(f"[ACT] {tool_name}({args})")
            
            if tool_name == "mission_complete":
                print("[+] Mission accomplished! Stopping loop.")
                self.is_done = True
                break
                
            result = execute_tool(tool_name, args)
            self._record_self_verification(tool_name, args, result)
            
            obs_text = self._format_observation(tool_name, result)
            print(f"[OBSERVE] {obs_text[:200]}...")
            
            self.history.append({
                "role": "user",
                "content": obs_text
            })
            
            if step % REFLECT_EVERY == 0:
                self._reflect()
                
        self._harvest_findings()
        elapsed = time.time() - self.start_time
        return {
            "steps": step,
            "duration": elapsed,
            "findings": len(self.findings)
        }

    def _call_ollama(self, messages: List[Dict]) -> str:
        """Call local Ollama service."""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 1024
            }
        }
        try:
            r = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=AGENT_TIMEOUT)
            if r.status_code == 200:
                return r.json().get("message", {}).get("content", "")
        except Exception as e:
            print(f"[!] Ollama error: {e}")
        return ""

    def _parse_action(self, text: str) -> Optional[Dict]:
        """Extract and parse action JSON from LLM output."""
        try:
            cleaned = text.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```[a-zA-Z]*\n", "", cleaned)
                cleaned = re.sub(r"\n```$", "", cleaned)
            cleaned = cleaned.strip()
            return json.loads(cleaned)
        except Exception:
            pass
        
        try:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
        except Exception:
            pass
        return None

    def _fallback_parse(self, text: str) -> Optional[Dict]:
        """Regex fallback to extract thought and action fields."""
        try:
            thought_match = re.search(r'"thought"\s*:\s*"([^"]+)"', text)
            action_match = re.search(r'"action"\s*:\s*"([^"]+)"', text)
            args_match = re.search(r'"args"\s*:\s*(\{.*\})', text, re.DOTALL)
            
            if action_match:
                thought = thought_match.group(1) if thought_match else ""
                action = action_match.group(1)
                args = {}
                if args_match:
                    try:
                        args = json.loads(args_match.group(1))
                    except Exception:
                        pass
                return {"thought": thought, "action": action, "args": args}
        except Exception:
            pass
        return None

    def _format_observation(self, tool_name: str, result: Dict) -> str:
        """Format tool execution results into model-readable context."""
        if result.get("success", False):
            status = "SUCCESS"
        else:
            status = "FAILED"
            
        output = f"Tool '{tool_name}' executed. Status: {status}\n"
        if "stdout" in result and result["stdout"]:
            output += f"Output:\n{result['stdout']}\n"
        if "stderr" in result and result["stderr"]:
            output += f"Error Output:\n{result['stderr']}\n"
        if "error" in result and result["error"]:
            output += f"Execution Error:\n{result['error']}\n"
        if "content" in result:
            output += f"File Contents:\n{result['content']}\n"
        if "matches" in result:
            output += f"Grep Matches:\n{json.dumps(result['matches'], indent=2)}\n"
            
        if len(output) > 4000:
            output = output[:4000] + "\n... [Output Truncated by Host] ..."
        return output

    def _compact_history(self):
        """Truncate history context to keep latest context window active."""
        if len(self.history) > HISTORY_LIMIT:
            self.history = self.history[:2] + self.history[-10:]

    def _reflect(self):
        """Force self reflection step to adapt planning strategy."""
        print("[*] Initiating self-reflection cycle...")
        prompt = "Reflect on your previous steps. What worked, what failed, and how must you adapt your strategy to reach the objective? Output JSON only."
        messages = [
            {"role": "system", "content": "You are a self-improving runtime controller. Analyze your execution log and output a list of critical adjustments."}
        ] + self.history[-6:] + [{"role": "user", "content": prompt}]
        
        resp = self._call_ollama(messages)
        if resp:
            self.history.append({
                "role": "user",
                "content": f"Self-Reflection Strategy Update: {resp}"
            })

    def _harvest_findings(self):
        """Scan logs and local workspaces for files written by self during run."""
        print("[*] Harvesting security vulnerabilities and reports...")
        findings_list = []
        try:
            for p in Path(WORKSPACE).glob("*.json"):
                if "findings" in p.name:
                    try:
                        with open(p, "r") as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                findings_list.extend(data)
                            elif isinstance(data, dict):
                                findings_list.append(data)
                        except Exception:
                            continue
            seen = set()
            deduped = []
            for f in findings_list:
                fid = f.get("id") or f.get("title") or str(f)
                if fid not in seen:
                    seen.add(fid)
                    deduped.append(f)
            self.findings = deduped
            with open(self.findings_file, "w") as f:
                json.dump(self.findings, f, indent=2)
            print(f"[+] Successfully harvested {len(self.findings)} findings.")
        except Exception as e:
            print(f"[!] Failed to harvest findings: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Nova Agent - Autonomous security assessment")
    parser.add_argument("--target", default="http://localhost:3000", help="Target URL or system")
    parser.add_argument("--objective", default="Find and exploit all critical vulnerabilities. Start with recon, then attack the high risk-endpoints, and exfiltrate data.", help="Mission objective")
    parser.add_argument("--max-steps", type=int, default=30, help="Maximum execution steps")
    
    args = parser.parse_args()
    
    agent = NovaAgent(target=args.target, objective=args.objective, max_steps=args.max_steps)
    agent.run()
