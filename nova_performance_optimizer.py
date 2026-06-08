"""
NOVA PERFORMANCE OPTIMIZER
===========================
Performance layer for NovaKaliAgent.

Features:
- Parallel tool execution
- Smart tool selection (fastest first)
- Resource scheduling
- Caching results
- Optimization recommendations

Usage:
    from nova_performance_optimizer import NovaPerformanceOptimizer
    optimizer = NovaPerformanceOptimizer()
    
    # Wrap your ExecutionPlan before executing
    optimized_plan = optimizer.optimize(plan)
    
    # Or run tools in parallel
    results = optimizer.run_parallel(tool_commands, target)
"""

import time
import hashlib
import json
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# TOOL SPEED PROFILES
# How long each Kali tool typically takes (seconds)
# Used for "fastest first" scheduling
# ──────────────────────────────────────────────
TOOL_SPEED_PROFILE = {
    # Very fast (< 5s)
    "whois":       {"avg_time": 2,   "category": "recon",        "weight": 1},
    "dig":         {"avg_time": 1,   "category": "recon",        "weight": 1},
    "nslookup":    {"avg_time": 1,   "category": "recon",        "weight": 1},
    "ping":        {"avg_time": 3,   "category": "recon",        "weight": 1},
    "curl":        {"avg_time": 3,   "category": "web",          "weight": 1},
    "wget":        {"avg_time": 4,   "category": "web",          "weight": 1},
    "host":        {"avg_time": 1,   "category": "recon",        "weight": 1},

    # Fast (5–30s)
    "nmap":        {"avg_time": 20,  "category": "scanning",     "weight": 2},
    "masscan":     {"avg_time": 10,  "category": "scanning",     "weight": 2},
    "nikto":       {"avg_time": 60,  "category": "web",          "weight": 3},
    "gobuster":    {"avg_time": 30,  "category": "web",          "weight": 2},
    "dirb":        {"avg_time": 45,  "category": "web",          "weight": 3},
    "wfuzz":       {"avg_time": 30,  "category": "web",          "weight": 2},

    # Medium (30s–5min)
    "sqlmap":      {"avg_time": 120, "category": "exploitation", "weight": 4},
    "hydra":       {"avg_time": 180, "category": "password",     "weight": 4},
    "john":        {"avg_time": 300, "category": "password",     "weight": 5},
    "hashcat":     {"avg_time": 300, "category": "password",     "weight": 5},
    "medusa":      {"avg_time": 120, "category": "password",     "weight": 4},

    # Slow (> 5min)
    "metasploit":  {"avg_time": 600, "category": "exploitation", "weight": 6},
    "openvas":     {"avg_time": 900, "category": "scanning",     "weight": 7},
    "nessus":      {"avg_time": 900, "category": "scanning",     "weight": 7},
    "burpsuite":   {"avg_time": 600, "category": "web",          "weight": 6},
}

# Tools that can safely run in parallel (don't interfere with each other)
PARALLELIZABLE_CATEGORIES = {"recon", "scanning", "web"}

# Tools that should run sequentially (results feed into each other)
SEQUENTIAL_CATEGORIES = {"exploitation", "post_exploitation", "password"}


# ──────────────────────────────────────────────
# CACHE
# ──────────────────────────────────────────────

@dataclass
class CacheEntry:
    key: str
    result: Any
    timestamp: float
    hits: int = 0
    tool: str = ""
    target: str = ""


class ResultCache:
    """
    In-memory cache for tool results.
    Avoids re-running the same command on the same target.
    """

    def __init__(self, ttl_seconds: int = 3600):
        self._store: Dict[str, CacheEntry] = {}
        self.ttl = ttl_seconds
        self.hits = 0
        self.misses = 0

    def _make_key(self, tool: str, command: str, target: str) -> str:
        raw = f"{tool}:{command}:{target}"
        return hashlib.md5(raw.encode()).hexdigest()

    def get(self, tool: str, command: str, target: str) -> Optional[Any]:
        key = self._make_key(tool, command, target)
        entry = self._store.get(key)
        if entry is None:
            self.misses += 1
            return None
        if time.time() - entry.timestamp > self.ttl:
            del self._store[key]
            self.misses += 1
            return None
        entry.hits += 1
        self.hits += 1
        logger.debug(f"Cache HIT for {tool} on {target}")
        return entry.result

    def set(self, tool: str, command: str, target: str, result: Any):
        key = self._make_key(tool, command, target)
        self._store[key] = CacheEntry(
            key=key,
            result=result,
            timestamp=time.time(),
            tool=tool,
            target=target
        )

    def clear(self):
        self._store.clear()

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        return {
            "total_requests": total,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{(self.hits / total * 100):.1f}%" if total > 0 else "0%",
            "cached_entries": len(self._store)
        }


# ──────────────────────────────────────────────
# RESOURCE SCHEDULER
# ──────────────────────────────────────────────

@dataclass
class ResourceBudget:
    max_parallel_workers: int = 4
    max_memory_mb: int = 512
    max_cpu_percent: int = 80
    timeout_per_tool: int = 300  # seconds


class ResourceScheduler:
    """
    Decides how many tools can run at once based on
    their weight and current resource budget.
    """

    def __init__(self, budget: Optional[ResourceBudget] = None):
        self.budget = budget or ResourceBudget()

    def schedule(self, tools: List[Dict]) -> Tuple[List[List[Dict]], int]:
        """
        Split tools into execution batches.
        
        Returns:
            (batches, recommended_workers)
            batches: list of groups that can run in parallel
        """
        parallel_tools = []
        sequential_tools = []

        for t in tools:
            cat = t.get("category", "recon")
            if cat in PARALLELIZABLE_CATEGORIES:
                parallel_tools.append(t)
            else:
                sequential_tools.append(t)

        # Calculate safe worker count based on total weight
        total_weight = sum(t.get("weight", 1) for t in parallel_tools)
        recommended_workers = min(
            self.budget.max_parallel_workers,
            max(1, self.budget.max_parallel_workers - (total_weight // 10))
        )

        # Build batches: parallel tools go in one batch, sequential each get their own
        batches = []
        if parallel_tools:
            batches.append(parallel_tools)
        for t in sequential_tools:
            batches.append([t])

        return batches, recommended_workers

    def can_add_tool(self, current_tools: List[Dict], new_tool: Dict) -> bool:
        """Check if adding a tool would exceed resource budget"""
        current_weight = sum(t.get("weight", 1) for t in current_tools)
        new_weight = new_tool.get("weight", 1)
        return (current_weight + new_weight) <= self.budget.max_parallel_workers * 2


# ──────────────────────────────────────────────
# SMART TOOL SELECTOR
# ──────────────────────────────────────────────

class SmartToolSelector:
    """
    Given a task type and target, picks the best tools
    and orders them fastest-first.
    """

    def select_and_sort(
        self,
        task_type: str,
        available_tools: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Select tools relevant to task_type and sort by speed (fastest first).
        
        Returns list of tool dicts with metadata.
        """
        selected = []

        for tool_name in available_tools:
            profile = TOOL_SPEED_PROFILE.get(tool_name)
            if profile is None:
                # Unknown tool — add with default profile
                profile = {"avg_time": 60, "category": "custom", "weight": 3}

            selected.append({
                "name": tool_name,
                "avg_time": profile["avg_time"],
                "category": profile["category"],
                "weight": profile["weight"]
            })

        # Sort: fastest first
        selected.sort(key=lambda x: x["avg_time"])
        return selected

    def fastest_for_task(self, task_type: str) -> List[str]:
        """Return the fastest tools available for a given task type"""
        task_map = {
            "recon":          ["dig", "whois", "nslookup", "nmap"],
            "scanning":       ["masscan", "nmap"],
            "web":            ["curl", "gobuster", "nikto"],
            "password":       ["john", "hashcat", "hydra"],
            "exploitation":   ["sqlmap", "metasploit"],
            "vuln_assessment":["nmap", "nikto", "openvas"],
        }
        tools = task_map.get(task_type, ["nmap", "whois"])
        # Sort by speed profile
        return sorted(tools, key=lambda t: TOOL_SPEED_PROFILE.get(t, {}).get("avg_time", 99))


# ──────────────────────────────────────────────
# PARALLEL EXECUTOR
# ──────────────────────────────────────────────

@dataclass
class ToolResult:
    tool: str
    command: str
    target: str
    output: str
    success: bool
    duration: float
    from_cache: bool = False
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ParallelExecutor:
    """
    Runs multiple tool commands concurrently using ThreadPoolExecutor.
    Respects resource budget and timeout limits.
    """

    def __init__(
        self,
        cache: ResultCache,
        budget: Optional[ResourceBudget] = None,
        dry_run: bool = False
    ):
        self.cache = cache
        self.budget = budget or ResourceBudget()
        self.dry_run = dry_run  # If True: don't actually run commands

    def run_parallel(
        self,
        tool_commands: List[str],
        target: str,
        workers: int = 4
    ) -> List[ToolResult]:
        """
        Execute tool commands in parallel.
        
        Args:
            tool_commands: list of shell commands e.g. ["nmap -sV 192.168.1.1"]
            target: target string (used for cache keying)
            workers: number of parallel threads
            
        Returns:
            List of ToolResult objects
        """
        results = []
        futures_map = {}

        with ThreadPoolExecutor(max_workers=workers) as executor:
            for cmd in tool_commands:
                tool_name = cmd.split()[0]

                # Check cache first
                cached = self.cache.get(tool_name, cmd, target)
                if cached is not None:
                    results.append(ToolResult(
                        tool=tool_name,
                        command=cmd,
                        target=target,
                        output=cached,
                        success=True,
                        duration=0.0,
                        from_cache=True
                    ))
                    continue

                future = executor.submit(self._run_single, cmd, target)
                futures_map[future] = cmd

            for future in as_completed(futures_map, timeout=self.budget.timeout_per_tool * len(futures_map) + 10):
                cmd = futures_map[future]
                tool_name = cmd.split()[0]
                try:
                    result = future.result(timeout=self.budget.timeout_per_tool)
                    self.cache.set(tool_name, cmd, target, result.output)
                    results.append(result)
                except TimeoutError:
                    results.append(ToolResult(
                        tool=tool_name,
                        command=cmd,
                        target=target,
                        output="",
                        success=False,
                        duration=float(self.budget.timeout_per_tool),
                        error="Timeout exceeded"
                    ))
                except Exception as e:
                    results.append(ToolResult(
                        tool=tool_name,
                        command=cmd,
                        target=target,
                        output="",
                        success=False,
                        duration=0.0,
                        error=str(e)
                    ))

        return results

    def _run_single(self, command: str, target: str) -> ToolResult:
        """Run a single command and return result"""
        tool_name = command.split()[0]
        start = time.time()

        if self.dry_run:
            time.sleep(0.1)  # Simulate execution
            return ToolResult(
                tool=tool_name,
                command=command,
                target=target,
                output=f"[DRY RUN] Would execute: {command}",
                success=True,
                duration=0.1
            )

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.budget.timeout_per_tool
            )
            duration = time.time() - start
            return ToolResult(
                tool=tool_name,
                command=command,
                target=target,
                output=proc.stdout + proc.stderr,
                success=proc.returncode == 0,
                duration=duration
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=tool_name,
                command=command,
                target=target,
                output="",
                success=False,
                duration=time.time() - start,
                error="Command timed out"
            )
        except Exception as e:
            return ToolResult(
                tool=tool_name,
                command=command,
                target=target,
                output="",
                success=False,
                duration=time.time() - start,
                error=str(e)
            )


# ──────────────────────────────────────────────
# OPTIMIZATION RECOMMENDATIONS ENGINE
# ──────────────────────────────────────────────

class OptimizationAdvisor:
    """
    Analyzes execution results and gives recommendations
    to improve future runs.
    """

    def analyze(self, results: List[ToolResult]) -> Dict[str, Any]:
        """Generate optimization recommendations from results"""
        recommendations = []
        warnings = []
        stats = self._compute_stats(results)

        # Check for slow tools
        for r in results:
            profile = TOOL_SPEED_PROFILE.get(r.tool, {})
            expected = profile.get("avg_time", 60)
            if r.duration > expected * 2:
                recommendations.append(
                    f"'{r.tool}' took {r.duration:.1f}s (expected ~{expected}s). "
                    f"Consider adding --max-rate or reducing scan scope."
                )

        # Check for failures
        failed = [r for r in results if not r.success]
        if failed:
            warnings.append(
                f"{len(failed)} tool(s) failed: {[r.tool for r in failed]}"
            )

        # Cache efficiency
        cached = [r for r in results if r.from_cache]
        if len(cached) > 0:
            recommendations.append(
                f"{len(cached)} result(s) served from cache — "
                f"saved ~{sum(TOOL_SPEED_PROFILE.get(r.tool, {}).get('avg_time', 10) for r in cached)}s"
            )

        # Parallelization suggestion
        slow_recon = [
            r for r in results
            if TOOL_SPEED_PROFILE.get(r.tool, {}).get("category") == "recon"
            and r.duration > 5
        ]
        if len(slow_recon) > 1:
            recommendations.append(
                "Multiple slow recon tools detected. Consider increasing parallel workers."
            )

        return {
            "stats": stats,
            "recommendations": recommendations,
            "warnings": warnings,
            "overall_score": self._score(results)
        }

    def _compute_stats(self, results: List[ToolResult]) -> Dict:
        if not results:
            return {}
        durations = [r.duration for r in results]
        return {
            "total_tools": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
            "from_cache": sum(1 for r in results if r.from_cache),
            "total_time_s": round(sum(durations), 2),
            "avg_time_s": round(sum(durations) / len(durations), 2),
            "slowest_tool": max(results, key=lambda r: r.duration).tool
        }

    def _score(self, results: List[ToolResult]) -> str:
        if not results:
            return "N/A"
        success_rate = sum(1 for r in results if r.success) / len(results)
        cache_rate = sum(1 for r in results if r.from_cache) / len(results)
        score = (success_rate * 0.6) + (cache_rate * 0.4)
        if score >= 0.8:
            return "EXCELLENT"
        elif score >= 0.6:
            return "GOOD"
        elif score >= 0.4:
            return "FAIR"
        return "POOR"


# ──────────────────────────────────────────────
# MAIN OPTIMIZER — Entry Point
# ──────────────────────────────────────────────

class NovaPerformanceOptimizer:
    """
    Main performance optimizer for NovaKaliAgent.
    
    Plug this into your agent to get:
    - Parallel tool execution
    - Smart tool selection (fastest first)
    - Resource scheduling
    - Result caching
    - Optimization recommendations
    
    Example:
        optimizer = NovaPerformanceOptimizer()
        
        # Optimize a list of tool commands before running
        sorted_commands = optimizer.sort_commands_by_speed(plan.tool_commands)
        
        # Run them in parallel
        results = optimizer.run_parallel(sorted_commands, target="192.168.1.1")
        
        # Get recommendations
        report = optimizer.get_report(results)
    """

    def __init__(
        self,
        budget: Optional[ResourceBudget] = None,
        cache_ttl: int = 3600,
        dry_run: bool = False
    ):
        self.budget = budget or ResourceBudget()
        self.cache = ResultCache(ttl_seconds=cache_ttl)
        self.selector = SmartToolSelector()
        self.scheduler = ResourceScheduler(self.budget)
        self.executor = ParallelExecutor(self.cache, self.budget, dry_run=dry_run)
        self.advisor = OptimizationAdvisor()
        self._history: List[ToolResult] = []

        logger.info("NovaPerformanceOptimizer initialized")

    def sort_commands_by_speed(self, commands: List[str]) -> List[str]:
        """
        Sort tool commands fastest-first.
        Pass in plan.tool_commands and get back a sorted list.
        """
        def get_speed(cmd: str) -> int:
            tool = cmd.split()[0]
            return TOOL_SPEED_PROFILE.get(tool, {}).get("avg_time", 60)

        return sorted(commands, key=get_speed)

    def run_parallel(
        self,
        commands: List[str],
        target: str,
        auto_sort: bool = True
    ) -> List[ToolResult]:
        """
        Run commands in parallel with smart scheduling.
        
        Args:
            commands: tool commands to run
            target: target IP/domain
            auto_sort: if True, sort fastest-first automatically
            
        Returns:
            List of ToolResult
        """
        if auto_sort:
            commands = self.sort_commands_by_speed(commands)

        # Get tool metadata for scheduling
        tool_metas = []
        for cmd in commands:
            tool = cmd.split()[0]
            profile = TOOL_SPEED_PROFILE.get(tool, {"category": "custom", "weight": 3})
            tool_metas.append({**profile, "name": tool, "command": cmd})

        _, recommended_workers = self.scheduler.schedule(tool_metas)
        workers = min(recommended_workers, self.budget.max_parallel_workers)

        logger.info(f"Running {len(commands)} commands with {workers} workers on {target}")

        results = self.executor.run_parallel(commands, target, workers=workers)
        self._history.extend(results)
        return results

    def get_report(self, results: Optional[List[ToolResult]] = None) -> Dict[str, Any]:
        """
        Get optimization report for a set of results.
        If results=None, uses full history.
        """
        target_results = results if results is not None else self._history
        analysis = self.advisor.analyze(target_results)
        cache_stats = self.cache.stats()

        return {
            "timestamp": datetime.now().isoformat(),
            "performance": analysis,
            "cache": cache_stats,
            "budget": {
                "max_workers": self.budget.max_parallel_workers,
                "timeout_per_tool": self.budget.timeout_per_tool
            }
        }

    def clear_cache(self):
        """Clear the result cache"""
        self.cache.clear()
        logger.info("Cache cleared")

    def set_budget(self, **kwargs):
        """
        Update resource budget dynamically.
        e.g. optimizer.set_budget(max_parallel_workers=8, timeout_per_tool=120)
        """
        for k, v in kwargs.items():
            if hasattr(self.budget, k):
                setattr(self.budget, k, v)
        logger.info(f"Budget updated: {kwargs}")


# ──────────────────────────────────────────────
# INTEGRATION HELPER
# Monkey-patch helper to plug optimizer into existing NovaKaliAgent
# ──────────────────────────────────────────────

def attach_optimizer(agent, dry_run: bool = False) -> NovaPerformanceOptimizer:
    """
    Attach the performance optimizer to an existing NovaKaliAgent instance.
    
    Usage:
        from nova_performance_optimizer import attach_optimizer
        optimizer = attach_optimizer(nova)
        
        # Now run optimized execution
        results = optimizer.run_parallel(plan.tool_commands, target=plan.target)
        print(optimizer.get_report(results))
    
    Args:
        agent: NovaKaliAgent instance
        dry_run: if True, simulate commands without executing
        
    Returns:
        Configured NovaPerformanceOptimizer
    """
    optimizer = NovaPerformanceOptimizer(dry_run=dry_run)
    agent.optimizer = optimizer
    logger.info("Performance optimizer attached to Nova agent")
    return optimizer


# ──────────────────────────────────────────────
# DEMO
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("NOVA PERFORMANCE OPTIMIZER — DEMO")
    print("=" * 60)

    # Initialize optimizer in dry_run mode (no real commands)
    optimizer = NovaPerformanceOptimizer(dry_run=True)

    # Simulate tool commands from a plan
    sample_commands = [
        "nmap -sV 192.168.1.1",
        "whois 192.168.1.1",
        "dig 192.168.1.1",
        "nikto -h 192.168.1.1",
        "gobuster dir -u http://192.168.1.1 -w wordlist.txt",
        "masscan 192.168.1.1 -p1-1000"
    ]

    print(f"\n[1] Original command order:")
    for cmd in sample_commands:
        print(f"    {cmd}")

    sorted_cmds = optimizer.sort_commands_by_speed(sample_commands)
    print(f"\n[2] Sorted fastest-first:")
    for cmd in sorted_cmds:
        tool = cmd.split()[0]
        speed = TOOL_SPEED_PROFILE.get(tool, {}).get("avg_time", "?")
        print(f"    [{speed}s] {cmd}")

    print(f"\n[3] Running in parallel (dry run)...")
    results = optimizer.run_parallel(sample_commands, target="192.168.1.1")

    print(f"\n[4] Results:")
    for r in results:
        cache_tag = "[CACHE]" if r.from_cache else ""
        print(f"    {r.tool}: {'OK' if r.success else 'FAIL'} ({r.duration:.2f}s) {cache_tag}")

    print(f"\n[5] Running same commands again (should hit cache)...")
    results2 = optimizer.run_parallel(sample_commands, target="192.168.1.1")
    cached_count = sum(1 for r in results2 if r.from_cache)
    print(f"    {cached_count}/{len(results2)} served from cache")

    print(f"\n[6] Optimization Report:")
    report = optimizer.get_report(results)
    print(json.dumps(report, indent=2))

    print("\n" + "=" * 60)
    print("Attach to your agent: optimizer = attach_optimizer(nova)")
    print("=" * 60)
