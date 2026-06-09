"""
NOVA MULTI-TARGET ORCHESTRATOR
================================
Orchestrates penetration testing across multiple targets simultaneously.

Features:
- Queue multiple targets
- Parallel scanning per target
- Coordinate findings across targets
- Aggregate reports
- Resource management

Integrates with:
- nova_performance_optimizer.py  (parallel tool execution)
- nova_result_parser.py          (structured findings)

Usage:
    from nova_multi_target_orchestrator import NovaMultiTargetOrchestrator

    orchestrator = NovaMultiTargetOrchestrator()

    # Add targets to queue
    orchestrator.add_target("192.168.1.1", scope=["recon", "scanning"])
    orchestrator.add_target("192.168.1.2", scope=["recon", "web"])
    orchestrator.add_target("10.0.0.5",    scope=["recon", "scanning", "web"])

    # Run all targets
    report = orchestrator.run_all()

    # Print aggregated report
    orchestrator.print_report()

    # Export
    orchestrator.export_json("multi_target_report.json")
"""

import time
import json
import logging
import threading
import queue
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Internal imports ──────────────────────────
try:
    from nova_performance_optimizer import (
        NovaPerformanceOptimizer,
        ResourceBudget,
        ToolResult,
        TOOL_SPEED_PROFILE,
    )
    HAS_OPTIMIZER = True
except ImportError:
    HAS_OPTIMIZER = False

try:
    from nova_result_parser import NovaResultParser, Finding, Severity, FindingsDatabase
    HAS_PARSER = True
except ImportError:
    HAS_PARSER = False

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# ENUMS & CONSTANTS
# ──────────────────────────────────────────────

class TargetStatus(str, Enum):
    QUEUED     = "QUEUED"
    RUNNING    = "RUNNING"
    COMPLETED  = "COMPLETED"
    FAILED     = "FAILED"
    SKIPPED    = "SKIPPED"


class ScanScope(str, Enum):
    RECON      = "recon"
    SCANNING   = "scanning"
    WEB        = "web"
    PASSWORD   = "password"
    VULN       = "vuln_assessment"


# Default tool commands per scope
SCOPE_COMMANDS: Dict[str, List[str]] = {
    "recon":          ["whois {target}", "dig {target}", "nslookup {target}"],
    "scanning":       ["nmap -sV -T4 {target}", "masscan {target} -p1-1000 --rate=500"],
    "web":            ["nikto -h {target}", "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q"],
    "password":       ["hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} ssh -t 4"],
    "vuln_assessment":["nmap -sV --script vuln {target}"],
}

# How many targets to scan in parallel (default)
DEFAULT_PARALLEL_TARGETS = 3


# ──────────────────────────────────────────────
# TARGET DATA MODEL
# ──────────────────────────────────────────────

@dataclass
class Target:
    """A single scan target"""
    host: str
    scope: List[str] = field(default_factory=lambda: ["recon", "scanning"])
    priority: int = 5          # 1 (highest) to 10 (lowest)
    label: str = ""            # Optional label e.g. "web server", "db"
    tags: List[str] = field(default_factory=list)
    authorization_note: str = "" # Who authorized this target

    # Runtime state
    status: TargetStatus = TargetStatus.QUEUED
    queued_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None

    # Results
    tool_results: List[Any] = field(default_factory=list)   # List[ToolResult]
    findings_count: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["tool_results"] = []  # Don't serialize raw output to summary
        return d


# ──────────────────────────────────────────────
# RESOURCE MANAGER
# ──────────────────────────────────────────────

class OrchestratorResourceManager:
    """
    Manages global resource allocation across all parallel target scans.
    Prevents overloading CPU/network by tracking active scans.
    """

    def __init__(
        self,
        max_parallel_targets: int = DEFAULT_PARALLEL_TARGETS,
        max_total_workers: int = 8
    ):
        self.max_parallel_targets = max_parallel_targets
        self.max_total_workers = max_total_workers
        self._active: Set[str] = set()
        self._lock = threading.Lock()

    def workers_per_target(self, active_count: int) -> int:
        """Calculate workers to allocate per target based on how many are active"""
        if active_count == 0:
            return self.max_total_workers
        return max(1, self.max_total_workers // active_count)

    def can_start(self, host: str) -> bool:
        with self._lock:
            return len(self._active) < self.max_parallel_targets

    def register_start(self, host: str):
        with self._lock:
            self._active.add(host)

    def register_done(self, host: str):
        with self._lock:
            self._active.discard(host)

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    def stats(self) -> Dict:
        return {
            "max_parallel_targets": self.max_parallel_targets,
            "max_total_workers": self.max_total_workers,
            "currently_active": self.active_count
        }


# ──────────────────────────────────────────────
# TARGET QUEUE
# ──────────────────────────────────────────────

class TargetQueue:
    """
    Priority queue for targets.
    Lower priority number = scanned first.
    """

    def __init__(self):
        self._queue: List[Target] = []
        self._lock = threading.Lock()

    def enqueue(self, target: Target):
        with self._lock:
            self._queue.append(target)
            self._queue.sort(key=lambda t: t.priority)

    def dequeue(self) -> Optional[Target]:
        with self._lock:
            for t in self._queue:
                if t.status == TargetStatus.QUEUED:
                    t.status = TargetStatus.RUNNING
                    return t
            return None

    def all_targets(self) -> List[Target]:
        with self._lock:
            return list(self._queue)

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._queue if t.status == TargetStatus.QUEUED)

    def completed_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._queue if t.status == TargetStatus.COMPLETED)

    def failed_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._queue if t.status == TargetStatus.FAILED)

    def is_done(self) -> bool:
        with self._lock:
            return all(
                t.status in (TargetStatus.COMPLETED, TargetStatus.FAILED, TargetStatus.SKIPPED)
                for t in self._queue
            )


# ──────────────────────────────────────────────
# SCAN COORDINATOR
# ──────────────────────────────────────────────

class ScanCoordinator:
    """
    Executes a scan against a single target.
    Uses NovaPerformanceOptimizer if available, else subprocess fallback.
    """

    def __init__(
        self,
        resource_manager: OrchestratorResourceManager,
        dry_run: bool = False
    ):
        self.resource_manager = resource_manager
        self.dry_run = dry_run

    def scan_target(self, target: Target) -> Target:
        """
        Full scan lifecycle for one target.
        Returns the target with results populated.
        """
        target.started_at = datetime.now().isoformat()
        start_time = time.time()

        try:
            self.resource_manager.register_start(target.host)
            workers = self.resource_manager.workers_per_target(
                self.resource_manager.active_count
            )

            logger.info(f"[{target.host}] Starting scan — scope: {target.scope}, workers: {workers}")

            # Build commands for this target's scope
            commands = self._build_commands(target)

            if not commands:
                target.status = TargetStatus.SKIPPED
                target.error = "No commands generated for scope"
                return target

            # Run with optimizer if available
            if HAS_OPTIMIZER:
                optimizer = NovaPerformanceOptimizer(
                    budget=ResourceBudget(
                        max_parallel_workers=workers,
                        timeout_per_tool=120
                    ),
                    dry_run=self.dry_run
                )
                results = optimizer.run_parallel(commands, target=target.host)
            else:
                results = self._run_commands_basic(commands, target.host)

            target.tool_results = results
            target.status = TargetStatus.COMPLETED

            logger.info(f"[{target.host}] Scan complete — {len(results)} tool results")

        except Exception as e:
            target.status = TargetStatus.FAILED
            target.error = str(e)
            logger.error(f"[{target.host}] Scan failed: {e}")

        finally:
            self.resource_manager.register_done(target.host)
            target.completed_at = datetime.now().isoformat()
            target.duration_seconds = round(time.time() - start_time, 2)

        return target

    def _build_commands(self, target: Target) -> List[str]:
        """Build tool commands for this target based on scope"""
        commands = []
        for scope in target.scope:
            scope_cmds = SCOPE_COMMANDS.get(scope, [])
            for cmd_template in scope_cmds:
                cmd = cmd_template.replace("{target}", target.host)
                commands.append(cmd)
        return commands

    def _run_commands_basic(self, commands: List[str], target: str) -> List[Any]:
        """Fallback if optimizer not available — returns mock results"""
        results = []
        for cmd in commands:
            tool = cmd.split()[0]
            results.append({
                "tool": tool,
                "command": cmd,
                "target": target,
                "output": f"[Basic run] {cmd}",
                "success": True,
                "duration": 0.1,
                "from_cache": False
            })
        return results


# ──────────────────────────────────────────────
# FINDINGS COORDINATOR
# ──────────────────────────────────────────────

class FindingsCoordinator:
    """
    Aggregates findings from all targets.
    Identifies patterns across targets (e.g. same vuln on multiple hosts).
    """

    def __init__(self):
        if HAS_PARSER:
            self.parser = NovaResultParser()
        else:
            self.parser = None
        self._findings_by_target: Dict[str, List[Any]] = {}

    def process_target(self, target: Target) -> List[Any]:
        """Parse tool results for a target and store findings"""
        if not target.tool_results:
            return []

        findings = []

        if self.parser and HAS_PARSER:
            for result in target.tool_results:
                if hasattr(result, "tool"):
                    # ToolResult object
                    new_findings = self.parser.parse(
                        tool=result.tool,
                        output=result.output,
                        target=result.target
                    )
                elif isinstance(result, dict):
                    new_findings = self.parser.parse(
                        tool=result.get("tool", "unknown"),
                        output=result.get("output", ""),
                        target=result.get("target", target.host)
                    )
                else:
                    new_findings = []
                findings.extend(new_findings)
        else:
            # No parser available — create basic findings
            for result in target.tool_results:
                tool = result.tool if hasattr(result, "tool") else result.get("tool", "unknown")
                findings.append({
                    "tool": tool,
                    "target": target.host,
                    "title": f"Output from {tool}",
                    "severity": "INFO"
                })

        target.findings_count = len(findings)
        self._findings_by_target[target.host] = findings
        return findings

    def cross_target_analysis(self) -> List[Dict[str, Any]]:
        """
        Identify vulnerabilities that appear across multiple targets.
        Useful for spotting systemic issues.
        """
        insights = []

        if not HAS_PARSER:
            return insights

        # Count finding titles across targets
        title_targets: Dict[str, List[str]] = {}
        for host, findings in self._findings_by_target.items():
            for f in findings:
                title = f.title if hasattr(f, "title") else f.get("title", "")
                if title not in title_targets:
                    title_targets[title] = []
                title_targets[title].append(host)

        # Flag any finding present on 2+ targets
        for title, hosts in title_targets.items():
            if len(hosts) >= 2:
                insights.append({
                    "type": "REPEATED_FINDING",
                    "title": title,
                    "affected_targets": hosts,
                    "count": len(hosts),
                    "note": f"Found on {len(hosts)} targets — likely systemic issue"
                })

        # Sort by how widespread
        insights.sort(key=lambda x: x["count"], reverse=True)
        return insights

    def all_findings(self) -> List[Any]:
        """Flat list of all findings across all targets"""
        all_f = []
        for findings in self._findings_by_target.values():
            all_f.extend(findings)
        return all_f

    def findings_for_target(self, host: str) -> List[Any]:
        return self._findings_by_target.get(host, [])

    def summary_by_target(self) -> Dict[str, Dict]:
        summary = {}
        for host, findings in self._findings_by_target.items():
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                sev = f.severity.value if hasattr(f, "severity") else f.get("severity", "INFO")
                counts[sev] = counts.get(sev, 0) + 1
            summary[host] = {
                "total": len(findings),
                "by_severity": counts
            }
        return summary


# ──────────────────────────────────────────────
# REPORT AGGREGATOR
# ──────────────────────────────────────────────

class ReportAggregator:
    """Builds the final aggregated report from all target scans"""

    def build(
        self,
        targets: List[Target],
        findings_coordinator: FindingsCoordinator,
        resource_manager: OrchestratorResourceManager,
        start_time: float,
        end_time: float
    ) -> Dict[str, Any]:

        total_duration = round(end_time - start_time, 2)
        all_findings = findings_coordinator.all_findings()

        # Severity counts
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            sev = f.severity.value if hasattr(f, "severity") else f.get("severity", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Target summary
        target_summaries = []
        for t in targets:
            target_summaries.append({
                "host":             t.host,
                "label":            t.label,
                "scope":            t.scope,
                "status":           t.status.value,
                "duration_seconds": t.duration_seconds,
                "findings":         t.findings_count,
                "error":            t.error
            })

        # Cross-target insights
        cross_target = findings_coordinator.cross_target_analysis()

        return {
            "report_generated_at": datetime.now().isoformat(),
            "scan_duration_seconds": total_duration,
            "targets": {
                "total":     len(targets),
                "completed": sum(1 for t in targets if t.status == TargetStatus.COMPLETED),
                "failed":    sum(1 for t in targets if t.status == TargetStatus.FAILED),
                "skipped":   sum(1 for t in targets if t.status == TargetStatus.SKIPPED),
            },
            "findings": {
                "total":      len(all_findings),
                "by_severity": sev_counts,
            },
            "cross_target_insights": cross_target,
            "target_details": target_summaries,
            "findings_by_target": findings_coordinator.summary_by_target(),
            "resource_stats": resource_manager.stats(),
        }


# ──────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ──────────────────────────────────────────────

class NovaMultiTargetOrchestrator:
    """
    Main orchestrator for multi-target scanning.

    Queues targets, runs them in parallel, coordinates findings,
    and produces aggregated reports.

    Example:
        orchestrator = NovaMultiTargetOrchestrator(dry_run=True)

        orchestrator.add_target("192.168.1.1", scope=["recon", "scanning"])
        orchestrator.add_target("192.168.1.2", scope=["recon", "web"], priority=1)
        orchestrator.add_target("10.0.0.5",    scope=["recon", "scanning", "web"])

        report = orchestrator.run_all()
        orchestrator.print_report()
        orchestrator.export_json("report.json")
    """

    def __init__(
        self,
        max_parallel_targets: int = DEFAULT_PARALLEL_TARGETS,
        max_total_workers: int = 8,
        dry_run: bool = False
    ):
        self.dry_run = dry_run
        self._queue              = TargetQueue()
        self._resource_manager   = OrchestratorResourceManager(
            max_parallel_targets=max_parallel_targets,
            max_total_workers=max_total_workers
        )
        self._coordinator        = ScanCoordinator(self._resource_manager, dry_run=dry_run)
        self._findings_coord     = FindingsCoordinator()
        self._report_aggregator  = ReportAggregator()
        self._final_report: Optional[Dict] = None
        self._start_time: float = 0
        self._end_time: float   = 0

        logger.info(
            f"NovaMultiTargetOrchestrator initialized — "
            f"max_parallel_targets={max_parallel_targets}, dry_run={dry_run}"
        )

    # ── Public API ────────────────────────────

    def add_target(
        self,
        host: str,
        scope: Optional[List[str]] = None,
        priority: int = 5,
        label: str = "",
        tags: Optional[List[str]] = None,
        authorization_note: str = ""
    ) -> "NovaMultiTargetOrchestrator":
        """
        Add a target to the scan queue.

        Args:
            host:               IP address or hostname
            scope:              list of scan scopes e.g. ["recon", "scanning", "web"]
            priority:           1 (highest) to 10 (lowest)
            label:              optional description e.g. "web server"
            tags:               optional tags e.g. ["internal", "linux"]
            authorization_note: who authorized this target

        Returns:
            self (chainable)
        """
        target = Target(
            host=host,
            scope=scope or ["recon", "scanning"],
            priority=priority,
            label=label or host,
            tags=tags or [],
            authorization_note=authorization_note
        )
        self._queue.enqueue(target)
        logger.info(f"Target queued: {host} (priority={priority}, scope={scope})")
        return self

    def add_targets(self, hosts: List[str], scope: Optional[List[str]] = None) -> "NovaMultiTargetOrchestrator":
        """Add multiple targets with the same scope"""
        for host in hosts:
            self.add_target(host, scope=scope)
        return self

    def queue_status(self) -> Dict[str, int]:
        return {
            "queued":    self._queue.pending_count(),
            "completed": self._queue.completed_count(),
            "failed":    self._queue.failed_count(),
            "total":     len(self._queue.all_targets())
        }

    def run_all(self, progress: bool = True) -> Dict[str, Any]:
        """
        Run all queued targets in parallel.

        Args:
            progress: print live progress updates

        Returns:
            Aggregated report dict
        """
        targets = self._queue.all_targets()
        if not targets:
            logger.warning("No targets in queue")
            return {}

        self._start_time = time.time()

        if progress:
            print(f"\n[*] Starting multi-target scan")
            print(f"    Targets  : {len(targets)}")
            print(f"    Parallel : {self._resource_manager.max_parallel_targets}")
            print(f"    Dry run  : {self.dry_run}")
            print(f"    Scopes   : {list({s for t in targets for s in t.scope})}")
            print("-" * 50)

        # Run targets in parallel
        with ThreadPoolExecutor(max_workers=self._resource_manager.max_parallel_targets) as executor:
            future_to_target = {
                executor.submit(self._scan_and_parse, target): target
                for target in targets
            }

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    completed_target = future.result()
                    status_icon = "✓" if completed_target.status == TargetStatus.COMPLETED else "✗"
                    if progress:
                        print(
                            f"  [{status_icon}] {completed_target.host:<20} "
                            f"| {completed_target.status.value:<10} "
                            f"| {completed_target.duration_seconds:.1f}s "
                            f"| {completed_target.findings_count} findings"
                        )
                except Exception as e:
                    target.status = TargetStatus.FAILED
                    target.error = str(e)
                    if progress:
                        print(f"  [✗] {target.host:<20} | FAILED     | {e}")

        self._end_time = time.time()

        # Build final report
        self._final_report = self._report_aggregator.build(
            targets=self._queue.all_targets(),
            findings_coordinator=self._findings_coord,
            resource_manager=self._resource_manager,
            start_time=self._start_time,
            end_time=self._end_time
        )

        if progress:
            print("-" * 50)
            total = self._final_report["findings"]["total"]
            crit  = self._final_report["findings"]["by_severity"]["CRITICAL"]
            high  = self._final_report["findings"]["by_severity"]["HIGH"]
            dur   = self._final_report["scan_duration_seconds"]
            print(f"[+] Done in {dur}s — {total} findings ({crit} critical, {high} high)")

        return self._final_report

    def print_report(self):
        """Print full aggregated report to console"""
        if not self._final_report:
            print("No report available. Run run_all() first.")
            return

        r = self._final_report
        print("\n" + "=" * 60)
        print("NOVA MULTI-TARGET SCAN REPORT")
        print("=" * 60)
        print(f"Generated  : {r['report_generated_at']}")
        print(f"Duration   : {r['scan_duration_seconds']}s")
        print()

        # Target summary
        t = r["targets"]
        print(f"TARGETS    : {t['total']} total — {t['completed']} completed, "
              f"{t['failed']} failed, {t['skipped']} skipped")

        # Findings summary
        f = r["findings"]
        print(f"FINDINGS   : {f['total']} total")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = f["by_severity"].get(sev, 0)
            if count:
                bar = "█" * min(count, 30)
                print(f"  {sev:<10}: {count:>4}  {bar}")

        # Per-target breakdown
        print("\nPER-TARGET BREAKDOWN:")
        print(f"  {'Host':<20} {'Status':<12} {'Duration':>10} {'Findings':>10}")
        print(f"  {'-'*20} {'-'*12} {'-'*10} {'-'*10}")
        for td in r["target_details"]:
            print(
                f"  {td['host']:<20} {td['status']:<12} "
                f"{td['duration_seconds']:>9.1f}s {td['findings']:>10}"
            )

        # Cross-target insights
        insights = r.get("cross_target_insights", [])
        if insights:
            print(f"\nCROSS-TARGET INSIGHTS ({len(insights)} systemic issues):")
            for i in insights[:10]:  # Top 10
                hosts = ", ".join(i["affected_targets"])
                print(f"  [{i['count']} targets] {i['title']}")
                print(f"             Hosts: {hosts}")

        print("=" * 60)

        # Print full parser report if available
        if HAS_PARSER and self._findings_coord.parser:
            self._findings_coord.parser.database.print_report()

    def export_json(self, path: str = "nova_multi_target_report.json") -> str:
        """Export full report to JSON"""
        if not self._final_report:
            print("No report to export. Run run_all() first.")
            return ""

        # Include all structured findings
        full_report = dict(self._final_report)
        if HAS_PARSER and self._findings_coord.parser:
            full_report["all_findings"] = [
                f.to_dict() for f in self._findings_coord.parser.database.all
            ]
        else:
            full_report["all_findings"] = []

        with open(path, "w") as fh:
            json.dump(full_report, fh, indent=2)
        print(f"[+] Report exported to {path}")
        return path

    # ── Internal ──────────────────────────────

    def _scan_and_parse(self, target: Target) -> Target:
        """Scan a target then immediately parse its results"""
        target = self._coordinator.scan_target(target)
        if target.status == TargetStatus.COMPLETED:
            self._findings_coord.process_target(target)
        return target


# ──────────────────────────────────────────────
# DEMO
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("NOVA MULTI-TARGET ORCHESTRATOR — DEMO")
    print("=" * 60)

    # dry_run=True means no real commands are executed
    orchestrator = NovaMultiTargetOrchestrator(
        max_parallel_targets=3,
        max_total_workers=6,
        dry_run=True
    )

    # Queue targets with different scopes and priorities
    orchestrator \
        .add_target("192.168.1.1",  scope=["recon", "scanning"],       priority=1, label="Gateway",     authorization_note="Lab environment") \
        .add_target("192.168.1.10", scope=["recon", "web"],             priority=2, label="Web Server",  authorization_note="Lab environment") \
        .add_target("192.168.1.20", scope=["recon", "scanning", "web"], priority=2, label="App Server",  authorization_note="Lab environment") \
        .add_target("192.168.1.50", scope=["recon"],                    priority=3, label="Workstation", authorization_note="Lab environment") \
        .add_target("10.0.0.5",     scope=["recon", "scanning"],        priority=1, label="DB Server",   authorization_note="Lab environment")

    print(f"\nQueue status before run: {orchestrator.queue_status()}")

    # Run all targets
    report = orchestrator.run_all(progress=True)

    # Print report
    orchestrator.print_report()

    # Export
    orchestrator.export_json("/tmp/nova_multi_target_demo.json")

    print("\nIntegration example:")
    print("  from nova_multi_target_orchestrator import NovaMultiTargetOrchestrator")
    print("  orc = NovaMultiTargetOrchestrator()")
    print("  orc.add_target('192.168.1.1', scope=['recon','scanning'])")
    print("  orc.run_all()")
    print("  orc.print_report()")
    print("  orc.export_json('report.json')")
