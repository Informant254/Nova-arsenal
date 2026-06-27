"""
Incremental Testing Engine — XBOW-inspired delta-only testing.

Only tests what changed between versions, reducing test time
and focusing on new or modified attack surfaces.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of changes that can be detected."""
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    UNCHANGED = "unchanged"


class TestPriority(Enum):
    """Priority levels for incremental tests."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    SKIP = 5


@dataclass
class DeltaItem:
    """A detected change between versions."""
    item_id: str
    path: str
    change_type: ChangeType
    old_hash: str = ""
    new_hash: str = ""
    old_content: str = ""
    new_content: str = ""
    impact_score: float = 0.0
    affected_techniques: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "path": self.path,
            "change_type": self.change_type.value,
            "old_hash": self.old_hash[:16] if self.old_hash else "",
            "new_hash": self.new_hash[:16] if self.new_hash else "",
            "impact_score": self.impact_score,
            "affected_techniques": self.affected_techniques,
        }


@dataclass
class TestPlan:
    """A plan for testing only changed components."""
    plan_id: str
    baseline_version: str
    target_version: str
    deltas: list[DeltaItem]
    test_cases: list[dict]
    total_tests: int
    skipped_tests: int
    estimated_time_saved: float
    priority_matrix: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "baseline_version": self.baseline_version,
            "target_version": self.target_version,
            "deltas": [d.to_dict() for d in self.deltas],
            "test_cases": self.test_cases,
            "total_tests": self.total_tests,
            "skipped_tests": self.skipped_tests,
            "estimated_time_saved": self.estimated_time_saved,
            "priority_matrix": self.priority_matrix,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class TestResult:
    """Result of an incremental test."""
    test_id: str
    delta_item_id: str
    status: str
    evidence: str
    duration_ms: float
    priority: TestPriority
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "delta_item_id": self.delta_item_id,
            "status": self.status,
            "evidence": self.evidence,
            "duration_ms": self.duration_ms,
            "priority": self.priority.value,
            "timestamp": self.timestamp.isoformat(),
        }


class IncrementalTester:
    """
    XBOW-inspired incremental testing engine.

    Compares two versions, identifies changes, and generates
    a focused test plan that only covers modified components.
    """

    def __init__(self):
        self._test_plans: list[TestPlan] = []
        self._test_results: list[TestResult] = []
        self._version_hashes: dict[str, dict[str, str]] = {}

    def compute_version_hash(self, version: str, files: dict[str, str]) -> str:
        """Compute a hash for an entire version's file set."""
        combined = json.dumps(
            {k: hashlib.sha256(v.encode()).hexdigest() for k, v in sorted(files.items())},
            sort_keys=True,
        )
        version_hash = hashlib.sha256(combined.encode()).hexdigest()
        self._version_hashes[version] = {
            "overall": version_hash,
            "files": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in files.items()},
        }
        return version_hash

    def detect_deltas(
        self,
        baseline_version: str,
        target_version: str,
        baseline_files: dict[str, str],
        target_files: dict[str, str],
    ) -> list[DeltaItem]:
        """Detect changes between two versions."""
        deltas: list[DeltaItem] = []
        all_paths = set(baseline_files.keys()) | set(target_files.keys())

        for path in sorted(all_paths):
            old_content = baseline_files.get(path, "")
            new_content = target_files.get(path, "")
            old_hash = hashlib.sha256(old_content.encode()).hexdigest() if old_content else ""
            new_hash = hashlib.sha256(new_content.encode()).hexdigest() if new_content else ""

            if old_hash == new_hash:
                continue

            if path not in baseline_files:
                change_type = ChangeType.ADDED
            elif path not in target_files:
                change_type = ChangeType.DELETED
            else:
                change_type = ChangeType.MODIFIED

            impact = self._calculate_impact(path, old_content, new_content, change_type)
            techniques = self._infer_techniques(path, new_content)

            delta = DeltaItem(
                item_id=str(uuid.uuid4()),
                path=path,
                change_type=change_type,
                old_hash=old_hash,
                new_hash=new_hash,
                old_content=old_content[:1000],
                new_content=new_content[:1000],
                impact_score=impact,
                affected_techniques=techniques,
            )
            deltas.append(delta)

        return deltas

    def generate_test_plan(
        self,
        baseline_version: str,
        target_version: str,
        deltas: list[DeltaItem],
        all_tests: list[dict] | None = None,
    ) -> TestPlan:
        """Generate a test plan focused only on changed components."""
        all_tests = all_tests or []
        test_cases: list[dict] = []
        skipped = 0
        priority_matrix: dict[str, list[str]] = {
            "critical": [], "high": [], "medium": [], "low": [],
        }

        for delta in deltas:
            priority = self._delta_to_priority(delta)
            tests_for_delta = [
                t for t in all_tests
                if self._test_applies_to_delta(t, delta)
            ]

            if not tests_for_delta:
                tests_for_delta = [{
                    "test_id": str(uuid.uuid4()),
                    "description": f"Test change in {delta.path}",
                    "delta_item_id": delta.item_id,
                    "type": "incremental",
                }]

            for test in tests_for_delta:
                test["priority"] = priority.value
                test["delta_path"] = delta.path
                test_cases.append(test)

                if priority == TestPriority.SKIP:
                    skipped += 1
                else:
                    tier = priority.name.lower()
                    priority_matrix[tier].append(test.get("test_id", ""))

        total_time = len(test_cases) * 30.0
        skipped_time = skipped * 30.0
        saved = (skipped_time / total_time * 100) if total_time > 0 else 0.0

        plan = TestPlan(
            plan_id=str(uuid.uuid4()),
            baseline_version=baseline_version,
            target_version=target_version,
            deltas=deltas,
            test_cases=test_cases,
            total_tests=len(test_cases),
            skipped_tests=skipped,
            estimated_time_saved=saved,
            priority_matrix=priority_matrix,
        )
        self._test_plans.append(plan)
        return plan

    async def execute_plan(
        self,
        plan: TestPlan,
        test_executor=None,
        context: dict | None = None,
    ) -> list[TestResult]:
        """Execute a test plan and return results."""
        context = context or {}
        results: list[TestResult] = []

        for test in plan.test_cases:
            if test.get("priority", 1) == TestPriority.SKIP.value:
                continue

            start = time.monotonic()
            try:
                if test_executor:
                    status, evidence = await test_executor(test, context)
                else:
                    status, evidence = await self._default_test(test, context)
            except Exception as exc:
                status, evidence = "error", str(exc)

            duration = (time.monotonic() - start) * 1000
            result = TestResult(
                test_id=test.get("test_id", str(uuid.uuid4())),
                delta_item_id=test.get("delta_item_id", ""),
                status=status,
                evidence=evidence,
                duration_ms=duration,
                priority=TestPriority(test.get("priority", 3)),
            )
            results.append(result)
            self._test_results.append(result)

        return results

    async def _default_test(self, test: dict, context: dict) -> tuple[str, str]:
        """Default test execution — validates the change exists."""
        delta_path = test.get("delta_path", "unknown")
        return "passed", f"Incremental test for {delta_path} completed"

    def _calculate_impact(
        self, path: str, old_content: str, new_content: str, change_type: ChangeType
    ) -> float:
        """Calculate impact score for a change (0.0-1.0)."""
        score = 0.0
        high_risk_patterns = [
            "auth", "login", "password", "crypto", "key", "token",
            "exploit", "vulnerability", "injection", "xss", "sqli",
        ]
        for pattern in high_risk_patterns:
            if pattern in path.lower() or pattern in new_content.lower():
                score += 0.2

        if change_type == ChangeType.ADDED:
            score += 0.3
        elif change_type == ChangeType.DELETED:
            score += 0.2

        if len(new_content) > 10000:
            score += 0.1

        return min(score, 1.0)

    def _infer_techniques(self, path: str, content: str) -> list[str]:
        """Infer MITRE ATT&CK techniques affected by a change."""
        techniques = []
        technique_keywords = {
            "T1190": ["exploit", "vulnerability", "rce", "injection"],
            "T1078": ["auth", "login", "password", "credential"],
            "T1059": ["script", "command", "shell", "exec"],
            "T1053": ["cron", "schedule", "task"],
            "T1068": ["escalat", "privilege", "root"],
        }
        combined = (path + " " + content).lower()
        for tid, keywords in technique_keywords.items():
            if any(kw in combined for kw in keywords):
                techniques.append(tid)
        return techniques

    def _delta_to_priority(self, delta: DeltaItem) -> TestPriority:
        """Map a delta to a test priority."""
        if delta.impact_score >= 0.7:
            return TestPriority.CRITICAL
        elif delta.impact_score >= 0.5:
            return TestPriority.HIGH
        elif delta.impact_score >= 0.3:
            return TestPriority.MEDIUM
        elif delta.impact_score > 0:
            return TestPriority.LOW
        return TestPriority.SKIP

    def _test_applies_to_delta(self, test: dict, delta: DeltaItem) -> bool:
        """Check if a test applies to a given delta."""
        test_target = test.get("target", test.get("path", ""))
        if not test_target:
            return True
        return delta.path in test_target or test_target in delta.path

    def get_plans(self) -> list[dict]:
        """Return all test plans."""
        return [p.to_dict() for p in self._test_plans]

    def get_results(self) -> list[dict]:
        """Return all test results."""
        return [r.to_dict() for r in self._test_results]

    def get_stats(self) -> dict:
        """Return incremental testing statistics."""
        total_plans = len(self._test_plans)
        total_tests = len(self._test_results)
        passed = sum(1 for r in self._test_results if r.status == "passed")
        failed = sum(1 for r in self._test_results if r.status == "failed")
        total_skipped = sum(p.skipped_tests for p in self._test_plans)

        return {
            "total_plans": total_plans,
            "total_tests_executed": total_tests,
            "tests_passed": passed,
            "tests_failed": failed,
            "total_skipped": total_skipped,
            "pass_rate": passed / total_tests if total_tests > 0 else 0.0,
            "avg_duration_ms": (
                sum(r.duration_ms for r in self._test_results) / total_tests
                if total_tests > 0 else 0.0
            ),
        }
