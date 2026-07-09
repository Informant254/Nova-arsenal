"""
Crash triage and deduplication for fuzz findings.

Buckets crashes by stack signature, ranks exploitability heuristically,
and prepares human-review packages. Does not generate exploit code.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


_SIGNAL_RE = re.compile(r"(SIG(?:SEGV|ABRT|BUS|FPE|ILL|SYS|TRAP)|ASAN|UBSAN|MSAN|heap-buffer|stack-buffer|use-after-free|SEGV)", re.I)
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")
_FRAME_RE = re.compile(r"(?:#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)|at\s+([\w./-]+\.\w+):(\d+))")


@dataclass
class CrashReport:
    """Raw crash input from a fuzzer or sanitizer."""

    crash_id: str
    engine: str
    signal: str = ""
    stack_trace: str = ""
    reproducer: str = ""
    stderr: str = ""
    target: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_id": self.crash_id,
            "engine": self.engine,
            "signal": self.signal,
            "stack_trace": self.stack_trace[:2000],
            "reproducer": self.reproducer[:500],
            "stderr": self.stderr[:1000],
            "target": self.target,
            "metadata": self.metadata,
        }


@dataclass
class TriagedCrash:
    """Deduped, ranked crash ready for analyst review."""

    bucket_id: str
    title: str
    severity: str
    exploitability: float
    uniqueness: float
    signal: str
    top_frames: List[str]
    sample_crash_ids: List[str]
    count: int
    recommendation: str
    sanitizer_hints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket_id": self.bucket_id,
            "title": self.title,
            "severity": self.severity,
            "exploitability": round(self.exploitability, 3),
            "uniqueness": round(self.uniqueness, 3),
            "signal": self.signal,
            "top_frames": self.top_frames,
            "sample_crash_ids": self.sample_crash_ids,
            "count": self.count,
            "recommendation": self.recommendation,
            "sanitizer_hints": self.sanitizer_hints,
        }


class CrashTriageEngine:
    """Deduplicate and rank crashes for zero-day candidate promotion."""

    def __init__(self, frame_depth: int = 5) -> None:
        self.frame_depth = frame_depth

    def stack_signature(self, stack_trace: str) -> str:
        frames = self._extract_frames(stack_trace)
        # Normalize addresses out so ASLR does not split buckets
        norm = "|".join(frames[: self.frame_depth]) or "unknown"
        norm = _ADDR_RE.sub("ADDR", norm)
        return hashlib.sha1(norm.encode()).hexdigest()[:16]

    def triage(self, crashes: Sequence[CrashReport]) -> List[TriagedCrash]:
        buckets: Dict[str, List[CrashReport]] = {}
        for c in crashes:
            text = "\n".join([c.stack_trace, c.stderr, c.signal])
            sig = self.stack_signature(text)
            buckets.setdefault(sig, []).append(c)

        triaged: List[TriagedCrash] = []
        for sig, group in buckets.items():
            sample = group[0]
            combined = "\n".join(
                [sample.stack_trace, sample.stderr, sample.signal] + [g.signal for g in group]
            )
            signal = self._detect_signal(combined)
            frames = self._extract_frames(combined)
            exp = self._exploitability(signal, combined)
            sev = self._severity(exp, signal)
            hints = self._sanitizer_hints(combined)
            triaged.append(
                TriagedCrash(
                    bucket_id=sig,
                    title=f"{signal or 'crash'} in {frames[0] if frames else 'unknown'}",
                    severity=sev,
                    exploitability=exp,
                    uniqueness=min(1.0, 1.0 / max(1, len(group) ** 0.5) + 0.3),
                    signal=signal,
                    top_frames=frames[: self.frame_depth],
                    sample_crash_ids=[g.crash_id for g in group[:5]],
                    count=len(group),
                    recommendation=self._recommendation(sev, signal, frames),
                    sanitizer_hints=hints,
                )
            )

        triaged.sort(key=lambda t: (t.exploitability, t.uniqueness), reverse=True)
        logger.info("Triaged %d crashes into %d buckets", len(crashes), len(triaged))
        return triaged

    async def triage_async(self, crashes: Sequence[CrashReport]) -> List[TriagedCrash]:
        return self.triage(crashes)

    def _extract_frames(self, text: str) -> List[str]:
        frames: List[str] = []
        for m in _FRAME_RE.finditer(text or ""):
            fn = m.group(1) or m.group(2)
            if fn:
                frames.append(fn)
        if not frames:
            # Fallback: lines that look like function names
            for line in (text or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                if any(x in line.lower() for x in ("#0", "#1", "in ", "at ")):
                    cleaned = _ADDR_RE.sub("", line).strip()
                    frames.append(cleaned[:80])
        return frames[:20]

    def _detect_signal(self, text: str) -> str:
        m = _SIGNAL_RE.search(text or "")
        return m.group(0).upper() if m else "UNKNOWN"

    def _exploitability(self, signal: str, text: str) -> float:
        score = 0.3
        s = signal.upper()
        t = (text or "").lower()
        if "USE-AFTER-FREE" in s or "use-after-free" in t:
            score = 0.92
        elif "HEAP-BUFFER" in s or "heap-buffer" in t:
            score = 0.88
        elif "STACK-BUFFER" in s or "stack-buffer" in t:
            score = 0.8
        elif "SEGV" in s or "SIGSEGV" in s:
            score = 0.7
        elif "SIGABRT" in s:
            score = 0.45
        elif "UBSAN" in s:
            score = 0.55
        elif "FPE" in s:
            score = 0.4
        if "write" in t and ("overflow" in t or "segv" in t):
            score = min(0.98, score + 0.1)
        if "pc is at" in t or "instruction pointer" in t:
            score = min(0.98, score + 0.05)
        return score

    def _severity(self, exploitability: float, signal: str) -> str:
        if exploitability >= 0.85:
            return "critical"
        if exploitability >= 0.65:
            return "high"
        if exploitability >= 0.45:
            return "medium"
        return "low"

    def _sanitizer_hints(self, text: str) -> List[str]:
        hints = []
        t = (text or "").lower()
        for key in ("heap-buffer-overflow", "stack-buffer-overflow", "use-after-free",
                    "double-free", "null-deref", "signed-integer-overflow"):
            if key in t or key.replace("-", " ") in t:
                hints.append(key)
        return hints

    def _recommendation(self, severity: str, signal: str, frames: List[str]) -> str:
        loc = frames[0] if frames else "the crashing function"
        if severity in {"critical", "high"}:
            return (
                f"High-priority: root-cause {loc} under ASan/UBSan; minimize reproducer; "
                f"assess reachability from untrusted input before disclosure."
            )
        return f"Document {signal} at {loc}; confirm not a harness artifact; lower priority if non-reachable."
