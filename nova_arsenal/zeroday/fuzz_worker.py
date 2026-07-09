"""
Live fuzz worker — detect installed engines and execute campaigns.

When AFL++, ffuf, honggfuzz, radamsa, or the built-in HTTP mutator are
available, jobs run for real (authorized testing only). Missing tools are
skipped with a clear status instead of failing the whole campaign.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from .crash_triage import CrashReport
from .fuzz_orchestrator import FuzzCampaign, FuzzEngine, FuzzJob

logger = logging.getLogger(__name__)


# engine -> candidate binary names on PATH
_ENGINE_BINARIES: Dict[str, List[str]] = {
    FuzzEngine.FFUF.value: ["ffuf"],
    FuzzEngine.AFLPP.value: ["afl-fuzz", "afl-fuzz++"],
    FuzzEngine.HONGGFUZZ.value: ["honggfuzz"],
    FuzzEngine.RADAMSA.value: ["radamsa"],
    FuzzEngine.LIBFUZZER.value: [],  # needs instrumented binary path
    FuzzEngine.BOOFUZZ.value: [],  # python package
    FuzzEngine.HTTP_MUTATOR.value: ["python", "python3"],
}


@dataclass
class EngineStatus:
    engine: str
    available: bool
    binary: str = ""
    version: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine,
            "available": self.available,
            "binary": self.binary,
            "version": self.version,
            "note": self.note,
        }


@dataclass
class LiveJobResult:
    job_id: str
    engine: str
    status: str  # ran | skipped_missing | planned | timeout | error | finished
    command: str = ""
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    elapsed_ms: float = 0.0
    crashes_found: int = 0
    crash_paths: List[str] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "engine": self.engine,
            "status": self.status,
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout[:3000],
            "stderr": self.stderr[:1500],
            "elapsed_ms": round(self.elapsed_ms, 2),
            "crashes_found": self.crashes_found,
            "crash_paths": self.crash_paths[:50],
            "artifacts": self.artifacts,
            "note": self.note,
        }


@dataclass
class LiveCampaignResult:
    target: str
    engines: List[EngineStatus] = field(default_factory=list)
    jobs: List[LiveJobResult] = field(default_factory=list)
    crashes: List[CrashReport] = field(default_factory=list)
    elapsed_ms: float = 0.0
    notes: List[str] = field(default_factory=list)

    @property
    def ran_count(self) -> int:
        return sum(1 for j in self.jobs if j.status in {"ran", "finished", "timeout"})

    @property
    def skipped_count(self) -> int:
        return sum(1 for j in self.jobs if j.status == "skipped_missing")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "engines": [e.to_dict() for e in self.engines],
            "jobs": [j.to_dict() for j in self.jobs],
            "crash_count": len(self.crashes),
            "crashes": [c.to_dict() for c in self.crashes],
            "ran_count": self.ran_count,
            "skipped_count": self.skipped_count,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "notes": self.notes,
        }


class LiveFuzzWorker:
    """
    Execute fuzz campaigns using tools present on the host.

    Usage:
        worker = LiveFuzzWorker(authorized=True, authorization_ref="ENG-1")
        result = await worker.run(campaign, dry_run=False)
    """

    def __init__(
        self,
        authorized: bool = False,
        authorization_ref: str = "",
        workers: int = 4,
        default_timeout: int = 60,
        output_dir: str = "./fuzz_out",
        only_engines: Optional[Sequence[str]] = None,
        prefer_short_runs: bool = True,
    ) -> None:
        self.authorized = authorized
        self.authorization_ref = authorization_ref
        self.workers = max(1, workers)
        self.default_timeout = default_timeout
        self.output_dir = output_dir
        self.only_engines = set(only_engines) if only_engines else None
        # Cap long-running fuzzers so orchestration stays responsive
        self.prefer_short_runs = prefer_short_runs
        self._engine_cache: Optional[Dict[str, EngineStatus]] = None

    def detect_engines(self, force: bool = False) -> Dict[str, EngineStatus]:
        if self._engine_cache is not None and not force:
            return self._engine_cache

        status: Dict[str, EngineStatus] = {}
        for engine, bins in _ENGINE_BINARIES.items():
            if engine == FuzzEngine.BOOFUZZ.value:
                available = self._python_module_available("boofuzz")
                status[engine] = EngineStatus(
                    engine=engine,
                    available=available,
                    binary="python-boofuzz" if available else "",
                    note="pip package boofuzz" if available else "pip install boofuzz",
                )
                continue
            if engine == FuzzEngine.LIBFUZZER.value:
                status[engine] = EngineStatus(
                    engine=engine,
                    available=False,
                    note="Requires instrumented harness binary via binary_path",
                )
                continue
            if engine == FuzzEngine.HTTP_MUTATOR.value:
                # Built-in; always available if python is
                py = shutil.which("python3") or shutil.which("python") or ""
                status[engine] = EngineStatus(
                    engine=engine,
                    available=bool(py),
                    binary=py,
                    note="Built-in Nova HTTP mutator",
                )
                continue

            found = ""
            for name in bins:
                path = shutil.which(name)
                if path:
                    found = path
                    break
            status[engine] = EngineStatus(
                engine=engine,
                available=bool(found),
                binary=found,
                version=self._quick_version(found) if found else "",
                note="" if found else f"Install {bins[0] if bins else engine}",
            )

        # AFL++ available also enables libFuzzer-style only if harness provided separately
        self._engine_cache = status
        return status

    def filter_runnable(self, campaign: FuzzCampaign) -> tuple[List[FuzzJob], List[FuzzJob]]:
        """Split jobs into (runnable, skipped)."""
        engines = self.detect_engines()
        runnable: List[FuzzJob] = []
        skipped: List[FuzzJob] = []
        for job in campaign.jobs:
            if self.only_engines and job.engine not in self.only_engines:
                skipped.append(job)
                continue
            st = engines.get(job.engine)
            if job.engine == FuzzEngine.AFLPP.value:
                # Need afl-fuzz AND a binary target in the command
                if st and st.available and "afl-fuzz" in job.command:
                    runnable.append(job)
                else:
                    skipped.append(job)
                continue
            if job.engine == FuzzEngine.LIBFUZZER.value:
                skipped.append(job)  # only with explicit harness runtime
                continue
            if st and st.available:
                runnable.append(job)
            else:
                skipped.append(job)
        return runnable, skipped

    async def run(
        self,
        campaign: FuzzCampaign,
        dry_run: bool = True,
        max_jobs: int = 16,
        job_timeout: Optional[int] = None,
    ) -> LiveCampaignResult:
        t0 = time.perf_counter()
        engines = self.detect_engines()
        notes: List[str] = []
        results: List[LiveJobResult] = []

        if not dry_run and not self.authorized:
            return LiveCampaignResult(
                target=campaign.target,
                engines=list(engines.values()),
                notes=["Live fuzz blocked: authorized=False"],
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if not dry_run and not self.authorization_ref:
            notes.append("authorization_ref empty — set for audit trail")

        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        runnable, skipped = self.filter_runnable(campaign)

        for job in skipped:
            eng = engines.get(job.engine)
            results.append(
                LiveJobResult(
                    job_id=job.job_id,
                    engine=job.engine,
                    status="skipped_missing",
                    command=job.command,
                    note=(eng.note if eng else "engine unavailable")
                    or "filtered by only_engines",
                )
            )

        runnable = runnable[:max_jobs]
        if len(runnable) < len([j for j in campaign.jobs if j not in skipped]):
            notes.append(f"Capped live jobs at max_jobs={max_jobs}")

        if dry_run:
            for job in runnable:
                results.append(
                    LiveJobResult(
                        job_id=job.job_id,
                        engine=job.engine,
                        status="planned",
                        command=self._prepare_command(job),
                        note="dry_run=True; tool is available",
                    )
                )
            notes.append(
                f"Dry-run: {sum(1 for r in results if r.status=='planned')} runnable, "
                f"{sum(1 for r in results if r.status=='skipped_missing')} skipped"
            )
            return LiveCampaignResult(
                target=campaign.target,
                engines=list(engines.values()),
                jobs=results,
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                notes=notes,
            )

        timeout = job_timeout or self.default_timeout
        if self.prefer_short_runs:
            timeout = min(timeout, 90)

        sem = asyncio.Semaphore(self.workers)
        live_results = await asyncio.gather(
            *[self._run_job(job, timeout, sem) for job in runnable]
        )
        results.extend(live_results)

        crashes = self.collect_crashes(campaign.target, results)
        notes.append(
            f"Live run complete: {sum(1 for r in live_results if r.status in {'ran','finished','timeout'})} executed, "
            f"{len(crashes)} crash artifacts"
        )
        return LiveCampaignResult(
            target=campaign.target,
            engines=list(engines.values()),
            jobs=results,
            crashes=crashes,
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            notes=notes,
        )

    def collect_crashes(
        self,
        target: str,
        job_results: Sequence[LiveJobResult],
    ) -> List[CrashReport]:
        crashes: List[CrashReport] = []
        seen: Set[str] = set()

        # Scan known output locations
        out = Path(self.output_dir)
        patterns = [
            "**/crashes/*",
            "**/crash*",
            "**/hangs/*",
            "**/default/crashes/*",
            "**/queue/id*",
        ]
        # Prefer explicit crash dirs from AFL
        paths: List[Path] = []
        if out.exists():
            for pat in patterns:
                paths.extend(out.glob(pat))

        for jr in job_results:
            paths.extend(Path(p) for p in jr.crash_paths)

        for path in paths:
            if not path.is_file():
                continue
            key = str(path.resolve()) if path.exists() else str(path)
            if key in seen:
                continue
            seen.add(key)
            # Skip readme/txt metadata from AFL
            if path.name.lower() in {"readme.txt", "README.txt"}:
                continue
            try:
                data = path.read_bytes()[:4096]
            except OSError:
                continue
            # Heuristic: small non-empty files under crashes/
            if b"COMMAND" in data and path.suffix == ".txt":
                continue
            crashes.append(
                CrashReport(
                    crash_id=f"live-{len(crashes):04d}",
                    engine=self._guess_engine(path),
                    signal="UNKNOWN",
                    stack_trace="",
                    reproducer=data[:200].hex() if self._looks_binary(data) else data.decode(errors="replace")[:500],
                    stderr="",
                    target=target,
                    metadata={"path": str(path)},
                )
            )

        # Parse ffuf JSON for interesting status anomalies (not crashes, but signals)
        for jr in job_results:
            if jr.engine != FuzzEngine.FFUF.value:
                continue
            for key, val in (jr.artifacts or {}).items():
                if key.startswith("ffuf_") and isinstance(val, dict):
                    results = val.get("results") or []
                    if results:
                        jr.artifacts["interesting_paths"] = len(results)

        return crashes

    async def _run_job(
        self,
        job: FuzzJob,
        timeout: int,
        sem: asyncio.Semaphore,
    ) -> LiveJobResult:
        async with sem:
            cmd = self._prepare_command(job)
            t0 = time.perf_counter()
            try:
                # Ensure per-job output dirs
                if job.engine == FuzzEngine.AFLPP.value:
                    m = re.search(r"-o\s+(\S+)", cmd)
                    if m:
                        Path(m.group(1).strip("\"'")).mkdir(parents=True, exist_ok=True)
                if job.engine == FuzzEngine.FFUF.value:
                    m = re.search(r"-o\s+(\S+)", cmd)
                    if m:
                        Path(m.group(1).strip("\"'")).parent.mkdir(parents=True, exist_ok=True)
                    # Prefer a small built-in wordlist if SecLists missing
                    cmd = self._maybe_fix_wordlist(cmd)

                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=os.getcwd(),
                )
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=timeout,
                    )
                    status = "finished" if proc.returncode == 0 else "ran"
                    rc = proc.returncode
                    note = ""
                except asyncio.TimeoutError:
                    proc.kill()
                    try:
                        stdout_b, stderr_b = await proc.communicate()
                    except Exception:  # noqa: BLE001
                        stdout_b, stderr_b = b"", b""
                    status = "timeout"
                    rc = None
                    note = f"Stopped after {timeout}s (fuzzers are long-running; artifacts may remain)"

                stdout = stdout_b.decode(errors="replace") if stdout_b else ""
                stderr = stderr_b.decode(errors="replace") if stderr_b else ""
                crash_paths = self._discover_job_crashes(job)
                artifacts: Dict[str, Any] = {}
                if job.engine == FuzzEngine.FFUF.value:
                    artifacts.update(self._load_ffuf_json(job))

                return LiveJobResult(
                    job_id=job.job_id,
                    engine=job.engine,
                    status=status,
                    command=cmd,
                    returncode=rc,
                    stdout=stdout,
                    stderr=stderr,
                    elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                    crashes_found=len(crash_paths),
                    crash_paths=crash_paths,
                    artifacts=artifacts,
                    note=note,
                )
            except Exception as exc:  # noqa: BLE001
                return LiveJobResult(
                    job_id=job.job_id,
                    engine=job.engine,
                    status="error",
                    command=cmd,
                    elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                    note=str(exc),
                )

    def _prepare_command(self, job: FuzzJob) -> str:
        cmd = job.command
        if job.engine == FuzzEngine.HTTP_MUTATOR.value:
            # Ensure authorization flags for live execute
            if "--authorized" not in cmd:
                cmd = cmd + " --authorized --execute"
            if "--out" not in cmd:
                cmd = cmd + f" --out {self.output_dir}"
        if job.engine == FuzzEngine.AFLPP.value and self.prefer_short_runs:
            # AFL++ doesn't have a clean max time; we rely on process timeout
            pass
        if job.engine == FuzzEngine.FFUF.value and self.prefer_short_runs:
            # Limit ffuf aggressiveness if not already
            if " -t " not in cmd:
                cmd = cmd + " -t 20"
            if " -maxtime " not in cmd:
                cmd = cmd + f" -maxtime {min(self.default_timeout, 60)}"
        return cmd

    def _maybe_fix_wordlist(self, cmd: str) -> str:
        m = re.search(r"-w\s+(\S+)", cmd)
        if not m:
            return cmd
        wl = m.group(1).strip("\"'")
        if Path(wl).exists():
            return cmd
        # Create a tiny fallback wordlist for live demos / CI
        fallback = Path(self.output_dir) / "wordlist_mini.txt"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        if not fallback.exists():
            fallback.write_text(
                "\n".join(
                    [
                        "admin", "api", "login", "upload", "backup", "config",
                        "debug", "test", "v1", "v2", "graphql", "health",
                        "robots.txt", "swagger", "internal",
                    ]
                )
                + "\n"
            )
        return cmd.replace(wl, str(fallback))

    def _discover_job_crashes(self, job: FuzzJob) -> List[str]:
        paths: List[str] = []
        out = Path(self.output_dir)
        if job.engine == FuzzEngine.AFLPP.value:
            m = re.search(r"-o\s+(\S+)", job.command)
            base = Path(m.group(1).strip("\"'")) if m else out / f"afl_{job.surface_id}"
            for p in base.glob("**/crashes/*"):
                if p.is_file() and p.name.lower() != "readme.txt":
                    paths.append(str(p))
        return paths

    def _load_ffuf_json(self, job: FuzzJob) -> Dict[str, Any]:
        m = re.search(r"-o\s+(\S+)", job.command)
        if not m:
            return {}
        path = Path(m.group(1).strip("\"'"))
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(errors="replace"))
            return {f"ffuf_{path.stem}": data if isinstance(data, dict) else {"raw": data}}
        except Exception:  # noqa: BLE001
            return {}

    def _quick_version(self, binary: str) -> str:
        if not binary:
            return ""
        try:
            import subprocess

            r = subprocess.run(
                [binary, "-V"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            out = (r.stdout or r.stderr or "").strip().splitlines()
            return out[0][:80] if out else ""
        except Exception:  # noqa: BLE001
            return ""

    def _python_module_available(self, name: str) -> bool:
        try:
            import importlib.util

            return importlib.util.find_spec(name) is not None
        except Exception:  # noqa: BLE001
            return False

    def _guess_engine(self, path: Path) -> str:
        s = str(path).lower()
        if "afl" in s:
            return FuzzEngine.AFLPP.value
        if "hongg" in s:
            return FuzzEngine.HONGGFUZZ.value
        return "unknown"

    def _looks_binary(self, data: bytes) -> bool:
        if not data:
            return False
        return b"\x00" in data[:200]
