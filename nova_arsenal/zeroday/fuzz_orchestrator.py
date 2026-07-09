"""
Coverage-guided fuzz campaign orchestrator.

Plans and (optionally) launches fuzz jobs for AFL++, libFuzzer, honggfuzz,
and protocol fuzzers. Generates harness plans and commands — does not embed
exploit payloads.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from .surface import SurfaceEndpoint

logger = logging.getLogger(__name__)


class FuzzEngine(str, Enum):
    AFLPP = "afl++"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"
    BOOFUZZ = "boofuzz"
    FFUF = "ffuf"
    RADAMSA = "radamsa"
    HTTP_MUTATOR = "http_mutator"


@dataclass
class FuzzJob:
    """A single fuzzing unit of work."""

    job_id: str
    engine: str
    target: str
    surface_id: str
    command: str
    harness_hint: str
    seed_corpus_hint: str
    timeout_seconds: int = 300
    parallel_jobs: int = 1
    priority: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "engine": self.engine,
            "target": self.target,
            "surface_id": self.surface_id,
            "command": self.command,
            "harness_hint": self.harness_hint,
            "seed_corpus_hint": self.seed_corpus_hint,
            "timeout_seconds": self.timeout_seconds,
            "parallel_jobs": self.parallel_jobs,
            "priority": round(self.priority, 3),
            "metadata": self.metadata,
        }


@dataclass
class FuzzCampaign:
    """Planned multi-engine fuzz campaign."""

    target: str
    jobs: List[FuzzJob] = field(default_factory=list)
    total_parallelism: int = 0
    estimated_startup_ms: float = 0.0
    notes: List[str] = field(default_factory=list)

    @property
    def job_count(self) -> int:
        return len(self.jobs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "job_count": self.job_count,
            "total_parallelism": self.total_parallelism,
            "estimated_startup_ms": round(self.estimated_startup_ms, 2),
            "jobs": [j.to_dict() for j in self.jobs],
            "notes": self.notes,
        }


class FuzzOrchestrator:
    """
    Build high-throughput fuzz campaigns from a ranked surface.

    By default only *plans* jobs (safe). Set execute=True to run shell commands
    when binaries are available (still requires authorized scope upstream).
    """

    def __init__(
        self,
        max_jobs: int = 32,
        default_timeout: int = 300,
        workers: int = 8,
    ) -> None:
        self.max_jobs = max_jobs
        self.default_timeout = default_timeout
        self.workers = workers

    def plan(
        self,
        target: str,
        endpoints: Sequence[SurfaceEndpoint],
        binary_path: str = "",
        corpus_dir: str = "./corpus",
        output_dir: str = "./fuzz_out",
    ) -> FuzzCampaign:
        t0 = time.perf_counter()
        jobs: List[FuzzJob] = []
        notes: List[str] = []

        ranked = sorted(endpoints, key=lambda e: e.fuzz_affinity, reverse=True)
        for idx, ep in enumerate(ranked):
            if len(jobs) >= self.max_jobs:
                notes.append(f"Capped at max_jobs={self.max_jobs}")
                break
            jobs.extend(
                self._jobs_for_endpoint(
                    target=target,
                    ep=ep,
                    idx=idx,
                    binary_path=binary_path,
                    corpus_dir=corpus_dir,
                    output_dir=output_dir,
                )
            )

        # Prefer highest priority jobs if over cap after expansion
        jobs = sorted(jobs, key=lambda j: j.priority, reverse=True)[: self.max_jobs]
        parallelism = sum(j.parallel_jobs for j in jobs)
        elapsed = (time.perf_counter() - t0) * 1000.0
        notes.append(
            "Campaign is a plan of orchestrated fuzzers; crashes need triage before claiming 0-day"
        )
        return FuzzCampaign(
            target=target,
            jobs=jobs,
            total_parallelism=parallelism,
            estimated_startup_ms=elapsed,
            notes=notes,
        )

    async def plan_async(self, *args: Any, **kwargs: Any) -> FuzzCampaign:
        return self.plan(*args, **kwargs)

    async def execute_campaign(
        self,
        campaign: FuzzCampaign,
        dry_run: bool = True,
        authorized: bool = False,
        authorization_ref: str = "",
        use_live_worker: bool = True,
        job_timeout: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute planned jobs.

        When use_live_worker=True (default), delegates to LiveFuzzWorker which:
        - detects installed engines (ffuf, afl-fuzz, honggfuzz, radamsa, http_mutator)
        - skips missing tools cleanly
        - collects crash artifacts for triage

        dry_run=True only plans runnable vs skipped without launching processes.
        """
        if use_live_worker:
            from .fuzz_worker import LiveFuzzWorker

            worker = LiveFuzzWorker(
                authorized=authorized or (not dry_run),
                authorization_ref=authorization_ref,
                workers=self.workers,
                default_timeout=job_timeout or min(self.default_timeout, 90),
                output_dir=self._infer_output_dir(campaign),
            )
            # If caller insists on live run, require explicit authorized flag
            if not dry_run:
                worker.authorized = authorized
            live = await worker.run(
                campaign,
                dry_run=dry_run,
                max_jobs=self.max_jobs,
                job_timeout=job_timeout,
            )
            return [j.to_dict() for j in live.jobs] + [
                {
                    "_meta": "live_campaign",
                    **{k: v for k, v in live.to_dict().items() if k != "jobs"},
                }
            ]

        if dry_run:
            return [
                {
                    "job_id": j.job_id,
                    "status": "planned",
                    "command": j.command,
                    "dry_run": True,
                }
                for j in campaign.jobs
            ]

        sem = asyncio.Semaphore(self.workers)

        async def run_one(job: FuzzJob) -> Dict[str, Any]:
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_shell(
                        job.command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(
                            proc.communicate(),
                            timeout=min(job.timeout_seconds, 30),
                        )
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.communicate()
                        return {
                            "job_id": job.job_id,
                            "status": "timeout_or_running",
                            "note": "Fuzzers run long; process killed after short orchestration timeout",
                        }
                    return {
                        "job_id": job.job_id,
                        "status": "finished" if proc.returncode == 0 else "error",
                        "returncode": proc.returncode,
                        "stdout": stdout.decode(errors="replace")[:2000],
                        "stderr": stderr.decode(errors="replace")[:1000],
                    }
                except Exception as exc:  # noqa: BLE001
                    return {"job_id": job.job_id, "status": "error", "error": str(exc)}

        results = await asyncio.gather(*[run_one(j) for j in campaign.jobs])
        return list(results)

    def _infer_output_dir(self, campaign: FuzzCampaign) -> str:
        for job in campaign.jobs:
            if "fuzz_out" in job.command:
                return "./fuzz_out"
        return "./fuzz_out"

    def _jobs_for_endpoint(
        self,
        target: str,
        ep: SurfaceEndpoint,
        idx: int,
        binary_path: str,
        corpus_dir: str,
        output_dir: str,
    ) -> List[FuzzJob]:
        jobs: List[FuzzJob] = []
        sid = ep.surface_id
        base_pri = ep.fuzz_affinity + ep.priority * 0.1

        if ep.service in {"http", "https", "http-proxy"}:
            url = ep.path if ep.path.startswith("http") else f"http://{target}:{ep.port or 80}{ep.path or '/'}"
            wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
            jobs.append(
                FuzzJob(
                    job_id=f"ffuf-{sid}-{idx}",
                    engine=FuzzEngine.FFUF.value,
                    target=target,
                    surface_id=sid,
                    command=(
                        f"ffuf -u {shlex.quote(url.rstrip('/') + '/FUZZ')} "
                        f"-w {shlex.quote(wordlist)} -mc all -t 50 -o "
                        f"{shlex.quote(output_dir + '/ffuf_' + sid + '.json')} -of json"
                    ),
                    harness_hint="Content discovery + parameter surface expansion before deep fuzz",
                    seed_corpus_hint="Seed with known API paths and parameter names from recon",
                    timeout_seconds=self.default_timeout,
                    parallel_jobs=4,
                    priority=base_pri + 1.0,
                    metadata={"url": url, "service": ep.service},
                )
            )
            jobs.append(
                FuzzJob(
                    job_id=f"httpmut-{sid}-{idx}",
                    engine=FuzzEngine.HTTP_MUTATOR.value,
                    target=target,
                    surface_id=sid,
                    command=(
                        f"python -m nova_arsenal.zeroday.http_mutator "
                        f"--url {shlex.quote(url)} --out {shlex.quote(output_dir)} "
                        f"--max-requests 500"
                    ),
                    harness_hint="Protocol-aware HTTP mutation (headers, methods, encodings, parsers)",
                    seed_corpus_hint="Recorded requests from Burp/proxy as seeds",
                    timeout_seconds=self.default_timeout,
                    parallel_jobs=2,
                    priority=base_pri + 2.0,
                    metadata={"bug_classes": ["http_smuggling", "parser", "auth"]},
                )
            )

        if binary_path:
            out = f"{output_dir}/afl_{sid}"
            jobs.append(
                FuzzJob(
                    job_id=f"afl-{sid}-{idx}",
                    engine=FuzzEngine.AFLPP.value,
                    target=target,
                    surface_id=sid,
                    command=(
                        f"afl-fuzz -i {shlex.quote(corpus_dir)} -o {shlex.quote(out)} "
                        f"-m none -t 1000 -- {shlex.quote(binary_path)} @@"
                    ),
                    harness_hint="Coverage-guided binary fuzz; compile target with afl-clang-fast",
                    seed_corpus_hint="Minimal valid files for the parser under test",
                    timeout_seconds=max(self.default_timeout, 3600),
                    parallel_jobs=self.workers,
                    priority=base_pri + 3.0,
                    metadata={"binary": binary_path},
                )
            )
            jobs.append(
                FuzzJob(
                    job_id=f"libfuzzer-{sid}-{idx}",
                    engine=FuzzEngine.LIBFUZZER.value,
                    target=target,
                    surface_id=sid,
                    command=(
                        f"{shlex.quote(binary_path)} -max_total_time={self.default_timeout} "
                        f"-workers={self.workers} -jobs={self.workers} {shlex.quote(corpus_dir)}"
                    ),
                    harness_hint="In-process libFuzzer harness for pure parse functions",
                    seed_corpus_hint="Small seeds covering grammar productions",
                    timeout_seconds=self.default_timeout,
                    parallel_jobs=self.workers,
                    priority=base_pri + 2.5,
                )
            )

        if ep.service in {"smb", "ftp", "mqtt", "amqp", "sip", "modbus"}:
            jobs.append(
                FuzzJob(
                    job_id=f"boofuzz-{sid}-{idx}",
                    engine=FuzzEngine.BOOFUZZ.value,
                    target=target,
                    surface_id=sid,
                    command=(
                        f"python -c \"print('boofuzz session for {ep.service} "
                        f"on {target}:{ep.port}')\""
                    ),
                    harness_hint=f"Define boofuzz protocol graph for {ep.service}; mutate length fields and TLVs",
                    seed_corpus_hint="Valid protocol handshakes as base messages",
                    timeout_seconds=self.default_timeout,
                    parallel_jobs=1,
                    priority=base_pri + 2.0,
                    metadata={"protocol": ep.service, "port": ep.port},
                )
            )

        if not jobs:
            jobs.append(
                FuzzJob(
                    job_id=f"radamsa-{sid}-{idx}",
                    engine=FuzzEngine.RADAMSA.value,
                    target=target,
                    surface_id=sid,
                    command=f"radamsa -n 1000 -o {shlex.quote(output_dir + '/rad_%n')} seeds/*",
                    harness_hint="Generic mutation when no specialized harness exists",
                    seed_corpus_hint="Any valid samples for the input format",
                    timeout_seconds=120,
                    parallel_jobs=1,
                    priority=base_pri,
                )
            )

        return jobs
