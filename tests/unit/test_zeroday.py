"""Unit tests for the zero-day research pipeline."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest

from nova_arsenal.zeroday import (
    AttackSurfaceMapper,
    CrashReport,
    CrashTriageEngine,
    FuzzOrchestrator,
    NoveltyScorer,
    StaticBugScanner,
    VariantAnalyzer,
    ZeroDayHuntConfig,
    ZeroDayHunter,
)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestAttackSurfaceMapper:
    def test_map_services(self):
        mapper = AttackSurfaceMapper()
        sm = mapper.map(
            "10.0.0.5",
            services={
                "https": {"ports": [443], "version": "nginx/1.25.0", "paths": ["/api", "/upload"]},
                "smb": [445],
            },
            technologies=["nginx", "php"],
        )
        assert len(sm.endpoints) >= 2
        assert sm.elapsed_ms < 500
        top = sm.top[0]
        assert top.priority > 0
        assert top.surface_id

    def test_seeded_when_empty(self):
        sm = AttackSurfaceMapper().map("example.com")
        assert len(sm.endpoints) >= 3
        assert any("seeded" in (e.tags or []) for e in sm.endpoints)


class TestVariantAnalyzer:
    def test_classify_and_expand(self):
        va = VariantAnalyzer()
        assert "rce" in va.classify("remote code execution via template")
        hyps = va.analyze(
            [{"cve_id": "CVE-2021-41773", "description": "path traversal in Apache", "severity": "high"}],
            services={"http": [80]},
        )
        assert len(hyps) >= 1
        assert hyps[0].source_cve == "CVE-2021-41773"
        assert hyps[0].test_ideas


class TestStaticBugScanner:
    def test_finds_command_injection_sink(self):
        scanner = StaticBugScanner()
        code = 'import os\ndef x(u):\n    os.system("ping " + u)\n'
        findings = scanner.scan_text(code, location="app.py")
        assert any(f.bug_class == "rce" for f in findings)

    def test_scan_files(self):
        scanner = StaticBugScanner()
        findings = scanner.scan_files(
            {
                "a.py": "password = 'supersecretvalue123'\n",
                "b.py": "DEBUG = True\n",
            }
        )
        assert len(findings) >= 1


class TestNoveltyScorer:
    def test_known_issue_low_novelty(self):
        n = NoveltyScorer().assess(title="EternalBlue MS17-010", description="SMB exploit")
        assert n.score < 0.5
        assert n.matched_known

    def test_novel_candidate_high(self):
        n = NoveltyScorer().assess(
            title="Heap buffer overflow in custom TLV parser",
            description="ASan heap-buffer-overflow in parse_tlv",
            evidence="use-after-free",
        )
        assert n.score >= 0.7


class TestCrashTriage:
    def test_dedup_and_rank(self):
        engine = CrashTriageEngine()
        crashes = [
            CrashReport(
                crash_id="c1",
                engine="afl++",
                signal="SIGSEGV",
                stack_trace="#0 0x1234 in parse_header\n#1 0x5678 in handle_req\nheap-buffer-overflow WRITE",
            ),
            CrashReport(
                crash_id="c2",
                engine="afl++",
                signal="SIGSEGV",
                stack_trace="#0 0x9999 in parse_header\n#1 0xaaaa in handle_req\nheap-buffer-overflow WRITE",
            ),
            CrashReport(
                crash_id="c3",
                engine="libfuzzer",
                signal="SIGABRT",
                stack_trace="#0 0x1 in unrelated_assert\n",
            ),
        ]
        triaged = engine.triage(crashes)
        assert len(triaged) == 2  # first two same bucket
        assert triaged[0].count >= 1
        assert triaged[0].exploitability > 0.5


class TestFuzzOrchestrator:
    def test_plan_http(self):
        from nova_arsenal.zeroday.surface import SurfaceEndpoint

        orch = FuzzOrchestrator(max_jobs=10)
        campaign = orch.plan(
            "example.com",
            [SurfaceEndpoint(target="example.com", service="http", port=80, path="/api")],
        )
        assert campaign.job_count >= 1
        assert any(j.engine in {"ffuf", "http_mutator"} for j in campaign.jobs)

    def test_execute_dry_run(self):
        from nova_arsenal.zeroday.surface import SurfaceEndpoint

        orch = FuzzOrchestrator(max_jobs=3)
        campaign = orch.plan(
            "example.com",
            [SurfaceEndpoint(target="example.com", service="smb", port=445)],
        )
        results = _run(orch.execute_campaign(campaign, dry_run=True, authorized=True))
        # Live worker returns planned/skipped rows (+ optional meta)
        statuses = [r.get("status") for r in results if "status" in r]
        assert statuses
        assert all(s in {"planned", "skipped_missing"} for s in statuses)


class TestLiveFuzzWorker:
    def test_detect_engines(self):
        from nova_arsenal.zeroday import LiveFuzzWorker

        worker = LiveFuzzWorker(authorized=True, authorization_ref="T")
        engines = worker.detect_engines()
        assert "ffuf" in engines
        assert "http_mutator" in engines
        assert engines["http_mutator"].available is True

    def test_dry_run_splits_runnable(self):
        from nova_arsenal.zeroday import LiveFuzzWorker
        from nova_arsenal.zeroday.surface import SurfaceEndpoint
        from nova_arsenal.zeroday.fuzz_orchestrator import FuzzOrchestrator

        orch = FuzzOrchestrator(max_jobs=5)
        campaign = orch.plan(
            "example.com",
            [SurfaceEndpoint(target="example.com", service="http", port=80, path="/")],
        )
        worker = LiveFuzzWorker(authorized=True, authorization_ref="T")
        live = _run(worker.run(campaign, dry_run=True))
        assert live.elapsed_ms >= 0
        assert any(j.status in {"planned", "skipped_missing"} for j in live.jobs)


class TestReconBridge:
    def test_findings_to_services(self):
        from nova_arsenal.zeroday import findings_to_services

        services = findings_to_services(
            [
                {
                    "title": "Open port 443/tcp https nginx/1.25",
                    "description": "Found https service version nginx/1.25 on port 443",
                    "evidence": "path /upload available",
                }
            ]
        )
        assert "https" in services
        assert 443 in services["https"].get("ports", [])


class TestZeroDayHunter:
    def test_blocks_unauthorized(self):
        hunter = ZeroDayHunter()
        result = _run(
            hunter.hunt(
                "lab.local",
                services={"http": [80]},
                config=ZeroDayHuntConfig(authorized=False),
            )
        )
        assert result.status == "blocked_unauthorized"
        assert result.candidates == []

    def test_full_hunt_fast(self):
        hunter = ZeroDayHunter()
        source = {
            "svc.py": "def run(cmd):\n    return os.system(cmd)\n",
        }
        crashes = [
            CrashReport(
                crash_id="x1",
                engine="afl++",
                stack_trace="#0 0x1 in parse\nuse-after-free",
                signal="SIGSEGV",
            )
        ]
        result = _run(
            hunter.hunt(
                "lab.local",
                services={
                    "https": {
                        "ports": [443],
                        "version": "CustomGW 0.9-beta",
                        "paths": ["/upload", "/api/v1"],
                        "params": ["file", "id"],
                    }
                },
                known_cves=[
                    {
                        "cve_id": "CVE-2021-41773",
                        "description": "path traversal in httpd",
                        "severity": "high",
                    }
                ],
                source_files=source,
                crashes=crashes,
                config=ZeroDayHuntConfig(
                    authorized=True,
                    authorization_ref="TEST-ENG-1",
                    max_candidates=30,
                ),
            )
        )
        assert result.status == "completed"
        assert result.elapsed_ms < 5000  # orchestration should be seconds-scale
        assert result.surface is not None
        assert result.fuzz_campaign is not None
        assert result.fuzz_campaign["job_count"] >= 1
        assert len(result.candidates) >= 1
        assert any(c.source_stage in {"variant", "static", "crash_triage", "surface"} for c in result.candidates)
        d = result.to_dict()
        assert "disclaimer" in d
        assert d["candidate_count"] == len(result.candidates)

    def test_exports(self):
        from nova_arsenal.zeroday import ZeroDayHunter, ZeroDayHuntConfig

        assert ZeroDayHunter is not None
        assert ZeroDayHuntConfig is not None
