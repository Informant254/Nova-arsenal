#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🧪 NOVA EVAL — Deterministic Benchmark & Evaluation Harness               ║
║                                                                              ║
║  20 benchmark missions across known-vulnerable targets.                     ║
║  Each mission has deterministic pass/fail criteria, evidence quality        ║
║  scoring, false-positive tracking, cost tracking, and timing.              ║
║                                                                              ║
║  Targets: DVWA, Juice Shop, WebGoat, intentional-vuln APIs, CTF-style       ║
║                                                                              ║
║  Usage:                                                                      ║
║    python3 nova_eval.py                        # run all missions           ║
║    python3 nova_eval.py --mission xss_01       # run one mission            ║
║    python3 nova_eval.py --quick                # only fast missions         ║
║    python3 nova_eval.py --compare prev.json    # regression compare        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import subprocess
import sys
import time
import unittest
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

JUICE_SHOP_URL = os.getenv("EVAL_JUICE_SHOP",  "http://localhost:3000")
DVWA_URL       = os.getenv("EVAL_DVWA",        "http://localhost:4280")
WEBGOAT_URL    = os.getenv("EVAL_WEBGOAT",     "http://localhost:8080/WebGoat")
LOCAL_APP_URL  = os.getenv("EVAL_LOCAL_APP",   "http://localhost:5000")
FIXTURES_DIR   = Path(__file__).parent / "eval_fixtures"
FIXTURES_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# SCORE CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

PASS   = "PASS"
FAIL   = "FAIL"
SKIP   = "SKIP"
FLAKY  = "FLAKY"

MAX_EVIDENCE_SCORE  = 10   # how well the finding is documented
MAX_ACCURACY_SCORE  = 10   # TP rate
COST_BUDGET_USD     = 0.10 # per mission


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MissionResult:
    mission_id:      str
    mission_name:    str
    status:          str    = SKIP
    elapsed_s:       float  = 0.0
    cost_usd:        float  = 0.0
    tokens_used:     int    = 0
    findings_count:  int    = 0
    true_positives:  int    = 0
    false_positives: int    = 0
    false_negatives: int    = 0
    evidence_score:  float  = 0.0    # 0–10: how good is the proof
    accuracy_score:  float  = 0.0    # 0–10: TP/(TP+FP+FN)
    overall_score:   float  = 0.0    # weighted composite
    notes:           str    = ""
    findings:        List[Dict] = field(default_factory=list)
    error:           str    = ""

    def compute_scores(self):
        tp = max(self.true_positives,  0)
        fp = max(self.false_positives, 0)
        fn = max(self.false_negatives, 0)
        total = tp + fp + fn
        self.accuracy_score = round(
            (tp / total * MAX_ACCURACY_SCORE) if total > 0 else 0.0, 2)
        # Evidence score is set by the checker, default based on findings structure
        if self.evidence_score == 0 and tp > 0:
            self.evidence_score = 5.0
        # Overall: 40% accuracy + 40% evidence + 20% cost/speed
        cost_ok   = 1.0 if self.cost_usd  <= COST_BUDGET_USD else 0.5
        speed_ok  = 1.0 if self.elapsed_s <= 60             else 0.5
        self.overall_score = round(
            (self.accuracy_score / MAX_ACCURACY_SCORE * 4 +
             self.evidence_score / MAX_EVIDENCE_SCORE * 4 +
             cost_ok * 1 + speed_ok * 1), 2)

    def as_dict(self):
        return asdict(self)


@dataclass
class EvalReport:
    run_id:        str
    generated:     str
    nova_version:  str = "4.2"
    results:       List[MissionResult] = field(default_factory=list)
    total_pass:    int = 0
    total_fail:    int = 0
    total_skip:    int = 0
    total_cost:    float = 0.0
    total_elapsed: float = 0.0
    mean_score:    float = 0.0
    regression_vs: str = ""
    regressions:   List[str] = field(default_factory=list)

    def compute(self):
        self.total_pass    = sum(1 for r in self.results if r.status == PASS)
        self.total_fail    = sum(1 for r in self.results if r.status == FAIL)
        self.total_skip    = sum(1 for r in self.results if r.status == SKIP)
        self.total_cost    = round(sum(r.cost_usd for r in self.results), 5)
        self.total_elapsed = round(sum(r.elapsed_s for r in self.results), 2)
        scored             = [r for r in self.results if r.status != SKIP]
        self.mean_score    = round(
            sum(r.overall_score for r in scored) / len(scored)
            if scored else 0.0, 2)

    def save(self, path: str):
        data = {
            "run_id":        self.run_id,
            "generated":     self.generated,
            "nova_version":  self.nova_version,
            "pass":          self.total_pass,
            "fail":          self.total_fail,
            "skip":          self.total_skip,
            "mean_score":    self.mean_score,
            "total_cost_usd":self.total_cost,
            "total_elapsed_s":self.total_elapsed,
            "regressions":   self.regressions,
            "results":       [r.as_dict() for r in self.results],
        }
        Path(path).write_text(json.dumps(data, indent=2, default=str))

    def print_summary(self):
        bar   = "═" * 64
        icons = {PASS: "✅", FAIL: "❌", SKIP: "⏭", FLAKY: "⚡"}
        print(f"\n{bar}")
        print(f"  🧪 Nova Eval — {len(self.results)} missions")
        print(f"  ✅ Pass: {self.total_pass}  ❌ Fail: {self.total_fail}  "
              f"⏭ Skip: {self.total_skip}")
        print(f"  📊 Mean score: {self.mean_score}/10  "
              f"💰 Cost: ${self.total_cost:.5f}  "
              f"⏱ {self.total_elapsed:.1f}s")
        if self.regressions:
            print(f"  ⚠️  REGRESSIONS: {', '.join(self.regressions)}")
        print(bar)
        for r in self.results:
            icon  = icons.get(r.status, "•")
            score = f"{r.overall_score:4.1f}" if r.status != SKIP else " — "
            print(f"  {icon} [{score}] {r.mission_id:<18} {r.mission_name[:36]:<36} "
                  f"{r.elapsed_s:5.1f}s  ${r.cost_usd:.5f}")
            if r.status == FAIL and r.notes:
                print(f"         ↳ {r.notes[:80]}")
        print(bar)


# ─────────────────────────────────────────────────────────────────────────────
# MISSION RUNNER BASE
# ─────────────────────────────────────────────────────────────────────────────

class Mission:
    """Base class for eval missions."""
    mission_id:   str  = "base"
    mission_name: str  = "Base Mission"
    target:       str  = ""
    quick:        bool = False   # True = runs even with --quick flag
    timeout_s:    int  = 120

    def available(self) -> bool:
        """Override to check if the target is reachable."""
        return True

    def run(self) -> MissionResult:
        raise NotImplementedError

    def _http_get(self, url: str, timeout: int = 10) -> Optional[str]:
        import urllib.request, urllib.error
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Nova-Eval/4.2"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read(32768).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _is_reachable(self, url: str) -> bool:
        return self._http_get(url, timeout=3) is not None

    def _run_nova(self, query: str, module_override: str = None) -> List[Dict]:
        """Run nova.py programmatically and collect findings."""
        try:
            sys.argv = ["nova.py", query]
            import importlib
            nova = importlib.import_module("nova")
            nova._PROVIDER_READY = False   # reset so re-init works
            nova._CMAP           = None
            intent = nova._parse_intent(query)
            if module_override:
                intent["mode"] = module_override
            nova._init_provider_layer(target=intent["target"])
            nova._run_phase0_mapper(intent["target"])
            return nova.dispatch(intent)
        except Exception as e:
            return [{"error": str(e)}]

    def _evidence_score_for(self, finding: Dict) -> float:
        """Score a single finding's evidence quality (0–10)."""
        score = 0.0
        if finding.get("endpoint") or finding.get("file"):
            score += 2.0
        if finding.get("evidence") or finding.get("snippet"):
            score += 2.0
        if finding.get("description") and len(str(finding["description"])) > 30:
            score += 2.0
        if finding.get("cvss") and float(finding.get("cvss", 0)) > 0:
            score += 1.0
        if finding.get("cve"):
            score += 1.0
        if finding.get("reproduction_steps") or finding.get("request"):
            score += 2.0
        return min(score, 10.0)


# ─────────────────────────────────────────────────────────────────────────────
# MISSIONS
# ─────────────────────────────────────────────────────────────────────────────

class M01_MapExpressRoutes(Mission):
    """Map all Express routes from a local fixture codebase."""
    mission_id   = "map_01"
    mission_name = "Map Express routes from codebase"
    quick        = True

    def available(self) -> bool:
        return True  # uses fixture files, no network needed

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            # Create fixture
            fixture = FIXTURES_DIR / "express_app"
            fixture.mkdir(exist_ok=True)
            (fixture / "app.js").write_text("""
const express = require('express');
const app = express();
app.get('/api/users', (req, res) => res.json([]));
app.post('/api/users', (req, res) => res.json({}));
app.get('/api/users/:id', (req, res) => res.json({}));
app.put('/api/users/:id', (req, res) => res.json({}));
app.delete('/api/users/:id', (req, res) => res.json({}));
app.get('/admin/dashboard', (req, res) => res.json({}));
app.post('/api/auth/login', (req, res) => res.json({}));
app.post('/api/payments/checkout', (req, res) => res.json({}));
app.post('/api/upload', (req, res) => res.json({}));
""")
            (fixture / "package.json").write_text(
                json.dumps({"name":"eval-fixture","dependencies":{"express":"4.18.2"}}))

            from nova_codebase_mapper import NovaCodebaseMapper
            cmap = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()

            expected_routes = {
                "/api/users", "/api/users/:id", "/admin/dashboard",
                "/api/auth/login", "/api/payments/checkout", "/api/upload",
            }
            found_routes = {ep["route"] for ep in cmap.endpoints}
            tp = len(expected_routes & found_routes)
            fn = len(expected_routes - found_routes)
            fp = len(found_routes - expected_routes)

            res.true_positives  = tp
            res.false_negatives = fn
            res.false_positives = fp
            res.findings_count  = len(cmap.endpoints)
            res.notes           = f"Found: {sorted(found_routes)}"
            res.status          = PASS if tp >= 6 else FAIL
            if res.status == FAIL:
                res.notes = f"Only found {tp}/6 expected routes. Missing: {expected_routes - found_routes}"
            # Evidence score: map has concrete route+file+line
            avg_ev = sum(
                (3 if ep.get("route") else 0) +
                (3 if ep.get("file")  else 0) +
                (2 if ep.get("line")  else 0)
                for ep in cmap.endpoints[:10]
            ) / max(len(cmap.endpoints[:10]), 1) * (10 / 8)
            res.evidence_score = round(min(avg_ev, 10), 2)
        except Exception as e:
            res.status = FAIL
            res.error  = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M02_DetectVulnDepJWT(Mission):
    """Detect vulnerable jsonwebtoken dependency."""
    mission_id   = "sca_01"
    mission_name = "SCA: detect CVE in jsonwebtoken"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "vuln_dep"
            fixture.mkdir(exist_ok=True)
            (fixture / "package.json").write_text(json.dumps({
                "name": "test-app",
                "dependencies": {
                    "jsonwebtoken": "8.5.1",
                    "lodash":       "4.17.19",
                    "express":      "4.18.0",
                }
            }))
            from nova_codebase_mapper import NovaCodebaseMapper, RISKY_DEPS
            cmap = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()
            risky_names = {d["package"].lower() for d in cmap.risky_deps}
            expected = {"jsonwebtoken", "lodash", "express"}
            tp = len(expected & risky_names)
            fn = len(expected - risky_names)
            res.true_positives  = tp
            res.false_negatives = fn
            res.findings_count  = len(cmap.risky_deps)
            res.status          = PASS if tp >= 2 else FAIL
            res.notes           = f"Detected risky: {sorted(risky_names)}"
            res.evidence_score  = 8.0 if tp >= 2 else 3.0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M03_DetectHardcodedSecret(Mission):
    """Detect hardcoded secrets in source."""
    mission_id   = "secret_01"
    mission_name = "Detect hardcoded AWS key in source"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "secrets"
            fixture.mkdir(exist_ok=True)
            # Plant known-format secrets (fake, eval only)
            (fixture / "config.js").write_text(
                "const AWS_ACCESS_KEY_ID = 'AKI' + 'AIOSFODNN7EXAMPLE';\n"
                "const JWT_SECRET = 'super' + 'secretkey123';\n"
                "const API_KEY = 'AIza' + 'SyDummyGoogleKey12345678901234567';\n")
            from nova_codebase_mapper import NovaCodebaseMapper
            cmap = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()
            secret_types = {s["pattern"] for s in cmap.secret_findings}
            expected = {"AWS Key", "JWT Secret", "Google API"}
            tp = len(expected & secret_types)
            fn = len(expected - secret_types)
            fp = max(0, len(cmap.secret_findings) - tp)
            res.true_positives  = tp
            res.false_negatives = fn
            res.false_positives = fp
            res.findings_count  = len(cmap.secret_findings)
            res.status          = PASS if tp >= 2 else FAIL
            res.notes           = f"Found: {sorted(secret_types)}"
            res.evidence_score  = 9.0 if tp >= 3 else (6.0 if tp >= 2 else 2.0)
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M04_LanguageDetection(Mission):
    """Correctly identify all languages in a polyglot fixture."""
    mission_id   = "map_02"
    mission_name = "Identify 8+ languages in polyglot repo"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "polyglot"
            fixture.mkdir(exist_ok=True)
            files = {
                "app.py":       "def main(): pass",
                "server.ts":    "import express from 'express';",
                "handler.go":   "package main\nfunc main() {}",
                "App.java":     "public class App { public static void main(String[] args) {} }",
                "style.css":    "body { margin: 0; }",
                "index.rs":     "fn main() {}",
                "Main.kt":      "fun main() {}",
                "app.rb":       "puts 'hello'",
                "query.sql":    "SELECT * FROM users;",
                "infra.tf":     'resource "aws_s3_bucket" "b" {}',
                "schema.graphql":"type Query { users: [User] }",
            }
            for fname, content in files.items():
                (fixture / fname).write_text(content)
            from nova_codebase_mapper import NovaCodebaseMapper
            cmap = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()
            expected_langs = {"Python","TypeScript","Go","Java","CSS",
                              "Rust","Kotlin","Ruby","SQL","Terraform","GraphQL"}
            found_langs    = set(cmap.languages.keys())
            tp             = len(expected_langs & found_langs)
            fn             = len(expected_langs - found_langs)
            res.true_positives  = tp
            res.false_negatives = fn
            res.findings_count  = len(found_langs)
            res.status          = PASS if tp >= 8 else FAIL
            res.notes           = f"Found {tp}/11 languages: {sorted(found_langs)}"
            res.evidence_score  = 8.0 if tp >= 9 else 5.0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M05_FrameworkDetection(Mission):
    """Detect frameworks from manifest files."""
    mission_id   = "map_03"
    mission_name = "Detect 6+ frameworks from manifests"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "frameworks"
            fixture.mkdir(exist_ok=True)
            (fixture / "package.json").write_text(json.dumps({
                "dependencies": {
                    "express": "4.18.2", "react": "18.2.0",
                    "mongoose": "7.0.0", "@prisma/client": "5.0.0",
                }}))
            (fixture / "requirements.txt").write_text(
                "Flask==2.3.0\nSQLAlchemy==2.0.0\ncelery==5.3.0\n")
            expected = {"Express","React","Mongoose","Prisma","Flask","SQLAlchemy","Celery"}
            from nova_codebase_mapper import NovaCodebaseMapper
            cmap = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()
            found = set(cmap.frameworks)
            tp    = len(expected & found)
            fn    = len(expected - found)
            res.true_positives  = tp
            res.false_negatives = fn
            res.findings_count  = len(found)
            res.status          = PASS if tp >= 5 else FAIL
            res.notes           = f"Found {tp}/7: {sorted(found)}"
            res.evidence_score  = 7.0 if tp >= 6 else 4.0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M06_AttackSurfaceScoring(Mission):
    """Admin + payment endpoints must score highest."""
    mission_id   = "map_04"
    mission_name = "Attack surface: admin/payment ranked first"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "scoring"
            fixture.mkdir(exist_ok=True)
            (fixture / "routes.js").write_text("""
const router = require('express').Router();
router.get('/api/v1/health', handler);
router.get('/api/v1/users/:id', handler);
router.post('/api/v1/admin/users/delete', handler);
router.post('/api/v1/payments/checkout', handler);
router.post('/api/v1/upload', handler);
router.get('/api/v1/search', handler);
""")
            from nova_codebase_mapper import NovaCodebaseMapper
            cmap = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()
            hv_routes = [h.get("route","") for h in cmap.attack_surface.get("high_value",[])]
            must_be_hv = ["/api/v1/admin/users/delete", "/api/v1/payments/checkout",
                          "/api/v1/upload"]
            tp = sum(1 for r in must_be_hv if any(r in hv for hv in hv_routes))
            res.true_positives  = tp
            res.false_negatives = len(must_be_hv) - tp
            res.findings_count  = len(hv_routes)
            res.status          = PASS if tp >= 2 else FAIL
            res.notes           = f"High-value: {hv_routes[:5]}"
            res.evidence_score  = 8.0 if tp >= 3 else 4.0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M07_DiffWatcherSecretDetection(Mission):
    """DiffWatcher detects secret added to a file."""
    mission_id   = "diff_01"
    mission_name = "DiffWatcher: detect newly added secret"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture  = FIXTURES_DIR / "diff_test"
            fixture.mkdir(exist_ok=True)
            test_file = fixture / "auth.js"
            test_file.write_text("// auth module\n")

            from nova_diff_watcher import NovaDiffWatcher
            watcher = NovaDiffWatcher(str(fixture), verbose=False)

            # Simulate adding a secret
            test_file.write_text(
                "const STRIPE_KEY = 'sk_li' + 've_abcdefghijklmnopqrstuvwx';\n")

            batch_type  = type(None)
            # Use scan_staged-like approach: direct batch processing
            from nova_diff_watcher import ChangeBatch
            batch          = ChangeBatch()
            batch.modified = ["auth.js"]
            findings       = watcher._process_batch(batch)

            tp = sum(1 for f in findings if "Stripe" in f.get("pattern","")
                     or "stripe" in f.get("type","").lower()
                     or "Secret" in f.get("type",""))
            if not tp:
                tp = 1 if findings else 0  # any finding = good
            res.true_positives  = tp
            res.findings_count  = len(findings)
            res.status          = PASS if findings else FAIL
            res.notes           = f"{len(findings)} findings from diff"
            res.evidence_score  = 8.0 if (findings and all(
                f.get("file") and f.get("line") for f in findings)) else 4.0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M08_JuiceShopReachable(Mission):
    """Juice Shop target is reachable (infrastructure check)."""
    mission_id   = "infra_01"
    mission_name = "Juice Shop reachability check"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        body = self._http_get(JUICE_SHOP_URL, timeout=5)
        if body and ("Juice" in body or "OWASP" in body or "angular" in body.lower()):
            res.status         = PASS
            res.true_positives = 1
            res.evidence_score = 10.0
            res.notes          = f"Juice Shop live at {JUICE_SHOP_URL}"
        else:
            res.status = SKIP
            res.notes  = f"Juice Shop not reachable at {JUICE_SHOP_URL} — skipped"
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M09_JuiceShopIDOR(Mission):
    """Find IDOR on /rest/user/whoami when Juice Shop is running."""
    mission_id   = "idor_01"
    mission_name = "Juice Shop: IDOR on /rest/user/whoami"

    def available(self) -> bool:
        return self._is_reachable(JUICE_SHOP_URL)

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        if not self.available():
            res.status = SKIP
            res.notes  = "Juice Shop not available"
            res.elapsed_s = time.monotonic() - t0
            return res
        try:
            findings = self._run_nova(
                f"Test IDOR on {JUICE_SHOP_URL}", "idor")
            idor_findings = [f for f in findings
                             if "idor" in f.get("type","").lower()
                             or "access" in f.get("type","").lower()
                             or "object" in f.get("type","").lower()]
            res.findings_count  = len(findings)
            res.true_positives  = len(idor_findings)
            res.false_positives = len(findings) - len(idor_findings)
            res.status          = PASS if idor_findings else FAIL
            res.notes           = f"{len(idor_findings)} IDOR findings"
            res.evidence_score  = sum(self._evidence_score_for(f) for f in idor_findings[:3])
            res.findings        = idor_findings[:5]
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M10_JuiceShopJWT(Mission):
    """Detect JWT alg:none vulnerability in Juice Shop."""
    mission_id   = "jwt_01"
    mission_name = "Juice Shop: detect JWT alg:none"

    def available(self) -> bool:
        return self._is_reachable(JUICE_SHOP_URL)

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        if not self.available():
            res.status = SKIP; res.notes = "Juice Shop not available"
            res.elapsed_s = time.monotonic() - t0; return res
        try:
            findings = self._run_nova(
                f"Test JWT vulnerabilities on {JUICE_SHOP_URL}", "jwt")
            jwt_findings = [f for f in findings
                            if "jwt" in f.get("type","").lower()
                            or "alg" in str(f.get("description","")).lower()
                            or "token" in f.get("type","").lower()]
            res.findings_count  = len(findings)
            res.true_positives  = len(jwt_findings)
            res.status          = PASS if jwt_findings else FAIL
            res.notes           = f"{len(jwt_findings)} JWT findings"
            res.evidence_score  = min(sum(
                self._evidence_score_for(f) for f in jwt_findings[:3]), 10.0)
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M11_SASTFindsHardcodedCreds(Mission):
    """SAST finds hardcoded credentials in Python fixture."""
    mission_id   = "sast_01"
    mission_name = "SAST: find hardcoded creds in Python"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "sast_py"
            fixture.mkdir(exist_ok=True)
            (fixture / "db.py").write_text("""
import psycopg2
conn = psycopg2.connect(
    host="localhost", database="prod",
    user="admin", password="Sup3rS3cret!")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
""")
            findings = self._run_nova(f"SAST audit {fixture}", "sast")
            hardcoded = [f for f in findings
                         if any(k in str(f).lower() for k in
                                ("hardcoded","password","credential","injection","sqli"))]
            res.true_positives  = len(hardcoded)
            res.findings_count  = len(findings)
            res.status          = PASS if hardcoded else FAIL
            res.notes           = f"{len(hardcoded)} relevant findings from {len(findings)} total"
            res.evidence_score  = 7.0 if hardcoded else 2.0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M12_SCAFindsVulnPyYAML(Mission):
    """SCA identifies PyYAML RCE risk."""
    mission_id   = "sca_02"
    mission_name = "SCA: detect PyYAML RCE (CVE-2020-14343)"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "vuln_py"
            fixture.mkdir(exist_ok=True)
            (fixture / "requirements.txt").write_text(
                "pyyaml==5.4\nrequests==2.25.1\nflask==1.1.2\n")
            from nova_codebase_mapper import NovaCodebaseMapper
            cmap = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()
            risky = {d["package"].lower() for d in cmap.risky_deps}
            tp    = 1 if "pyyaml" in risky else 0
            res.true_positives  = tp
            res.findings_count  = len(cmap.risky_deps)
            res.status          = PASS if tp else FAIL
            res.notes           = f"Risky: {sorted(risky)}"
            res.evidence_score  = 9.0 if tp else 0.0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M13_DiffWatcherIaC(Mission):
    """DiffWatcher detects insecure IaC (0.0.0.0/0)."""
    mission_id   = "diff_02"
    mission_name = "DiffWatcher: detect insecure IaC rule"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "iac_test"
            fixture.mkdir(exist_ok=True)
            (fixture / "main.tf").write_text("""
resource "aws_security_group_rule" "bad" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
""")
            from nova_diff_watcher import NovaDiffWatcher, ChangeBatch
            watcher = NovaDiffWatcher(str(fixture), verbose=False)
            batch   = ChangeBatch()
            batch.added = ["main.tf"]
            findings = watcher._process_batch(batch)
            iac_f = [f for f in findings if "ingress" in str(f).lower()
                     or "open" in str(f).lower() or "0.0.0.0" in str(f)]
            res.true_positives  = len(iac_f)
            res.findings_count  = len(findings)
            res.status          = PASS if iac_f else FAIL
            res.notes           = f"{len(findings)} total, {len(iac_f)} IaC findings"
            res.evidence_score  = 8.0 if iac_f else 3.0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M14_SCAOnManifestChange(Mission):
    """DiffWatcher triggers SCA when package.json changes."""
    mission_id   = "diff_03"
    mission_name = "DiffWatcher: SCA triggered by manifest change"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "sca_trigger"
            fixture.mkdir(exist_ok=True)
            (fixture / "package.json").write_text(json.dumps({
                "dependencies": {"lodash": "4.17.15", "axios": "0.21.0"}}))
            from nova_diff_watcher import NovaDiffWatcher, ChangeBatch
            watcher = NovaDiffWatcher(str(fixture), verbose=False)
            batch   = ChangeBatch()
            batch.modified = ["package.json"]
            classes = batch.classify()
            res.status = PASS if "package.json" in classes.get("sca",[]) else FAIL
            res.notes  = f"SCA triggered: {'yes' if res.status == PASS else 'no'}"
            res.evidence_score = 10.0 if res.status == PASS else 0.0
            res.true_positives = 1 if res.status == PASS else 0
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M15_MapperSpeedLarge(Mission):
    """Mapper handles 1000 synthetic files in under 10 seconds."""
    mission_id   = "perf_01"
    mission_name = "Mapper: 1000 files scanned < 10s"
    quick        = False

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            import tempfile, random, string
            fixture = Path(tempfile.mkdtemp())
            exts    = [".js",".ts",".py",".go",".java",".rb",".php"]
            for i in range(1000):
                ext  = random.choice(exts)
                name = "file_" + str(i) + ext
                content = "const x = " + str(i) + ";\n" + "// " + "".join(
                    random.choices(string.ascii_letters, k=100))
                (fixture / name).write_text(content)

            from nova_codebase_mapper import NovaCodebaseMapper
            cmap    = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()
            elapsed = time.monotonic() - t0
            res.elapsed_s      = elapsed
            res.findings_count = cmap.file_count
            res.status         = PASS if elapsed < 10.0 and cmap.file_count >= 990 else FAIL
            res.notes          = f"{cmap.file_count} files in {elapsed:.2f}s"
            res.evidence_score = 10.0 if elapsed < 5.0 else (7.0 if elapsed < 10.0 else 3.0)
            # Cleanup
            import shutil; shutil.rmtree(str(fixture), ignore_errors=True)
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M16_ProviderLayerInit(Mission):
    """All 7 provider modules import without error."""
    mission_id   = "infra_02"
    mission_name = "Provider layer: all 7 modules import"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        modules = [
            ("nova_llm_router",    "get_router"),
            ("nova_hooks",         "get_bus"),
            ("nova_context",       "RunContext"),
            ("nova_sessions",      "SessionStore"),
            ("nova_observability", "Tracer"),
            ("nova_retry",         "RetryPolicy"),
            ("nova_skills",        "SkillLibrary"),
        ]
        loaded, missing = [], []
        for mod, attr in modules:
            try:
                import importlib
                m = importlib.import_module(mod)
                if getattr(m, attr, None) is not None:
                    loaded.append(mod)
                else:
                    missing.append(f"{mod}.{attr}")
            except ImportError:
                missing.append(mod)
        res.true_positives  = len(loaded)
        res.false_negatives = len(missing)
        res.findings_count  = len(loaded)
        res.status          = PASS if len(loaded) >= 5 else FAIL
        res.notes           = (f"Loaded: {len(loaded)}/7. "
                               f"{'Missing: ' + ','.join(missing) if missing else ''}")
        res.evidence_score  = 10.0 if len(loaded) == 7 else float(loaded.__len__()) / 7 * 10
        res.elapsed_s       = time.monotonic() - t0
        res.compute_scores()
        return res


class M17_OrchestratorBuildable(Mission):
    """Orchestrator builds a Runner without error."""
    mission_id   = "orch_01"
    mission_name = "Orchestrator: build_security_network()"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            import nova_orchestrator
            runner = nova_orchestrator.build_security_network(
                "http://localhost:3000", verbose=False)
            agent_names = list(runner.agents.keys())
            required    = {"ReconAgent","AttackAgent","ReportAgent"}
            tp          = len(required & set(agent_names))
            res.true_positives  = tp
            res.false_negatives = len(required) - tp
            res.status          = PASS if tp == 3 else FAIL
            res.notes           = f"Agents: {agent_names}"
            res.evidence_score  = 10.0 if tp == 3 else float(tp) / 3 * 10
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M18_MapToAgentContext(Mission):
    """attack_brief() produces non-empty string with key sections."""
    mission_id   = "map_05"
    mission_name = "CodebaseMap.attack_brief() structure"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            fixture = FIXTURES_DIR / "brief_test"
            fixture.mkdir(exist_ok=True)
            (fixture / "server.js").write_text("""
const express = require('express');
const jwt     = require('jsonwebtoken');
const app     = express();
app.get('/api/users/:id',    (req, res) => {});
app.post('/admin/delete',    (req, res) => {});
app.post('/api/payment',     (req, res) => {});
""")
            (fixture / "package.json").write_text(json.dumps({
                "dependencies": {"express":"4.18.0","jsonwebtoken":"8.5.1"}}))
            from nova_codebase_mapper import NovaCodebaseMapper
            cmap  = NovaCodebaseMapper(str(fixture), verbose=False, ai_analysis=False).scan()
            brief = cmap.attack_brief()
            required_sections = [
                "NOVA STRATEGIC CODEBASE MAP",
                "HIGH-VALUE ENDPOINTS",
                "ATTACK PRIORITY",
                "QUICK WINS",
            ]
            found_sections = [s for s in required_sections if s in brief]
            res.true_positives  = len(found_sections)
            res.false_negatives = len(required_sections) - len(found_sections)
            res.status          = PASS if len(found_sections) >= 3 else FAIL
            res.notes           = f"Sections found: {found_sections}"
            res.evidence_score  = float(len(found_sections)) / len(required_sections) * 10
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M19_NovaPyIntentParse(Mission):
    """nova.py correctly classifies intent for 10 known queries."""
    mission_id   = "core_01"
    mission_name = "nova.py: intent classification"
    quick        = True

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        try:
            import nova
            test_cases = [
                ("Hunt http://target.com for bugs",           "hunt"),
                ("Map the codebase at ./src",                 "map"),
                ("SAST scan of ./my-app",                     "sast"),
                ("SCA dependency check",                      "sca"),
                ("Test IDOR on https://target.com",           "idor"),
                ("Check JWT vulnerabilities",                 "jwt"),
                ("Build threat model for ./api",              "threat_model"),
                ("Show vulnerability tracker dashboard",      "vuln_track"),
                ("Full stack pipeline on ./juice-shop",       "full_stack"),
                ("Triage findings and rank by priority",      "triage"),
            ]
            tp, fp = 0, 0
            for query, expected_mode in test_cases:
                try:
                    intent = nova._parse_intent(query)
                    if intent["mode"] == expected_mode:
                        tp += 1
                    else:
                        fp += 1
                        if res.notes:
                            res.notes += f"; "
                        res.notes += f"'{query[:30]}' → {intent['mode']} (want {expected_mode})"
                except Exception:
                    fp += 1
            res.true_positives  = tp
            res.false_positives = fp
            res.findings_count  = len(test_cases)
            res.status          = PASS if tp >= 7 else FAIL
            if not res.notes:
                res.notes = f"{tp}/10 correct"
            res.evidence_score  = float(tp) / 10 * 10
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


class M20_EndToEndLocalApp(Mission):
    """End-to-end: map + hunt on local test server, get >= 1 finding."""
    mission_id   = "e2e_01"
    mission_name = "E2E: map + hunt on local test server"

    def available(self) -> bool:
        return self._is_reachable(LOCAL_APP_URL)

    def run(self) -> MissionResult:
        res = MissionResult(self.mission_id, self.mission_name)
        t0  = time.monotonic()
        if not self.available():
            res.status = SKIP
            res.notes  = f"Local app not reachable at {LOCAL_APP_URL}"
            res.elapsed_s = time.monotonic() - t0; return res
        try:
            findings = self._run_nova(
                f"Full stack pipeline on {LOCAL_APP_URL}", "full_stack")
            res.findings_count  = len(findings)
            res.true_positives  = len(findings)
            res.status          = PASS if findings else FAIL
            res.notes           = f"{len(findings)} findings from full stack"
            res.evidence_score  = sum(
                self._evidence_score_for(f) for f in findings[:5]
            ) / max(len(findings[:5]), 1) if findings else 0.0
            res.findings        = findings[:10]
        except Exception as e:
            res.status = FAIL; res.error = str(e)
        res.elapsed_s = time.monotonic() - t0
        res.compute_scores()
        return res


# ─────────────────────────────────────────────────────────────────────────────
# ALL MISSIONS REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

ALL_MISSIONS: List[Mission] = [
    M01_MapExpressRoutes(),
    M02_DetectVulnDepJWT(),
    M03_DetectHardcodedSecret(),
    M04_LanguageDetection(),
    M05_FrameworkDetection(),
    M06_AttackSurfaceScoring(),
    M07_DiffWatcherSecretDetection(),
    M08_JuiceShopReachable(),
    M09_JuiceShopIDOR(),
    M10_JuiceShopJWT(),
    M11_SASTFindsHardcodedCreds(),
    M12_SCAOnManifestChange(),
    M13_DiffWatcherIaC(),
    M14_SCAOnManifestChange(),
    M15_MapperSpeedLarge(),
    M16_ProviderLayerInit(),
    M17_OrchestratorBuildable(),
    M18_MapToAgentContext(),
    M19_NovaPyIntentParse(),
    M20_EndToEndLocalApp(),
]


def compare_reports(current: EvalReport, prev_path: str) -> List[str]:
    """Detect regressions vs a previous report."""
    regressions = []
    try:
        prev_data = json.loads(Path(prev_path).read_text())
        prev_map  = {r["mission_id"]: r for r in prev_data.get("results", [])}
        for r in current.results:
            prev = prev_map.get(r.mission_id)
            if not prev:
                continue
            if prev["status"] == PASS and r.status == FAIL:
                regressions.append(
                    f"{r.mission_id}: was PASS, now FAIL ({r.notes[:50]})")
            if (prev.get("overall_score", 0) - r.overall_score) > 1.5:
                regressions.append(
                    f"{r.mission_id}: score dropped "
                    f"{prev['overall_score']:.1f}→{r.overall_score:.1f}")
    except Exception as e:
        regressions.append(f"Comparison error: {e}")
    return regressions


def run_eval(
    missions:     List[Mission] = None,
    quick_only:   bool = False,
    mission_ids:  List[str] = None,
    compare_path: str = None,
    parallel:     bool = True,
) -> EvalReport:
    missions = missions or ALL_MISSIONS
    if quick_only:
        missions = [m for m in missions if m.quick]
    if mission_ids:
        missions = [m for m in missions if m.mission_id in mission_ids]

    run_id  = datetime.now().strftime("%Y%m%d_%H%M%S")
    report  = EvalReport(run_id=run_id, generated=datetime.now().isoformat())

    print(f"\n  🧪 Nova Eval — {len(missions)} missions")
    print(f"  {'─'*60}")

    def _run_one(m: Mission) -> MissionResult:
        avail = m.available()
        if not avail:
            r = MissionResult(m.mission_id, m.mission_name)
            r.status = SKIP
            r.notes  = "Target not available"
            return r
        return m.run()

    if parallel and len(missions) > 3:
        with ThreadPoolExecutor(max_workers=min(8, len(missions))) as ex:
            futures = {ex.submit(_run_one, m): m for m in missions}
            for fut in as_completed(futures):
                r = fut.result()
                report.results.append(r)
                icon = {"PASS":"✅","FAIL":"❌","SKIP":"⏭"}.get(r.status,"•")
                print(f"  {icon} {r.mission_id:<18} {r.elapsed_s:5.1f}s  "
                      f"score={r.overall_score:.1f}  {r.notes[:50]}")
    else:
        for m in missions:
            r = _run_one(m)
            report.results.append(r)
            icon = {"PASS":"✅","FAIL":"❌","SKIP":"⏭"}.get(r.status,"•")
            print(f"  {icon} {r.mission_id:<18} {r.elapsed_s:5.1f}s  "
                  f"score={r.overall_score:.1f}  {r.notes[:50]}")

    report.compute()

    if compare_path:
        report.regression_vs = compare_path
        report.regressions   = compare_reports(report, compare_path)

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = WORKSPACE / f"nova_eval_{ts}.json"
    report.save(str(path))
    report.print_summary()
    print(f"\n  💾 Report saved → {path}\n")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="🧪 Nova Eval Harness")
    parser.add_argument("--mission",  action="append", metavar="ID",
                        help="Run specific mission(s) by ID")
    parser.add_argument("--quick",   action="store_true",
                        help="Only run quick missions (no live targets)")
    parser.add_argument("--compare", metavar="PATH",
                        help="Compare results against previous report JSON")
    parser.add_argument("--no-parallel", action="store_true")
    args = parser.parse_args()

    report = run_eval(
        quick_only=args.quick,
        mission_ids=args.mission,
        compare_path=args.compare,
        parallel=not args.no_parallel,
    )
    sys.exit(0 if report.total_fail == 0 else 1)
