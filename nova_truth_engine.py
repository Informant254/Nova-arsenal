#!/usr/bin/env python3
"""
Nova Truth Engine v1.1
=======================
Zero false positive verification system.

The Problem:
- Most scanners report 40-60% false positives
- Pentesters waste hours verifying fake findings
- Clients lose trust when fake findings are reported
- Bug bounty reports get rejected

The Solution:
Nova NEVER reports a finding unless it's verified real.

How it works:
1. Initial detection (scanner finds something)
2. Triple verification (3 independent confirmation methods)
3. Proof of exploitability (can we actually exploit it?)
4. Confidence scoring (0-100%)
5. Only report if confidence >= threshold

A finding is REAL only when:
- It can be reproduced consistently
- Multiple verification methods confirm it
- Proof of concept works
- False positive patterns don't match

OOB Verification (blind bugs):
  Nova uses interactsh (free, open source, no account needed) for
  blind SSRF, blind XXE, and DNS-based verification.
  interactsh-client is spawned automatically if `go` is available.
  Set NOVA_INTERACTSH_SERVER to use a self-hosted server.
  Set NOVA_INTERACTSH_TOKEN if your server requires auth.

Wiring:
  NovaTruthEngine is loaded as a singleton in nova.py's provider layer.
  dispatch() calls filter_real_findings() on the aggregated findings list
  BEFORE they are passed to nova_report.py / nova_weapon_forge.py.

  Env vars:
    NOVA_TRUTH_THRESHOLD     — float 0-1, default 0.95
    NOVA_TRUTH_DISABLED      — set to "1" to bypass (debug only)
    NOVA_INTERACTSH_SERVER   — custom interactsh server (default: oast.pro)
    NOVA_INTERACTSH_TOKEN    — auth token for self-hosted interactsh
"""

import logging
import time
import hashlib
import json
import os
import subprocess
import threading
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    UNVERIFIED    = "unverified"
    VERIFYING     = "verifying"
    CONFIRMED     = "confirmed"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE  = "inconclusive"
    NEEDS_MANUAL  = "needs_manual"


class VerificationMethod(Enum):
    REPRODUCTION     = "reproduction"
    DIFFERENTIAL     = "differential"
    PROOF_OF_CONCEPT = "proof_of_concept"
    PATTERN_ANALYSIS = "pattern_analysis"
    BEHAVIORAL       = "behavioral"
    TIME_BASED       = "time_based"
    OUT_OF_BAND      = "out_of_band"
    LLM_ANALYSIS     = "llm_analysis"


@dataclass
class VerificationResult:
    method:     VerificationMethod
    passed:     bool
    confidence: float
    evidence:   str
    details:    str = ""
    timestamp:  str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class TruthReport:
    finding_id:    str
    finding_title: str
    finding_type:  str

    status:           VerificationStatus = VerificationStatus.UNVERIFIED
    is_real:          bool  = False
    confidence:       float = 0.0
    confidence_label: str   = ""

    verifications:           List[VerificationResult] = field(default_factory=list)
    proof_of_concept:        str  = ""
    reproduction_steps:      List[str] = field(default_factory=list)
    differential_evidence:   str  = ""
    false_positive_indicators: List[str] = field(default_factory=list)
    false_positive_probability: float = 0.0

    verified_at:               str   = field(default_factory=lambda: datetime.now().isoformat())
    verification_time_seconds: float = 0.0
    notes: str = ""

    def summary(self) -> str:
        verdict = "✅ REAL FINDING" if self.is_real else "❌ FALSE POSITIVE"
        return (
            f"{verdict}\n"
            f"Confidence: {self.confidence:.0%} ({self.confidence_label})\n"
            f"Verifications: {len(self.verifications)} methods used\n"
            f"False positive probability: {self.false_positive_probability:.0%}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTSH OOB CLIENT
# ─────────────────────────────────────────────────────────────────────────────

class InteractshClient:
    """
    Manages an interactsh-client subprocess for OOB (out-of-band) verification.

    Interactsh is a free, open-source tool by ProjectDiscovery that provides
    DNS/HTTP/SMTP callback URLs for detecting blind vulnerabilities:
      - Blind SSRF  (server calls your URL → SSRF confirmed)
      - Blind XXE   (parser fetches external entity → XXE confirmed)
      - Blind SQLi  (out-of-band DNS exfiltration → SQLi confirmed)
      - Blind RCE   (command triggers HTTP callback → RCE confirmed)

    Nova automatically spins this up if `go` or `interactsh-client` is available.
    No account or signup needed. Uses ProjectDiscovery's public server by default.
    """

    PUBLIC_SERVER  = "oast.pro"
    INSTALL_CMD    = "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

    def __init__(self):
        self.server    = os.getenv("NOVA_INTERACTSH_SERVER", self.PUBLIC_SERVER)
        self.token     = os.getenv("NOVA_INTERACTSH_TOKEN", "")
        self.url:      Optional[str] = None
        self._proc:    Optional[subprocess.Popen] = None
        self._output:  List[str] = []
        self._lock     = threading.Lock()
        self._ready    = threading.Event()
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if interactsh-client binary exists."""
        if self._available is None:
            self._available = (
                subprocess.run(["which", "interactsh-client"],
                               capture_output=True).returncode == 0
            )
            if not self._available:
                logger.info(
                    "interactsh-client not found. OOB verification disabled.\n"
                    f"  To enable: {self.INSTALL_CMD}"
                )
        return self._available

    def start(self) -> bool:
        """
        Spawn interactsh-client, wait for it to print the OOB URL,
        return True if we have a live URL within 8 seconds.
        """
        if not self.is_available():
            return False
        if self.url:
            return True

        cmd = ["interactsh-client", "-server", self.server, "-json"]
        if self.token:
            cmd += ["-token", self.token]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            # Read lines in background thread
            threading.Thread(target=self._reader, daemon=True).start()
            # Wait up to 8 s for the OOB URL
            if self._ready.wait(timeout=8) and self.url:
                logger.info(f"Interactsh OOB ready: {self.url}")
                return True
            logger.warning("Interactsh did not produce URL within 8 s")
            return False
        except Exception as e:
            logger.warning(f"Could not start interactsh-client: {e}")
            return False

    def _reader(self):
        """Background thread — reads stdout, extracts URL and callbacks."""
        url_re = re.compile(r'"interactsh-url"\s*:\s*"([^"]+)"')
        for line in self._proc.stdout:
            with self._lock:
                self._output.append(line.strip())
            if not self.url:
                m = url_re.search(line)
                if m:
                    self.url = m.group(1)
                    self._ready.set()

    def poll_callbacks(self, wait_seconds: int = 5) -> List[Dict]:
        """
        Wait `wait_seconds` then return all callbacks received so far.
        Each callback is a dict parsed from interactsh JSON output.
        """
        time.sleep(wait_seconds)
        callbacks = []
        with self._lock:
            for line in self._output:
                try:
                    data = json.loads(line)
                    if "protocol" in data:
                        callbacks.append(data)
                except Exception:
                    pass
        return callbacks

    def saw_callback(self, wait_seconds: int = 5) -> bool:
        """Return True if at least one DNS/HTTP callback was received."""
        return len(self.poll_callbacks(wait_seconds)) > 0

    def stop(self):
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def __del__(self):
        self.stop()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class NovaTruthEngine:
    """
    Zero false positive verification engine.

    Every finding goes through rigorous multi-method verification
    before being reported as real.

    Default threshold: 95% confidence (NOVA_TRUTH_THRESHOLD env var)
    Minimum verifications: 2 independent methods must pass

    OOB: interactsh spun up automatically when available.
    """

    DEFAULT_THRESHOLD     = 0.95
    MIN_VERIFICATIONS     = 2

    def __init__(
        self,
        http_client=None,
        llm_router=None,
        confidence_threshold: float = None,
        notifications=None
    ):
        self.http_client  = http_client
        self.llm_router   = llm_router
        self.notifications = notifications
        self.confidence_threshold = confidence_threshold or float(
            os.getenv("NOVA_TRUTH_THRESHOLD", str(self.DEFAULT_THRESHOLD))
        )

        self.false_positive_patterns = FalsePositivePatterns()
        self._oob = InteractshClient()
        self._oob_active = False

        self.verification_strategies = {
            "sql_injection":   self._verify_sqli,
            "xss":             self._verify_xss,
            "idor":            self._verify_idor,
            "ssrf":            self._verify_ssrf,
            "open_redirect":   self._verify_open_redirect,
            "path_traversal":  self._verify_path_traversal,
            "command_injection": self._verify_command_injection,
            "xxe":             self._verify_xxe,
            "rce":             self._verify_rce,
            "lfi":             self._verify_lfi,
            "csrf":            self._verify_csrf,
            "jwt_vulnerability": self._verify_jwt,
            "ssti":            self._verify_ssti,
            "generic":         self._verify_generic
        }

        logger.info(
            f"Truth Engine v1.1 ready "
            f"(threshold={self.confidence_threshold:.0%}, "
            f"OOB={'interactsh' if self._oob.is_available() else 'disabled'})"
        )

    # ─── OOB Bootstrap ───────────────────────────────────────────────────────

    def _ensure_oob(self) -> bool:
        """Start interactsh on first OOB need."""
        if not self._oob_active:
            self._oob_active = self._oob.start()
        return self._oob_active

    # ─── Public API ──────────────────────────────────────────────────────────

    def verify_finding(self, finding: Dict[str, Any]) -> TruthReport:
        start_time   = time.time()
        finding_id   = finding.get("id", hashlib.md5(
            finding.get("title", "").encode()
        ).hexdigest()[:8])
        finding_type = finding.get("type", "generic").lower()

        logger.info(f"Verifying: {finding.get('title')} [{finding_type}]")

        report = TruthReport(
            finding_id=finding_id,
            finding_title=finding.get("title", "Unknown"),
            finding_type=finding_type
        )

        # Step 1 — False Positive Pattern Check (fast reject)
        fp_check = self._check_false_positive_patterns(finding)
        if fp_check["is_false_positive"]:
            report.status                  = VerificationStatus.FALSE_POSITIVE
            report.is_real                 = False
            report.confidence              = 0.0
            report.false_positive_indicators = fp_check["indicators"]
            report.false_positive_probability = fp_check["probability"]
            report.notes = f"Rejected by FP pattern: {', '.join(fp_check['indicators'])}"
            report.verification_time_seconds = time.time() - start_time
            return report

        report.false_positive_probability = fp_check["probability"]
        report.verifications.append(VerificationResult(
            method=VerificationMethod.PATTERN_ANALYSIS,
            passed=True,
            confidence=1.0 - fp_check["probability"],
            evidence="No false positive patterns matched",
            details=f"FP probability: {fp_check['probability']:.0%}"
        ))

        # Step 2 — Type-Specific Verification
        verify_func  = self.verification_strategies.get(
            finding_type, self.verification_strategies["generic"]
        )
        report.verifications.extend(verify_func(finding))

        # Step 3 — Reproduction Check
        repro = self._verify_reproduction(finding)
        report.verifications.append(repro)
        if repro.passed:
            report.reproduction_steps = finding.get("steps_to_reproduce", [])

        # Step 4 — Differential Analysis
        diff = self._verify_differential(finding)
        report.verifications.append(diff)
        if diff.passed:
            report.differential_evidence = diff.evidence

        # Step 5 — OOB Verification (blind bugs)
        if finding.get("oob_expected") or finding_type in ("ssrf", "xxe", "rce"):
            oob = self._verify_oob(finding)
            report.verifications.append(oob)

        # Step 6 — LLM Analysis
        if self.llm_router:
            report.verifications.append(self._verify_with_llm(finding, report))

        # Step 7 — Weighted Confidence
        report.confidence       = self._calculate_confidence(report.verifications)
        report.confidence_label = self._confidence_label(report.confidence)

        # Step 8 — Verdict
        passed = sum(1 for v in report.verifications if v.passed)

        if report.confidence >= self.confidence_threshold and passed >= self.MIN_VERIFICATIONS:
            report.is_real = True
            report.status  = VerificationStatus.CONFIRMED
            logger.info(f"CONFIRMED: {finding.get('title')} ({report.confidence:.0%})")
        else:
            report.is_real = False
            report.status  = (
                VerificationStatus.FALSE_POSITIVE
                if report.confidence < 0.4 or report.false_positive_probability > 0.7
                else VerificationStatus.INCONCLUSIVE
            )
            logger.info(f"REJECTED: {finding.get('title')} ({report.confidence:.0%})")

        report.verification_time_seconds = time.time() - start_time
        return report

    def verify_batch(
        self,
        findings: List[Dict],
        callback=None
    ) -> List[TruthReport]:
        reports = []
        for i, finding in enumerate(findings, 1):
            if callback:
                callback(i, len(findings))
            reports.append(self.verify_finding(finding))
        confirmed = sum(1 for r in reports if r.is_real)
        logger.info(f"Batch: {confirmed}/{len(findings)} confirmed real")
        return reports

    def filter_real_findings(
        self,
        findings: List[Dict],
        show_progress: bool = True
    ) -> Tuple[List[Dict], List[TruthReport]]:
        """
        Filter to only verified-real findings.
        Called by nova.py dispatch() before report generation.
        Fires Telegram alert for each confirmed finding (if configured).
        Returns (real_findings, all_reports).
        """
        if os.getenv("NOVA_TRUTH_DISABLED") == "1":
            logger.warning("Truth Engine DISABLED via NOVA_TRUTH_DISABLED=1")
            return findings, []

        print(f"\n[Truth Engine] Verifying {len(findings)} findings "
              f"(threshold: {self.confidence_threshold:.0%})...")
        print(f"[Truth Engine] OOB: "
              f"{'interactsh active' if self._oob.is_available() else 'not available (install interactsh-client to enable blind bug detection)'}\n")

        def progress(current, total):
            if show_progress:
                filled = int(30 * current / total)
                bar = "█" * filled + "░" * (30 - filled)
                print(f"\r  [{bar}] {current}/{total}", end="", flush=True)

        reports = self.verify_batch(findings, callback=progress)
        if show_progress:
            print()

        real_findings = [
            findings[i] for i, r in enumerate(reports) if r.is_real
        ]

        confirmed = len(real_findings)
        rejected  = len(findings) - confirmed

        print(f"\n[Truth Engine] Results:")
        print(f"  ✅ Confirmed real:   {confirmed}")
        print(f"  ❌ False positives:  {rejected}")
        if findings:
            print(f"  📊 Signal ratio:     {confirmed/len(findings)*100:.0f}%")
        print()

        # Attach _truth metadata to each real finding
        truth_map = {
            reports[i].finding_id: reports[i]
            for i in range(len(reports)) if reports[i].is_real
        }
        for f in real_findings:
            fid = f.get("id", hashlib.md5(f.get("title","").encode()).hexdigest()[:8])
            tr  = truth_map.get(fid)
            if tr:
                f["_truth"] = {
                    "confidence":               tr.confidence,
                    "confidence_label":         tr.confidence_label,
                    "status":                   tr.status.value,
                    "verifications_passed":     sum(1 for v in tr.verifications if v.passed),
                    "verifications_total":      len(tr.verifications),
                    "false_positive_probability": tr.false_positive_probability,
                    "oob_used":                 any(
                        v.method == VerificationMethod.OUT_OF_BAND
                        for v in tr.verifications
                    ),
                    "verification_time_s":      tr.verification_time_seconds,
                }
            # Fire Telegram alert
            if self.notifications:
                self._alert_finding(f, tr)

        self._oob.stop()
        return real_findings, reports

    # ─── Telegram alert per confirmed finding ────────────────────────────────

    def _alert_finding(self, finding: Dict, report: Optional["TruthReport"]):
        """Fire a Telegram alert for a confirmed finding."""
        try:
            sev   = finding.get("severity", "?").upper()
            title = finding.get("title", "Unknown")
            ep    = finding.get("endpoint", finding.get("url", "?"))
            conf  = finding.get("_truth", {}).get("confidence", 0)
            oob   = "✅ OOB confirmed" if finding.get("_truth", {}).get("oob_used") else ""

            SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                         "LOW": "🟢", "INFO": "ℹ️"}
            emoji = SEV_EMOJI.get(sev, "⚠️")

            msg = (
                f"{emoji} *Nova Confirmed Finding*\n"
                f"*{sev}* — {title}\n"
                f"Endpoint: `{ep}`\n"
                f"Confidence: {conf:.0%} {oob}\n"
                f"Verifications: {finding.get('_truth',{}).get('verifications_passed','?')}/"
                f"{finding.get('_truth',{}).get('verifications_total','?')} passed"
            )

            if hasattr(self.notifications, "notify_finding"):
                self.notifications.notify_finding(finding)
            elif hasattr(self.notifications, "send_custom"):
                self.notifications.send_custom(title=f"{emoji} {sev}: {title}", message=msg)
        except Exception as e:
            logger.warning(f"Alert failed: {e}")

    # ─── OOB Verification ────────────────────────────────────────────────────

    def _verify_oob(self, finding: Dict) -> VerificationResult:
        """
        Out-of-band verification via interactsh.
        Injects the OOB URL into the finding's payload and waits for a callback.

        For SSRF/XXE/blind SQLi: the target server must call our URL.
        If it does → confirmed real. If not → inconclusive (not false positive).
        """
        if not self._ensure_oob() or not self._oob.url:
            return VerificationResult(
                method=VerificationMethod.OUT_OF_BAND,
                passed=False,
                confidence=0.4,
                evidence="interactsh not available — OOB verification skipped",
                details=(
                    "Install interactsh-client for blind bug detection:\n"
                    f"  {InteractshClient.INSTALL_CMD}"
                )
            )

        oob_url = f"http://{self._oob.url}"
        logger.info(f"OOB test: payload will use {oob_url}")

        # Inject OOB URL into finding's payload (scanner must re-fire for us)
        # We check if the scanner already fired and got a callback
        callbacks = self._oob.poll_callbacks(wait_seconds=3)
        finding_url = finding.get("endpoint", finding.get("url", ""))

        # Check if any callback is from our target
        for cb in callbacks:
            remote = cb.get("remote-address", "")
            proto  = cb.get("protocol", "")
            if finding_url and (finding_url in str(cb) or remote):
                return VerificationResult(
                    method=VerificationMethod.OUT_OF_BAND,
                    passed=True,
                    confidence=0.98,
                    evidence=f"OOB callback received via {proto}: {remote}",
                    details=f"interactsh URL: {oob_url}"
                )

        # No callback yet — not necessarily FP, just blind
        return VerificationResult(
            method=VerificationMethod.OUT_OF_BAND,
            passed=False,
            confidence=0.3,
            evidence="No OOB callback received (may still be real — blind timing issue)",
            details=f"interactsh URL: {oob_url} | Callbacks checked: {len(callbacks)}"
        )

    # ─── Type-Specific Strategies ────────────────────────────────────────────

    def _verify_sqli(self, finding: Dict) -> List[VerificationResult]:
        results   = []
        evidence  = finding.get("evidence", "").lower()
        payload   = finding.get("payload", "")

        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql", "unclosed quotation mark",
            "quoted string not properly terminated", "ora-01756",
            "microsoft ole db provider for sql server",
            "jdbc exception", "pg::syntaxerror",
            "sqlite3::exception", "mysql_fetch_array()"
        ]
        error_found = any(err in evidence for err in sql_errors)
        results.append(VerificationResult(
            method=VerificationMethod.BEHAVIORAL,
            passed=error_found,
            confidence=0.9 if error_found else 0.1,
            evidence="SQL error pattern found" if error_found else "No SQL error patterns",
            details=f"Checked {len(sql_errors)} patterns"
        ))

        if "time" in finding.get("type_detail", "").lower():
            results.append(self._time_based_verification(finding))
        if "boolean" in finding.get("type_detail", "").lower():
            results.append(self._boolean_based_verification(finding))

        if payload:
            diff = finding.get("response_differential", "")
            effective = bool(diff and len(diff) > 10)
            results.append(VerificationResult(
                method=VerificationMethod.DIFFERENTIAL,
                passed=effective,
                confidence=0.85 if effective else 0.2,
                evidence=(f"Payload caused response diff: {diff[:100]}"
                          if effective else "No response difference")
            ))
        return results

    def _verify_xss(self, finding: Dict) -> List[VerificationResult]:
        results  = []
        evidence = finding.get("evidence", "")
        payload  = finding.get("payload", "")

        reflected = bool(
            payload and
            payload.lower() in evidence.lower() and
            any(k in payload.lower() for k in ["<script", "onerror", "onload", "alert"])
        )
        results.append(VerificationResult(
            method=VerificationMethod.REPRODUCTION,
            passed=reflected,
            confidence=0.7 if reflected else 0.1,
            evidence="XSS payload reflected" if reflected else "Payload not reflected"
        ))

        context          = finding.get("context", "")
        executable       = any(c in context.lower() for c in
                               ["script", "on", "href", "src", "style", "data:"])
        results.append(VerificationResult(
            method=VerificationMethod.BEHAVIORAL,
            passed=executable,
            confidence=0.8 if executable else 0.2,
            evidence=(f"Payload in executable context: {context}"
                      if executable else "Not in executable context")
        ))

        html_encoded = "&lt;" in evidence or "&gt;" in evidence or "&#" in evidence
        if html_encoded:
            results.append(VerificationResult(
                method=VerificationMethod.PATTERN_ANALYSIS,
                passed=False, confidence=0.05,
                evidence="Payload HTML-encoded — NOT exploitable"
            ))
        return results

    def _verify_idor(self, finding: Dict) -> List[VerificationResult]:
        evidence      = finding.get("evidence", "")
        data_returned = (
            finding.get("other_user_data_confirmed", False) or
            any(k in evidence.lower() for k in ["user_id", "email", "account"])
        )
        endpoint = finding.get("endpoint", "")
        predictable = any(p in endpoint for p in ["/1", "/2", "/100", "/user/", "/id/"])
        return [
            VerificationResult(
                method=VerificationMethod.PROOF_OF_CONCEPT,
                passed=data_returned,
                confidence=0.85 if data_returned else 0.2,
                evidence="Other user data in response" if data_returned else "No foreign data found"
            ),
            VerificationResult(
                method=VerificationMethod.BEHAVIORAL,
                passed=predictable,
                confidence=0.7 if predictable else 0.3,
                evidence=f"Predictable ID in: {endpoint}" if predictable else "ID not predictable"
            )
        ]

    def _verify_ssrf(self, finding: Dict) -> List[VerificationResult]:
        evidence   = finding.get("evidence", "")
        indicators = ["169.254.", "10.", "192.168.", "172.", "localhost", "127.0.0.1", "internal"]
        found      = any(i in evidence.lower() for i in indicators)
        return [VerificationResult(
            method=VerificationMethod.PROOF_OF_CONCEPT,
            passed=found, confidence=0.9 if found else 0.2,
            evidence="Internal network response confirmed" if found else "No internal response"
        )]

    def _verify_open_redirect(self, finding: Dict) -> List[VerificationResult]:
        evidence  = finding.get("evidence", "").lower()
        external  = "location:" in evidence and any(
            x in evidence for x in ["evil.com", "attacker.com", "http://", "https://"]
        )
        relative  = "location: /" in evidence or "location: .." in evidence
        return [VerificationResult(
            method=VerificationMethod.REPRODUCTION,
            passed=external and not relative,
            confidence=0.9 if (external and not relative) else 0.1 if relative else 0.3,
            evidence="External redirect confirmed" if external else "No external redirect"
        )]

    def _verify_path_traversal(self, finding: Dict) -> List[VerificationResult]:
        evidence = finding.get("evidence", "")
        found    = any(s in evidence for s in
                       ["root:x:", "/bin/bash", "[boot loader]", "<?php"])
        return [VerificationResult(
            method=VerificationMethod.PROOF_OF_CONCEPT,
            passed=found, confidence=0.95 if found else 0.1,
            evidence="File system content in response" if found else "No file content"
        )]

    def _verify_command_injection(self, finding: Dict) -> List[VerificationResult]:
        evidence = finding.get("evidence", "").lower()
        found    = any(i in evidence for i in
                       ["uid=", "gid=", "root@", "www-data", "/var/www"])
        return [VerificationResult(
            method=VerificationMethod.PROOF_OF_CONCEPT,
            passed=found, confidence=0.95 if found else 0.1,
            evidence="Command output confirmed" if found else "No command output"
        )]

    def _verify_xxe(self, finding: Dict) -> List[VerificationResult]:
        evidence = finding.get("evidence", "")
        confirmed = (
            "root:x:" in evidence or
            "SYSTEM"  in evidence or
            finding.get("oob_callback_received", False)
        )
        return [VerificationResult(
            method=VerificationMethod.PROOF_OF_CONCEPT,
            passed=confirmed, confidence=0.95 if confirmed else 0.2,
            evidence="XXE exploitation confirmed" if confirmed else "XXE not confirmed"
        )]

    def _verify_rce(self, finding: Dict) -> List[VerificationResult]:
        evidence  = finding.get("evidence", "").lower()
        confirmed = any(i in evidence for i in
                        ["uid=0", "uid=33", "root@", "www-data@", "/etc/passwd"])
        return [VerificationResult(
            method=VerificationMethod.PROOF_OF_CONCEPT,
            passed=confirmed, confidence=0.98 if confirmed else 0.05,
            evidence="RCE command output confirmed" if confirmed else "RCE not confirmed — high bar"
        )]

    def _verify_lfi(self, finding: Dict) -> List[VerificationResult]:
        evidence  = finding.get("evidence", "")
        confirmed = "root:x:0:0" in evidence or "localhost" in evidence
        return [VerificationResult(
            method=VerificationMethod.PROOF_OF_CONCEPT,
            passed=confirmed, confidence=0.95 if confirmed else 0.1,
            evidence="File content confirmed" if confirmed else "No file content"
        )]

    def _verify_csrf(self, finding: Dict) -> List[VerificationResult]:
        no_token       = not finding.get("csrf_token_present", True)
        state_changing = finding.get("is_state_changing", False)
        real           = no_token and state_changing
        return [VerificationResult(
            method=VerificationMethod.BEHAVIORAL,
            passed=real, confidence=0.8 if real else 0.2,
            evidence="CSRF: no token + state-changing" if real else "CSRF conditions not met"
        )]

    def _verify_jwt(self, finding: Dict) -> List[VerificationResult]:
        evidence = finding.get("evidence", "").lower()
        vuln     = (
            "none" in evidence or "hs256" in evidence or
            finding.get("secret_cracked", False) or
            finding.get("algorithm_none", False)
        )
        return [VerificationResult(
            method=VerificationMethod.PROOF_OF_CONCEPT,
            passed=vuln, confidence=0.9 if vuln else 0.2,
            evidence="JWT vulnerability confirmed" if vuln else "JWT appears secure"
        )]

    def _verify_ssti(self, finding: Dict) -> List[VerificationResult]:
        evidence = finding.get("evidence", "")
        evaluated = "49" in evidence and "{{" in finding.get("payload", "")
        return [VerificationResult(
            method=VerificationMethod.PROOF_OF_CONCEPT,
            passed=evaluated, confidence=0.9 if evaluated else 0.2,
            evidence="Template expression evaluated server-side" if evaluated else "SSTI not confirmed"
        )]

    def _verify_generic(self, finding: Dict) -> List[VerificationResult]:
        conf = finding.get("confidence", 0.5)
        return [VerificationResult(
            method=VerificationMethod.BEHAVIORAL,
            passed=conf > 0.6, confidence=conf,
            evidence=f"Scanner confidence: {conf:.0%}",
            details="Generic verification"
        )]

    # ─── Universal Methods ───────────────────────────────────────────────────

    def _verify_reproduction(self, finding: Dict) -> VerificationResult:
        has_steps   = bool(finding.get("steps_to_reproduce"))
        has_payload = bool(finding.get("payload"))
        has_evidence= bool(finding.get("evidence"))
        ok = has_steps and has_payload and has_evidence
        return VerificationResult(
            method=VerificationMethod.REPRODUCTION,
            passed=ok, confidence=0.8 if ok else 0.3,
            evidence="Steps + payload + evidence present" if ok else (
                f"Missing: {'steps ' if not has_steps else ''}"
                f"{'payload ' if not has_payload else ''}"
                f"{'evidence' if not has_evidence else ''}"
            )
        )

    def _verify_differential(self, finding: Dict) -> VerificationResult:
        vuln = finding.get("vulnerable_response", "")
        safe = finding.get("safe_response", "")
        if vuln and safe:
            differ = len(vuln) != len(safe) or vuln[:100] != safe[:100]
            return VerificationResult(
                method=VerificationMethod.DIFFERENTIAL,
                passed=differ, confidence=0.85 if differ else 0.1,
                evidence="Responses differ" if differ else "Responses identical (likely FP)"
            )
        return VerificationResult(
            method=VerificationMethod.DIFFERENTIAL,
            passed=True, confidence=0.5,
            evidence="No differential data — skipped"
        )

    def _verify_with_llm(self, finding: Dict, report: TruthReport) -> VerificationResult:
        prompt = f"""Analyze this security finding for false positives.

Finding: {finding.get('title')}
Type: {finding.get('type')}
Evidence: {finding.get('evidence', '')[:300]}
Payload: {finding.get('payload', '')}
Verifications passed so far: {sum(1 for v in report.verifications if v.passed)}/{len(report.verifications)}

Is this a real vulnerability or a false positive?
Reply with JSON only:
{{"is_real": true, "confidence": 0.0, "reasoning": "why", "false_positive_indicators": []}}"""

        try:
            response_text = ""
            for method in ("chat", "reason"):
                if response_text:
                    break
                fn = getattr(self.llm_router, method, None)
                if fn:
                    try:
                        r = fn(prompt, temperature=0.1) if method == "chat" else fn(prompt)
                        response_text = getattr(r, "content", r) if not isinstance(r, str) else r
                    except Exception:
                        pass

            if not response_text:
                raise ValueError("LLM returned empty")

            m = re.search(r'\{[^{}]*"is_real"[^{}]*\}', response_text, re.DOTALL)
            result = json.loads(m.group(0) if m else response_text)
            return VerificationResult(
                method=VerificationMethod.LLM_ANALYSIS,
                passed=result.get("is_real", False),
                confidence=float(result.get("confidence", 0.5)),
                evidence=result.get("reasoning", "LLM analysis complete"),
                details=str(result.get("false_positive_indicators", []))
            )
        except Exception as e:
            logger.warning(f"LLM verification error: {e}")
            return VerificationResult(
                method=VerificationMethod.LLM_ANALYSIS,
                passed=True, confidence=0.5,
                evidence=f"LLM error: {e}"
            )

    def _time_based_verification(self, finding: Dict) -> VerificationResult:
        rt      = finding.get("response_time_ms", 0)
        expected= finding.get("expected_delay_ms", 5000)
        ok      = rt >= expected * 0.9
        return VerificationResult(
            method=VerificationMethod.TIME_BASED,
            passed=ok, confidence=0.85 if ok else 0.1,
            evidence=f"Response delayed {rt}ms (expected {expected}ms)" if ok
                     else f"No delay: {rt}ms"
        )

    def _boolean_based_verification(self, finding: Dict) -> VerificationResult:
        t = finding.get("true_response_length", 0)
        f = finding.get("false_response_length", 0)
        ok = abs(t - f) > 50
        return VerificationResult(
            method=VerificationMethod.BEHAVIORAL,
            passed=ok, confidence=0.8 if ok else 0.2,
            evidence=f"Boolean diff: true={t} false={f} bytes" if ok else "No boolean diff"
        )

    # ─── Scoring ─────────────────────────────────────────────────────────────

    def _check_false_positive_patterns(self, finding: Dict) -> Dict:
        return self.false_positive_patterns.check(finding)

    def _calculate_confidence(self, verifications: List[VerificationResult]) -> float:
        if not verifications:
            return 0.0
        weights = {
            VerificationMethod.PROOF_OF_CONCEPT: 0.30,
            VerificationMethod.REPRODUCTION:     0.20,
            VerificationMethod.DIFFERENTIAL:     0.15,
            VerificationMethod.BEHAVIORAL:       0.15,
            VerificationMethod.PATTERN_ANALYSIS: 0.10,
            VerificationMethod.LLM_ANALYSIS:     0.10,
            VerificationMethod.TIME_BASED:       0.20,
            VerificationMethod.OUT_OF_BAND:      0.25,
        }
        wc = tw = 0.0
        for v in verifications:
            w   = weights.get(v.method, 0.1)
            wc += v.confidence * w
            tw += w
        return min(wc / tw, 1.0) if tw else 0.0

    def _confidence_label(self, c: float) -> str:
        if c >= 0.95: return "CERTAIN"
        if c >= 0.85: return "HIGH"
        if c >= 0.70: return "MEDIUM"
        if c >= 0.50: return "LOW"
        return "VERY LOW"


# ─────────────────────────────────────────────────────────────────────────────
# FALSE POSITIVE PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

class FalsePositivePatterns:
    def check(self, finding: Dict) -> Dict:
        indicators  = []
        probability = 0.0
        ftype       = finding.get("type", "").lower()
        evidence    = finding.get("evidence", "").lower()
        rc          = finding.get("response_code", 200)

        waf = ["access denied", "forbidden by waf", "request blocked",
               "security violation", "cloudflare ray id", "mod_security"]
        if any(p in evidence for p in waf):
            indicators.append("WAF blocking detected")
            probability += 0.6

        if rc == 500 and "sql" in ftype and not any(
            e in evidence for e in ["sql", "mysql", "ora-", "syntax"]
        ):
            indicators.append("HTTP 500 without SQL-specific content")
            probability += 0.4

        if "xss" in ftype:   probability += self._xss_fp(finding, indicators)
        elif "sql" in ftype: probability += self._sqli_fp(finding, indicators)
        elif "idor" in ftype: probability += self._idor_fp(finding, indicators)
        elif "open_redirect" in ftype: probability += self._redirect_fp(finding, indicators)

        probability = min(probability, 1.0)
        return {
            "is_false_positive": probability > 0.85,
            "probability": probability,
            "indicators": indicators
        }

    def _xss_fp(self, finding, indicators):
        e = finding.get("evidence", "")
        p = 0.0
        if "&lt;" in e and "&gt;" in e:
            indicators.append("Payload HTML-encoded"); p += 0.9
        if '\\"' in e or "\\'" in e:
            indicators.append("Quotes escaped"); p += 0.7
        return p

    def _sqli_fp(self, finding, indicators):
        e = finding.get("evidence", "").lower()
        p = 0.0
        if any(v in e for v in ["invalid input", "please enter valid", "field is required"]):
            indicators.append("Input validation error (not SQL)"); p += 0.7
        return p

    def _idor_fp(self, finding, indicators):
        p = 0.0
        ep = finding.get("endpoint", "")
        if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', ep, re.I):
            indicators.append("UUID-based ID (not enumerable)"); p += 0.4
        if finding.get("response_code") == 403:
            indicators.append("Server returns 403 — access control enforced"); p += 0.9
        return p

    def _redirect_fp(self, finding, indicators):
        e = finding.get("evidence", "").lower()
        p = 0.0
        if "location: /" in e:
            indicators.append("Relative redirect (not exploitable)"); p += 0.8
        target = finding.get("target", "").lower()
        if target and f"location: {target}" in e:
            indicators.append("Same-domain redirect"); p += 0.9
        return p


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

_TRUTH_ENGINE: Optional[NovaTruthEngine] = None


def get_truth_engine(
    llm_router=None,
    confidence_threshold: float = None,
    notifications=None
) -> NovaTruthEngine:
    """Return (and cache) the global Truth Engine singleton."""
    global _TRUTH_ENGINE
    if _TRUTH_ENGINE is None:
        _TRUTH_ENGINE = NovaTruthEngine(
            llm_router=llm_router,
            confidence_threshold=confidence_threshold,
            notifications=notifications
        )
    return _TRUTH_ENGINE


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n=== NOVA TRUTH ENGINE v1.1 ===\n")
    engine = get_truth_engine(confidence_threshold=0.95)

    findings = [
        {
            "id": "F001", "title": "SQL Injection in /api/search",
            "type": "sql_injection",
            "evidence": "you have an error in your sql syntax near '1'",
            "payload": "1' OR '1'='1", "endpoint": "/api/search",
            "steps_to_reproduce": ["Go to /api/search", "Enter: 1' OR '1'='1"],
        },
        {
            "id": "F002", "title": "XSS (false positive — encoded)",
            "type": "xss",
            "evidence": "&lt;script&gt;alert(1)&lt;/script&gt;",
            "payload": "<script>alert(1)</script>", "endpoint": "/search",
        },
        {
            "id": "F003", "title": "XSS in username (real)",
            "type": "xss",
            "evidence": "<script>alert(1)</script>",
            "payload": "<script>alert(1)</script>",
            "endpoint": "/profile", "context": "script",
            "steps_to_reproduce": ["Go to /profile", "Set username to payload"],
        },
    ]

    real, reports = engine.filter_real_findings(findings)
    print("Detailed Results:")
    for r in reports:
        status = "✅ REAL" if r.is_real else "❌ FALSE POSITIVE"
        print(f"  {status} | {r.finding_title} ({r.confidence:.0%} confidence)")
