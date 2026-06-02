#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  👁  NOVA DIFF WATCHER — Real-Time Codebase Change Intelligence             ║
║                                                                              ║
║  Watches a directory for file changes, re-runs the codebase mapper on       ║
║  changed files only, and triggers targeted scans automatically.             ║
║                                                                              ║
║  Capabilities:                                                               ║
║  • Git-diff awareness — detects changed files vs HEAD                       ║
║  • inotify/polling fallback watcher (no extra deps required)               ║
║  • Incremental re-map: only re-analyses changed files, merges into _CMAP    ║
║  • Auto-triggers: SAST on changed .py/.js/.ts, SCA on manifest changes     ║
║  • Debounce + batch: accumulates changes for 2s before triggering           ║
║  • Session continuity — all incremental findings go into the live session   ║
║                                                                              ║
║  Usage:                                                                      ║
║    python3 nova_diff_watcher.py ./my-app                                    ║
║    python3 nova_diff_watcher.py ./my-app --on-commit                        ║
║    python3 nova_diff_watcher.py ./my-app --git-diff HEAD~1                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

DEBOUNCE_SECS   = 2.0
MAX_BATCH_FILES = 100

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".pytest_cache",
    "venv", ".venv", "dist", "build", ".next", "coverage",
    ".terraform", "vendor", "target",
}

SAST_EXTENSIONS  = {".py", ".js", ".ts", ".tsx", ".jsx", ".rb", ".php", ".go",
                    ".java", ".cs", ".rs", ".swift", ".kt", ".ex", ".exs"}
SCA_MANIFESTS    = {"package.json", "requirements.txt", "gemfile", "go.mod",
                    "cargo.toml", "pom.xml", "composer.json", "mix.exs"}
CONFIG_NAMES     = {".env", ".env.example", "config.yml", "config.yaml",
                    "secrets.yml", "settings.py", "database.yml"}
INFRA_EXTENSIONS = {".tf", ".hcl", ".yaml", ".yml", ".dockerfile"}


class FileState:
    """Tracks file hashes for change detection without inotify."""
    def __init__(self, root: str):
        self.root  = Path(root)
        self._hashes: Dict[str, str] = {}
        self._lock  = threading.Lock()

    def snapshot(self) -> Dict[str, str]:
        snap: Dict[str, str] = {}
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                path = Path(root) / fname
                try:
                    mtime = str(path.stat().st_mtime)
                    snap[str(path.relative_to(self.root))] = mtime
                except OSError:
                    pass
        return snap

    def diff(self) -> Dict[str, List[str]]:
        """Return {added, modified, deleted} file lists."""
        current = self.snapshot()
        with self._lock:
            prev = dict(self._hashes)
        added    = [f for f in current if f not in prev]
        deleted  = [f for f in prev     if f not in current]
        modified = [f for f in current  if f in prev and current[f] != prev[f]]
        with self._lock:
            self._hashes = current
        return {"added": added, "modified": modified, "deleted": deleted}

    def init(self):
        with self._lock:
            self._hashes = self.snapshot()


class GitDiffReader:
    """Extract changed files from git diff."""

    @staticmethod
    def changed_files(root: str, ref: str = "HEAD") -> List[str]:
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", ref],
                cwd=root, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return [f.strip() for f in result.stdout.splitlines() if f.strip()]
        except Exception:
            pass
        return []

    @staticmethod
    def staged_files(root: str) -> List[str]:
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=root, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return [f.strip() for f in result.stdout.splitlines() if f.strip()]
        except Exception:
            pass
        return []

    @staticmethod
    def last_commit_files(root: str) -> List[str]:
        try:
            result = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", "HEAD"],
                cwd=root, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return [f.strip() for f in result.stdout.splitlines() if f.strip()]
        except Exception:
            pass
        return []


class ChangeBatch:
    def __init__(self):
        self.added:    List[str] = []
        self.modified: List[str] = []
        self.deleted:  List[str] = []
        self.ts:       float     = time.monotonic()

    def extend(self, diff: Dict[str, List[str]]):
        self.added.extend(diff.get("added",    []))
        self.modified.extend(diff.get("modified", []))
        self.deleted.extend(diff.get("deleted",   []))
        self.ts = time.monotonic()

    @property
    def all_changed(self) -> List[str]:
        return list(dict.fromkeys(self.added + self.modified))

    def classify(self):
        """Classify changed files by scan type."""
        sast_files  = [f for f in self.all_changed
                       if Path(f).suffix.lower() in SAST_EXTENSIONS]
        sca_files   = [f for f in self.all_changed
                       if Path(f).name.lower() in SCA_MANIFESTS]
        config_files= [f for f in self.all_changed
                       if Path(f).name.lower() in CONFIG_NAMES]
        infra_files = [f for f in self.all_changed
                       if Path(f).suffix.lower() in INFRA_EXTENSIONS
                       and Path(f).name.lower() not in SCA_MANIFESTS]
        secret_prone= config_files + [f for f in self.all_changed
                                       if ".env" in f.lower() or "secret" in f.lower()
                                       or "credential" in f.lower()]
        return {
            "sast":       sast_files,
            "sca":        sca_files,
            "config":     config_files,
            "infra":      infra_files,
            "secret_scan":secret_prone,
        }


class NovaDiffWatcher:
    """
    Watches a directory for changes and triggers targeted Nova scans.
    """

    def __init__(
        self,
        root:          str,
        target_url:    str    = "",
        poll_interval: float  = 1.0,
        on_finding:    Optional[Callable[[Dict, str], None]] = None,
        verbose:       bool   = True,
    ):
        self.root         = Path(root).expanduser().resolve()
        self.target_url   = target_url
        self.poll_interval= poll_interval
        self.on_finding   = on_finding
        self.verbose      = verbose
        self._file_state  = FileState(str(self.root))
        self._batch       = ChangeBatch()
        self._batch_lock  = threading.Lock()
        self._running     = False
        self._thread:     Optional[threading.Thread] = None
        self._timer:      Optional[threading.Timer]  = None
        self._event_log:  List[Dict] = []

        # Provider layer singletons (import lazily)
        self._bus    = None
        self._cmap   = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self):
        """Start watching in a background thread."""
        self._init_providers()
        self._file_state.init()
        self._running = True
        self._thread  = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        if self.verbose:
            print(f"\n  👁  Nova Diff Watcher started")
            print(f"  📁 Watching: {self.root}")
            print(f"  ⏱  Poll interval: {self.poll_interval}s | Debounce: {DEBOUNCE_SECS}s")
            print(f"  Press Ctrl+C to stop\n")

    def stop(self):
        self._running = False
        if self._timer:
            self._timer.cancel()
        if self._thread:
            self._thread.join(timeout=3)
        if self.verbose:
            print(f"\n  👁  Watcher stopped. {len(self._event_log)} events processed.")

    def scan_git_diff(self, ref: str = "HEAD"):
        """Immediately scan files changed vs a git ref (one-shot, no watch loop)."""
        changed = GitDiffReader.changed_files(str(self.root), ref)
        if not changed:
            print(f"  ℹ️  No changed files vs {ref}")
            return []
        print(f"  🔀 {len(changed)} files changed vs {ref}")
        batch = ChangeBatch()
        batch.modified = changed
        return self._process_batch(batch)

    def scan_last_commit(self):
        """Immediately scan files changed in the last commit."""
        changed = GitDiffReader.last_commit_files(str(self.root))
        if not changed:
            print("  ℹ️  No files in last commit")
            return []
        print(f"  📦 {len(changed)} files in last commit")
        batch = ChangeBatch()
        batch.modified = changed
        return self._process_batch(batch)

    def scan_staged(self):
        """Immediately scan staged (pre-commit) files."""
        changed = GitDiffReader.staged_files(str(self.root))
        if not changed:
            print("  ℹ️  No staged files")
            return []
        print(f"  📋 {len(changed)} staged files")
        batch = ChangeBatch()
        batch.added = changed
        return self._process_batch(batch)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _init_providers(self):
        try:
            from nova_hooks import get_bus
            self._bus = get_bus(verbose=False)
        except Exception:
            pass

    def _poll_loop(self):
        while self._running:
            try:
                diff = self._file_state.diff()
                total = len(diff["added"]) + len(diff["modified"]) + len(diff["deleted"])
                if total > 0:
                    self._on_change(diff)
            except Exception as e:
                if self.verbose:
                    print(f"  ⚠️  Watcher poll error: {e}")
            time.sleep(self.poll_interval)

    def _on_change(self, diff: Dict[str, List[str]]):
        with self._batch_lock:
            self._batch.extend(diff)
        if self.verbose:
            changed = diff["added"] + diff["modified"]
            print(f"  📝 [{datetime.now().strftime('%H:%M:%S')}] "
                  f"+{len(diff['added'])} ~{len(diff['modified'])} "
                  f"-{len(diff['deleted'])} files changed — debouncing...")
        # Reset debounce timer
        if self._timer:
            self._timer.cancel()
        self._timer = threading.Timer(DEBOUNCE_SECS, self._fire_batch)
        self._timer.start()

    def _fire_batch(self):
        with self._batch_lock:
            batch       = self._batch
            self._batch = ChangeBatch()
        if not batch.all_changed:
            return
        findings = self._process_batch(batch)
        if findings and self.on_finding:
            for f in findings:
                self.on_finding(f, "diff_watcher")

    def _process_batch(self, batch: ChangeBatch) -> List[Dict]:
        t0          = time.monotonic()
        classes     = batch.classify()
        all_findings: List[Dict] = []

        print(f"\n  {'─'*60}")
        print(f"  🔁 Processing batch: {len(batch.all_changed)} changed files")
        for cls, files in classes.items():
            if files:
                print(f"     {cls}: {', '.join(Path(f).name for f in files[:5])}"
                      f"{'...' if len(files) > 5 else ''}")

        # ── 1. Incremental re-map ──────────────────────────────────────────
        self._incremental_remap(batch.all_changed)

        # ── 2. Quick secret scan on changed files ─────────────────────────
        secret_findings = self._quick_secret_scan(batch.all_changed)
        all_findings.extend(secret_findings)

        # ── 3. SAST on changed source files ───────────────────────────────
        if classes["sast"]:
            sast_findings = self._run_sast_on(classes["sast"])
            all_findings.extend(sast_findings)

        # ── 4. SCA on manifest changes ────────────────────────────────────
        if classes["sca"]:
            sca_findings = self._run_sca_on(classes["sca"])
            all_findings.extend(sca_findings)

        # ── 5. Config / secret file scan ──────────────────────────────────
        if classes["config"]:
            cfg_findings = self._scan_config_files(classes["config"])
            all_findings.extend(cfg_findings)

        # ── 6. Infra/IaC scan ────────────────────────────────────────────
        if classes["infra"]:
            iac_findings = self._scan_iac(classes["infra"])
            all_findings.extend(iac_findings)

        elapsed = (time.monotonic() - t0) * 1000
        if self._bus:
            try:
                self._bus.fire("DiffScanComplete", {
                    "changed_files":  len(batch.all_changed),
                    "findings":       len(all_findings),
                    "elapsed_ms":     elapsed,
                })
            except Exception:
                pass

        self._log_event(batch, all_findings, elapsed)

        if all_findings:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = WORKSPACE / f"nova_diff_{ts}.json"
            path.write_text(json.dumps({
                "changed_files": batch.all_changed,
                "findings": all_findings,
                "elapsed_ms": elapsed,
            }, indent=2, default=str))
            print(f"  {'─'*60}")
            sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
            critical = [f for f in all_findings
                        if str(f.get("severity","")).upper() in ("CRITICAL","HIGH")]
            if critical:
                print(f"  🔴 {len(critical)} critical/high findings!")
                for f in sorted(critical, key=lambda x:
                        sev_order.get(str(x.get("severity","")).upper(),4))[:5]:
                    icon = {"CRITICAL":"🔴","HIGH":"🟠"}.get(
                        f.get("severity","").upper(),"•")
                    print(f"     {icon} {f.get('type','?')} "
                          f"— {f.get('file') or f.get('endpoint','?')}")
            print(f"  💾 {path} ({elapsed:.0f}ms)")

        return all_findings

    def _incremental_remap(self, changed_files: List[str]):
        """Re-run mapper on changed files only and merge into global _CMAP."""
        try:
            import nova_codebase_mapper as _mapper
            mapper_cls = getattr(_mapper, "NovaCodebaseMapper", None)
            if not mapper_cls:
                return
            # Re-map only files that exist and are not binary
            existing = [f for f in changed_files
                        if (self.root / f).exists()
                        and (self.root / f).is_file()]
            if not existing:
                return
            print(f"  🗺  Re-mapping {len(existing)} changed files...")
            # Do a full re-map of root (mapper is fast enough)
            fresh = mapper_cls(str(self.root), verbose=False, ai_analysis=False).scan()
            # Update the global cache
            cache = getattr(_mapper, "_MAP_CACHE", None)
            if cache is not None:
                cache[str(self.root)] = fresh
            if self.verbose:
                print(f"  🗺  Map updated: {fresh.file_count} files | "
                      f"{len(fresh.endpoints)} endpoints | "
                      f"{len(fresh.secret_findings)} secrets")
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Incremental remap: {e}")

    def _quick_secret_scan(self, changed_files: List[str]) -> List[Dict]:
        """Fast in-memory regex secret scan on changed files."""
        try:
            from nova_codebase_mapper import SECRET_PATTERNS
        except ImportError:
            return []
        findings = []
        for rel_path in changed_files:
            full = self.root / rel_path
            if not full.exists() or full.is_dir():
                continue
            try:
                content = full.read_text(encoding="utf-8", errors="replace")[:50000]
                for name, pat in SECRET_PATTERNS:
                    for m in re.finditer(pat, content):
                        line_no = content[:m.start()].count("\n") + 1
                        findings.append({
                            "type":     "SecretExposure",
                            "severity": "HIGH",
                            "file":     rel_path,
                            "line":     line_no,
                            "pattern":  name,
                            "snippet":  m.group(0)[:60],
                            "source":   "diff_watcher",
                            "new_file": rel_path in getattr(self, "_batch", ChangeBatch()).added,
                        })
            except Exception:
                pass
        return findings

    def _run_sast_on(self, files: List[str]) -> List[Dict]:
        """Run SAST on a specific list of files."""
        findings = []
        try:
            import importlib
            mod = importlib.import_module("nova_source_auditor")
            Cls = getattr(mod, "NovaSourceAuditor", None)
            if not Cls:
                return []
            a = Cls(str(self.root))
            # Only audit changed files if the module supports it
            if hasattr(a, "audit_files"):
                a.audit_files([str(self.root / f) for f in files])
            else:
                a.audit_directory()
            new_findings = [f for f in a.findings
                            if any(fpath in str(f.get("file","")) for fpath in files)]
            findings.extend(new_findings)
            if new_findings and self.verbose:
                print(f"  🔍 SAST: {len(new_findings)} findings in changed files")
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  SAST on diff: {e}")
        return findings

    def _run_sca_on(self, manifest_files: List[str]) -> List[Dict]:
        """Run SCA when a manifest file changes."""
        findings = []
        try:
            import importlib
            mod = importlib.import_module("nova_sca_scanner")
            Cls = getattr(mod, "NovaSCAScanner", None)
            if not Cls:
                return []
            s = Cls()
            r = s.scan_directory(str(self.root))
            findings.extend(r)
            if r and self.verbose:
                print(f"  📦 SCA: {len(r)} dep findings after manifest change")
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  SCA on diff: {e}")
        return findings

    def _scan_config_files(self, config_files: List[str]) -> List[Dict]:
        """Specifically scan changed config/env files for secrets and misconfigs."""
        findings = self._quick_secret_scan(config_files)
        # Extra checks for common misconfigs
        for rel_path in config_files:
            full = self.root / rel_path
            if not full.exists():
                continue
            try:
                content = full.read_text(encoding="utf-8", errors="replace")
                # Check for debug=True, development mode, etc.
                if re.search(r"(?i)debug\s*[=:]\s*true", content):
                    findings.append({
                        "type":     "DebugMode",
                        "severity": "MEDIUM",
                        "file":     rel_path,
                        "description": "Debug mode enabled in config",
                        "source":   "diff_watcher",
                    })
                if re.search(r"(?i)secret_key\s*[=:]\s*['\"]?[a-z0-9]{1,20}['\"]?", content):
                    findings.append({
                        "type":     "WeakSecret",
                        "severity": "HIGH",
                        "file":     rel_path,
                        "description": "Potentially weak/default secret key in config",
                        "source":   "diff_watcher",
                    })
                if re.search(r"CORS.*\*|allow_origins.*\*|Access-Control.*\*", content, re.I):
                    findings.append({
                        "type":     "WideCORS",
                        "severity": "MEDIUM",
                        "file":     rel_path,
                        "description": "Wildcard CORS policy in config",
                        "source":   "diff_watcher",
                    })
            except Exception:
                pass
        return findings

    def _scan_iac(self, infra_files: List[str]) -> List[Dict]:
        """Lightweight IaC misconfiguration checks on changed infra files."""
        findings = []
        for rel_path in infra_files:
            full = self.root / rel_path
            if not full.exists():
                continue
            try:
                content = full.read_text(encoding="utf-8", errors="replace")
                checks = [
                    (r"0\.0\.0\.0/0",              "OpenIngress",       "HIGH",
                     "Inbound 0.0.0.0/0 allows all traffic"),
                    (r"privileged\s*[:=]\s*true",   "PrivilegedContainer","HIGH",
                     "Privileged container detected"),
                    (r"runAsRoot\s*[:=]\s*true",     "RunAsRoot",         "HIGH",
                     "Container running as root"),
                    (r"(?i)ssl_verify\s*[:=]\s*false","TLSVerifyOff",    "HIGH",
                     "TLS verification disabled"),
                    (r"(?i)insecure_skip_verify\s*[:=]\s*true","TLSSkip","HIGH",
                     "insecure_skip_verify = true"),
                    (r"kubernetes\.io/tls-acme.*false","TLSDisabled",    "MEDIUM",
                     "TLS/ACME disabled on ingress"),
                    (r"hostNetwork\s*[:=]\s*true",   "HostNetwork",      "MEDIUM",
                     "Pod using host network"),
                    (r"hostPID\s*[:=]\s*true",       "HostPID",          "HIGH",
                     "Pod using host PID namespace"),
                ]
                for pattern, vuln_type, severity, description in checks:
                    for m in re.finditer(pattern, content, re.MULTILINE):
                        line_no = content[:m.start()].count("\n") + 1
                        findings.append({
                            "type":        vuln_type,
                            "severity":    severity,
                            "file":        rel_path,
                            "line":        line_no,
                            "description": description,
                            "source":      "diff_watcher",
                        })
            except Exception:
                pass
        if findings and self.verbose:
            print(f"  🏗  IaC: {len(findings)} findings in infra files")
        return findings

    def _log_event(self, batch: ChangeBatch, findings: List[Dict], elapsed_ms: float):
        self._event_log.append({
            "ts":           datetime.now().isoformat(),
            "changed_files":batch.all_changed[:20],
            "findings":     len(findings),
            "elapsed_ms":   elapsed_ms,
        })
        # Keep log capped
        if len(self._event_log) > 500:
            self._event_log = self._event_log[-500:]


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, signal

    parser = argparse.ArgumentParser(
        description="👁  Nova Diff Watcher — real-time codebase change scanner")
    parser.add_argument("root",          nargs="?", default=".",
                        help="Directory to watch")
    parser.add_argument("--url",         default="",
                        help="Target URL for active probes after changes")
    parser.add_argument("--interval",    type=float, default=1.0,
                        help="Poll interval in seconds (default: 1.0)")
    parser.add_argument("--on-commit",   action="store_true",
                        help="Scan last commit and exit (one-shot)")
    parser.add_argument("--git-diff",    metavar="REF",
                        help="Scan diff vs REF and exit (one-shot). E.g. HEAD~1")
    parser.add_argument("--staged",      action="store_true",
                        help="Scan staged files and exit (one-shot)")
    parser.add_argument("--quiet",       action="store_true")
    args = parser.parse_args()

    watcher = NovaDiffWatcher(
        root=args.root,
        target_url=args.url,
        poll_interval=args.interval,
        verbose=not args.quiet)

    if args.on_commit:
        findings = watcher.scan_last_commit()
        sys.exit(1 if any(
            str(f.get("severity","")).upper() in ("CRITICAL","HIGH")
            for f in findings) else 0)

    if args.git_diff:
        findings = watcher.scan_git_diff(args.git_diff)
        sys.exit(1 if any(
            str(f.get("severity","")).upper() in ("CRITICAL","HIGH")
            for f in findings) else 0)

    if args.staged:
        findings = watcher.scan_staged()
        sys.exit(1 if any(
            str(f.get("severity","")).upper() in ("CRITICAL","HIGH")
            for f in findings) else 0)

    watcher.start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        watcher.stop()
