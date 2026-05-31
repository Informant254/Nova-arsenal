#!/usr/bin/env python3
"""
NOVA FILE PRIORITIZER v1.0
Mythos-style 1-5 risk scoring for source files.
Ranks files by vulnerability likelihood before scanning — highest first.
Mirrors the Claude Mythos internal file ranking system.
"""

import os
import re
import json
from typing import List, Dict, Tuple
from datetime import datetime


SCORE_RULES: List[Tuple[int, List[str], str]] = [
    (5, [
        r'(login|auth|signin|authenticate|password|credential)',
        r'(upload|file.*write|multipart|form.*data)',
        r'(exec|shell|system|popen|spawn|child_process)',
        r'(deserializ|pickle|marshal|yaml\.load|fromJSON)',
        r'(sql|query|execute|cursor|sequelize|knex|typeorm)',
        r'(req\.body|req\.params|req\.query|request\.form|request\.json)',
        r'(xml|xxe|libxml|DOMParser|parseString)',
        r'(jwt|token.*sign|token.*verify|session.*secret)',
        r'(eval\s*\(|Function\s*\(|compile\s*\()',
        r'(ssrf|fetch\s*\(.*req\.|axios.*req\.|http.*get.*req\.)',
    ], "Takes raw user input AND touches dangerous sinks"),

    (4, [
        r'(redirect|location\.href|res\.redirect)',
        r'(readFile|sendFile|createReadStream|path\.join)',
        r'(cors|origin|access.control|allow.origin)',
        r'(rate.?limit|throttl|brute)',
        r'(crypto|cipher|hash|hmac|bcrypt|scrypt)',
        r'(webhook|callback.*url|notify.*url)',
        r'(admin|superuser|privileged|sudo)',
        r'(import|require|__import__|dynamic.*load)',
        r'(prototype|__proto__|constructor\[|Object\.assign)',
        r'(race|concurrent|mutex|lock|atomic)',
    ], "High-impact logic — auth flow, file I/O, redirects, crypto"),

    (3, [
        r'(router|route|endpoint|handler|controller)',
        r'(middleware|interceptor|filter|guard)',
        r'(validate|sanitize|escape|encode|decode)',
        r'(permission|role|acl|policy|scope)',
        r'(cache|redis|memcache|session\.store)',
        r'(email|smtp|sendgrid|mailgun)',
        r'(payment|stripe|paypal|card)',
        r'(log|audit|track|monitor)',
        r'(env|config|settings|secret)',
    ], "Business logic — routing, validation, permissions"),

    (2, [
        r'(model|schema|entity|migration)',
        r'(util|helper|common|shared)',
        r'(format|parse|convert|transform)',
        r'(test|spec|mock|fixture|stub)',
        r'(type|interface|enum|const)',
    ], "Support code — models, utilities, types"),
]

SKIP_PATTERNS = [
    r'node_modules/', r'\.git/', r'dist/', r'build/', r'coverage/',
    r'vendor/', r'\.min\.(js|css)$', r'\.map$', r'\.lock$',
    r'(test|spec)\.(ts|js|py)$',
]

SUPPORTED_EXTENSIONS = {
    '.ts', '.js', '.py', '.java', '.go', '.rb', '.php',
    '.cs', '.cpp', '.c', '.rs', '.swift', '.kt',
}


class NovaFilePrioritizer:
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.results: List[Dict] = []

    def should_skip(self, path: str) -> bool:
        for pat in SKIP_PATTERNS:
            if re.search(pat, path, re.IGNORECASE):
                return True
        return False

    def score_file(self, filepath: str) -> Dict:
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            return {"file": filepath, "score": 0, "reasons": [], "ext": ext}

        if self.should_skip(filepath):
            return {"file": filepath, "score": 0, "reasons": ["skipped"], "ext": ext}

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()
        except Exception:
            return {"file": filepath, "score": 1, "reasons": ["unreadable"], "ext": ext}

        best_score = 1
        reasons = []

        for score, patterns, label in SCORE_RULES:
            matched = [p for p in patterns if re.search(p, content, re.IGNORECASE)]
            if matched:
                if score > best_score:
                    best_score = score
                reasons.append(f"[{score}] {label} ({len(matched)} pattern(s) matched)")

        return {
            "file": filepath,
            "score": best_score,
            "reasons": reasons,
            "size_bytes": len(content),
            "ext": ext,
        }

    def prioritize_directory(self, directory: str) -> List[Dict]:
        scored = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".") and d not in ("node_modules", "dist", "build", "vendor")
            ]
            for fname in files:
                fpath = os.path.join(root, fname)
                result = self.score_file(fpath)
                if result["score"] > 0:
                    scored.append(result)

        scored.sort(key=lambda x: (-x["score"], -x.get("size_bytes", 0)))
        self.results = scored

        if self.verbose:
            self._print_ranking(scored)

        return scored

    def prioritize_file_list(self, file_paths: List[str]) -> List[Dict]:
        scored = [self.score_file(fp) for fp in file_paths]
        scored = [s for s in scored if s["score"] > 0]
        scored.sort(key=lambda x: (-x["score"], -x.get("size_bytes", 0)))
        self.results = scored
        if self.verbose:
            self._print_ranking(scored)
        return scored

    def _print_ranking(self, scored: List[Dict]):
        print("\n🦅 NOVA FILE PRIORITIZER — Risk Ranking")
        print("=" * 60)
        score_labels = {5: "🔴 CRITICAL", 4: "🟠 HIGH", 3: "🟡 MEDIUM", 2: "🟢 LOW", 1: "⚪ MINIMAL"}
        for item in scored[:30]:
            label = score_labels.get(item["score"], "?")
            fname = os.path.basename(item["file"])
            print(f"  [{item['score']}] {label:15s} {fname}")
            if item.get("reasons"):
                print(f"       └─ {item['reasons'][0]}")
        total = len(scored)
        print(f"\n  📊 Ranked {total} files | "
              f"Critical: {sum(1 for s in scored if s['score']==5)} | "
              f"High: {sum(1 for s in scored if s['score']==4)} | "
              f"Medium: {sum(1 for s in scored if s['score']==3)}")

    def save_ranking(self, output_path: str):
        report = {
            "generated": datetime.now().isoformat(),
            "total_files": len(self.results),
            "ranking": self.results,
            "summary": {
                "score_5": [r["file"] for r in self.results if r["score"] == 5],
                "score_4": [r["file"] for r in self.results if r["score"] == 4],
                "score_3": [r["file"] for r in self.results if r["score"] == 3],
            }
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  💾 Ranking saved → {output_path}")
        return report

    def get_scan_order(self, max_files: int = 50) -> List[str]:
        return [r["file"] for r in self.results[:max_files] if r["score"] >= 2]


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    prioritizer = NovaFilePrioritizer(verbose=True)
    if os.path.isdir(target):
        results = prioritizer.prioritize_directory(target)
    elif os.path.isfile(target):
        results = prioritizer.prioritize_file_list([target])
    else:
        print(f"Target not found: {target}")
        sys.exit(1)
    out = target.rstrip("/").replace("/", "_") + "_priority.json"
    prioritizer.save_ranking(out)
