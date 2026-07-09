"""
Static / pattern-based bug-class candidate scanner.

Scans source, configs, or response snippets for high-signal vulnerability
patterns that often indicate novel or under-tested sinks. Heuristic only —
not a full SAST engine.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


@dataclass
class StaticFinding:
    """A static analysis candidate."""

    finding_id: str
    title: str
    bug_class: str
    severity: str
    confidence: float
    location: str
    snippet: str
    rationale: str
    cwe: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "bug_class": self.bug_class,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "location": self.location,
            "snippet": self.snippet[:300],
            "rationale": self.rationale,
            "cwe": self.cwe,
            "tags": self.tags,
        }


# (name, bug_class, severity, confidence, cwe, pattern, rationale)
_RULES: List[Tuple[str, str, str, float, str, re.Pattern[str], str]] = [
    (
        "command_injection_sink",
        "rce",
        "critical",
        0.72,
        "CWE-78",
        re.compile(
            r"(os\.system|subprocess\.(?:call|run|Popen)|popen\s*\(|Runtime\.exec|"
            r"child_process\.exec|shell_exec\s*\(|system\s*\(|exec\s*\(|eval\s*\()",
            re.I,
        ),
        "Dangerous command/code execution sink — verify inputs are constrained",
    ),
    (
        "sql_string_concat",
        "sqli",
        "high",
        0.68,
        "CWE-89",
        re.compile(
            r"(execute\s*\(\s*[f\"'].*\+|query\s*\(\s*[\"'].*\+|SELECT\s+.+\+\s*\w+|"
            r"cursor\.execute\s*\(\s*[f\"']|\.format\s*\(.*SELECT|f[\"'].*SELECT)",
            re.I,
        ),
        "SQL built via string concatenation / formatting — injection candidate",
    ),
    (
        "insecure_deserialize",
        "rce",
        "critical",
        0.75,
        "CWE-502",
        re.compile(
            r"(pickle\.loads|yaml\.load\s*\(|unserialize\s*\(|ObjectInputStream|"
            r"JSON\.parse\s*\(.*reviver|Marshal\.load|binary_to_term)",
            re.I,
        ),
        "Insecure deserialization sink — high RCE potential",
    ),
    (
        "path_join_user",
        "path_traversal",
        "high",
        0.62,
        "CWE-22",
        re.compile(
            r"(os\.path\.join\s*\([^)]*request|open\s*\([^)]*request|send_file\s*\(|"
            r"File\s*\([^)]*getParameter|path\.join\s*\([^)]*req\.|readFile\s*\([^)]*req)",
            re.I,
        ),
        "User-influenced path construction — traversal risk",
    ),
    (
        "ssrf_request",
        "ssrf",
        "high",
        0.65,
        "CWE-918",
        re.compile(
            r"(requests\.(get|post|request)\s*\(|urllib\.request\.urlopen|fetch\s*\([^)]*req|"
            r"HttpClient|curl_exec\s*\(|file_get_contents\s*\(\s*\$)",
            re.I,
        ),
        "Server-side outbound request sink — check URL allowlisting",
    ),
    (
        "weak_crypto",
        "crypto",
        "medium",
        0.55,
        "CWE-327",
        re.compile(r"\b(MD5|SHA1|DES|RC4|ECB)\b|hashlib\.md5|CryptoJS\.MD5", re.I),
        "Weak or obsolete cryptography primitive",
    ),
    (
        "hardcoded_secret",
        "secret",
        "high",
        0.7,
        "CWE-798",
        re.compile(
            r"(api[_-]?key|secret|password|passwd|token)\s*=\s*[\"'][^\"']{8,}[\"']",
            re.I,
        ),
        "Possible hardcoded credential / secret",
    ),
    (
        "jwt_none_alg",
        "auth_bypass",
        "critical",
        0.8,
        "CWE-347",
        re.compile(r"algorithms\s*=\s*\[[^\]]*none|alg[\"']?\s*:\s*[\"']none[\"']", re.I),
        "JWT none algorithm acceptance — auth bypass candidate",
    ),
    (
        "debug_enabled",
        "misconfig",
        "medium",
        0.5,
        "CWE-489",
        re.compile(r"(DEBUG\s*=\s*True|app\.debug\s*=\s*true|flask\.env.*development)", re.I),
        "Debug mode indicators — information disclosure / RCE risk in some stacks",
    ),
    (
        "unsafe_redirect",
        "open_redirect",
        "medium",
        0.58,
        "CWE-601",
        re.compile(
            r"(redirect\s*\(\s*request\.|Location:\s*\$|res\.redirect\s*\(\s*req\.|"
            r"window\.location\s*=\s*[^;]*location\.search)",
            re.I,
        ),
        "User-controlled redirect target",
    ),
    (
        "xxe_enabled",
        "xxe",
        "high",
        0.7,
        "CWE-611",
        re.compile(
            r"(XMLParser\s*\(|load_xml|DocumentBuilderFactory|XMLInputFactory|"
            r"libxml_disable_entity_loader\s*\(\s*false|resolve_entities\s*=\s*True)",
            re.I,
        ),
        "XML parser configuration may allow external entities",
    ),
    (
        "prototype_pollution",
        "prototype_pollution",
        "high",
        0.6,
        "CWE-1321",
        re.compile(r"(__proto__|constructor\s*\[|Object\.assign\s*\(\s*\{\}|lodash\.merge|deepMerge)", re.I),
        "Potential prototype pollution pattern in JS object merge",
    ),
    (
        "race_check_use",
        "race",
        "medium",
        0.5,
        "CWE-367",
        re.compile(r"(os\.path\.exists\s*\(.*\n.*open\s*\(|access\s*\(.*\n.*open\s*\()", re.S | re.I),
        "Classic TOCTOU check-then-use pattern",
    ),
    (
        "mass_assignment",
        "auth_bypass",
        "medium",
        0.55,
        "CWE-915",
        re.compile(r"(update\s*\(\s*request\.(json|form|data)|setattr\s*\(.*request|mass.?assign)", re.I),
        "Possible mass assignment from request body",
    ),
]


class StaticBugScanner:
    """Heuristic static scanner for novel-bug candidates."""

    def __init__(self, rules: Optional[Sequence[Any]] = None) -> None:
        self.rules = list(rules) if rules is not None else list(_RULES)

    def scan_text(
        self,
        content: str,
        location: str = "<memory>",
        max_findings: int = 100,
    ) -> List[StaticFinding]:
        findings: List[StaticFinding] = []
        if not content:
            return findings

        for name, bug_class, severity, conf, cwe, pattern, rationale in self.rules:
            for match in pattern.finditer(content):
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                snippet = content[start:end].replace("\n", " ")
                fid = hashlib.sha1(f"{location}:{name}:{match.start()}".encode()).hexdigest()[:12]
                findings.append(
                    StaticFinding(
                        finding_id=fid,
                        title=name.replace("_", " ").title(),
                        bug_class=bug_class,
                        severity=severity,
                        confidence=conf,
                        location=f"{location}:{match.start()}",
                        snippet=snippet,
                        rationale=rationale,
                        cwe=cwe,
                        tags=["static", bug_class],
                    )
                )
                if len(findings) >= max_findings:
                    return findings
        return findings

    def scan_files(
        self,
        files: Dict[str, str],
        max_findings: int = 200,
    ) -> List[StaticFinding]:
        out: List[StaticFinding] = []
        for path, content in files.items():
            remaining = max_findings - len(out)
            if remaining <= 0:
                break
            out.extend(self.scan_text(content, location=path, max_findings=remaining))
        logger.info("Static scan: %d findings across %d files", len(out), len(files))
        return out

    async def scan_files_async(self, files: Dict[str, str], max_findings: int = 200) -> List[StaticFinding]:
        return self.scan_files(files, max_findings=max_findings)
