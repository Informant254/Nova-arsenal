import asyncio
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern

logger = logging.getLogger(__name__)


class ChallengeType(Enum):
    WEB = "web"
    CRYPTO = "crypto"
    STEGO = "stego"
    FORENSICS = "forensics"
    REVERSING = "reversing"
    PWN = "pwn"
    OSINT = "osint"
    RECON = "recon"
    MISC = "misc"


@dataclass
class CtfFlag:
    flag: str
    challenge_type: ChallengeType
    confidence: float = 1.0
    method: str = ""
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CtfChallenge:
    name: str
    challenge_type: ChallengeType
    description: str = ""
    points: int = 0
    solved: bool = False
    flag: Optional[CtfFlag] = None
    hints: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    url: str = ""
    port: int = 0
    solve_steps: List[str] = field(default_factory=list)


FLAG_GREP_PATTERN = "flag\\{[^}]+\\}|CTF\\{[^}]+\\}"

FLAG_PATTERNS: List[Pattern] = [
    re.compile(r'(?i)flag\{([^}]+)\}'),
    re.compile(r'(?i)CTF\{([^}]+)\}'),
    re.compile(r'(?i)CTF_([a-zA-Z0-9_]+)'),
    re.compile(r'(?i)FLAG[:\s]+([a-zA-Z0-9_!@#$%^&*()=+\[\]{}|;:,.<>?]+)'),
    re.compile(r'(?i)([a-zA-Z0-9]{20,40})'),
]

CHALLENGE_TYPE_PATTERNS: Dict[ChallengeType, List[Pattern]] = {
    ChallengeType.WEB: [
        re.compile(r'(?i)(web|http|XSS|SQL[-\s]?injection|admin|login|cookie|session|csrf|ssrf)'),
    ],
    ChallengeType.CRYPTO: [
        re.compile(r'(?i)(crypto|cipher|encrypt|decrypt|RSA|AES|hash|md5|sha|base64|XOR|substitution|vigenere|caesar)'),
    ],
    ChallengeType.STEGO: [
        re.compile(r'(?i)(stego|steganography|LSB|image|hidden|embedded|pixel|exif)'),
    ],
    ChallengeType.FORENSICS: [
        re.compile(r'(?i)(forensic|memory|dump|pcap|network|traffic|volatility|binwalk|strings)'),
    ],
    ChallengeType.REVERSING: [
        re.compile(r'(?i)(reverse|rev|binary|disassem|ghidra|ida|radare|angr|decompile)'),
    ],
    ChallengeType.PWN: [
        re.compile(r'(?i)(pwn|binary|exploit|buffer|overflow|ROP|shellcode|format.string|ret2)'),
    ],
    ChallengeType.OSINT: [
        re.compile(r'(?i)(OSINT|recon|social|search|find|locate|people|email|domain)'),
    ],
    ChallengeType.RECON: [
        re.compile(r'(?i)(recon|scan|port|service|enumeration|discover|fingerprint)'),
    ],
}


class CtfSolver:
    def __init__(self) -> None:
        self.challenges: List[CtfChallenge] = []
        self.solved_challenges: List[CtfChallenge] = []
        self.total_points: int = 0
        self.solved_points: int = 0

    def classify_challenge(self, name: str, description: str = "", url: str = "") -> ChallengeType:
        text = f"{name} {description} {url}"
        best_type = ChallengeType.MISC
        best_score = 0

        for ctype, patterns in CHALLENGE_TYPE_PATTERNS.items():
            score = 0
            for pat in patterns:
                matches = pat.findall(text)
                score += len(matches) * 2
            if score > best_score:
                best_score = score
                best_type = ctype

        return best_type

    def extract_flags(self, text: str, source: str = "") -> List[CtfFlag]:
        flags = []
        seen = set()

        for pat in FLAG_PATTERNS:
            for match in pat.finditer(text):
                raw = match.group(0)
                if raw.lower() in seen:
                    continue
                seen.add(raw.lower())

                flag_value = raw
                if match.lastindex and match.group(1):
                    flag_value = match.group(1)

                ctype = self.classify_challenge(source, raw)
                confidence = 1.0
                if match.lastindex and len(match.group()) < 6:
                    confidence = 0.3
                elif "flag{" in raw.lower() or "ctf{" in raw.lower():
                    confidence = 1.0

                flags.append(CtfFlag(
                    flag=flag_value,
                    challenge_type=ctype,
                    confidence=confidence,
                    method=f"regex:{pat.pattern[:40]}",
                    source=source,
                ))

        return flags

    async def solve_web(self, challenge: CtfChallenge) -> Optional[CtfFlag]:
        logger.info(f"[CTF] Solving web challenge: {challenge.name}")
        url = challenge.url or f"http://{challenge.name}"
        commands = [
            f"curl -s -L -v '{url}' 2>&1 | head -200",
            f"curl -s '{url}' | grep -oE '{FLAG_GREP_PATTERN}' || true",
            f"curl -s '{url}/robots.txt' 2>/dev/null | head -50 || true",
            f"gobuster dir -u '{url}' -w /usr/share/wordlists/dirb/common.txt -q 2>/dev/null | head -30 || true",
            f"curl -s -c /tmp/ctf_cookies -b /tmp/ctf_cookies '{url}' -L 2>/dev/null | head -200",
        ]
        for cmd in commands:
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                flags = self.extract_flags(output, source=cmd[:40])
                if flags:
                    flags[0].method = "web_solve"
                    return flags[0]
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.debug(f"[CTF] Web command failed: {e}")
        return None

    async def solve_crypto(self, challenge: CtfChallenge) -> Optional[CtfFlag]:
        logger.info(f"[CTF] Solving crypto challenge: {challenge.name}")
        for filepath in challenge.files:
            try:
                proc = await asyncio.create_subprocess_shell(
                    f"cat '{filepath}' 2>/dev/null",
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                content = stdout.decode(errors="replace")
                flags = self.extract_flags(content, source=filepath)
                if flags:
                    return flags[0]

                if re.search(r'(?i)base64', content):
                    decoded = re.sub(r'\s', '', content)
                    try:
                        import base64
                        plain = base64.b64decode(decoded).decode(errors="replace")
                        for line in plain.split('\n'):
                            flags = self.extract_flags(line, source="base64_decoded")
                            if flags:
                                return flags[0]
                    except Exception:
                        pass
            except Exception:
                continue
        return None

    async def solve_stego(self, challenge: CtfChallenge) -> Optional[CtfFlag]:
        logger.info(f"[CTF] Solving stego challenge: {challenge.name}")
        for filepath in challenge.files:
            commands = [
                f"strings '{filepath}' 2>/dev/null | grep -oE '{FLAG_GREP_PATTERN}' || true",
                f"exiftool '{filepath}' 2>/dev/null | head -40 || true",
                f"zsteg '{filepath}' 2>/dev/null | grep -oE '{FLAG_GREP_PATTERN}' || true",
                f"steghide extract -sf '{filepath}' -p '' -f 2>/dev/null && cat *.flag* 2>/dev/null || true",
                f"binwalk -Me '{filepath}' 2>/dev/null && find _'{filepath}.extracted' -name '*.txt' -exec cat {{}} \\; 2>/dev/null || true",
            ]
            for cmd in commands:
                try:
                    proc = await asyncio.create_subprocess_shell(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                    output = stdout.decode(errors="replace")
                    flags = self.extract_flags(output, source=cmd[:40])
                    if flags:
                        flags[0].method = "stego_solve"
                        return flags[0]
                except Exception:
                    continue
        return None

    async def solve_osint(self, challenge: CtfChallenge) -> Optional[CtfFlag]:
        logger.info(f"[CTF] Solving OSINT challenge: {challenge.name}")
        target = challenge.url or challenge.name
        commands = [
            f"whois '{target}' 2>/dev/null | head -60 || true",
            f"dig any '{target}' 2>/dev/null | head -40 || true",
            f"nslookup '{target}' 2>/dev/null || true",
            f"curl -s 'https://api.github.com/search/code?q={target}' 2>/dev/null | head -100 || true",
        ]
        for cmd in commands:
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                flags = self.extract_flags(output, source=cmd[:40])
                if flags:
                    return flags[0]
            except Exception:
                continue
        return None

    async def solve_challenge(self, challenge: CtfChallenge) -> Optional[CtfFlag]:
        solvers = {
            ChallengeType.WEB: self.solve_web,
            ChallengeType.CRYPTO: self.solve_crypto,
            ChallengeType.STEGO: self.solve_stego,
            ChallengeType.OSINT: self.solve_osint,
            ChallengeType.RECON: self.solve_osint,
        }

        solver = solvers.get(challenge.challenge_type)
        if solver:
            try:
                return await asyncio.wait_for(solver(challenge), timeout=120)
            except asyncio.TimeoutError:
                logger.warning(f"[CTF] Solver timed out for {challenge.name}")
            except Exception as e:
                logger.error(f"[CTF] Solver error for {challenge.name}: {e}")

        return None

    async def solve_all(self, timeout: int = 300) -> List[CtfFlag]:
        tasks = []
        for challenge in self.challenges:
            if challenge.solved:
                continue
            task = asyncio.create_task(self._solve_one(challenge))
            tasks.append(task)

        if not tasks:
            return []

        done, _ = await asyncio.wait(tasks, timeout=timeout)
        results = []
        for task in done:
            try:
                flag = task.result()
                if flag:
                    results.append(flag)
            except Exception:
                pass
        return results

    async def _solve_one(self, challenge: CtfChallenge) -> Optional[CtfFlag]:
        flag = await self.solve_challenge(challenge)
        if flag:
            challenge.solved = True
            challenge.flag = flag
            self.solved_challenges.append(challenge)
            self.solved_points += challenge.points
            logger.info(f"[CTF] SOLVED: {challenge.name} -> {flag.flag}")
        return flag

    def add_challenge(self, name: str, description: str = "",
                      challenge_type: Optional[ChallengeType] = None,
                      points: int = 0, url: str = "", port: int = 0,
                      files: Optional[List[str]] = None) -> CtfChallenge:
        if challenge_type is None:
            challenge_type = self.classify_challenge(name, description, url)

        challenge = CtfChallenge(
            name=name,
            challenge_type=challenge_type,
            description=description,
            points=points,
            url=url,
            port=port,
            files=files or [],
        )
        self.challenges.append(challenge)
        self.total_points += points
        return challenge

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_challenges": len(self.challenges),
            "solved": len(self.solved_challenges),
            "total_points": self.total_points,
            "solved_points": self.solved_points,
            "completion_pct": round(len(self.solved_challenges) / max(len(self.challenges), 1) * 100, 1),
            "by_type": {
                ct.value: {
                    "total": sum(1 for c in self.challenges if c.challenge_type == ct),
                    "solved": sum(1 for c in self.solved_challenges if c.challenge_type == ct),
                }
                for ct in ChallengeType
            },
        }
