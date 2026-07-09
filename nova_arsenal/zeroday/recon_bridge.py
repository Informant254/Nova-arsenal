"""
Bridge recon/swarm findings into ZeroDayHunter service maps.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

_PORT_RE = re.compile(
    r"\b(?:port\s*)?(\d{1,5})/(tcp|udp)\b|\b(\d{1,5})\s*/\s*(tcp|udp)\b|"
    r"\b(?:on\s+port\s+|:)(\d{1,5})\b",
    re.I,
)
_SERVICE_RE = re.compile(
    r"\b(http|https|ssh|smb|microsoft-ds|ftp|rdp|msrpc|ldap|kerberos|mysql|"
    r"postgresql|redis|mongodb|smtp|imap|pop3|dns|snmp|vnc|winrm|nfs|docker|"
    r"kubernetes|grpc|mqtt)\b",
    re.I,
)
_VERSION_RE = re.compile(
    r"(?:version|ver\.?)\s*[:=]?\s*([vV]?\d+(?:\.\d+){0,3}[\w.-]*)|"
    r"\b([A-Za-z][\w.+-]{1,30})/(\d+(?:\.\d+){0,3}[\w.-]*)",
    re.I,
)

_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "smb": 445,
    "microsoft-ds": 445,
    "ftp": 21,
    "rdp": 3389,
    "msrpc": 135,
    "ldap": 389,
    "mysql": 3306,
    "postgresql": 5432,
    "redis": 6379,
    "smtp": 25,
    "dns": 53,
    "snmp": 161,
    "vnc": 5900,
    "winrm": 5985,
    "nfs": 2049,
}


def findings_to_services(
    findings: Sequence[Any],
    target: str = "",
) -> Dict[str, Any]:
    """
    Convert swarm/agent findings into a ZeroDayHunter services map.

    Accepts SwarmFinding objects or plain dicts with title/description/evidence.
    """
    services: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        if hasattr(f, "to_dict"):
            d = f.to_dict()
        elif isinstance(f, dict):
            d = f
        else:
            d = {
                "title": getattr(f, "title", ""),
                "description": getattr(f, "description", ""),
                "evidence": getattr(f, "evidence", ""),
            }
        text = " ".join(
            str(d.get(k, ""))
            for k in ("title", "description", "evidence", "endpoint", "severity")
        )
        _absorb_text(services, text)

    if not services:
        # Minimal seed so researcher still has work after empty recon
        services = {
            "https": {"ports": [443], "paths": ["/"], "tags": ["recon-seed"]},
            "http": {"ports": [80], "paths": ["/"], "tags": ["recon-seed"]},
        }
    return services


def _absorb_text(services: Dict[str, Dict[str, Any]], text: str) -> None:
    if not text:
        return
    found_services = {m.group(1).lower() for m in _SERVICE_RE.finditer(text)}
    ports: List[Tuple[int, str]] = []
    for m in _PORT_RE.finditer(text):
        if m.group(1):
            ports.append((int(m.group(1)), (m.group(2) or "tcp").lower()))
        elif m.group(3):
            ports.append((int(m.group(3)), (m.group(4) or "tcp").lower()))
        elif m.group(5):
            p = int(m.group(5))
            if 1 <= p <= 65535:
                ports.append((p, "tcp"))

    version = ""
    vm = _VERSION_RE.search(text)
    if vm:
        version = vm.group(1) or f"{vm.group(2)}/{vm.group(3)}"

    paths = re.findall(r"(/(?:[A-Za-z0-9._~/-]{1,60}))", text)
    paths = [p for p in paths if not p.startswith("//")][:10]

    if not found_services and ports:
        for port, _proto in ports:
            svc = _port_to_service(port)
            found_services.add(svc)

    for svc in found_services or set():
        entry = services.setdefault(
            svc,
            {"ports": [], "paths": [], "version": "", "tags": ["from-recon"]},
        )
        if version and not entry.get("version"):
            entry["version"] = version
        for port, _proto in ports:
            if port not in entry["ports"] and _port_matches_service(port, svc):
                entry["ports"].append(port)
        if not entry["ports"]:
            default = _DEFAULT_PORTS.get(svc)
            if default:
                entry["ports"].append(default)
        for p in paths:
            if p not in entry["paths"] and svc in {"http", "https", "http-proxy"}:
                entry["paths"].append(p)


def _port_to_service(port: int) -> str:
    for svc, p in _DEFAULT_PORTS.items():
        if p == port:
            return svc
    if port in {80, 8080, 8000, 8888}:
        return "http"
    if port in {443, 8443}:
        return "https"
    return "unknown"


def _port_matches_service(port: int, svc: str) -> bool:
    default = _DEFAULT_PORTS.get(svc)
    if default == port:
        return True
    if svc in {"http", "https"} and port in {80, 443, 8080, 8443, 8000, 8888}:
        return True
    if svc == "unknown":
        return True
    # Allow associating unspecified ports when only one service mentioned
    return default is None
