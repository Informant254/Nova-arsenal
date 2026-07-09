"""
High-speed attack surface mapper and prioritizer.

Maps services/endpoints into a ranked queue so expensive fuzzing and
deep analysis hit the highest-yield surfaces first.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

logger = logging.getLogger(__name__)


# Surfaces historically rich in novel bugs get higher base scores.
_HIGH_YIELD_SERVICES = {
    "http": 8.0,
    "https": 8.5,
    "http-proxy": 7.0,
    "smb": 9.0,
    "microsoft-ds": 9.0,
    "rdp": 8.5,
    "ssh": 6.5,
    "ftp": 7.0,
    "tftp": 7.5,
    "snmp": 7.0,
    "ldap": 7.5,
    "kerberos": 8.0,
    "mssql": 8.0,
    "mysql": 7.0,
    "postgresql": 7.0,
    "redis": 7.5,
    "mongodb": 7.0,
    "elasticsearch": 7.5,
    "docker": 8.0,
    "kubernetes": 8.5,
    "grpc": 8.0,
    "mqtt": 7.0,
    "amqp": 7.0,
    "nfs": 8.0,
    "iscsi": 8.0,
    "sip": 7.5,
    "rtsp": 7.0,
    "vnc": 7.5,
    "winrm": 8.0,
    "rpcbind": 8.5,
    "msrpc": 9.0,
}

_DANGEROUS_PATH_HINTS = (
    "upload", "import", "export", "parse", "xml", "svg", "pdf", "zip",
    "admin", "debug", "internal", "graphql", "rpc", "deserialize",
    "eval", "exec", "shell", "cmd", "webhook", "callback", "proxy",
    "file", "path", "template", "render", "preview", "convert",
)

_VERSION_RE = re.compile(
    r"(?P<name>[A-Za-z][\w.+-]{1,40})\s*(?:/|v)?(?P<ver>\d+(?:\.\d+){0,3}[a-z0-9-]*)",
    re.I,
)


@dataclass
class SurfaceEndpoint:
    """A single prioritizable attack surface node."""

    target: str
    service: str
    port: int = 0
    protocol: str = "tcp"
    path: str = ""
    version: str = ""
    banner: str = ""
    technologies: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    priority: float = 0.0
    blast_radius: float = 0.0
    fuzz_affinity: float = 0.0
    novelty_prior: float = 0.5
    rationale: str = ""

    @property
    def surface_id(self) -> str:
        raw = f"{self.target}|{self.service}|{self.port}|{self.path}|{self.version}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "surface_id": self.surface_id,
            "target": self.target,
            "service": self.service,
            "port": self.port,
            "protocol": self.protocol,
            "path": self.path,
            "version": self.version,
            "banner": self.banner[:200],
            "technologies": self.technologies,
            "params": self.params,
            "methods": self.methods,
            "tags": self.tags,
            "priority": round(self.priority, 3),
            "blast_radius": round(self.blast_radius, 3),
            "fuzz_affinity": round(self.fuzz_affinity, 3),
            "novelty_prior": round(self.novelty_prior, 3),
            "rationale": self.rationale,
        }


@dataclass
class SurfaceMap:
    """Ranked attack surface for a target."""

    target: str
    endpoints: List[SurfaceEndpoint] = field(default_factory=list)
    elapsed_ms: float = 0.0
    notes: List[str] = field(default_factory=list)

    @property
    def top(self) -> List[SurfaceEndpoint]:
        return sorted(self.endpoints, key=lambda e: e.priority, reverse=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "endpoint_count": len(self.endpoints),
            "elapsed_ms": round(self.elapsed_ms, 2),
            "top_endpoints": [e.to_dict() for e in self.top[:25]],
            "notes": self.notes,
        }


class AttackSurfaceMapper:
    """
    Build and rank an attack surface from recon artifacts in near-real-time.

    Accepts loose service dicts (from nmap parsers, agent findings, etc.)
    and produces a deterministic priority queue for the zero-day pipeline.
    """

    def __init__(
        self,
        max_endpoints: int = 500,
        boost_unversioned: float = 1.15,
    ) -> None:
        self.max_endpoints = max_endpoints
        self.boost_unversioned = boost_unversioned

    def map(
        self,
        target: str,
        services: Optional[Dict[str, Any]] = None,
        endpoints: Optional[Sequence[Dict[str, Any]]] = None,
        technologies: Optional[Sequence[str]] = None,
        findings: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> SurfaceMap:
        t0 = time.perf_counter()
        mapped: List[SurfaceEndpoint] = []
        notes: List[str] = []

        services = services or {}
        technologies = list(technologies or [])
        findings = list(findings or [])

        for svc_name, meta in services.items():
            mapped.extend(self._from_service(target, svc_name, meta, technologies))

        for ep in endpoints or []:
            mapped.append(self._from_endpoint_dict(target, ep, technologies))

        if not mapped:
            # Minimal default surface so the pipeline always has work units.
            notes.append("No recon input; seeded common high-yield service probes")
            for name, port in (
                ("https", 443),
                ("http", 80),
                ("ssh", 22),
                ("smb", 445),
                ("rdp", 3389),
            ):
                mapped.append(
                    SurfaceEndpoint(
                        target=target,
                        service=name,
                        port=port,
                        tags=["seeded"],
                    )
                )

        for f in findings:
            self._boost_from_finding(mapped, f)

        for ep in mapped:
            self._score(ep)

        # Dedup by surface_id, keep highest priority
        by_id: Dict[str, SurfaceEndpoint] = {}
        for ep in mapped:
            prev = by_id.get(ep.surface_id)
            if prev is None or ep.priority > prev.priority:
                by_id[ep.surface_id] = ep

        ranked = sorted(by_id.values(), key=lambda e: e.priority, reverse=True)
        if len(ranked) > self.max_endpoints:
            notes.append(f"Truncated surface from {len(ranked)} to {self.max_endpoints}")
            ranked = ranked[: self.max_endpoints]

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        logger.info(
            "Surface map for %s: %d endpoints in %.1fms",
            target,
            len(ranked),
            elapsed_ms,
        )
        return SurfaceMap(
            target=target,
            endpoints=ranked,
            elapsed_ms=elapsed_ms,
            notes=notes,
        )

    async def map_async(self, *args: Any, **kwargs: Any) -> SurfaceMap:
        # CPU-bound and already sub-ms for typical sizes; async for API symmetry.
        return self.map(*args, **kwargs)

    def _from_service(
        self,
        target: str,
        svc_name: str,
        meta: Any,
        technologies: Sequence[str],
    ) -> List[SurfaceEndpoint]:
        results: List[SurfaceEndpoint] = []
        name = str(svc_name).lower().strip()

        if isinstance(meta, list):
            # ports list: {"http": [80, 8080]}
            for port in meta:
                results.append(
                    SurfaceEndpoint(
                        target=target,
                        service=name,
                        port=int(port) if str(port).isdigit() else 0,
                        technologies=list(technologies),
                    )
                )
            return results

        if isinstance(meta, dict):
            ports = meta.get("ports") or meta.get("port") or [meta.get("port", 0)]
            if not isinstance(ports, list):
                ports = [ports]
            version = str(meta.get("version") or meta.get("product") or "")
            banner = str(meta.get("banner") or meta.get("product") or "")
            proto = str(meta.get("protocol") or "tcp")
            paths = meta.get("paths") or meta.get("endpoints") or [""]
            if not isinstance(paths, list):
                paths = [paths]
            for port in ports:
                for path in paths:
                    results.append(
                        SurfaceEndpoint(
                            target=target,
                            service=name,
                            port=int(port) if str(port).isdigit() else 0,
                            protocol=proto,
                            path=str(path or ""),
                            version=version,
                            banner=banner,
                            technologies=list(
                                dict.fromkeys(
                                    list(technologies) + list(meta.get("technologies") or [])
                                )
                            ),
                            params=list(meta.get("params") or []),
                            methods=list(meta.get("methods") or []),
                            tags=list(meta.get("tags") or []),
                        )
                    )
            return results

        # bare truthy value
        results.append(
            SurfaceEndpoint(
                target=target,
                service=name,
                technologies=list(technologies),
            )
        )
        return results

    def _from_endpoint_dict(
        self,
        target: str,
        ep: Dict[str, Any],
        technologies: Sequence[str],
    ) -> SurfaceEndpoint:
        return SurfaceEndpoint(
            target=str(ep.get("target") or target),
            service=str(ep.get("service") or ep.get("type") or "http").lower(),
            port=int(ep.get("port") or 0),
            protocol=str(ep.get("protocol") or "tcp"),
            path=str(ep.get("path") or ep.get("url") or ""),
            version=str(ep.get("version") or ""),
            banner=str(ep.get("banner") or ""),
            technologies=list(
                dict.fromkeys(list(technologies) + list(ep.get("technologies") or []))
            ),
            params=list(ep.get("params") or []),
            methods=list(ep.get("methods") or []),
            tags=list(ep.get("tags") or []),
        )

    def _boost_from_finding(
        self,
        endpoints: List[SurfaceEndpoint],
        finding: Dict[str, Any],
    ) -> None:
        text = " ".join(
            str(finding.get(k, ""))
            for k in ("title", "description", "endpoint", "evidence", "type")
        ).lower()
        for ep in endpoints:
            if ep.path and ep.path.lower() in text:
                ep.tags = list(dict.fromkeys(ep.tags + ["finding-linked"]))
                ep.novelty_prior = min(1.0, ep.novelty_prior + 0.1)
            if ep.service and ep.service in text:
                ep.tags = list(dict.fromkeys(ep.tags + ["finding-service"]))

    def _score(self, ep: SurfaceEndpoint) -> None:
        base = _HIGH_YIELD_SERVICES.get(ep.service, 5.0)
        path_l = (ep.path or "").lower()
        danger_hits = sum(1 for h in _DANGEROUS_PATH_HINTS if h in path_l)
        param_boost = min(3.0, 0.4 * len(ep.params))
        method_boost = 0.5 if any(m.upper() in {"POST", "PUT", "PATCH"} for m in ep.methods) else 0.0
        tech_boost = min(2.0, 0.25 * len(ep.technologies))

        version_factor = 1.0
        if not ep.version:
            version_factor = self.boost_unversioned  # unknown versions → more novel risk
        else:
            # Very new or odd version strings get slight novelty prior
            if re.search(r"(alpha|beta|rc|dev|snapshot)", ep.version, re.I):
                version_factor = 1.2
                ep.novelty_prior = min(1.0, ep.novelty_prior + 0.15)

        # Parse banner for product/version if missing
        if not ep.version and ep.banner:
            m = _VERSION_RE.search(ep.banner)
            if m:
                ep.version = m.group("ver")

        blast = base * 0.1 + danger_hits * 0.8 + param_boost * 0.5
        if ep.service in {"smb", "msrpc", "rdp", "kerberos", "ldap"}:
            blast += 2.0  # domain-wide impact class

        fuzz = 3.0 + danger_hits * 1.2 + param_boost
        if ep.service in {"http", "https", "grpc", "ftp", "tftp"}:
            fuzz += 2.0
        if any(t in {"upload", "parser", "file"} for t in ep.tags):
            fuzz += 1.5

        priority = (base + danger_hits * 1.5 + param_boost + method_boost + tech_boost) * version_factor
        priority += blast * 0.3 + fuzz * 0.2
        priority *= 0.85 + 0.3 * ep.novelty_prior

        ep.blast_radius = blast
        ep.fuzz_affinity = fuzz
        ep.priority = priority
        ep.rationale = (
            f"service={ep.service} base={base:.1f} danger_path_hits={danger_hits} "
            f"params={len(ep.params)} version_factor={version_factor:.2f}"
        )
