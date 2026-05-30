#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🛡️  NOVA SCOPE MANAGER v1.0 — HACKERONE LIVE SCOPE SYNC         ║
║                                                                      ║
║   Pulls your active HackerOne program scopes in real-time.          ║
║   Nova always knows exactly what is in and out of bounds.           ║
║                                                                      ║
║   Features:                                                          ║
║   • Fetch all programs you participate in (invited + public)        ║
║   • Pull in-scope / out-of-scope assets per program                 ║
║   • Auto-convert to Nova Daybreak ScopeRule objects                 ║
║   • Local cache (TTL: 1 hour) — avoids H1 rate limits              ║
║   • Asset type filtering (URL, WILDCARD, CIDR, etc.)               ║
║   • Scope diff — detect changes since last sync                     ║
║   • Export scope as Markdown, JSON, or plain list                   ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import time
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

import requests


# ── CONFIG ────────────────────────────────────────────────────────────────────

H1_API_BASE       = "https://api.hackerone.com/v1"
CACHE_DIR         = Path(os.path.expanduser("~/.nova/scope_cache"))
LOCAL_CONFIG_PATH = Path(os.path.expanduser("~/.nova/scope_config.json"))
CACHE_TTL         = 3600          # seconds (1 hour)
MAX_PROGRAMS      = 100           # max programs to fetch per sync


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────

@dataclass
class Asset:
    identifier:  str          # e.g. "*.konghq.com", "192.168.0.0/24"
    asset_type:  str          # URL, WILDCARD, CIDR, ANDROID, IOS, OTHER
    eligible_for_bounty: bool = True
    eligible_for_submission: bool = True
    max_severity: str = "critical"
    instruction: str = ""

    def to_pattern(self) -> str:
        """Convert to a Nova scope pattern."""
        t = self.asset_type.upper()
        if t in ("URL", "WILDCARD", "DOMAIN"):
            # strip scheme for pattern matching
            p = re.sub(r'^https?://', '', self.identifier).rstrip('/')
            return p
        return self.identifier


@dataclass
class ProgramScope:
    handle:       str
    name:         str
    url:          str
    state:        str          # public_mode / private
    in_scope:     List[Asset]  = field(default_factory=list)
    out_of_scope: List[Asset]  = field(default_factory=list)
    offers_bounties: bool      = False
    synced_at:    str          = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_scope_rule(self):
        """Convert to a Nova Daybreak ScopeRule."""
        # import here to avoid circular dependency
        try:
            from nova_daybreak import ScopeRule
        except ImportError:
            # Minimal stand-in if nova_daybreak not in path
            from dataclasses import dataclass as dc, field as fi
            @dc
            class ScopeRule:
                program: str; platform: str = "hackerone"
                in_scope: list = fi(default_factory=list)
                out_of_scope: list = fi(default_factory=list)
                rules: list = fi(default_factory=list)

        in_patterns  = [a.to_pattern() for a in self.in_scope
                        if a.asset_type.upper() in ("URL","WILDCARD","DOMAIN","CIDR")]
        out_patterns = [a.to_pattern() for a in self.out_of_scope
                        if a.asset_type.upper() in ("URL","WILDCARD","DOMAIN","CIDR")]

        return ScopeRule(
            program=self.name,
            platform="hackerone",
            in_scope=in_patterns,
            out_of_scope=out_patterns,
            rules=[f"Max severity: {a.max_severity}" for a in self.in_scope if a.max_severity],
        )

    def bounty_eligible_targets(self) -> List[str]:
        """Return only targets eligible for bounty."""
        return [a.to_pattern() for a in self.in_scope if a.eligible_for_bounty]


# ── H1 API CLIENT ─────────────────────────────────────────────────────────────

class H1Client:
    """
    Thin wrapper around the HackerOne Hackers API.
    Docs: https://api.hackerone.com/hacker-resources/
    """

    def __init__(self, username: str, api_token: str):
        self.session = requests.Session()
        self.session.auth   = (username, api_token)
        self.session.headers.update({
            "Accept":     "application/json",
            "User-Agent": "Nova-Scope-Manager/1.0",
        })

    def _get(self, path: str, params: Dict = None) -> Dict:
        r = self.session.get(f"{H1_API_BASE}{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def me(self) -> Dict:
        """Verify credentials and return authenticated user info."""
        return self._get("/hackers/me")

    def programs(self, page: int = 1, per_page: int = 25) -> Dict:
        """List programs the hacker has access to."""
        return self._get("/hackers/programs", params={
            "page[number]": page,
            "page[size]":   per_page,
            "sort":         "-updated_at",
        })

    def program(self, handle: str) -> Dict:
        """Fetch a single program by handle."""
        return self._get(f"/hackers/programs/{handle}")

    def structured_scope(self, handle: str) -> Dict:
        """Fetch structured scope (in/out of scope assets)."""
        return self._get(f"/hackers/programs/{handle}/structured_scopes", params={
            "page[size]": 100,
        })


# ── SCOPE PARSER ──────────────────────────────────────────────────────────────

class ScopeParser:
    """Converts H1 API responses into ProgramScope objects."""

    SUPPORTED_TYPES = {"URL", "WILDCARD", "CIDR", "ANDROID", "IOS", "OTHER",
                       "DOMAIN", "EXECUTABLE", "HARDWARE", "SOURCE_CODE"}

    @classmethod
    def parse_program(cls, prog_data: Dict, scope_data: Dict) -> ProgramScope:
        attrs = prog_data.get("attributes", {})

        in_scope:  List[Asset] = []
        out_scope: List[Asset] = []

        for item in scope_data.get("data", []):
            a     = item.get("attributes", {})
            asset = Asset(
                identifier=a.get("asset_identifier", ""),
                asset_type=a.get("asset_type", "OTHER"),
                eligible_for_bounty=a.get("eligible_for_bounty", False),
                eligible_for_submission=a.get("eligible_for_submission", True),
                max_severity=a.get("max_severity", "critical"),
                instruction=a.get("instruction", ""),
            )
            if asset.identifier:
                if a.get("eligible_for_submission", True):
                    in_scope.append(asset)
                else:
                    out_scope.append(asset)

        return ProgramScope(
            handle=prog_data.get("id", ""),
            name=attrs.get("name", ""),
            url=f"https://hackerone.com/{prog_data.get('id','')}",
            state=attrs.get("state", ""),
            in_scope=in_scope,
            out_of_scope=out_scope,
            offers_bounties=attrs.get("offers_bounties", False),
        )


# ── CACHE ─────────────────────────────────────────────────────────────────────

class ScopeCache:
    """File-based cache for program scopes."""

    def __init__(self, cache_dir: Path = CACHE_DIR, ttl: int = CACHE_TTL):
        self.dir = cache_dir
        self.ttl = ttl
        self.dir.mkdir(parents=True, exist_ok=True)

    def _key(self, handle: str) -> Path:
        h = hashlib.md5(handle.encode()).hexdigest()[:8]
        return self.dir / f"scope_{handle}_{h}.json"

    def get(self, handle: str) -> Optional[ProgramScope]:
        path = self._key(handle)
        if not path.exists():
            return None
        try:
            data    = json.loads(path.read_text())
            synced  = datetime.fromisoformat(data.get("synced_at", "2000-01-01T00:00:00+00:00"))
            age     = (datetime.now(timezone.utc) - synced).total_seconds()
            if age > self.ttl:
                return None
            # Rebuild from dict
            in_scope  = [Asset(**a) for a in data.get("in_scope",  [])]
            out_scope = [Asset(**a) for a in data.get("out_of_scope", [])]
            return ProgramScope(
                handle=data["handle"], name=data["name"], url=data["url"],
                state=data["state"], in_scope=in_scope, out_of_scope=out_scope,
                offers_bounties=data.get("offers_bounties", False),
                synced_at=data["synced_at"],
            )
        except Exception:
            return None

    def put(self, scope: ProgramScope):
        path = self._key(scope.handle)
        data = asdict(scope)
        path.write_text(json.dumps(data, indent=2))

    def list_cached(self) -> List[str]:
        return [f.stem.split("_")[1] for f in self.dir.glob("scope_*.json")]

    def invalidate(self, handle: str = None):
        if handle:
            p = self._key(handle)
            if p.exists():
                p.unlink()
        else:
            for f in self.dir.glob("scope_*.json"):
                f.unlink()
        print("  🗑️  Cache cleared.")


# ── SCOPE DIFF ────────────────────────────────────────────────────────────────

class ScopeDiff:
    """Detect scope changes between two syncs."""

    @staticmethod
    def diff(old: ProgramScope, new: ProgramScope) -> Dict:
        old_in  = {a.identifier for a in old.in_scope}
        new_in  = {a.identifier for a in new.in_scope}
        old_out = {a.identifier for a in old.out_of_scope}
        new_out = {a.identifier for a in new.out_of_scope}

        added   = new_in  - old_in
        removed = old_in  - new_in
        newly_oos = new_out - old_out

        return {
            "program":      new.handle,
            "added":        sorted(added),
            "removed":      sorted(removed),
            "newly_out_of_scope": sorted(newly_oos),
            "changed": bool(added or removed or newly_oos),
        }

    @staticmethod
    def print_diff(diff: Dict):
        if not diff["changed"]:
            return
        print(f"\n  🔔 Scope change detected: {diff['program']}")
        for a in diff["added"]:
            print(f"     ✅ Added to scope:     {a}")
        for a in diff["removed"]:
            print(f"     ❌ Removed from scope: {a}")
        for a in diff["newly_out_of_scope"]:
            print(f"     ⛔ Now out of scope:   {a}")


# ── SCOPE MANAGER ─────────────────────────────────────────────────────────────

class NovaScopeManager:
    """
    Main scope manager.  Syncs HackerOne program scopes and makes
    them available to Nova Daybreak as ScopeRule objects.

    Usage:
        mgr = NovaScopeManager()   # reads H1_USERNAME + H1_API_TOKEN from env
        scopes = mgr.sync_all()
        rule = scopes["kong-inc"].to_scope_rule()
    """

    def __init__(self,
                 username: str  = None,
                 api_token: str = None,
                 cache_ttl: int = CACHE_TTL):
        self.username  = username  or os.getenv("H1_USERNAME",  "")
        self.api_token = api_token or os.getenv("H1_API_TOKEN", "")
        self.cache     = ScopeCache(ttl=cache_ttl)
        self._client:  Optional[H1Client]     = None
        self._scopes:  Dict[str, ProgramScope] = {}

    def _client_(self) -> H1Client:
        if not self._client:
            if not self.username or not self.api_token:
                raise RuntimeError(
                    "HackerOne credentials not set.\n"
                    "Set H1_USERNAME and H1_API_TOKEN as environment variables:\n"
                    "  export H1_USERNAME='your_h1_handle'\n"
                    "  export H1_API_TOKEN='your_api_token'\n"
                    "Create tokens at: https://hackerone.com/settings/api_token/edit"
                )
            self._client = H1Client(self.username, self.api_token)
        return self._client

    # ── SYNC ──────────────────────────────────────────────────────

    def verify_credentials(self) -> bool:
        """Verify H1 credentials are valid."""
        try:
            me = self._client_().me()
            handle = me.get("data", {}).get("attributes", {}).get("username", "")
            print(f"  ✅ Authenticated as: @{handle}")
            return True
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                print("  ❌ H1 API: Invalid credentials (401).")
                print("     To fix: regenerate your token at")
                print("     https://hackerone.com/settings/api_token/edit")
                print("     then update H1_API_TOKEN in your environment.")
                print("  ℹ️  Falling back to local config if available.")
            else:
                print(f"  ❌ H1 API error: {e}")
            return False
        except RuntimeError as e:
            print(f"  ⚠️  {e}")
            return False
        except Exception as e:
            print(f"  ❌ Connection error: {e}")
            return False

    def sync_program(self, handle: str, force: bool = False) -> Optional[ProgramScope]:
        """Sync a single program by handle."""
        # Check cache first
        if not force:
            cached = self.cache.get(handle)
            if cached:
                self._scopes[handle] = cached
                return cached

        try:
            client     = self._client_()
            prog_data  = client.program(handle)["data"]
            scope_data = client.structured_scope(handle)
            scope      = ScopeParser.parse_program(prog_data, scope_data)

            # Diff with cached version
            old = self.cache.get(handle)
            if old:
                diff = ScopeDiff.diff(old, scope)
                ScopeDiff.print_diff(diff)

            self.cache.put(scope)
            self._scopes[handle] = scope
            return scope

        except requests.HTTPError as e:
            print(f"  ⚠️  Could not fetch {handle}: HTTP {e.response.status_code}")
            return None
        except Exception as e:
            print(f"  ⚠️  Error syncing {handle}: {e}")
            return None

    def sync_all(self, force: bool = False,
                 bounty_only: bool = False) -> Dict[str, ProgramScope]:
        """Sync all programs you participate in."""
        print("\n" + "=" * 60)
        print("🛡️  NOVA SCOPE MANAGER — Syncing HackerOne scopes")
        print("=" * 60)

        if not self.verify_credentials():
            # Try local config file as fallback
            local = self.load_from_local_config()
            if local:
                return self._scopes
            print("\n  💡 No local config found either.")
            print(f"     Run: python3 nova_scope_manager.py init-config")
            print(f"     Then edit: {LOCAL_CONFIG_PATH}")
            return {}

        handles = self._fetch_all_handles(bounty_only=bounty_only)
        print(f"\n  📋 {len(handles)} programs found. Syncing scopes...")

        for i, handle in enumerate(handles, 1):
            cached = self.cache.get(handle) if not force else None
            if cached:
                self._scopes[handle] = cached
                age_min = int((datetime.now(timezone.utc) -
                               datetime.fromisoformat(cached.synced_at)).total_seconds() / 60)
                print(f"  [{i:02d}] ✅ {handle:<30} (cached {age_min}m ago)")
            else:
                scope = self.sync_program(handle, force=True)
                if scope:
                    ins  = len(scope.in_scope)
                    outs = len(scope.out_of_scope)
                    bounty = "💰" if scope.offers_bounties else "  "
                    print(f"  [{i:02d}] {bounty} {handle:<30} in={ins} out={outs}")
                time.sleep(0.3)   # polite rate limiting

        print(f"\n  ✅ {len(self._scopes)} programs synced.")
        return self._scopes

    def _fetch_all_handles(self, bounty_only: bool = False) -> List[str]:
        """Paginate through all program handles."""
        handles  = []
        page     = 1
        per_page = 25
        client   = self._client_()

        while len(handles) < MAX_PROGRAMS:
            try:
                data  = client.programs(page=page, per_page=per_page)
                items = data.get("data", [])
                if not items:
                    break
                for item in items:
                    attrs = item.get("attributes", {})
                    if bounty_only and not attrs.get("offers_bounties"):
                        continue
                    handle = item.get("id", "")
                    if handle:
                        handles.append(handle)
                if len(items) < per_page:
                    break
                page += 1
            except Exception:
                break

        return handles

    # ── LOOKUP & HELPERS ──────────────────────────────────────────

    def get(self, handle: str) -> Optional[ProgramScope]:
        """Get a program scope (from memory, cache, or H1 API)."""
        if handle in self._scopes:
            return self._scopes[handle]
        return self.sync_program(handle)

    def scope_rule_for(self, handle: str):
        """Get a Nova Daybreak ScopeRule for a program."""
        scope = self.get(handle)
        if scope:
            return scope.to_scope_rule()
        return None

    def find_by_domain(self, domain: str) -> List[ProgramScope]:
        """Find all programs that include a given domain in scope."""
        matches = []
        for scope in self._scopes.values():
            patterns = [a.to_pattern() for a in scope.in_scope]
            if any(self._domain_matches(domain, p) for p in patterns):
                matches.append(scope)
        return matches

    @staticmethod
    def _domain_matches(domain: str, pattern: str) -> bool:
        d = domain.lower().lstrip("https://").lstrip("http://")
        p = pattern.lower()
        if p.startswith("*."):
            return d.endswith(p[2:]) or d == p[2:]
        return p in d or d in p

    def all_bounty_targets(self) -> List[Tuple[str, str]]:
        """Return (program, target) pairs for all bounty-eligible targets."""
        results = []
        for scope in self._scopes.values():
            if scope.offers_bounties:
                for t in scope.bounty_eligible_targets():
                    results.append((scope.name, t))
        return results

    # ── LOCAL CONFIG FALLBACK ─────────────────────────────────────

    def load_from_local_config(self, path: Path = None) -> Dict[str, ProgramScope]:
        """
        Load scopes from a local JSON config file (fallback when H1 API is
        unavailable or credentials are invalid).

        Config format (~/.nova/scope_config.json):
        {
          "programs": [
            {
              "handle": "my-program",
              "name":   "My Bug Bounty Program",
              "url":    "https://hackerone.com/my-program",
              "state":  "public_mode",
              "offers_bounties": true,
              "in_scope": [
                {"identifier": "*.example.com", "asset_type": "WILDCARD",
                 "eligible_for_bounty": true, "max_severity": "critical"}
              ],
              "out_of_scope": [
                {"identifier": "blog.example.com", "asset_type": "URL",
                 "eligible_for_bounty": false, "max_severity": "none"}
              ]
            }
          ]
        }
        """
        cfg_path = path or LOCAL_CONFIG_PATH
        if not cfg_path.exists():
            return {}

        try:
            data = json.loads(cfg_path.read_text())
            programs = data.get("programs", [])
            loaded = 0
            for p in programs:
                in_scope  = [Asset(**a) for a in p.get("in_scope",  [])]
                out_scope = [Asset(**a) for a in p.get("out_of_scope", [])]
                scope = ProgramScope(
                    handle=p.get("handle", ""),
                    name=p.get("name", p.get("handle", "")),
                    url=p.get("url", ""),
                    state=p.get("state", "public_mode"),
                    in_scope=in_scope,
                    out_of_scope=out_scope,
                    offers_bounties=p.get("offers_bounties", False),
                )
                if scope.handle:
                    self._scopes[scope.handle] = scope
                    loaded += 1
            if loaded:
                print(f"  📁 Loaded {loaded} program(s) from local config: {cfg_path}")
            return self._scopes
        except Exception as e:
            print(f"  ⚠️  Could not load local config: {e}")
            return {}

    @classmethod
    def create_local_config_template(cls, path: Path = None):
        """
        Write a starter scope_config.json template the user can fill in.
        Run once, then edit the file to add your programs and targets.
        """
        cfg_path = path or LOCAL_CONFIG_PATH
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        if cfg_path.exists():
            print(f"  ℹ️  Config already exists at {cfg_path} — not overwriting.")
            return

        template = {
            "_comment": (
                "Nova Scope Manager — local fallback config. "
                "Add your H1 programs here for offline / no-API-key use. "
                "asset_type: URL | WILDCARD | CIDR | ANDROID | IOS | OTHER"
            ),
            "programs": [
                {
                    "handle": "your-program-handle",
                    "name":   "Your Program Name",
                    "url":    "https://hackerone.com/your-program-handle",
                    "state":  "public_mode",
                    "offers_bounties": True,
                    "in_scope": [
                        {
                            "identifier":             "*.example.com",
                            "asset_type":             "WILDCARD",
                            "eligible_for_bounty":    True,
                            "eligible_for_submission": True,
                            "max_severity":           "critical",
                            "instruction":            ""
                        }
                    ],
                    "out_of_scope": [
                        {
                            "identifier":             "blog.example.com",
                            "asset_type":             "URL",
                            "eligible_for_bounty":    False,
                            "eligible_for_submission": False,
                            "max_severity":           "none",
                            "instruction":            "No testing"
                        }
                    ]
                }
            ]
        }
        cfg_path.write_text(json.dumps(template, indent=2))
        print(f"  ✅ Template written to: {cfg_path}")
        print(f"     Edit it to add your real programs, then run:")
        print(f"     python3 nova_scope_manager.py sync")

    # ── EXPORT ────────────────────────────────────────────────────

    def export_markdown(self, path: str = "nova_scope_report.md"):
        """Export all synced scopes as a Markdown reference."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            "# 🛡️ Nova Scope Manager — Active HackerOne Scopes",
            "",
            f"**Synced:** {now}  ",
            f"**Programs:** {len(self._scopes)}  ",
            f"**Bounty programs:** {sum(1 for s in self._scopes.values() if s.offers_bounties)}  ",
            "",
            "---",
            "",
        ]
        for scope in sorted(self._scopes.values(), key=lambda s: s.name):
            bounty = " 💰" if scope.offers_bounties else ""
            lines += [
                f"## {scope.name}{bounty}",
                f"**Handle:** `{scope.handle}` | **State:** {scope.state}  ",
                f"**URL:** {scope.url}  ",
                "",
                "### ✅ In Scope",
                "",
            ]
            if scope.in_scope:
                for a in scope.in_scope:
                    bounty_tag = " *(bounty eligible)*" if a.eligible_for_bounty else ""
                    lines.append(f"- `{a.identifier}` [{a.asset_type}]{bounty_tag}")
            else:
                lines.append("_No structured scope defined_")

            if scope.out_of_scope:
                lines += ["", "### ❌ Out of Scope", ""]
                for a in scope.out_of_scope:
                    lines.append(f"- `{a.identifier}` [{a.asset_type}]")

            lines += ["", "---", ""]

        Path(path).write_text("\n".join(lines))
        print(f"  📝 Scope report → {path}")

    def export_json(self, path: str = "nova_scopes.json"):
        """Export all synced scopes as JSON."""
        data = {handle: asdict(scope) for handle, scope in self._scopes.items()}
        Path(path).write_text(json.dumps(data, indent=2))
        print(f"  📦 Scope JSON → {path}")

    def print_summary(self):
        """Print a quick scope summary table."""
        if not self._scopes:
            print("  No scopes synced yet. Run sync_all() first.")
            return
        print(f"\n{'='*65}")
        print(f"{'Program':<30} {'In':<5} {'Out':<5} {'Bounty'}")
        print(f"{'='*65}")
        for s in sorted(self._scopes.values(), key=lambda x: x.name):
            bounty = "💰 Yes" if s.offers_bounties else "  No"
            print(f"  {s.name:<28} {len(s.in_scope):<5} {len(s.out_of_scope):<5} {bounty}")
        print(f"{'='*65}")
        total_in = sum(len(s.in_scope) for s in self._scopes.values())
        print(f"  Total assets in scope: {total_in}")


# ── INTEGRATION HELPERS ───────────────────────────────────────────────────────

def load_scope_for_target(target: str,
                           h1_username: str = None,
                           h1_token:    str = None):
    """
    Convenience function: given a target URL, find the matching H1
    program and return its ScopeRule ready for Nova Daybreak.

    Example:
        from nova_scope_manager import load_scope_for_target
        from nova_daybreak import NovaDaybreak

        scope = load_scope_for_target("https://konghq.com")
        nova  = NovaDaybreak(target="https://konghq.com", scope=scope)
        nova.run(raw_findings=my_findings)
    """
    mgr = NovaScopeManager(username=h1_username, api_token=h1_token)
    mgr.sync_all(bounty_only=False)

    domain = re.sub(r'^https?://', '', target).split('/')[0]
    matches = mgr.find_by_domain(domain)

    if not matches:
        print(f"  ⚠️  No H1 program found for {domain}. Using permissive scope.")
        try:
            from nova_daybreak import ScopeRule
        except ImportError:
            class ScopeRule:
                def __init__(self, **kw): [setattr(self,k,v) for k,v in kw.items()]
        return ScopeRule(
            program=domain, platform="hackerone",
            in_scope=[domain, f"*.{domain}"], out_of_scope=[],
        )

    if len(matches) == 1:
        rule = matches[0].to_scope_rule()
        print(f"  ✅ Scope matched: {matches[0].name}")
        return rule

    # Multiple matches — pick the one with most in-scope assets
    best = max(matches, key=lambda s: len(s.in_scope))
    print(f"  ✅ Best scope match: {best.name} ({len(matches)} programs overlap)")
    return best.to_scope_rule()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="🛡️ Nova Scope Manager — HackerOne live scope sync"
    )
    sub = parser.add_subparsers(dest="cmd")

    # sync
    p_sync = sub.add_parser("sync", help="Sync all program scopes from H1")
    p_sync.add_argument("--force",       action="store_true", help="Bypass cache")
    p_sync.add_argument("--bounty-only", action="store_true", help="Only bounty programs")
    p_sync.add_argument("--export-md",   action="store_true", help="Export Markdown report")
    p_sync.add_argument("--export-json", action="store_true", help="Export JSON")

    # show
    p_show = sub.add_parser("show", help="Show scope for a specific program")
    p_show.add_argument("handle", help="Program handle (e.g. kong-inc)")

    # find
    p_find = sub.add_parser("find", help="Find programs by domain")
    p_find.add_argument("domain", help="Domain to search (e.g. konghq.com)")

    # targets
    p_tgt = sub.add_parser("targets", help="List all bounty-eligible targets")

    # clear
    p_clr = sub.add_parser("clear", help="Clear scope cache")
    p_clr.add_argument("handle", nargs="?", help="Specific handle to clear (omit for all)")

    # verify
    sub.add_parser("verify", help="Verify H1 credentials")

    # init-config
    sub.add_parser("init-config", help="Create ~/.nova/scope_config.json template for offline use")

    args = parser.parse_args()

    mgr = NovaScopeManager()

    if args.cmd == "init-config":
        NovaScopeManager.create_local_config_template()

    elif args.cmd == "verify":
        mgr.verify_credentials()

    elif args.cmd == "sync":
        scopes = mgr.sync_all(force=args.force, bounty_only=args.bounty_only)
        mgr.print_summary()
        if args.export_md:
            mgr.export_markdown()
        if args.export_json:
            mgr.export_json()

    elif args.cmd == "show":
        scope = mgr.get(args.handle)
        if scope:
            print(f"\n  Program: {scope.name}")
            print(f"  URL:     {scope.url}")
            print(f"  Bounty:  {'Yes 💰' if scope.offers_bounties else 'No'}")
            print(f"\n  ✅ In scope ({len(scope.in_scope)}):")
            for a in scope.in_scope:
                bounty = " [bounty]" if a.eligible_for_bounty else ""
                print(f"     {a.identifier:<45} [{a.asset_type}]{bounty}")
            if scope.out_of_scope:
                print(f"\n  ❌ Out of scope ({len(scope.out_of_scope)}):")
                for a in scope.out_of_scope:
                    print(f"     {a.identifier:<45} [{a.asset_type}]")
        else:
            print(f"  ❌ Program not found: {args.handle}")

    elif args.cmd == "find":
        mgr.sync_all()
        matches = mgr.find_by_domain(args.domain)
        if matches:
            print(f"\n  Programs covering {args.domain}:")
            for m in matches:
                print(f"     • {m.name} ({m.handle})")
        else:
            print(f"  ❌ No programs found for {args.domain}")

    elif args.cmd == "targets":
        mgr.sync_all(bounty_only=True)
        targets = mgr.all_bounty_targets()
        if targets:
            print(f"\n  💰 Bounty-eligible targets ({len(targets)}):")
            for program, target in sorted(targets):
                print(f"     [{program}] {target}")
        else:
            print("  No bounty targets found.")

    elif args.cmd == "clear":
        mgr.cache.invalidate(args.handle)

    else:
        parser.print_help()
        print("\nQuick start:")
        print("  export H1_USERNAME='your_handle'")
        print("  export H1_API_TOKEN='your_token'   # https://hackerone.com/settings/api_token/edit")
        print("  python3 nova_scope_manager.py sync --export-md")
        print("  python3 nova_scope_manager.py find konghq.com")
        print("  python3 nova_scope_manager.py targets")
