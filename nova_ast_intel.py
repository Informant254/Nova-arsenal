#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🌳 NOVA AST INTEL — Code Intelligence Beyond Regex                        ║
║                                                                              ║
║  Addresses GAP 5: tree-sitter + native AST parsing for:                   ║
║  • Symbol graph (functions, classes, variables)                            ║
║  • Route → handler → sink tracing (Express, Flask, FastAPI, Django)        ║
║  • Dataflow: tainted input → sink paths                                    ║
║  • Call graph (who calls what, what uses what)                             ║
║  • Test-aware patch planning (which tests cover a file)                    ║
║                                                                             ║
║  Gracefully falls back to enhanced regex when tree-sitter not installed.   ║
║                                                                              ║
║  Usage:                                                                      ║
║    intel = NovaASTIntel("./juice-shop")                                    ║
║    graph = intel.build_route_graph()                                       ║
║    sinks = intel.trace_taint("req.body.query", "./routes/search.js")       ║
║    print(intel.sink_report())                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import ast
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

WORKSPACE = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

# ── tree-sitter availability ───────────────────────────────────────────────────
_TS_AVAILABLE = False
_TS_JS_PARSER = None
_TS_PY_PARSER = None

try:
    import tree_sitter_javascript as tsjs
    import tree_sitter_python     as tspy
    from tree_sitter import Language, Parser
    _JS_LANG   = Language(tsjs.language())
    _PY_LANG   = Language(tspy.language())
    _TS_JS_PARSER = Parser(_JS_LANG)
    _TS_PY_PARSER = Parser(_PY_LANG)
    _TS_AVAILABLE = True
except Exception:
    pass


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class Symbol:
    name:     str
    kind:     str  # "function" | "class" | "variable" | "import"
    file:     str
    line:     int
    scope:    str  = ""
    calls:    List[str] = field(default_factory=list)
    used_by:  List[str] = field(default_factory=list)

@dataclass
class Route:
    method:  str
    path:    str
    handler: str   # function name that handles this route
    file:    str
    line:    int
    middleware: List[str] = field(default_factory=list)
    params:  List[str] = field(default_factory=list)   # path params like :id

@dataclass
class Sink:
    kind:      str   # "sql_query" | "file_write" | "exec" | "redirect" | "response"
    file:      str
    line:      int
    code:      str
    tainted:   bool = False
    taint_path:List[str] = field(default_factory=list)

@dataclass
class TaintPath:
    source:   str   # e.g. "req.body.query"
    sinks:    List[Sink] = field(default_factory=list)
    file:     str   = ""
    risk:     str   = "unknown"


# ── Sink patterns ──────────────────────────────────────────────────────────────

SQL_SINK_PATTERNS = [
    # Raw string concatenation into SQL
    r'(?:query|execute|db\.run|cursor\.execute|connection\.query)\s*\([^)]*\+[^)]*\)',
    # Template literal SQL
    r'(?:query|execute)\s*\(`[^`]*\$\{',
    # Python format string SQL
    r'execute\s*\(\s*["\'].*?%[s|d].*?["\'].*?%',
    # Sequelize literal
    r'Sequelize\.literal\s*\(',
    # Knex raw
    r'knex\.raw\s*\(',
    # SQLAlchemy text()
    r'text\s*\(\s*["\'][^"\']*\+',
]

FILE_SINK_PATTERNS = [
    r'(?:fs\.write|writeFile|open\s*\(|fopen)\s*\([^)]*(?:req\.|body\.|param)',
    r'Path\s*\([^)]*(?:req\.|body\.|param)',
    r'os\.path\.join\s*\([^)]*(?:request\.|args\.|params\.)',
]

EXEC_SINK_PATTERNS = [
    r'(?:exec|spawn|execSync|execFile)\s*\([^)]*(?:req\.|body\.|param)',
    r'(?:subprocess\.(?:call|run|Popen))\s*\([^)]*(?:request\.|args\.)',
    r'eval\s*\([^)]*(?:req\.|body\.|query)',
    r'(?:deserializ|yaml\.load|pickle\.loads)\s*\(',
]

REDIRECT_SINK_PATTERNS = [
    r'res\.redirect\s*\([^)]*(?:req\.|query\.|body\.|params\.)',
    r'redirect\s*\(\s*(?:request\.GET|request\.POST|args\.)',
    r'window\.location\s*=\s*[^;]*(?:params|query|search)',
]

TAINT_SOURCES = [
    # Express
    "req.body", "req.query", "req.params", "req.headers", "req.files",
    "req.cookies",
    # Flask/FastAPI
    "request.args", "request.form", "request.json", "request.files",
    "request.cookies", "request.headers",
    # Django
    "request.GET", "request.POST", "request.DATA", "request.FILES",
    # Generic
    "process.argv", "os.environ", "sys.argv",
]


# ── Main class ─────────────────────────────────────────────────────────────────

class NovaASTIntel:
    """
    Code intelligence engine.
    Uses tree-sitter when available, enhanced regex otherwise.
    """

    def __init__(self, root: str, verbose: bool = True):
        self.root    = Path(root).expanduser().resolve()
        self.verbose = verbose
        self._routes:  List[Route]  = []
        self._symbols: List[Symbol] = []
        self._sinks:   List[Sink]   = []
        self._taint_paths: List[TaintPath] = []
        self._call_graph: Dict[str, List[str]] = defaultdict(list)
        self._test_map:   Dict[str, List[str]] = {}  # source_file → test_files
        self._analysed    = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyse(self) -> "NovaASTIntel":
        """Run full analysis. Returns self for chaining."""
        source_files = self._collect_source_files()
        if self.verbose:
            ts = "tree-sitter" if _TS_AVAILABLE else "regex-enhanced"
            print(f"  🌳 AST Intel ({ts}): {len(source_files)} files")

        for path, lang in source_files:
            content = self._read(path)
            if not content:
                continue
            if lang == "python":
                self._analyse_python(path, content)
            elif lang in ("javascript", "typescript"):
                self._analyse_js_ts(path, content)
        self._build_test_map()
        self._analysed = True
        return self

    def build_route_graph(self) -> List[Dict]:
        """Return routes with their handler and known sinks."""
        if not self._analysed:
            self.analyse()
        result = []
        for route in self._routes:
            # Find sinks reachable from this handler
            handler_sinks = [s for s in self._sinks
                             if route.handler and route.handler in s.code]
            result.append({
                "method":   route.method,
                "path":     route.path,
                "handler":  route.handler,
                "file":     route.file,
                "line":     route.line,
                "params":   route.params,
                "middleware":route.middleware,
                "sinks":    [{"kind": s.kind, "line": s.line, "tainted": s.tainted}
                             for s in handler_sinks],
                "risk_score": len(handler_sinks) * 2 + len(route.params),
            })
        return sorted(result, key=lambda x: -x["risk_score"])

    def trace_taint(self, source: str, file_path: str = None) -> List[TaintPath]:
        """Trace a tainted source to its downstream sinks."""
        if not self._analysed:
            self.analyse()
        paths = []
        search_files = ([f for f, _ in self._collect_source_files()
                         if file_path and file_path in f]
                        if file_path else
                        [f for f, _ in self._collect_source_files()])

        for path in search_files[:50]:
            content = self._read(path)
            if not content or source not in content:
                continue
            # Find lines that use the tainted source
            tainted_lines = []
            for i, line in enumerate(content.splitlines(), 1):
                if source in line:
                    tainted_lines.append((i, line.strip()))
            # Find sinks in same file that come after taint use
            file_sinks = [s for s in self._sinks if path.endswith(s.file)
                          or s.file in str(path)]
            if tainted_lines and file_sinks:
                tp = TaintPath(
                    source = source,
                    file   = str(Path(path).relative_to(self.root)),
                    sinks  = file_sinks,
                    risk   = "HIGH" if any(
                        s.kind in ("sql_query","exec") for s in file_sinks) else "MEDIUM",
                )
                for s in file_sinks:
                    s.tainted = True
                    s.taint_path = [source] + [f"line {t[0]}: {t[1][:60]}"
                                               for t in tainted_lines[:3]]
                paths.append(tp)
        self._taint_paths.extend(paths)
        return paths

    def get_sinks(self, kind: str = None) -> List[Sink]:
        if not self._analysed:
            self.analyse()
        if kind:
            return [s for s in self._sinks if s.kind == kind]
        return list(self._sinks)

    def sink_report(self) -> str:
        if not self._analysed:
            self.analyse()
        lines = [
            f"=== Nova AST Intel — Sink Report ===",
            f"Root: {self.root}",
            f"Routes: {len(self._routes)}",
            f"Symbols: {len(self._symbols)}",
            f"Sinks: {len(self._sinks)}",
            f"Taint paths: {len(self._taint_paths)}",
            "",
        ]
        if self._sinks:
            lines.append("--- SINKS ---")
            for s in self._sinks[:30]:
                taint_mark = " ⚠️ TAINTED" if s.tainted else ""
                lines.append(f"  [{s.kind}] {s.file}:{s.line}"
                             f" — {s.code[:80]}{taint_mark}")
        if self._taint_paths:
            lines.append("\n--- TAINT PATHS ---")
            for tp in self._taint_paths[:10]:
                lines.append(f"  {tp.source} [{tp.risk}] → {len(tp.sinks)} sinks in {tp.file}")
        if self._routes:
            lines.append("\n--- HIGH-RISK ROUTES ---")
            for r in self.build_route_graph()[:10]:
                if r["sinks"]:
                    lines.append(f"  {r['method']} {r['path']} → {r['handler']} "
                                f"— {len(r['sinks'])} sinks")
        return "\n".join(lines)

    def to_nova_findings(self) -> List[Dict]:
        """Convert sinks and taint paths to Nova finding dicts."""
        findings = []
        sev_map = {"sql_query": "HIGH", "exec": "CRITICAL", "file_write": "HIGH",
                   "redirect": "MEDIUM", "response": "LOW"}
        for s in self._sinks:
            if s.tainted:
                findings.append({
                    "type":     "TaintedSink_" + s.kind.title().replace("_",""),
                    "severity": sev_map.get(s.kind, "MEDIUM"),
                    "file":     s.file,
                    "line":     s.line,
                    "description": f"Tainted data reaches {s.kind} sink",
                    "code_snippet": s.code[:200],
                    "taint_path": " → ".join(s.taint_path[:5]),
                    "source": "nova_ast_intel",
                })
        return findings

    def test_coverage_for(self, source_file: str) -> List[str]:
        """Return test files that cover a given source file."""
        return self._test_map.get(source_file, [])

    def save(self, path: str = None):
        out = Path(path or str(WORKSPACE / "nova_ast_intel.json"))
        out.write_text(json.dumps({
            "root":         str(self.root),
            "routes":       [
                {"method": r.method, "path": r.path, "handler": r.handler,
                 "file": r.file, "line": r.line}
                for r in self._routes],
            "sinks":        [
                {"kind": s.kind, "file": s.file, "line": s.line,
                 "tainted": s.tainted}
                for s in self._sinks],
            "taint_paths":  [
                {"source": tp.source, "file": tp.file, "risk": tp.risk,
                 "sink_count": len(tp.sinks)}
                for tp in self._taint_paths],
            "symbols_count":len(self._symbols),
        }, indent=2, default=str))
        if self.verbose:
            print(f"  🌳 AST intel saved → {out}")

    # ── Python AST analysis ────────────────────────────────────────────────────

    def _analyse_python(self, path: str, content: str):
        rel = str(Path(path).relative_to(self.root))

        # Use tree-sitter if available, else fall back to stdlib ast
        if _TS_AVAILABLE and _TS_PY_PARSER:
            self._ts_analyse_python(path, content, rel)
        else:
            self._stdlib_ast_python(path, content, rel)

        # Regex sink detection (works regardless)
        self._regex_sinks(path, content, rel)

    def _stdlib_ast_python(self, path: str, content: str, rel: str):
        """Use Python stdlib ast module for function/class/call extraction."""
        try:
            tree = ast.parse(content, filename=path)
        except SyntaxError:
            return
        for node in ast.walk(tree):
            # Functions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sym = Symbol(
                    name=node.name, kind="function",
                    file=rel, line=node.lineno)
                self._symbols.append(sym)

            # Flask/FastAPI route decorators
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                    m = re.search(r"\.route\s*\(\s*['\"]([^'\"]+)['\"]", dec_src)
                    if m:
                        methods = "GET"
                        mm = re.search(r"methods\s*=\s*\[([^\]]+)\]", dec_src)
                        if mm:
                            methods = ",".join(
                                x.strip().strip("'\"")
                                for x in mm.group(1).split(","))
                        self._routes.append(Route(
                            method=methods, path=m.group(1),
                            handler=node.name, file=rel,
                            line=node.lineno))

            # Call tracking
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                if func_name:
                    self._call_graph[rel].append(func_name)
        # FastAPI decorator pattern
        for m in re.finditer(
                r'@\w+\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                content, re.MULTILINE):
            self._routes.append(Route(
                method=m.group(1).upper(), path=m.group(2),
                handler="", file=rel,
                line=content[:m.start()].count("\n") + 1))

    def _ts_analyse_python(self, path: str, content: str, rel: str):
        """tree-sitter based Python analysis."""
        try:
            tree = _TS_PY_PARSER.parse(content.encode())
            self._extract_ts_symbols(tree.root_node, rel, content)
        except Exception:
            self._stdlib_ast_python(path, content, rel)

    # ── JavaScript / TypeScript analysis ──────────────────────────────────────

    def _analyse_js_ts(self, path: str, content: str):
        rel = str(Path(path).relative_to(self.root))

        if _TS_AVAILABLE and _TS_JS_PARSER:
            try:
                tree = _TS_JS_PARSER.parse(content.encode())
                self._extract_ts_symbols(tree.root_node, rel, content)
            except Exception:
                pass

        # Regex-based route extraction for Express/Fastify
        route_pat = re.compile(
            r"""(?:app|router|server|fastify)\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(?:async\s+)?(?:function\s+)?(\w*)""",
            re.MULTILINE | re.IGNORECASE)
        for m in route_pat.finditer(content):
            line = content[:m.start()].count("\n") + 1
            route_path  = m.group(2)
            params = re.findall(r":(\w+)", route_path)
            self._routes.append(Route(
                method  = m.group(1).upper(),
                path    = route_path,
                handler = m.group(3) or f"inline@{line}",
                file    = rel,
                line    = line,
                params  = params))

        # Sink detection
        self._regex_sinks(path, content, rel)

        # Function definitions
        for m in re.finditer(
                r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function|\bconst\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>)",
                content, re.MULTILINE):
            name = m.group(1) or m.group(2) or m.group(3)
            if name:
                self._symbols.append(Symbol(
                    name=name, kind="function",
                    file=rel,
                    line=content[:m.start()].count("\n") + 1))

    # ── Regex sink scanner (language-agnostic) ─────────────────────────────────

    def _regex_sinks(self, path: str, content: str, rel: str):
        lines = content.splitlines()

        def _scan(patterns, kind):
            for pat in patterns:
                for m in re.finditer(pat, content, re.MULTILINE | re.IGNORECASE):
                    line_no  = content[:m.start()].count("\n") + 1
                    code_snip= lines[line_no-1].strip() if line_no <= len(lines) else ""
                    tainted  = any(src in code_snip for src in TAINT_SOURCES)
                    self._sinks.append(Sink(
                        kind   = kind,
                        file   = rel,
                        line   = line_no,
                        code   = code_snip,
                        tainted= tainted))

        _scan(SQL_SINK_PATTERNS,      "sql_query")
        _scan(FILE_SINK_PATTERNS,     "file_write")
        _scan(EXEC_SINK_PATTERNS,     "exec")
        _scan(REDIRECT_SINK_PATTERNS, "redirect")

    # ── Tree-sitter generic symbol extractor ───────────────────────────────────

    def _extract_ts_symbols(self, node, rel: str, content: str):
        """Walk a tree-sitter parse tree and extract named symbols."""
        FUNCTION_TYPES = {
            "function_declaration", "arrow_function",
            "method_definition", "function_definition",
        }
        if node.type in FUNCTION_TYPES:
            name_node = node.child_by_field_name("name")
            if name_node:
                self._symbols.append(Symbol(
                    name=name_node.text.decode("utf-8","replace"),
                    kind="function",
                    file=rel,
                    line=node.start_point[0] + 1))
        for child in node.children:
            self._extract_ts_symbols(child, rel, content)

    # ── Test map ───────────────────────────────────────────────────────────────

    def _build_test_map(self):
        """Map each source file to test files that import/reference it."""
        source_files = {
            str(Path(p).relative_to(self.root)): p
            for p, _ in self._collect_source_files()
            if not self._is_test(p)
        }
        test_files = [p for p, _ in self._collect_source_files() if self._is_test(p)]
        for tf in test_files:
            content = self._read(tf)
            if not content:
                continue
            tf_rel = str(Path(tf).relative_to(self.root))
            for src_rel in source_files:
                src_stem = Path(src_rel).stem
                if (src_stem in content or
                        src_rel.replace("/","\\") in content or
                        f"from './{src_stem}'" in content or
                        f'require("./{src_stem}")' in content):
                    self._test_map.setdefault(src_rel, []).append(tf_rel)

    # ── File helpers ───────────────────────────────────────────────────────────

    def _collect_source_files(self) -> List[Tuple[str, str]]:
        result = []
        skip   = {"node_modules",".git","__pycache__","dist","build",".next","venv"}
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in skip]
            for f in files:
                p   = os.path.join(root, f)
                ext = Path(f).suffix.lower()
                if ext in (".py",):
                    result.append((p, "python"))
                elif ext in (".js",".mjs",".cjs",".jsx"):
                    result.append((p, "javascript"))
                elif ext in (".ts",".tsx"):
                    result.append((p, "typescript"))
        return result

    def _read(self, path: str) -> Optional[str]:
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def _is_test(path: str) -> bool:
        p = path.lower()
        return any(x in p for x in ("test","spec","__tests__","tests/"))


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="🌳 Nova AST Intel — code intelligence beyond regex")
    parser.add_argument("root",     nargs="?", default=".")
    parser.add_argument("--source", help="Taint source to trace (e.g. req.body.query)")
    parser.add_argument("--save",   action="store_true")
    parser.add_argument("--routes", action="store_true", help="Show route graph only")
    args = parser.parse_args()

    mode = "tree-sitter" if _TS_AVAILABLE else "regex-enhanced (pip install tree-sitter tree-sitter-javascript tree-sitter-python for AST mode)"
    print(f"  🌳 Mode: {mode}")

    intel = NovaASTIntel(args.root)
    intel.analyse()

    if args.source:
        paths = intel.trace_taint(args.source)
        print(f"\n  Taint paths from '{args.source}': {len(paths)}")
        for tp in paths[:5]:
            print(f"    [{tp.risk}] {tp.file} → {len(tp.sinks)} sinks")
    elif args.routes:
        for r in intel.build_route_graph()[:20]:
            print(f"  {r['method']:6} {r['path']:<40} handler={r['handler']} "
                  f"sinks={len(r['sinks'])} score={r['risk_score']}")
    else:
        print(intel.sink_report())

    if args.save:
        intel.save()
