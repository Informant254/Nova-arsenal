#!/usr/bin/env python3
"""Local repository intelligence for Nova agent runs.

Builds a lightweight symbol and test index without external APIs so local Ollama
models can navigate codebases with less guessing.
"""

import ast
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".yarn", "dist", "build", "coverage",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".angular", ".next", "tmp", "temp",
}
CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go",
    ".rs", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp",
}
TEST_MARKERS = ("test", "spec", "__tests__", "cypress", "e2e")
MAX_FILE_BYTES = 512_000


def _repo_root(path: str = ".") -> Path:
    """Return the git root for path, or the resolved path when not in git."""
    base = Path(path).expanduser().resolve()
    try:
        result = subprocess.run(
            ["git", "-C", str(base), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip()).resolve()
    except Exception:
        pass
    return base


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _iter_code_files(root: Path, max_files: int) -> List[Path]:
    files: List[Path] = []
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORE_DIRS and not d.startswith(".")]
        for name in filenames:
            path = Path(current_root) / name
            if path.suffix.lower() not in CODE_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(path)
            if len(files) >= max_files:
                return files
    return files


def _detect_stack(root: Path) -> Dict[str, Any]:
    manifests = {
        "package.json": "node",
        "pyproject.toml": "python",
        "requirements.txt": "python",
        "go.mod": "go",
        "Cargo.toml": "rust",
        "pom.xml": "java",
        "build.gradle": "java",
    }
    detected = []
    for manifest, stack in manifests.items():
        if (root / manifest).exists():
            detected.append({"stack": stack, "manifest": manifest})
    commands = []
    package_json = root / "package.json"
    if package_json.exists():
        try:
            scripts = json.loads(package_json.read_text(encoding="utf-8")).get("scripts", {})
            for name in ("lint", "test", "test:server", "test:api", "test:frontend", "build", "build:server"):
                if name in scripts:
                    commands.append(f"npm run {name}")
        except Exception:
            pass
    if (root / "pyproject.toml").exists() or (root / "pytest.ini").exists():
        commands.append("python -m pytest")
    if (root / "go.mod").exists():
        commands.append("go test ./...")
    if (root / "Cargo.toml").exists():
        commands.append("cargo test")
    return {"detected": detected, "suggested_commands": commands}


def _python_symbols(path: Path) -> List[Dict[str, Any]]:
    symbols: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return symbols
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.append({
                "name": node.name,
                "kind": "class" if isinstance(node, ast.ClassDef) else "function",
                "line": node.lineno,
            })
    return symbols[:80]


def _regex_symbols(path: Path) -> List[Dict[str, Any]]:
    symbols: List[Dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return symbols
    patterns = [
        ("class", re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")),
        ("function", re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)")),
        ("function", re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(")),
        ("function", re.compile(r"\b([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*{")),
    ]
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        for kind, pattern in patterns:
            match = pattern.search(line)
            if match:
                symbols.append({"name": match.group(1), "kind": kind, "line": line_no})
                break
        if len(symbols) >= 80:
            break
    return symbols


def _imports(path: Path) -> List[str]:
    imports: List[str] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[:200]
    except Exception:
        return imports
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("import ", "from ", "const ", "require(")) or " require(" in stripped:
            imports.append(stripped[:200])
        if len(imports) >= 30:
            break
    return imports


def build_repo_index(root: str = ".", max_files: int = 800) -> Dict[str, Any]:
    """Build a compact local code index with symbols, tests, manifests, and commands."""
    started = time.time()
    repo = _repo_root(root)
    files = _iter_code_files(repo, max_files=max_files)
    indexed_files = []
    test_files = []
    for path in files:
        rel = _relative(path, repo)
        lower = rel.lower()
        symbols = _python_symbols(path) if path.suffix == ".py" else _regex_symbols(path)
        entry = {
            "path": rel,
            "extension": path.suffix.lower(),
            "size": path.stat().st_size,
            "symbols": symbols,
            "imports": _imports(path),
        }
        indexed_files.append(entry)
        if any(marker in lower for marker in TEST_MARKERS):
            test_files.append(rel)
    index = {
        "root": str(repo),
        "generated_at": int(time.time()),
        "file_count": len(indexed_files),
        "truncated": len(indexed_files) >= max_files,
        "stack": _detect_stack(repo),
        "files": indexed_files,
        "test_files": test_files[:300],
        "duration_s": round(time.time() - started, 2),
    }
    return index


def save_repo_index(root: str = ".", output: str = None, max_files: int = 800) -> Dict[str, Any]:
    """Build and save the repo index to a JSON cache file."""
    index = build_repo_index(root=root, max_files=max_files)
    repo = Path(index["root"])
    output_path = Path(output).expanduser() if output else repo / ".nova_repo_index.json"
    output_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    index["index_file"] = str(output_path)
    return index


def query_repo_index(query: str, root: str = ".", index_file: str = None, limit: int = 20) -> Dict[str, Any]:
    """Search the cached index by path, symbol, or import text."""
    repo = _repo_root(root)
    path = Path(index_file).expanduser() if index_file else repo / ".nova_repo_index.json"
    if not path.exists():
        save_repo_index(root=str(repo), output=str(path))
    index = json.loads(path.read_text(encoding="utf-8"))
    terms = [term.lower() for term in re.findall(r"[\w.$/@:-]+", query) if term]
    matches = []
    for entry in index.get("files", []):
        haystack_parts = [entry.get("path", "")]
        haystack_parts.extend(symbol.get("name", "") for symbol in entry.get("symbols", []))
        haystack_parts.extend(entry.get("imports", []))
        haystack = "\n".join(haystack_parts).lower()
        score = sum(1 for term in terms if term in haystack)
        if score:
            matches.append({
                "score": score,
                "path": entry.get("path"),
                "symbols": entry.get("symbols", [])[:20],
                "imports": entry.get("imports", [])[:8],
            })
    matches.sort(key=lambda item: (-item["score"], item["path"] or ""))
    return {"success": True, "query": query, "index_file": str(path), "matches": matches[:limit], "count": len(matches)}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build/query Nova's local repo intelligence index")
    parser.add_argument("--root", default=".")
    parser.add_argument("--query", default="")
    parser.add_argument("--max-files", type=int, default=800)
    args = parser.parse_args()
    if args.query:
        print(json.dumps(query_repo_index(args.query, root=args.root), indent=2))
    else:
        print(json.dumps(save_repo_index(root=args.root, max_files=args.max_files), indent=2))
