#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🗺  NOVA CODEBASE MAPPER — Hyper-Fast Strategic Codebase Intelligence     ║
║                                                                              ║
║  Reads an entire codebase in parallel (64–128 threads), builds a full       ║
║  strategic attack-surface map, and feeds it into every Nova module.         ║
║                                                                              ║
║  Capabilities:                                                               ║
║  • 10 000 files < 2 s │ 100 000 files < 15 s  (parallel I/O + sampling)    ║
║  • 30+ language detection (extension + shebang + content signatures)        ║
║  • 25+ framework detection (manifest + import patterns)                     ║
║  • Endpoint/route extraction (Express · Flask · Django · FastAPI · Spring   ║
║    · Rails · Gin · Echo · Laravel · Phoenix · Next.js · Nuxt)               ║
║  • Auth pattern detection (JWT · OAuth · SAML · LDAP · API keys · sessions) ║
║  • Database / ORM detection                                                 ║
║  • Dependency + risky-version mapping                                       ║
║  • Quick secret regex scan (API keys · tokens · passwords)                 ║
║  • AI-powered attack-surface prioritisation via nova_llm_router             ║
║  • Full JSON + Markdown output                                              ║
║                                                                              ║
║  Usage:                                                                      ║
║    from nova_codebase_mapper import NovaCodebaseMapper                      ║
║    cmap = NovaCodebaseMapper("./juice-shop").scan()                         ║
║    print(cmap.summary())                                                    ║
║    print(cmap.attack_brief())    # paste into any agent's system prompt     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import os
import re
import sys
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Constants ──────────────────────────────────────────────────────────────────
MAX_FILE_SIZE    = 2 * 1024 * 1024   # 2 MB — skip massive binaries
SAMPLE_BYTES     = 8 * 1024          # first 8 KB for detection
MAX_WORKERS      = min(128, (os.cpu_count() or 4) * 16)
WORKSPACE        = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))
WORKSPACE.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# LANGUAGE SIGNATURES
# ─────────────────────────────────────────────────────────────────────────────

EXTENSION_LANG: Dict[str, str] = {
    # Web
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".jsx": "JavaScript",
    ".html": "HTML", ".htm": "HTML", ".hbs": "Handlebars",
    ".ejs": "EJS", ".pug": "Pug", ".vue": "Vue",
    ".css": "CSS", ".scss": "SCSS", ".sass": "SASS", ".less": "LESS",
    # Python
    ".py": "Python", ".pyw": "Python", ".pyx": "Python",
    # Ruby
    ".rb": "Ruby", ".rake": "Ruby", ".gemspec": "Ruby",
    # Java / JVM
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
    ".scala": "Scala", ".groovy": "Groovy",
    # .NET
    ".cs": "C#", ".vb": "VB.NET", ".fs": "F#",
    # Go
    ".go": "Go",
    # Rust
    ".rs": "Rust",
    # C / C++
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++",
    ".cxx": "C++", ".hpp": "C++", ".hxx": "C++",
    # PHP
    ".php": "PHP", ".phtml": "PHP",
    # Swift
    ".swift": "Swift",
    # Dart
    ".dart": "Dart",
    # Elixir / Erlang
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang",
    # Haskell
    ".hs": "Haskell", ".lhs": "Haskell",
    # Clojure
    ".clj": "Clojure", ".cljs": "ClojureScript",
    # Shell
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".fish": "Shell", ".ps1": "PowerShell",
    # Data / Config
    ".json": "JSON", ".yaml": "YAML", ".yml": "YAML",
    ".toml": "TOML", ".xml": "XML", ".ini": "INI",
    ".env": "EnvFile", ".conf": "Config",
    # Infra
    ".tf": "Terraform", ".hcl": "HCL",
    ".dockerfile": "Dockerfile",
    # Database
    ".sql": "SQL",
    # Solidity
    ".sol": "Solidity",
    # GraphQL
    ".graphql": "GraphQL", ".gql": "GraphQL",
    # Markdown / Docs
    ".md": "Markdown", ".rst": "RST", ".txt": "Text",
}

SHEBANG_LANG: Dict[str, str] = {
    "python":  "Python",  "python3": "Python",
    "ruby":    "Ruby",    "ruby3":   "Ruby",
    "node":    "JavaScript",
    "bash":    "Shell",   "sh":      "Shell",
    "perl":    "Perl",    "php":     "PHP",
}

BINARY_SIGNATURES = {
    b"\x7fELF", b"MZ", b"\x89PNG", b"\xff\xd8\xff",
    b"GIF8",    b"PK\x03\x04", b"\x1f\x8b",
    b"BM",      b"\x00\x00\x01\x00",
}

SKIP_DIRS: Set[str] = {
    "node_modules", ".git", "__pycache__", ".pytest_cache",
    ".mypy_cache", "venv", ".venv", "env", ".env",
    "dist", "build", ".next", ".nuxt", "coverage",
    ".terraform", "vendor", "target", "out", ".idea",
    ".vscode", "*.egg-info", ".tox", "htmlcov",
}

# ─────────────────────────────────────────────────────────────────────────────
# FRAMEWORK DETECTION
# ─────────────────────────────────────────────────────────────────────────────

FRAMEWORK_SIGNATURES: List[Tuple[str, str, str]] = [
    # (framework_name, detection_file_glob, content_pattern)
    ("Express",     "package.json",      r'"express"'),
    ("Fastify",     "package.json",      r'"fastify"'),
    ("NestJS",      "package.json",      r'"@nestjs/core"'),
    ("Next.js",     "package.json",      r'"next"'),
    ("Nuxt",        "package.json",      r'"nuxt"'),
    ("React",       "package.json",      r'"react"'),
    ("Vue",         "package.json",      r'"vue"'),
    ("Angular",     "package.json",      r'"@angular/core"'),
    ("Svelte",      "package.json",      r'"svelte"'),
    ("Koa",         "package.json",      r'"koa"'),
    ("Hapi",        "package.json",      r'"@hapi/hapi"'),
    ("ApolloServer","package.json",      r'"apollo-server"'),
    ("GraphQL-js",  "package.json",      r'"graphql"'),
    ("Sequelize",   "package.json",      r'"sequelize"'),
    ("TypeORM",     "package.json",      r'"typeorm"'),
    ("Mongoose",    "package.json",      r'"mongoose"'),
    ("Prisma",      "package.json",      r'"@prisma/client"'),
    ("Flask",       "requirements.txt",  r"[Ff]lask"),
    ("Django",      "requirements.txt",  r"[Dd]jango"),
    ("FastAPI",     "requirements.txt",  r"[Ff]ast[Aa][Pp][Ii]"),
    ("SQLAlchemy",  "requirements.txt",  r"[Ss][Qq][Ll][Aa]lchemy"),
    ("Celery",      "requirements.txt",  r"[Cc]elery"),
    ("Spring Boot", "pom.xml",           r"spring-boot"),
    ("Spring Boot", "build.gradle",      r"spring-boot"),
    ("Hibernate",   "pom.xml",           r"hibernate"),
    ("Ruby on Rails","Gemfile",          r"rails"),
    ("Sinatra",     "Gemfile",           r"sinatra"),
    ("Laravel",     "composer.json",     r'"laravel/framework"'),
    ("Symfony",     "composer.json",     r'"symfony/framework"'),
    ("Gin",         "go.mod",            r"github.com/gin-gonic/gin"),
    ("Echo",        "go.mod",            r"github.com/labstack/echo"),
    ("Fiber",       "go.mod",            r"github.com/gofiber/fiber"),
    ("GORM",        "go.mod",            r"gorm.io/gorm"),
    ("Actix-web",   "Cargo.toml",        r"actix-web"),
    ("Phoenix",     "mix.exs",           r"phoenix"),
    ("Ecto",        "mix.exs",           r"ecto"),
    ("ASP.NET",     "*.csproj",          r"Microsoft.AspNetCore"),
    ("Entity Framework","*.csproj",      r"EntityFrameworkCore"),
    ("Solidity",    "hardhat.config*",   r"hardhat"),
    ("Truffle",     "truffle-config*",   r"truffle"),
]

# ─────────────────────────────────────────────────────────────────────────────
# ROUTE / ENDPOINT EXTRACTION PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

ROUTE_PATTERNS: List[Tuple[str, str, str]] = [
    # (framework_hint, regex, method_group_or_literal)
    # Express / Koa / Fastify
    ("Express",  r"""(?:app|router|server)\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)""",   "method+route"),
    ("Express",  r"""router\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)""",                       "method+route"),
    ("Fastify",  r"""fastify\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)""",                      "method+route"),
    # Flask
    ("Flask",    r"""@\w+\.route\s*\(\s*['"]([^'"]+)['"],?\s*(?:methods=\[([^\]]+)\])?""",              "route+methods"),
    # Django urls
    ("Django",   r"""(?:path|re_path|url)\s*\(\s*['"]([^'"]+)['"]""",                                   "route"),
    # FastAPI
    ("FastAPI",  r"""@\w+\.(get|post|put|patch|delete|options)\s*\(\s*['"]([^'"]+)['"]""",              "method+route"),
    # Spring
    ("Spring",   r"""@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)""", "route"),
    # Rails
    ("Rails",    r"""(?:get|post|put|patch|delete|resources|resource)\s+['"]([^'"]+)['"]""",            "route"),
    # Laravel
    ("Laravel",  r"""Route::(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]""",                     "method+route"),
    # Gin / Fiber / Echo
    ("Gin",      r"""(?:r|router|engine|group)\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*"([^"]+)""",         "method+route"),
    # Phoenix
    ("Phoenix",  r"""(?:get|post|put|patch|delete|resources)\s+"([^"]+)"""  ,                           "route"),
    # ASP.NET
    ("ASP.NET",  r"""\[(?:Http(?:Get|Post|Put|Delete|Patch)|Route)\s*\(\s*"([^"]+)"\s*\)\]""",         "route"),
    # Next.js API routes (file path is the route)
    ("Next.js",  r"""pages/api/(.+?)\.(?:ts|js|tsx|jsx)""",                                             "filepath_route"),
    # Generic REST-looking patterns
    ("Generic",  r"""['"/]api/v?\d*/([a-z_\-/{}:]+)""",                                                 "route"),
]

# ─────────────────────────────────────────────────────────────────────────────
# AUTH PATTERN DETECTION
# ─────────────────────────────────────────────────────────────────────────────

AUTH_PATTERNS: List[Tuple[str, str]] = [
    ("JWT",          r"(?:jsonwebtoken|jwt\.sign|jwt\.verify|Bearer\s+[A-Za-z0-9\-._~+/]+=*|JWTAuth)"),
    ("OAuth2",       r"(?:oauth2|OAuthHandler|access_token|refresh_token|authorization_code|client_credentials)"),
    ("Session",      r"(?:express-session|req\.session|flask\.session|HttpSession|SESSION_SECRET|session_start)"),
    ("API Key",      r"(?:api[_\-]?key|x-api-key|apikey|Authorization.*ApiKey)"),
    ("Basic Auth",   r"(?:basic\s+auth|btoa|atob.*password|Authorization.*Basic)"),
    ("SAML",         r"(?:saml|SAMLResponse|SAMLRequest|passport-saml)"),
    ("LDAP",         r"(?:ldap|LDAPAuth|ActiveDirectory|ldapjs)"),
    ("Bcrypt",       r"(?:bcrypt|bcryptjs|argon2|scrypt|pbkdf2)"),
    ("CSRF Token",   r"(?:csrf|csrfToken|_csrf|XSRF-TOKEN|csrf_token)"),
    ("2FA/TOTP",     r"(?:totp|speakeasy|authenticator|otplib|two_factor|2fa|otp)"),
    ("Passport.js",  r"(?:passport\.authenticate|passport-local|passport-jwt)"),
    ("Firebase Auth",r"(?:firebase\.auth|FirebaseAuth|signInWithEmailAndPassword)"),
]

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE / ORM PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

DB_PATTERNS: List[Tuple[str, str]] = [
    ("PostgreSQL",   r"(?:pg\.|Pool\(|psycopg2|psql|DATABASE_URL.*postgres|sequelize.*postgres|Postgres)"),
    ("MySQL",        r"(?:mysql|mysql2|PyMySQL|MySQLdb|MYSQL_|mariadb)"),
    ("SQLite",       r"(?:sqlite3|better-sqlite3|sqlite|\.db\b|Database\(':memory:'\))"),
    ("MongoDB",      r"(?:mongoose|MongoClient|mongodb\+srv|pymongo|MONGO_URI)"),
    ("Redis",        r"(?:ioredis|redis\.createClient|Redis\(|aioredis|REDIS_URL|FlushAll)"),
    ("Elasticsearch",r"(?:elasticsearch|ElasticSearch|@elastic/elasticsearch)"),
    ("DynamoDB",     r"(?:DynamoDB|dynamodb|aws-sdk.*DynamoDB)"),
    ("Firebase/Firestore",r"(?:firestore|firebase-admin|initializeApp)"),
    ("Cassandra",    r"(?:cassandra-driver|CassandraCluster)"),
    ("Neo4j",        r"(?:neo4j|Cypher|MATCH \(n\))"),
    ("InfluxDB",     r"(?:influxdb|InfluxDBClient)"),
    ("Prisma",       r"(?:PrismaClient|prisma\.)"),
    ("Sequelize ORM",r"(?:Sequelize|DataTypes\.|Model\.init)"),
    ("TypeORM",      r"(?:getRepository|@Entity|createConnection)"),
    ("SQLAlchemy",   r"(?:SQLAlchemy|db\.session|Column\(|relationship\()"),
    ("Drizzle ORM",  r"(?:drizzle\(|pgTable|sqliteTable|mysqlTable)"),
    ("GORM",         r"(?:gorm\.Open|db\.Find|db\.Create|AutoMigrate)"),
]

# ─────────────────────────────────────────────────────────────────────────────
# SECRET / CREDENTIAL PATTERNS (quick regex, not semgrep)
# ─────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS: List[Tuple[str, str]] = [
    ("AWS Key",          r"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}"),
    ("AWS Secret",       r"aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    ("GitHub Token",     r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}"),
    ("Slack Token",      r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    ("Stripe Secret",    r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),
    ("Stripe Publish",   r"pk_(?:live|test)_[0-9a-zA-Z]{24,}"),
    ("Google API",       r"AIza[0-9A-Za-z\-_]{35}"),
    ("SendGrid",         r"SG\.[A-Za-z0-9\-_.]{22,}\.[A-Za-z0-9\-_.]{43,}"),
    ("Twilio",           r"SK[0-9a-fA-F]{32}"),
    ("JWT Secret",       r"(?:jwt[_\-]?secret|JWT_SECRET|jwtSecret)\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*]{8,}"),
    ("Private Key",      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Hardcoded Pass",   r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]"),
    ("DB Conn String",   r"(?:mongodb|postgres|mysql|redis)://[^@\s]{3,}@[^\s]{3,}"),
    ("Bearer Token",     r"(?:Authorization|token)\s*[=:]\s*['\"]?(?:Bearer\s+)?[A-Za-z0-9\-._~+/]{20,}"),
    ("Heroku API",       r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    ("Anthropic Key",    r"sk-ant-[A-Za-z0-9\-]{20,}"),
    ("OpenAI Key",       r"sk-[A-Za-z0-9]{48,}"),
    ("Telegram Token",   r"[0-9]{8,10}:[A-Za-z0-9\-_]{35}"),
]

# ─────────────────────────────────────────────────────────────────────────────
# HIGH-VALUE ATTACK SURFACE HEURISTICS
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_SURFACE_KEYWORDS: Dict[str, List[str]] = {
    "admin":       ["admin", "administrator", "superuser", "root", "management"],
    "payment":     ["payment", "pay", "charge", "billing", "invoice", "stripe", "checkout", "cart", "order", "price", "amount", "discount", "coupon", "refund"],
    "auth":        ["login", "logout", "register", "signup", "password", "token", "auth", "oauth", "session", "2fa", "verify"],
    "file_upload": ["upload", "file", "attachment", "multer", "busboy", "formdata", "multipart"],
    "user_data":   ["user", "profile", "account", "personal", "pii", "email", "phone"],
    "api_key":     ["apikey", "api_key", "secret", "credential", "key"],
    "debug":       ["debug", "test", "dev", "development", "staging", "trace", "verbose"],
    "internal":    ["internal", "private", "hidden", "undocumented"],
    "webhook":     ["webhook", "callback", "notify", "event"],
    "graphql":     ["graphql", "gql", "introspection"],
    "ssrf_prone":  ["fetch", "axios", "requests.get", "urllib", "curl", "http.get", "proxy", "redirect", "url=", "target="],
    "sqli_prone":  ["query", "execute", "raw", "WHERE", "SELECT", "INSERT", "UPDATE", "format", "interpolat"],
    "idor_prone":  ["id", "userId", "user_id", "accountId", "orderId", "itemId", "doc_id"],
    "race_prone":  ["balance", "withdraw", "transfer", "deduct", "credit", "lock", "mutex"],
    "deserialization":["pickle", "yaml.load", "deserializ", "ObjectInputStream", "JSON.parse", "eval("],
    "crypto":      ["encrypt", "decrypt", "hash", "sign", "verify", "cipher", "aes", "rsa"],
}

# ─────────────────────────────────────────────────────────────────────────────
# RISKY DEPENDENCY VERSIONS (partial — augmented by nova_zero_day_correlator)
# ─────────────────────────────────────────────────────────────────────────────

RISKY_DEPS: Dict[str, Dict] = {
    "jsonwebtoken":   {"safe_from": "9.0.0", "cve": "CVE-2022-23529", "risk": "Algorithm confusion"},
    "lodash":         {"safe_from": "4.17.21","cve": "CVE-2021-23337", "risk": "Prototype pollution"},
    "axios":          {"safe_from": "1.6.0",  "cve": "CVE-2023-45857", "risk": "CSRF via cookie"},
    "express":        {"safe_from": "4.19.2", "cve": "CVE-2024-29041", "risk": "Open redirect"},
    "pyyaml":         {"safe_from": "6.0",    "cve": "CVE-2020-14343", "risk": "RCE via yaml.load"},
    "sqlalchemy":     {"safe_from": "2.0.0",  "cve": "CVE-2019-7164",  "risk": "SQL injection"},
    "flask":          {"safe_from": "2.3.0",  "cve": "CVE-2023-25577", "risk": "DoS"},
    "django":         {"safe_from": "4.2.10", "cve": "CVE-2024-24680", "risk": "DoS"},
    "requests":       {"safe_from": "2.32.0", "cve": "CVE-2024-35195", "risk": "Proxy auth header leak"},
    "pillow":         {"safe_from": "10.2.0", "cve": "CVE-2023-50447", "risk": "Arbitrary code via crafted image"},
    "tar":            {"safe_from": "6.2.1",  "cve": "CVE-2024-28863", "risk": "Path traversal"},
    "semver":         {"safe_from": "7.5.2",  "cve": "CVE-2022-25883", "risk": "ReDoS"},
    "minimatch":      {"safe_from": "3.0.5",  "cve": "CVE-2022-3517",  "risk": "ReDoS"},
    "tough-cookie":   {"safe_from": "4.1.3",  "cve": "CVE-2023-26136", "risk": "Prototype pollution"},
    "vm2":            {"safe_from": "9999",   "cve": "CVE-2023-32314", "risk": "RCE sandbox escape — AVOID"},
    "serialize-javascript":{"safe_from": "6.0.2","cve": "CVE-2020-7660","risk": "XSS via serialised code"},
    "node-fetch":     {"safe_from": "3.0.0",  "cve": "CVE-2022-0235",  "risk": "SSRF via redirect"},
    "follow-redirects":{"safe_from":"1.15.4", "cve": "CVE-2023-26159", "risk": "Open redirect / SSRF"},
    "multer":         {"safe_from": "1.4.5",  "cve": "CVE-2022-24434", "risk": "DoS via crafted filename"},
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FileInfo:
    path:      str
    language:  str
    size:      int
    lines:     int
    sample:    str  = field(repr=False)  # first 8 KB


@dataclass
class Endpoint:
    route:     str
    method:    str
    file:      str
    line:      int
    framework: str
    tags:      List[str] = field(default_factory=list)


@dataclass
class SecretFinding:
    pattern_name: str
    file:         str
    line:         int
    snippet:      str


@dataclass
class CodebaseMap:
    target:          str
    scan_time_ms:    float
    file_count:      int
    total_lines:     int
    total_size_kb:   float
    skipped_files:   int
    languages:       Dict[str, Dict]          # name → {files, lines, pct}
    primary_language:str
    frameworks:      List[str]
    entry_points:    List[str]
    endpoints:       List[Dict]
    auth_patterns:   List[str]
    databases:       List[str]
    config_files:    List[str]
    secret_findings: List[Dict]
    risky_deps:      List[Dict]
    all_deps:        Dict[str, str]           # package → version
    data_models:     List[str]
    test_files:      int
    source_files:    int
    attack_surface:  Dict
    strategic_summary: str = ""
    raw_map_path:    str = ""
    is_own_repo:     bool = False   # True when scanning Nova's own codebase

    def summary(self) -> str:
        langs = ", ".join(
            f"{k}({v['files']}f)" for k, v in
            sorted(self.languages.items(), key=lambda x: x[1]["files"], reverse=True)[:8])
        return (
            f"📁 {self.file_count} files | {self.total_lines:,} lines | "
            f"{self.scan_time_ms:.0f}ms\n"
            f"🗣  Languages: {langs}\n"
            f"🏗  Frameworks: {', '.join(self.frameworks[:10]) or 'unknown'}\n"
            f"🌐 Endpoints: {len(self.endpoints)} discovered\n"
            f"🔐 Auth: {', '.join(self.auth_patterns[:5]) or 'none detected'}\n"
            f"🗄  Databases: {', '.join(self.databases[:5]) or 'none detected'}\n"
            f"🔑 Secrets: {len(self.secret_findings)} potential secrets\n"
            f"⚠️  Risky deps: {len(self.risky_deps)} CVE-affected packages")

    def attack_brief(self) -> str:
        """
        Compact strategic brief — inject this into any agent system prompt.
        Gives the LLM everything it needs to attack intelligently.
        """
        lines = [
            "=== NOVA STRATEGIC CODEBASE MAP ===",
            f"Target: {self.target}",
            f"Primary language: {self.primary_language}",
            f"Frameworks: {', '.join(self.frameworks[:8])}",
            f"Auth mechanisms: {', '.join(self.auth_patterns)}",
            f"Databases: {', '.join(self.databases)}",
            "",
            "--- HIGH-VALUE ENDPOINTS ---",
        ]
        prio = self.attack_surface.get("high_value", [])[:15]
        for h in prio:
            lines.append(f"  • {h.get('route', h.get('file','?'))} — {h.get('reason','')}")

        lines += ["", "--- QUICK WINS ---"]
        for q in self.attack_surface.get("quick_wins", [])[:10]:
            lines.append(f"  ✓ {q}")

        if self.secret_findings:
            lines += ["", "--- POTENTIAL SECRETS FOUND ---"]
            for s in self.secret_findings[:5]:
                lines.append(f"  🔑 {s['pattern']} in {s['file']}:{s['line']}")

        if self.risky_deps:
            lines += ["", "--- CVE-AFFECTED DEPENDENCIES ---"]
            for d in self.risky_deps[:5]:
                lines.append(f"  ⚠ {d['package']} {d['version']} — {d['risk']} ({d['cve']})")

        lines += ["", "--- ATTACK PRIORITY ORDER ---"]
        for i, a in enumerate(self.attack_surface.get("attack_priority", [])[:10], 1):
            lines.append(f"  {i}. [{a.get('attack','?')}] {a.get('target','?')} — {a.get('rationale','')}")

        if self.strategic_summary:
            lines += ["", "--- AI ANALYSIS ---", self.strategic_summary]

        lines.append("=== END MAP ===")
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "target":           self.target,
            "scan_time_ms":     self.scan_time_ms,
            "file_count":       self.file_count,
            "total_lines":      self.total_lines,
            "total_size_kb":    round(self.total_size_kb, 2),
            "skipped_files":    self.skipped_files,
            "primary_language": self.primary_language,
            "languages":        self.languages,
            "frameworks":       self.frameworks,
            "entry_points":     self.entry_points,
            "endpoints":        self.endpoints,
            "auth_patterns":    self.auth_patterns,
            "databases":        self.databases,
            "config_files":     self.config_files,
            "secret_findings":  self.secret_findings,
            "risky_deps":       self.risky_deps,
            "all_deps":         self.all_deps,
            "data_models":      self.data_models,
            "test_coverage":    {
                "test_files":   self.test_files,
                "source_files": self.source_files,
                "ratio":        round(self.test_files / max(self.source_files, 1), 2),
            },
            "attack_surface":   self.attack_surface,
            "strategic_summary":self.strategic_summary,
            "generated":        datetime.now().isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# SCOPE GUARD: Own-repo detection
# ─────────────────────────────────────────────────────────────────────────────

_NOVA_SENTINEL_FILES: Set[str] = {
    "nova.py", "nova_codebase_mapper.py", "nova_ci_runner.py",
    "nova_weapon_forge.py", "nova_cicd_scanner.py",
}

def _is_nova_own_repo(directory) -> bool:
    """Return True when `directory` is the Nova Arsenal codebase itself."""
    try:
        root_files = {f.name for f in directory.iterdir() if f.is_file()}
        return len(root_files & _NOVA_SENTINEL_FILES) >= 2
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# NOVA CODEBASE MAPPER
# ─────────────────────────────────────────────────────────────────────────────

class NovaCodebaseMapper:
    """
    Hyper-fast parallel codebase scanner.
    Call .scan() to get a full CodebaseMap.
    """

    def __init__(self, target: str, verbose: bool = True, ai_analysis: bool = True):
        self.target      = Path(target).expanduser().resolve()
        self.verbose      = verbose
        self.ai_analysis  = ai_analysis
        self._lock        = threading.Lock()

        # Accumulators
        self._files:        List[FileInfo] = []
        self._skipped:      int            = 0
        self._endpoints:    List[Dict]     = []
        self._secrets:      List[Dict]     = []
        self._auth_hits:    Set[str]       = set()
        self._db_hits:      Set[str]       = set()
        self._frameworks:   Set[str]       = set()
        self._models:       Set[str]       = set()
        self._entry_points: List[str]      = []
        self._config_files: List[str]      = []
        self._deps:         Dict[str,str]  = {}
        self._test_count:   int            = 0
        self._src_count:    int            = 0

        # Scope guard: detect if scanning Nova's own codebase
        self._own_repo: bool = _is_nova_own_repo(self.target)
        if self._own_repo and verbose:
            print("  ⚠️  [SCOPE GUARD] Scanning Nova's own codebase detected.")
            print("     Secret and dependency findings will be tagged 'local_nova_codebase'")
            print("     and will NOT be injected as remote target findings.")

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self) -> CodebaseMap:
        t0 = time.monotonic()

        if self.verbose:
            print(f"\n  🗺  Nova Codebase Mapper — scanning {self.target}")
            print(f"  ⚡ {MAX_WORKERS} parallel threads")

        if not self.target.is_dir():
            print(f"  ⚠  {self.target} is not a directory — returning minimal map")
            return self._minimal_map(str(self.target), 0)

        # ── Phase 1: Enumerate all files (fast — os.walk) ──────────────────
        all_files = list(self._enumerate_files())

        if self.verbose:
            print(f"  📂 {len(all_files)} files found — reading in parallel...")

        # ── Phase 2: Read files in parallel ────────────────────────────────
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(self._read_file, f): f for f in all_files}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass

        # ── Phase 3: Parse manifests (single-threaded, few files) ──────────
        self._parse_manifests()

        # ── Phase 4: Detect frameworks from file samples ───────────────────
        self._detect_frameworks_from_samples()

        # ── Phase 5: Build attack surface map ──────────────────────────────
        attack_surface = self._build_attack_surface()

        # ── Phase 6: AI strategic analysis (optional) ──────────────────────
        strategic_summary = ""
        if self.ai_analysis:
            strategic_summary = self._ai_strategic_analysis(attack_surface)

        # ── Assemble result ─────────────────────────────────────────────────
        elapsed = (time.monotonic() - t0) * 1000

        lang_stats = self._compute_lang_stats()
        primary    = max(lang_stats, key=lambda k: lang_stats[k]["files"], default="Unknown")
        primary    = primary if primary not in ("JSON","YAML","Markdown","Text","EnvFile") else \
                     next((k for k in sorted(lang_stats, key=lambda k: lang_stats[k]["files"],
                                             reverse=True)
                           if k not in ("JSON","YAML","Markdown","Text","EnvFile","Config")),
                          primary)

        # ── SCOPE GUARD: tag secrets/deps when scanning own codebase ────────
        raw_secrets   = self._secrets[:50]
        raw_risky_deps = self._check_risky_deps()
        if self._own_repo:
            for s in raw_secrets:
                s.setdefault("scope", "local_nova_codebase")
                s.setdefault("warning", "Found in Nova's own codebase — NOT a target vulnerability")
            for d in raw_risky_deps:
                d.setdefault("scope", "local_nova_codebase")
                d.setdefault("warning", "Dependency from Nova/Juice Shop — NOT a target vulnerability")

        cmap = CodebaseMap(
            target          = str(self.target),
            scan_time_ms    = elapsed,
            file_count      = len(self._files),
            total_lines     = sum(f.lines for f in self._files),
            total_size_kb   = sum(f.size for f in self._files) / 1024,
            skipped_files   = self._skipped,
            languages       = lang_stats,
            primary_language= primary,
            frameworks      = sorted(self._frameworks),
            entry_points    = self._entry_points[:20],
            endpoints       = self._endpoints[:200],
            auth_patterns   = sorted(self._auth_hits),
            databases       = sorted(self._db_hits),
            config_files    = self._config_files[:30],
            secret_findings = raw_secrets,
            risky_deps      = raw_risky_deps,
            all_deps        = dict(sorted(self._deps.items())[:200]),
            data_models     = sorted(self._models)[:50],
            test_files      = self._test_count,
            source_files    = self._src_count,
            attack_surface  = attack_surface,
            strategic_summary = strategic_summary,
            is_own_repo     = self._own_repo,
        )

        # ── Save output ─────────────────────────────────────────────────────
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = WORKSPACE / f"nova_codebase_map_{ts}.json"
        path.write_text(json.dumps(cmap.to_dict(), indent=2, default=str))
        cmap.raw_map_path = str(path)

        if self.verbose:
            print(f"\n{cmap.summary()}")
            print(f"  💾 Map saved → {path}")

        return cmap

    # ── Internal: file enumeration ─────────────────────────────────────────────

    def _enumerate_files(self):
        for root, dirs, files in os.walk(self.target):
            # Prune skip dirs in-place
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS
                       and not d.startswith(".") or d in (".github", ".well-known")]
            for fname in files:
                yield Path(root) / fname

    # ── Internal: per-file read + analyse ─────────────────────────────────────

    def _read_file(self, path: Path):
        try:
            size = path.stat().st_size
            if size > MAX_FILE_SIZE:
                with self._lock:
                    self._skipped += 1
                return

            # Read sample (first 8 KB)
            with open(path, "rb") as fh:
                raw = fh.read(SAMPLE_BYTES)

            # Skip binary
            for sig in BINARY_SIGNATURES:
                if raw.startswith(sig):
                    with self._lock:
                        self._skipped += 1
                    return

            # Decode
            try:
                sample = raw.decode("utf-8", errors="replace")
            except Exception:
                with self._lock:
                    self._skipped += 1
                return

            # Language detection
            lang = self._detect_language(path, sample)

            # Line count (fast: count newlines in full file)
            if size <= SAMPLE_BYTES:
                lines = sample.count("\n") + 1
            else:
                # Count newlines across full file without loading it all
                try:
                    with open(path, "rb") as fh:
                        lines = sum(chunk.count(b"\n") for chunk in iter(
                            lambda: fh.read(65536), b"")) + 1
                except Exception:
                    lines = sample.count("\n") + 1

            finfo = FileInfo(
                path   = str(path.relative_to(self.target)),
                language = lang,
                size   = size,
                lines  = lines,
                sample = sample,
            )

            with self._lock:
                self._files.append(finfo)
                if not self._is_test_file(finfo.path):
                    self._src_count += 1
                else:
                    self._test_count += 1

            # Per-file analysis (runs in the same thread)
            self._analyse_file(finfo)

        except (PermissionError, OSError):
            pass

    def _detect_language(self, path: Path, sample: str) -> str:
        ext = path.suffix.lower()
        # Special filename cases
        name = path.name.lower()
        if name == "dockerfile" or name.startswith("dockerfile"):
            return "Dockerfile"
        if name in ("makefile", "gnumakefile"):
            return "Makefile"
        if name in ("gemfile", "gemfile.lock"):
            return "Ruby"
        if name in ("rakefile",):
            return "Ruby"
        if name in ("procfile",):
            return "Config"
        if ext == "" and sample.startswith("#!"):
            shebang = sample.split("\n")[0]
            for key, lang in SHEBANG_LANG.items():
                if key in shebang:
                    return lang
        return EXTENSION_LANG.get(ext, "Other")

    def _is_test_file(self, rel_path: str) -> bool:
        p = rel_path.lower()
        return any(x in p for x in (
            "test", "spec", "__tests__", "tests/", "testing",
            "_test.", ".test.", "_spec.", ".spec."))

    def _analyse_file(self, finfo: FileInfo):
        sample = finfo.sample
        path   = finfo.path
        lang   = finfo.language

        # ── Entry points ────────────────────────────────────────────────────
        fname = Path(path).name.lower()
        if fname in ("server.ts","server.js","app.ts","app.js","main.py",
                     "app.py","index.ts","index.js","main.ts","main.go",
                     "main.rs","application.java","program.cs","server.go",
                     "manage.py","wsgi.py","asgi.py"):
            with self._lock:
                if path not in self._entry_points:
                    self._entry_points.append(path)

        # ── Config files ────────────────────────────────────────────────────
        if lang in ("EnvFile","Config","YAML","TOML","JSON") or fname in (
                ".env.example",".env.sample","config.yml","config.yaml",
                "settings.py","config.py","database.yml","secrets.yml"):
            with self._lock:
                if path not in self._config_files:
                    self._config_files.append(path)

        # ── Endpoints (route extraction) ────────────────────────────────────
        if lang in ("JavaScript","TypeScript","Python","Ruby","PHP","Go","Java","C#","Elixir"):
            self._extract_endpoints(finfo)

        # ── Auth patterns ───────────────────────────────────────────────────
        for name, pat in AUTH_PATTERNS:
            if re.search(pat, sample, re.IGNORECASE):
                with self._lock:
                    self._auth_hits.add(name)

        # ── Database patterns ───────────────────────────────────────────────
        for name, pat in DB_PATTERNS:
            if re.search(pat, sample, re.IGNORECASE):
                with self._lock:
                    self._db_hits.add(name)

        # ── Secret patterns ─────────────────────────────────────────────────
        for secret_name, pat in SECRET_PATTERNS:
            for m in re.finditer(pat, sample):
                line_no = sample[:m.start()].count("\n") + 1
                snippet = m.group(0)[:60] + ("..." if len(m.group(0)) > 60 else "")
                with self._lock:
                    self._secrets.append({
                        "pattern": secret_name, "file": path,
                        "line": line_no, "snippet": snippet,
                    })

        # ── Data models (class/struct/model names) ──────────────────────────
        model_pats = [
            r"class\s+(\w+)\s*(?:\(.*Model.*\)|extends\s+Model|implements\s+Entity)",
            r"@Entity[^)]*\)\s+(?:public\s+)?class\s+(\w+)",
            r"pgTable\s*\(\s*['\"](\w+)['\"]",
            r"Schema\s*\(\s*\{[^}]*\}\s*\)\s*;\s*\w+\s*=\s*model\s*\(\s*['\"](\w+)['\"]",
            r"class\s+(\w+)\s*<\s*ActiveRecord::Base",
        ]
        for mp in model_pats:
            for m in re.finditer(mp, sample):
                with self._lock:
                    self._models.add(m.group(1))

    def _extract_endpoints(self, finfo: FileInfo):
        sample = finfo.sample
        path   = finfo.path

        for fw, pattern, style in ROUTE_PATTERNS:
            try:
                for m in re.finditer(pattern, sample, re.MULTILINE | re.IGNORECASE):
                    line_no = sample[:m.start()].count("\n") + 1
                    if style == "method+route":
                        method = m.group(1).upper()
                        route  = m.group(2)
                    elif style == "route+methods":
                        route  = m.group(1)
                        raw_methods = m.group(2) if m.lastindex >= 2 else ""
                        method = ",".join(x.strip().strip("'\"")
                                          for x in raw_methods.split(",")) if raw_methods else "GET"
                    elif style == "filepath_route":
                        route  = "/" + m.group(1).replace("[", ":").replace("]","")
                        method = "ANY"
                    else:
                        route  = m.group(1)
                        method = "ANY"

                    # Tag for attack surface
                    tags = self._tag_endpoint(route, path, finfo.sample)

                    with self._lock:
                        self._endpoints.append({
                            "route":     route,
                            "method":    method,
                            "file":      path,
                            "line":      line_no,
                            "framework": fw,
                            "tags":      tags,
                        })
            except re.error:
                pass

    def _tag_endpoint(self, route: str, path: str, sample: str) -> List[str]:
        tags = []
        combined = (route + path + sample[:500]).lower()
        for tag, keywords in ATTACK_SURFACE_KEYWORDS.items():
            if any(k in combined for k in keywords):
                tags.append(tag)
        return tags

    # ── Manifest parsing ───────────────────────────────────────────────────────

    def _parse_manifests(self):
        manifest_names = [
            "package.json", "requirements.txt", "Gemfile",
            "go.mod", "Cargo.toml", "pom.xml", "build.gradle",
            "composer.json", "mix.exs", "pyproject.toml",
            "setup.py", "setup.cfg", "Pipfile",
        ]
        for finfo in self._files:
            fname = Path(finfo.path).name.lower()
            if fname not in [m.lower() for m in manifest_names]:
                continue
            sample = finfo.sample

            # package.json
            if fname == "package.json":
                try:
                    data = json.loads(finfo.sample)
                    all_d = {}
                    all_d.update(data.get("dependencies", {}))
                    all_d.update(data.get("devDependencies", {}))
                    with self._lock:
                        self._deps.update({k: str(v) for k, v in all_d.items()})
                except Exception:
                    pass

            # requirements.txt
            elif fname in ("requirements.txt", "requirements-dev.txt"):
                for line in sample.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"([\w\-]+)\s*[>=<!~^]+\s*([\d.]+)", line)
                    if m:
                        with self._lock:
                            self._deps[m.group(1).lower()] = m.group(2)

            # Gemfile
            elif fname == "gemfile":
                for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", sample):
                    with self._lock:
                        self._deps[m.group(1)] = m.group(2) or "?"

            # go.mod
            elif fname == "go.mod":
                for m in re.finditer(r"^\s+([\w./\-]+)\s+(v[\d.]+)", sample, re.MULTILINE):
                    with self._lock:
                        self._deps[m.group(1)] = m.group(2)

            # Cargo.toml
            elif fname == "cargo.toml":
                for m in re.finditer(r'^([\w\-]+)\s*=\s*["\']?([0-9][^"\'}\n]*)', sample, re.MULTILINE):
                    with self._lock:
                        self._deps[m.group(1)] = m.group(2).strip()

    def _detect_frameworks_from_samples(self):
        """Detect frameworks from manifest file content collected in _files."""
        file_map: Dict[str, str] = {
            Path(f.path).name.lower(): f.sample for f in self._files
        }
        for fw, manifest, pat in FRAMEWORK_SIGNATURES:
            manifest_key = manifest.lower().rstrip("*")
            # Check all files whose name starts with manifest_key
            for fname, sample in file_map.items():
                if fname.startswith(manifest_key.lstrip("*")) or fname == manifest_key:
                    if re.search(pat, sample, re.IGNORECASE):
                        self._frameworks.add(fw)
                        break

    # ── Attack surface builder ─────────────────────────────────────────────────

    def _build_attack_surface(self) -> Dict:
        high_value:    List[Dict] = []
        quick_wins:    List[str]  = []
        attack_priority: List[Dict] = []

        # Tag all endpoints
        endpoint_score: List[Tuple[int, Dict]] = []
        for ep in self._endpoints:
            score = 0
            tags  = ep.get("tags", [])
            route = ep.get("route", "")
            reasoning_parts = []

            if "admin" in tags:      score += 10; reasoning_parts.append("admin route")
            if "payment" in tags:    score += 9;  reasoning_parts.append("payment/financial data")
            if "file_upload" in tags:score += 8;  reasoning_parts.append("file upload")
            if "auth" in tags:       score += 7;  reasoning_parts.append("auth endpoint")
            if "ssrf_prone" in tags: score += 6;  reasoning_parts.append("SSRF-prone pattern")
            if "sqli_prone" in tags: score += 6;  reasoning_parts.append("raw query pattern")
            if "idor_prone" in tags: score += 5;  reasoning_parts.append("ID-based lookup")
            if "race_prone" in tags: score += 5;  reasoning_parts.append("balance/transfer logic")
            if "debug" in tags:      score += 4;  reasoning_parts.append("debug/dev endpoint")
            if "user_data" in tags:  score += 3;  reasoning_parts.append("user PII")
            if "graphql" in tags:    score += 4;  reasoning_parts.append("GraphQL — check introspection")
            if "deserialization" in tags: score += 7; reasoning_parts.append("deserialisation pattern")
            if "webhook" in tags:    score += 3;  reasoning_parts.append("webhook/callback")

            endpoint_score.append((score, {**ep, "score": score,
                                            "reasoning": ", ".join(reasoning_parts)}))

        endpoint_score.sort(key=lambda x: -x[0])
        high_value = [e for _, e in endpoint_score if e["score"] >= 5][:30]

        # Attack priority
        for score, ep in endpoint_score[:20]:
            tags    = ep.get("tags", [])
            route   = ep.get("route", "?")
            attacks = []
            if "idor_prone" in tags:
                attacks.append(("IDOR", f"Enumerate IDs on {route}"))
            if "sqli_prone" in tags:
                attacks.append(("SQLi", f"Inject payloads at {route}"))
            if "file_upload" in tags:
                attacks.append(("FileUpload", f"Upload webshell via {route}"))
            if "ssrf_prone" in tags:
                attacks.append(("SSRF", f"Point URL params at 169.254.169.254 via {route}"))
            if "auth" in tags:
                attacks.append(("AuthBypass", f"Test auth bypass at {route}"))
            if "race_prone" in tags:
                attacks.append(("Race", f"Concurrent requests to {route}"))
            if "payment" in tags:
                attacks.append(("BusinessLogic", f"Negative/zero price via {route}"))
            for atk, rationale in attacks:
                attack_priority.append({
                    "priority": len(attack_priority) + 1,
                    "attack":   atk,
                    "target":   route,
                    "file":     ep.get("file", "?"),
                    "rationale":rationale,
                })

        # Quick wins
        ep_routes = {ep["route"].lower() for ep in self._endpoints}
        if any("graphql" in r for r in ep_routes):
            quick_wins.append("GraphQL introspection — try {__schema{types{name}}}")
        if any("debug" in r or "dev" in r or "test" in r for r in ep_routes):
            quick_wins.append("Debug/dev endpoints found — may expose stack traces or configs")
        if any("swagger" in r or "openapi" in r or "api-docs" in r for r in ep_routes):
            quick_wins.append("Swagger/OpenAPI spec exposed — maps all endpoints automatically")
        if any(".git" in str(f.path) or "/.git/" in str(f.path)
               for f in self._files):
            quick_wins.append(".git directory accessible — run git log --all to extract secrets")
        if self.secret_findings if hasattr(self, 'secret_findings') else self._secrets:
            quick_wins.append(f"{len(self._secrets)} potential secrets found in source — check immediately")
        for dep in self._deps:
            if dep.lower() in ("vm2", "node-serialize", "serialize-javascript"):
                quick_wins.append(f"Dangerous package '{dep}' — known RCE path")
        if "JWT" in self._auth_hits:
            quick_wins.append("JWT auth detected — test alg:none, key confusion, expired token reuse")
        if "Session" in self._auth_hits:
            quick_wins.append("Session auth detected — test fixation, prediction, and CSRF")

        return {
            "high_value":     high_value,
            "quick_wins":     quick_wins,
            "attack_priority":attack_priority,
        }

    def _check_risky_deps(self) -> List[Dict]:
        risky = []
        for pkg, version in self._deps.items():
            if pkg.lower() in RISKY_DEPS:
                info = RISKY_DEPS[pkg.lower()]
                risky.append({
                    "package":  pkg,
                    "version":  version,
                    "cve":      info["cve"],
                    "risk":     info["risk"],
                    "safe_from":info["safe_from"],
                })
        return risky

    def _compute_lang_stats(self) -> Dict[str, Dict]:
        counts: Dict[str, Dict] = defaultdict(lambda: {"files": 0, "lines": 0})
        for f in self._files:
            counts[f.language]["files"] += 1
            counts[f.language]["lines"] += f.lines
        total_files = max(len(self._files), 1)
        return {
            lang: {
                "files": v["files"],
                "lines": v["lines"],
                "pct":   round(v["files"] / total_files * 100, 1),
            }
            for lang, v in sorted(counts.items(), key=lambda x: -x[1]["files"])
        }

    # ── AI strategic analysis ──────────────────────────────────────────────────

    def _ai_strategic_analysis(self, attack_surface: Dict) -> str:
        router = None
        try:
            from nova_llm_router import get_router
            router = get_router()
        except Exception:
            pass

        if not router:
            return self._rule_based_analysis(attack_surface)

        brief = {
            "languages":   [k for k in self._compute_lang_stats().keys()][:8],
            "frameworks":  list(self._frameworks)[:10],
            "auth":        list(self._auth_hits),
            "databases":   list(self._db_hits),
            "endpoints":   len(self._endpoints),
            "high_value":  [h.get("route","?") + " (" + h.get("reasoning","") + ")"
                            for h in attack_surface.get("high_value",[])[:10]],
            "risky_deps":  [f"{d['package']} — {d['risk']}"
                            for d in self._check_risky_deps()[:5]],
            "secrets":     len(self._secrets),
            "models":      sorted(self._models)[:20],
        }

        prompt = (
            f"You are a senior security researcher. I have just scanned a codebase "
            f"and gathered this intelligence:\n\n{json.dumps(brief, indent=2)}\n\n"
            f"In 200 words max, give me:\n"
            f"1. The #1 most likely critical vulnerability to find (and exactly how)\n"
            f"2. The #1 business-logic flaw to try (specific to this tech stack)\n"
            f"3. Any unusual or stack-specific risk I should not miss\n"
            f"Be concrete, specific, and attack-focused. No fluff."
        )
        try:
            resp = router.chat(prompt, system=(
                "You are Nova's strategic attack analyst. "
                "Output raw tactical attack guidance only."))
            return resp.content
        except Exception as e:
            return self._rule_based_analysis(attack_surface)

    def _rule_based_analysis(self, attack_surface: Dict) -> str:
        lines = []
        if "PostgreSQL" in self._db_hits or "MySQL" in self._db_hits:
            lines.append("SQL database detected — prioritise SQLi on search, filter, and order parameters.")
        if "MongoDB" in self._db_hits:
            lines.append("MongoDB detected — test NoSQLi: {\"$gt\":\"\"} and {\"$where\":\"sleep(5000)\"}")
        if "JWT" in self._auth_hits:
            lines.append("JWT auth — test alg:none, RS→HS key confusion, expired token replay.")
        if "File upload" in str(attack_surface.get("high_value",[])):
            lines.append("File upload endpoint — test MIME-type bypass, path traversal in filename, polyglot payloads.")
        if "GraphQL" in self._frameworks or any("graphql" in e.get("route","") for e in self._endpoints):
            lines.append("GraphQL — run introspection, try batching, alias overload DoS, and IDOR via direct object ID fields.")
        if not lines:
            lines.append("Standard web app — run IDOR, CSRF, and auth bypass checks on authenticated endpoints.")
        return " ".join(lines)

    def _minimal_map(self, target: str, elapsed: float) -> CodebaseMap:
        return CodebaseMap(
            target=target, scan_time_ms=elapsed, file_count=0, total_lines=0,
            total_size_kb=0, skipped_files=0, languages={}, primary_language="Unknown",
            frameworks=[], entry_points=[], endpoints=[], auth_patterns=[],
            databases=[], config_files=[], secret_findings=[], risky_deps=[],
            all_deps={}, data_models=[], test_files=0, source_files=0,
            attack_surface={"high_value":[],"quick_wins":[],"attack_priority":[]})


# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_MAP_CACHE: Dict[str, CodebaseMap] = {}
_MAP_LOCK  = threading.Lock()


def get_codebase_map(target: str, force: bool = False,
                     verbose: bool = True) -> Optional[CodebaseMap]:
    """
    Return a cached CodebaseMap for `target`.
    If the cache is empty or `force=True`, run a fresh scan.
    """
    with _MAP_LOCK:
        if not force and target in _MAP_CACHE:
            return _MAP_CACHE[target]
    cmap = NovaCodebaseMapper(target, verbose=verbose).scan()
    with _MAP_LOCK:
        _MAP_CACHE[target] = cmap
    return cmap


def map_to_agent_context(cmap: Optional[CodebaseMap]) -> str:
    """Convert a CodebaseMap to a compact string for injection into agent prompts."""
    if not cmap:
        return ""
    return cmap.attack_brief()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="🗺  Nova Codebase Mapper — hyper-fast strategic codebase scanner")
    parser.add_argument("target", nargs="?", default=".",
                        help="Directory to scan (default: .)")
    parser.add_argument("--no-ai",    action="store_true",
                        help="Skip AI strategic analysis")
    parser.add_argument("--brief",    action="store_true",
                        help="Print attack brief (for pasting into agents)")
    parser.add_argument("--quiet",    action="store_true")
    args = parser.parse_args()

    mapper = NovaCodebaseMapper(
        args.target,
        verbose=not args.quiet,
        ai_analysis=not args.no_ai)
    cmap = mapper.scan()

    if args.brief:
        print("\n" + cmap.attack_brief())
    else:
        print(f"\n{cmap.summary()}")
        print(f"\n  Top attack priorities:")
        for a in cmap.attack_surface.get("attack_priority", [])[:5]:
            print(f"  {a['priority']}. [{a['attack']}] {a['target']} — {a['rationale']}")
        if cmap.secret_findings:
            print(f"\n  🔑 Secrets ({len(cmap.secret_findings)}):")
            for s in cmap.secret_findings[:5]:
                print(f"     {s['pattern']} in {s['file']}:{s['line']}")
        print(f"\n  💾 Full map → {cmap.raw_map_path}")
