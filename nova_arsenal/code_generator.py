"""
Code Generator - Generates Python and Bash code from task descriptions.

The agent can write, save, and execute custom code when existing tools
are insufficient for a task.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class CodeLanguage(Enum):
    PYTHON = "python"
    BASH = "bash"
    RUBY = "ruby"
    PERL = "perl"


@dataclass
class GeneratedCode:
    """A piece of generated code."""
    language: CodeLanguage
    code: str
    description: str
    filename: str
    dependencies: list[str]
    safe_to_run: bool = True


class CodeGenerator:
    """
    Generates code for security tasks.
    
    The agent uses this when:
    - No existing tool fits the task
    - Custom logic is needed
    - A one-off script would solve the problem faster
    - Automation of repetitive tasks is needed
    """

    def __init__(self) -> None:
        self._templates: dict[str, str] = self._load_templates()

    def _load_templates(self) -> dict[str, str]:
        return {
            "port_scanner": '''#!/usr/bin/env python3
"""Custom port scanner with service detection."""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(host: str, port: int, timeout: float = 2.0) -> tuple[int, bool, str]:
    """Scan a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            return port, True, service
        return port, False, ""
    except Exception:
        return port, False, ""

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ports = range(1, 1025)
    
    print(f"Scanning {{host}}...")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
                print(f"  Port {{port}}: OPEN ({{service}})")
    
    print(f"\\nFound {{len(open_ports)}} open ports")

if __name__ == "__main__":
    main()
''',

            "subdomain_enum": '''#!/usr/bin/env python3
"""Subdomain enumeration using DNS resolution."""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_subdomain(domain: str) -> tuple[str, bool, str]:
    """Check if a subdomain exists."""
    try:
        ip = socket.gethostbyname(domain)
        return domain, True, ip
    except socket.gaierror:
        return domain, False, ""

def main():
    base_domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Default common subdomains
    prefixes = [
        "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns",
        "webmail", "admin", "test", "dev", "staging", "api", "app",
        "blog", "shop", "store", "portal", "vpn", "remote", "git",
        "jenkins", "ci", "cd", "k8s", "docker", "registry", "monitor",
        "grafana", "kibana", "elastic", "db", "mysql", "redis", "mongo",
        "backup", "old", "new", "demo", "sandbox", "lab", "corp",
    ]
    
    if wordlist:
        with open(wordlist) as f:
            prefixes = [line.strip() for line in f if line.strip()]
    
    print(f"Enumerating subdomains of {{base_domain}}...")
    found = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(check_subdomain, f"{{p}}.{{base_domain}}"): p
            for p in prefixes
        }
        for future in as_completed(futures):
            subdomain, exists, ip = future.result()
            if exists:
                found.append((subdomain, ip))
                print(f"  [+] {{subdomain}} -> {{ip}}")
    
    print(f"\\nFound {{len(found)}} subdomains")

if __name__ == "__main__":
    main()
''',

            "web_screenshot": '''#!/usr/bin/env python3
"""Take screenshots of web pages using requests + Pillow."""

import sys
import requests
from urllib.parse import urljoin

def check_url(url: str) -> dict:
    """Check URL status and gather info."""
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        return {
            "url": resp.url,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "length": len(resp.text),
            "title": extract_title(resp.text),
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

def extract_title(html: str) -> str:
    """Extract title from HTML."""
    import re
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    
    result = check_url(url)
    print(f"URL: {{result.get('url', url)}}")
    if "error" in result:
        print(f"Error: {{result['error']}}")
    else:
        print(f"Status: {{result['status']}}")
        print(f"Title: {{result.get('title', 'N/A')}}")
        print(f"Size: {{result.get('length', 0)}} bytes")
        print("Headers:")
        for k, v in result.get("headers", {}).items():
            print(f"  {{k}}: {{v}}")

if __name__ == "__main__":
    main()
''',

            "nmap_parser": '''#!/usr/bin/env python3
"""Parse nmap XML output into structured findings."""

import sys
import xml.etree.ElementTree as ET
import json

def parse_nmap_xml(xml_file: str) -> list[dict]:
    """Parse nmap XML output."""
    findings = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall(".//host"):
            addr = host.find("address")
            ip = addr.get("addr", "unknown") if addr is not None else "unknown"
            
            for port_elem in host.findall(".//port"):
                portid = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "")
                
                state = port_elem.find("state")
                state_str = state.get("state", "") if state is not None else ""
                
                service = port_elem.find("service")
                service_name = service.get("name", "") if service is not None else ""
                service_product = service.get("product", "") if service is not None else ""
                service_version = service.get("version", "") if service is not None else ""
                
                if state_str == "open":
                    findings.append({
                        "host": ip,
                        "port": int(portid) if portid.isdigit() else portid,
                        "protocol": protocol,
                        "state": state_str,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                    })
    except ET.ParseError as e:
        print(f"XML parse error: {{e}}", file=sys.stderr)
    
    return findings

def main():
    if len(sys.argv) < 2:
        print("Usage: nmap_parser.py <nmap_xml_file>")
        sys.exit(1)
    
    findings = parse_nmap_xml(sys.argv[1])
    print(json.dumps(findings, indent=2))
    print(f"\\nFound {{len(findings)}} open ports")

if __name__ == "__main__":
    main()
''',

            "param_fuzzer": '''#!/usr/bin/env python3
"""Fuzz URL parameters for injection points."""

import sys
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

def fuzz_params(url: str, params_to_test: list[str] = None) -> list[dict]:
    """Test URL parameters for injection."""
    if params_to_test is None:
        params_to_test = ["id", "q", "search", "page", "cmd", "file", "path", "url", "redirect"]
    
    results = []
    
    for param in params_to_test:
        test_url = f"{{url}}?{{param}}=nova_test"
        try:
            resp = requests.get(test_url, timeout=10)
            
            # Check for reflection
            reflected = "nova_test" in resp.text
            
            # Check for error-based indicators
            error_indicators = ["sql", "syntax", "error", "warning", "exception", "stack trace"]
            has_errors = any(ind in resp.text.lower() for ind in error_indicators)
            
            results.append({
                "param": param,
                "status": resp.status_code,
                "reflected": reflected,
                "errors": has_errors,
                "length": len(resp.text),
            })
            
            status = "VULNERABLE" if reflected or has_errors else "safe"
            print(f"  [{{status}}] {{param}} ({{resp.status_code}}, reflected={{reflected}})")
            
        except requests.RequestException as e:
            results.append({"param": param, "error": str(e)})
            print(f"  [ERROR] {{param}}: {{e}}")
    
    return results

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"Fuzzing parameters at {{url}}...")
    results = fuzz_params(url)
    
    vulns = [r for r in results if r.get("reflected") or r.get("errors")]
    print(f"\\nPotential vulnerabilities: {{len(vulns)}}")

if __name__ == "__main__":
    main()
''',
        }

    def generate(
        self,
        task: str,
        language: CodeLanguage = CodeLanguage.PYTHON,
        target: str = "",
        context: str = "",
    ) -> GeneratedCode:
        """Generate code for a task."""
        task_lower = task.lower()

        # Match task to template
        template_key = None
        if any(w in task_lower for w in ["port scan", "port scanner", "scan port"]):
            template_key = "port_scanner"
        elif any(w in task_lower for w in ["subdomain", "enumerate subdomain", "dns enum"]):
            template_key = "subdomain_enum"
        elif any(w in task_lower for w in ["screenshot", "web screenshot", "capture page"]):
            template_key = "web_screenshot"
        elif any(w in task_lower for w in ["nmap", "parse nmap", "nmap output"]):
            template_key = "nmap_parser"
        elif any(w in task_lower for w in ["fuzz", "parameter fuzz", "param injection"]):
            template_key = "param_fuzzer"
        else:
            # Generate custom code via LLM prompt
            return self._generate_custom(task, language, target, context)

        template = self._templates.get(template_key, "")
        if template and target:
            template = template.replace("example.com", target)

        return GeneratedCode(
            language=language,
            code=template or "# Unable to generate code for this task",
            description=f"Auto-generated for: {task}",
            filename=f"nova_{template_key}.py" if template_key else "nova_script.py",
            dependencies=self._get_dependencies(template_key or ""),
        )

    def _generate_custom(
        self,
        task: str,
        language: CodeLanguage,
        target: str,
        context: str,
    ) -> GeneratedCode:
        """Generate custom code (returns a skeleton for LLM to complete)."""
        if language == CodeLanguage.BASH:
            code = f"""#!/bin/bash
# Auto-generated for: {task}
# Target: {target}

set -e

echo "[*] Starting: {task}"
echo "[*] Target: {target}"

# TODO: Implement task logic
# This script was generated by Nova-Arsenal CodeGenerator

echo "[*] Complete"
"""
        else:
            code = f'''#!/usr/bin/env python3
"""
Auto-generated for: {task}
Target: {target}
"""

import sys
import requests

def main():
    """Execute: {task}"""
    target = "{target}"
    
    print(f"[*] Starting: {task}")
    print(f"[*] Target: {{target}}")
    
    # TODO: Implement task logic
    # This script was generated by Nova-Arsenal CodeGenerator
    
    print("[*] Complete")

if __name__ == "__main__":
    main()
'''

        return GeneratedCode(
            language=language,
            code=code,
            description=f"Custom generated for: {task}",
            filename="nova_custom.py" if language == CodeLanguage.PYTHON else "nova_custom.sh",
            dependencies=[],
        )

    def _get_dependencies(self, template_key: str) -> list[str]:
        deps = {
            "port_scanner": [],
            "subdomain_enum": [],
            "web_screenshot": ["requests"],
            "nmap_parser": [],
            "param_fuzzer": ["requests"],
        }
        return deps.get(template_key, [])

    def list_templates(self) -> list[str]:
        return list(self._templates.keys())

    def get_template(self, name: str) -> Optional[str]:
        return self._templates.get(name)
