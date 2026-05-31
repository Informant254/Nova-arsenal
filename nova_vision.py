#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   👁️  NOVA VISION v1.0 — SCREENSHOT & VISUAL ANALYSIS              ║
║                                                                      ║
║   Closes the Claude Mythos / computer-use vision gap.                ║
║                                                                      ║
║   Claude Mythos sees screenshots and reasons about UI visually.     ║
║   Nova now does the same — local vision model (llava/moondream)     ║
║   analyzes every page screenshot for:                               ║
║                                                                      ║
║   • Hidden/invisible form fields                                     ║
║   • Auth flows the DOM doesn't reveal in plain HTML                 ║
║   • Admin panels, debug endpoints, file upload forms                ║
║   • JavaScript-rendered content that grep_code misses               ║
║   • Visual trust indicators (lock icons, badge texts, role labels)  ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import base64
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

OLLAMA_URL   = os.getenv("NOVA_LLM_URL",   "http://localhost:11434")
WORKSPACE    = Path(os.path.expanduser(os.getenv("NOVA_WORKSPACE", "~/nova_workspace")))

# Vision-capable models in preference order
VISION_MODELS = [
    "llava:34b", "llava:13b", "llava:7b", "llava",
    "llava-phi3", "moondream", "bakllava",
    "minicpm-v", "llava-llama3",
]

# Security-focused visual analysis prompt
VISUAL_ANALYSIS_PROMPT = """You are a senior penetration tester analyzing a web application screenshot.

Identify ALL of the following security-relevant elements you can see:

1. FORMS: List every form, its fields, and apparent purpose (login, search, upload, admin, etc.)
2. HIDDEN/SUSPICIOUS ELEMENTS: Any elements that appear unusual or security-sensitive
3. AUTH STATE: Is the user logged in? What role/privilege level is shown?
4. NAVIGATION: Admin panels, user management, file upload, API endpoints visible in menus
5. INPUT FIELDS: Every text box, dropdown, file upload, or user-controlled field
6. TRUST INDICATORS: SSL badges, role indicators, privilege notices
7. ERROR MESSAGES: Any visible error or debug information
8. ATTACK VECTORS: List the 3 most promising attack vectors based on what you see

Output as JSON:
{
  "forms": [{"purpose": "...", "fields": [...], "action": "..."}],
  "auth_state": "unauthenticated|user|admin|unknown",
  "role_shown": "...",
  "admin_links": [...],
  "upload_forms": [...],
  "input_fields": [...],
  "visible_errors": [...],
  "attack_vectors": [
    {"type": "...", "target": "...", "reasoning": "..."}
  ],
  "summary": "one paragraph visual assessment"
}"""


def _get_vision_model() -> Optional[str]:
    """Find the best available vision-capable model."""
    try:
        req = urllib.request.Request(f"{OLLAMA_URL.rstrip('/')}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        installed = [m["name"] for m in data.get("models", [])]
        for preferred in VISION_MODELS:
            for installed_name in installed:
                if preferred.split(":")[0] in installed_name:
                    return installed_name
    except Exception:
        pass
    return None


def _screenshot_playwright(url: str, output_path: Path, full_page: bool = True,
                            wait_ms: int = 2000) -> bool:
    """Take a screenshot using Playwright. Returns True on success."""
    script = f"""
import asyncio
from playwright.async_api import async_playwright

async def screenshot():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={{"width": 1280, "height": 900}})
        try:
            await page.goto("{url}", wait_until="networkidle", timeout=15000)
            await page.wait_for_timeout({wait_ms})
            await page.screenshot(path="{output_path}", full_page={str(full_page)})
        finally:
            await browser.close()

asyncio.run(screenshot())
"""
    try:
        result = subprocess.run(
            ["python3", "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        return output_path.exists() and output_path.stat().st_size > 1000
    except Exception:
        return False


def _screenshot_cli(url: str, output_path: Path) -> bool:
    """Fallback: use chromium-browser or google-chrome CLI."""
    for browser in ["chromium-browser", "chromium", "google-chrome", "google-chrome-stable"]:
        try:
            result = subprocess.run([
                browser, "--headless", "--disable-gpu",
                f"--screenshot={output_path}",
                "--window-size=1280,900", url,
            ], capture_output=True, timeout=20)
            if output_path.exists() and output_path.stat().st_size > 1000:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def take_screenshot(url: str, save_as: str = None) -> Optional[Path]:
    """
    Take a screenshot of a URL using Playwright (with CLI fallback).
    Returns path to the screenshot file or None on failure.
    """
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    fname = save_as or f"screenshot_{ts}.png"
    out = WORKSPACE / "screenshots" / fname
    out.parent.mkdir(parents=True, exist_ok=True)

    if _screenshot_playwright(url, out):
        return out
    if _screenshot_cli(url, out):
        return out
    return None


def _analyze_with_vision(image_path: Path, model: str,
                          custom_prompt: str = None) -> Optional[Dict]:
    """Send screenshot to local Ollama vision model for analysis."""
    prompt = custom_prompt or VISUAL_ANALYSIS_PROMPT
    try:
        image_b64 = base64.b64encode(image_path.read_bytes()).decode("utf-8")
    except Exception:
        return None

    payload = json.dumps({
        "model": model,
        "messages": [{
            "role": "user",
            "content": prompt,
            "images": [image_b64],
        }],
        "stream": False, "format": "json",
        "options": {"temperature": 0.1, "num_predict": 1500},
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            f"{OLLAMA_URL.rstrip('/')}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        content = raw.get("message", {}).get("content", "").strip()
        if not content:
            return None
        # Try JSON parse
        try:
            return json.loads(content)
        except Exception:
            # Extract JSON block if wrapped in text
            m = re.search(r'\{[\s\S]+\}', content)
            if m:
                return json.loads(m.group(0))
        return {"summary": content, "raw": True}
    except Exception:
        return None


def _heuristic_analyze(image_path: Path) -> Dict:
    """
    Heuristic fallback when no vision model is available.
    Returns a useful placeholder that tells the agent what to do.
    """
    size_kb = image_path.stat().st_size // 1024
    return {
        "forms": [],
        "auth_state": "unknown",
        "attack_vectors": [
            {"type": "manual", "target": "screenshot taken", "reasoning":
             "No vision model installed. Install with: ollama pull llava — then re-run visual_analyze."},
        ],
        "summary": (
            f"Screenshot captured ({size_kb}KB) but no vision model available. "
            f"Install a vision model: ollama pull llava (7B) or ollama pull moondream (1.8B). "
            f"Screenshot saved to: {image_path}"
        ),
        "screenshot_path": str(image_path),
        "vision_model": None,
    }


def visual_analyze(url: str, prompt: str = None,
                   save_as: str = None) -> Dict[str, Any]:
    """
    Main entry point: take screenshot of URL and analyze it visually.

    Returns structured dict with:
    - forms, auth_state, attack_vectors, admin_links, upload_forms
    - summary, screenshot_path, vision_model used
    """
    print(f"  👁️  Visual analysis: {url}")

    # Step 1 — screenshot
    shot = take_screenshot(url, save_as=save_as)
    if not shot:
        return {
            "success": False,
            "error": f"Screenshot failed for {url}. Check Playwright installation: python3 -m playwright install chromium",
            "attack_vectors": [],
        }
    print(f"  📸 Screenshot: {shot} ({shot.stat().st_size//1024}KB)")

    # Step 2 — find vision model
    model = _get_vision_model()
    if not model:
        print("  ⚠️  No vision model installed. Run: ollama pull llava")
        result = _heuristic_analyze(shot)
        result["screenshot_path"] = str(shot)
        return result

    print(f"  🧠 Analyzing with {model}...")

    # Step 3 — analyze
    analysis = _analyze_with_vision(shot, model, prompt)
    if not analysis:
        return {
            "success": False,
            "error": f"Vision analysis failed with model {model}",
            "screenshot_path": str(shot),
            "attack_vectors": [],
        }

    analysis["screenshot_path"] = str(shot)
    analysis["vision_model"]    = model
    analysis["success"]         = True

    # Print top attack vectors
    vectors = analysis.get("attack_vectors", [])
    if vectors:
        print(f"  🎯 {len(vectors)} attack vector(s) identified visually:")
        for v in vectors[:3]:
            print(f"     • [{v.get('type','')}] {v.get('target','')} — {v.get('reasoning','')[:80]}")

    return analysis


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    result = visual_analyze(url)
    print("\n=== VISUAL ANALYSIS RESULT ===")
    print(json.dumps(result, indent=2, default=str))
