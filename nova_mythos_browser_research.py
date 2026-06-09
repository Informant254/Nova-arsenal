# nova_mythos_browser_research.py
# Powerful browser research for real-time vuln adaptation

from nova_llm_router import get_router, LLMRouter
from typing import List, Dict

try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


def get_llm(provider_hint: str = "") -> LLMRouter:
    """Compatibility shim — returns the global LLMRouter instance."""
    return get_router()


class MythosBrowserResearch:
    def __init__(self):
        self.llm = get_router()

    async def research_vuln(self, query: str, max_pages: int = 3) -> List[Dict]:
        results: List[Dict] = []
        if not _PLAYWRIGHT_AVAILABLE:
            print("  ⚠️  playwright not installed — browser research unavailable")
            return results
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            search_url = (
                f"https://www.google.com/search?q="
                f"{query.replace(' ', '+')}+vulnerability+writeup"
            )
            await page.goto(search_url)
            content = await page.content()
            if _BS4_AVAILABLE:
                soup = BeautifulSoup(content, "html.parser")
                for link in soup.select("a[href]")[:max_pages]:
                    href = link.get("href", "")
                    if href.startswith("http") and "google" not in href:
                        results.append({"url": href, "title": link.get_text()[:120]})
            await browser.close()
        return results
