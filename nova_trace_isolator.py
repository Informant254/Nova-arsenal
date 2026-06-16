#!/usr/bin/env python3
"""
🦅 NOVA TRACE ISOLATOR v2.0 — Universal Stealth Service
Provides centralized proxy-chaining, User-Agent rotation, and behavioral deception.
"""
import random
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

class NovaTraceIsolator:
    def __init__(self, proxy_list=None):
        self.proxies = proxy_list or []
        self.session = requests.Session()

    def get_stealth_headers(self):
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def get_proxy(self):
        if not self.proxies:
            return None
        proxy = random.choice(self.proxies)
        return {"http": proxy, "https": proxy}

    def stealth_request(self, method, url, **kwargs):
        """Execute a request with full stealth protocols."""
        headers = self.get_stealth_headers()
        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        kwargs["headers"] = headers
        
        proxy = self.get_proxy()
        if proxy:
            kwargs["proxies"] = proxy
            
        return self.session.request(method, url, **kwargs)

def get_isolator():
    return NovaTraceIsolator()
