#!/usr/bin/env python3
"""
HA fetcher: minimal, safe data pull from Hybrid Analysis API (v2).
Only pulls lightweight, non-binary data by default. Keeps a small cache.
"""
import os
import time
import json
import requests
from pathlib import Path

BASE_URL = os.environ.get("HA_BASE_URL", "https://hybrid-analysis.com/api/v2")
API_KEY = os.environ.get("HA_API_KEY") or os.environ.get("HA_API")
HEADERS = {
    "api-key": API_KEY or "",
    "User-Agent": "AISlop HA Fetcher",
    "Accept": "application/json",
}

CACHE_DIR = Path("cache"); CACHE_DIR.mkdir(parents=True, exist_ok=True)

class HAClient:
    def __init__(self, base_url: str = BASE_URL, retries: int = 3, min_interval: float = 3.0, backoff: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.retries = retries
        self.min_interval = min_interval
        self.backoff = backoff
        self.last = 0.0

    def _wait(self):
        since = time.time() - self.last
        if since < self.min_interval:
            time.sleep(self.min_interval - since)
        self.last = time.time()

    def rate_get(self, path: str, params: dict = None) -> dict | None:
        url = f"{self.base_url}{path}"
        for i in range(self.retries):
            self._wait()
            resp = requests.get(url, headers=HEADERS, params=params, timeout=20, verify=False)
            if resp.status_code in (429, 503):
                time.sleep(self.backoff * (2 ** i))
                continue
            if resp.ok:
                try:
                    return resp.json()
                except Exception:
                    return None
        return None

    def get_latest(self, limit: int = 50):
        data = self.rate_get("/feed/latest", {"limit": limit})
        if not data:
            return []
        if isinstance(data, dict) and "data" in data:
            d = data["data"]
            return d if isinstance(d, list) else []
        if isinstance(data, list):
            return data
        return []

    def get_overview(self, sha256: str) -> dict:
        path = f"/overview/{sha256}"
        data = self.rate_get(path)
        return data or {}

    def get_summary(self, report_id: str) -> dict:
        data = self.rate_get(f"/report/{report_id}/summary")
        return data or {}

    def get_strings(self, report_id: str) -> list[str]:
        paths = ["/report/{}".format(report_id), "/report/{}/memory-strings".format(report_id)]
        for p in paths:
            try:
                data = self.rate_get(p, {})
                if isinstance(data, dict):
                    strings = data.get("data") or data.get("strings")
                    if isinstance(strings, list):
                        return [str(x) for x in strings]
            except Exception:
                continue
        return []

def safe_load_json(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None
