"""Optional threat-intelligence clients.

Only URLs and SHA-256 hashes are sent to third parties. Raw email bodies and
uploaded files never leave the app. All calls are best-effort and fail open
(the local heuristics still produce a report).
"""

from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from .utils import USER_AGENT, rdap_domain_age_days

_CACHE: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 900  # 15 minutes


def _cache_get(key: str) -> Any | None:
    item = _CACHE.get(key)
    if not item:
        return None
    created, value = item
    if time.monotonic() - created > _CACHE_TTL:
        _CACHE.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: Any) -> Any:
    _CACHE[key] = (time.monotonic(), value)
    return value


@dataclass
class IntelResult:
    source: str
    found: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    score: int = 0
    categories: list[str] = field(default_factory=list)
    permalink: str = ""
    error: str = ""

    @property
    def detections(self) -> int:
        return self.malicious + self.suspicious

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "found": self.found,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "reputation": self.reputation,
            "score": self.score,
            "categories": self.categories,
            "permalink": self.permalink,
            "error": self.error,
        }


class IntelClient:
    def __init__(
        self,
        virustotal_key: str | None = None,
        safe_browsing_key: str | None = None,
        urlscan_key: str | None = None,
    ) -> None:
        self.virustotal_key = virustotal_key or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.safe_browsing_key = safe_browsing_key or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        self.urlscan_key = urlscan_key or os.getenv("URLSCAN_API_KEY", "").strip()

    @property
    def available(self) -> list[str]:
        sources = []
        if self.virustotal_key:
            sources.append("VirusTotal")
        if self.safe_browsing_key:
            sources.append("Google Safe Browsing")
        sources.append("urlscan.io")
        sources.append("RDAP")
        return sources

    def _get(self, url: str, *, headers: dict | None = None, params: dict | None = None) -> requests.Response | None:
        merged = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if headers:
            merged.update(headers)
        try:
           return requests.get(
               url,
               headers=merged,
               params=params,
               timeout=7,
               allow_redirects=False,
)
        except requests.RequestException:
            return None

    def virustotal_url(self, url: str) -> IntelResult:
        if not self.virustotal_key:
            return IntelResult(source="VirusTotal", error="API key not configured")
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        key = f"vt:url:{url_id}"
        cached = _cache_get(key)
        if cached is not None:
            return cached
        response = self._get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": self.virustotal_key},
        )
        if response is None:
            return _cache_set(key, IntelResult(source="VirusTotal", error="Request failed"))
        if response.status_code == 404:
            return _cache_set(key, IntelResult(source="VirusTotal", found=False))
        if response.status_code != 200:
            return _cache_set(
                key,
                IntelResult(source="VirusTotal", error=f"HTTP {response.status_code}"),
            )
        try:
            attributes = response.json()["data"]["attributes"]
        except (KeyError, ValueError):
            return _cache_set(key, IntelResult(source="VirusTotal", error="Unexpected response"))
        stats = attributes.get("last_analysis_stats", {})
        result = IntelResult(
            source="VirusTotal",
            found=True,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            reputation=int(attributes.get("reputation", 0)),
            categories=list(attributes.get("categories", {}).values())[:8],
            permalink=f"https://www.virustotal.com/gui/url/{url_id}",
        )
        return _cache_set(key, result)

    def virustotal_file(self, sha256: str) -> IntelResult:
        if not self.virustotal_key:
            return IntelResult(source="VirusTotal", error="API key not configured")
        key = f"vt:file:{sha256}"
        cached = _cache_get(key)
        if cached is not None:
            return cached
        response = self._get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": self.virustotal_key},
        )
        if response is None:
            return _cache_set(key, IntelResult(source="VirusTotal", error="Request failed"))
        if response.status_code == 404:
            return _cache_set(key, IntelResult(source="VirusTotal", found=False))
        if response.status_code != 200:
            return _cache_set(
                key,
                IntelResult(source="VirusTotal", error=f"HTTP {response.status_code}"),
            )
        try:
            attributes = response.json()["data"]["attributes"]
        except (KeyError, ValueError):
            return _cache_set(key, IntelResult(source="VirusTotal", error="Unexpected response"))
        stats = attributes.get("last_analysis_stats", {})
        result = IntelResult(
            source="VirusTotal",
            found=True,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            reputation=int(attributes.get("reputation", 0)),
            categories=list(attributes.get("tags", []))[:8],
            permalink=f"https://www.virustotal.com/gui/file/{sha256}",
        )
        return _cache_set(key, result)

    def urlscan_domain(self, domain: str) -> IntelResult:
        if not domain:
            return IntelResult(source="urlscan.io", error="No domain")
        key = f"urlscan:{domain}"
        cached = _cache_get(key)
        if cached is not None:
            return cached
        headers = {"x-api-key": self.urlscan_key} if self.urlscan_key else None
        response = self._get(
            "https://urlscan.io/api/v1/search/",
            headers=headers,
            params={"q": f"domain:{domain}", "size": 20},
        )
        if response is None:
            return _cache_set(key, IntelResult(source="urlscan.io", error="Request failed"))
        if response.status_code != 200:
            return _cache_set(
                key,
                IntelResult(source="urlscan.io", error=f"HTTP {response.status_code}"),
            )
        try:
            payload = response.json()
            results = payload.get("results", [])
        except ValueError:
            return _cache_set(key, IntelResult(source="urlscan.io", error="Unexpected response"))
        malicious = 0
        suspicious = 0
        for item in results:
            verdicts = item.get("verdicts", {}) or {}
            overall = verdicts.get("overall", {}) or {}
            if overall.get("malicious"):
                malicious += 1
            elif int(overall.get("score", 0) or 0) >= 50:
                suspicious += 1
        result = IntelResult(
            source="urlscan.io",
            found=bool(results),
            malicious=malicious,
            suspicious=suspicious,
            undetected=max(0, len(results) - malicious - suspicious),
            score=min(100, malicious * 40 + suspicious * 15),
            permalink=f"https://urlscan.io/domain/{domain}",
        )
        return _cache_set(key, result)

    def google_safe_browsing(self, url: str) -> IntelResult:
        if not self.safe_browsing_key:
            return IntelResult(source="Google Safe Browsing", error="API key not configured")
        key = f"gsb:{url}"
        cached = _cache_get(key)
        if cached is not None:
            return cached
        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            response = requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": self.safe_browsing_key},
                json=payload,
                headers={"User-Agent": USER_AGENT},
                timeout=7,
                allow_redirects=False,
            )
        except requests.RequestException:
            return _cache_set(key, IntelResult(source="Google Safe Browsing", error="Request failed"))
        if response.status_code != 200:
            return _cache_set(
                key,
                IntelResult(source="Google Safe Browsing", error=f"HTTP {response.status_code}"),
            )
        try:
            matches = response.json().get("matches", [])
        except ValueError:
            return _cache_set(key, IntelResult(source="Google Safe Browsing", error="Unexpected response"))
        result = IntelResult(
            source="Google Safe Browsing",
            found=bool(matches),
            malicious=len(matches),
            categories=sorted({match.get("threatType", "") for match in matches}),
            permalink="https://transparencyreport.google.com/safe-browsing/search",
        )
        return _cache_set(key, result)

    def domain_age(self, domain: str) -> int | None:
        return rdap_domain_age_days(domain)
