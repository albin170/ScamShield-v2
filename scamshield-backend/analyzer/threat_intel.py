"""
Threat Intelligence Provider Adapters — ScamShield
Modular integrations for external threat-intelligence feeds:
- URLhaus (abuse.ch) — live public feed of active malicious URLs (no key required)
- VirusTotal v3 — URL reputation lookup (server-side API key)
- Google Safe Browsing v4 — phishing/malware threat matches (server-side API key)

Includes:
- Safe server-side API key storage (never sent to client)
- In-memory TTL caching
- Explicit provider timeouts and rate limit protection
- Accurate provider availability reporting (never invent responses)
- Transparent provenance tracking (sources consulted, checks not completed)
"""
import os
import time
import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import urllib.request
import urllib.parse
import json


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ThreatIntelResult:
    provider: str
    status: str            # "match" | "clean" | "unavailable" | "skipped" | "rate_limited"
    is_malicious: bool
    threat_type: Optional[str] = None
    details: str = ""
    cached: bool = False
    response_time_ms: float = 0.0
    timestamp: str = field(default_factory=_now_iso)


class ThreatIntelProvider:
    name: str = "base"
    is_enabled: bool = True

    def query(self, url: str) -> ThreatIntelResult:
        raise NotImplementedError


class URLhausAdapter(ThreatIntelProvider):
    """
    abuse.ch URLhaus threat feed adapter.
    Free, publicly available repository of verified malicious URLs.
    No secret key required.
    """
    name = "URLhaus (abuse.ch)"

    def __init__(self, timeout_sec: float = 3.5):
        self.timeout_sec = timeout_sec

    def query(self, url: str) -> ThreatIntelResult:
        start = time.perf_counter()
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        data = urllib.parse.urlencode({"url": url}).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "User-Agent": "ScamShield-ThreatIntel/3.0",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                elapsed = (time.perf_counter() - start) * 1000
                res_json = json.loads(resp.read().decode("utf-8"))
                query_status = res_json.get("query_status", "")

                if query_status == "ok":
                    urlhaus_status = res_json.get("url_status", "")
                    threat = res_json.get("threat", "malware_download")
                    return ThreatIntelResult(
                        provider=self.name,
                        status="match",
                        is_malicious=True,
                        threat_type=threat,
                        details=f"Listed in URLhaus database as active threat (Status: {urlhaus_status}, Threat: {threat}).",
                        response_time_ms=round(elapsed, 1),
                    )
                elif query_status == "no_results":
                    return ThreatIntelResult(
                        provider=self.name,
                        status="clean",
                        is_malicious=False,
                        details="URL not listed in active URLhaus threat database.",
                        response_time_ms=round(elapsed, 1),
                    )
                else:
                    return ThreatIntelResult(
                        provider=self.name,
                        status="unavailable",
                        is_malicious=False,
                        details=f"URLhaus returned query status: {query_status}",
                        response_time_ms=round(elapsed, 1),
                    )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ThreatIntelResult(
                provider=self.name,
                status="unavailable",
                is_malicious=False,
                details=f"URLhaus lookup unavailable ({type(e).__name__}).",
                response_time_ms=round(elapsed, 1),
            )


class VirusTotalAdapter(ThreatIntelProvider):
    """
    VirusTotal v3 URL reputation adapter.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    name = "VirusTotal"

    def __init__(self, api_key: Optional[str] = None, timeout_sec: float = 3.5):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.timeout_sec = timeout_sec

    def query(self, url: str) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(
                provider=self.name,
                status="skipped",
                is_malicious=False,
                details="VirusTotal integration not configured (VIRUSTOTAL_API_KEY missing).",
            )

        start = time.perf_counter()
        # VT URL ID is base64 of URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        req = urllib.request.Request(
            endpoint,
            headers={
                "x-apikey": self.api_key,
                "User-Agent": "ScamShield-ThreatIntel/3.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                elapsed = (time.perf_counter() - start) * 1000
                res = json.loads(resp.read().decode("utf-8"))
                attributes = res.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious = last_analysis_stats.get("malicious", 0)
                suspicious = last_analysis_stats.get("suspicious", 0)

                if malicious >= 2:
                    return ThreatIntelResult(
                        provider=self.name,
                        status="match",
                        is_malicious=True,
                        threat_type="malicious_url",
                        details=f"{malicious} security vendors flagged this URL as malicious on VirusTotal.",
                        response_time_ms=round(elapsed, 1),
                    )
                elif malicious == 1 or suspicious >= 2:
                    return ThreatIntelResult(
                        provider=self.name,
                        status="match",
                        is_malicious=False,
                        threat_type="suspicious_url",
                        details=f"Flagged as suspicious on VirusTotal ({malicious} malicious, {suspicious} suspicious vendors).",
                        response_time_ms=round(elapsed, 1),
                    )
                else:
                    return ThreatIntelResult(
                        provider=self.name,
                        status="clean",
                        is_malicious=False,
                        details="No security vendors flagged this URL as malicious on VirusTotal.",
                        response_time_ms=round(elapsed, 1),
                    )
        except urllib.error.HTTPError as he:
            elapsed = (time.perf_counter() - start) * 1000
            if he.code == 404:
                return ThreatIntelResult(
                    provider=self.name,
                    status="clean",
                    is_malicious=False,
                    details="URL not previously indexed in VirusTotal database.",
                    response_time_ms=round(elapsed, 1),
                )
            elif he.code == 429:
                return ThreatIntelResult(
                    provider=self.name,
                    status="rate_limited",
                    is_malicious=False,
                    details="VirusTotal API rate limit reached.",
                    response_time_ms=round(elapsed, 1),
                )
            return ThreatIntelResult(
                provider=self.name,
                status="unavailable",
                is_malicious=False,
                details=f"VirusTotal lookup error HTTP {he.code}.",
                response_time_ms=round(elapsed, 1),
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ThreatIntelResult(
                provider=self.name,
                status="unavailable",
                is_malicious=False,
                details=f"VirusTotal lookup unavailable ({type(e).__name__}).",
                response_time_ms=round(elapsed, 1),
            )


class GoogleSafeBrowsingAdapter(ThreatIntelProvider):
    """
    Google Safe Browsing v4 threatMatches adapter.
    Requires SAFEBROWSING_API_KEY environment variable.
    """
    name = "Google Safe Browsing"

    def __init__(self, api_key: Optional[str] = None, timeout_sec: float = 3.5):
        self.api_key = api_key or os.getenv("SAFEBROWSING_API_KEY", "").strip()
        self.timeout_sec = timeout_sec

    def query(self, url: str) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(
                provider=self.name,
                status="skipped",
                is_malicious=False,
                details="Safe Browsing integration not configured (SAFEBROWSING_API_KEY missing).",
            )

        start = time.perf_counter()
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": "scamshield-app", "clientVersion": "3.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                elapsed = (time.perf_counter() - start) * 1000
                res = json.loads(resp.read().decode("utf-8"))
                matches = res.get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType", "SOCIAL_ENGINEERING")
                    return ThreatIntelResult(
                        provider=self.name,
                        status="match",
                        is_malicious=True,
                        threat_type=threat_type,
                        details=f"Identified as {threat_type} by Google Safe Browsing.",
                        response_time_ms=round(elapsed, 1),
                    )
                else:
                    return ThreatIntelResult(
                        provider=self.name,
                        status="clean",
                        is_malicious=False,
                        details="No threat matches reported by Google Safe Browsing.",
                        response_time_ms=round(elapsed, 1),
                    )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ThreatIntelResult(
                provider=self.name,
                status="unavailable",
                is_malicious=False,
                details=f"Safe Browsing lookup unavailable ({type(e).__name__}).",
                response_time_ms=round(elapsed, 1),
            )


class ThreatIntelManager:
    """
    Orchestrates threat intelligence queries across all configured adapters.
    Features in-memory TTL caching and provider status metrics.
    """
    def __init__(self, cache_ttl_sec: int = 600):
        self.providers: list[ThreatIntelProvider] = [
            URLhausAdapter(),
            VirusTotalAdapter(),
            GoogleSafeBrowsingAdapter(),
        ]
        self._cache: dict[str, tuple[float, list[ThreatIntelResult]]] = {}
        self.cache_ttl_sec = cache_ttl_sec
        self.provider_stats: dict[str, dict] = {
            p.name: {
                "total_queries": 0,
                "matches": 0,
                "errors": 0,
                "last_success": None,
                "configured": bool(getattr(p, "api_key", True)),
            }
            for p in self.providers
        }

    def _cache_key(self, url: str) -> str:
        return hashlib.sha256(url.strip().lower().encode("utf-8")).hexdigest()

    def query_all(self, url: str, enable_external: bool = True) -> list[ThreatIntelResult]:
        """Query all enabled adapters for a URL, applying cache where available."""
        if not enable_external:
            return []

        ck = self._cache_key(url)
        now = time.time()

        if ck in self._cache:
            ts, results = self._cache[ck]
            if now - ts < self.cache_ttl_sec:
                return [
                    ThreatIntelResult(
                        provider=r.provider,
                        status=r.status,
                        is_malicious=r.is_malicious,
                        threat_type=r.threat_type,
                        details=r.details,
                        cached=True,
                        response_time_ms=0.0,
                    )
                    for r in results
                ]

        results = []
        for provider in self.providers:
            res = provider.query(url)
            results.append(res)

            # Update stats
            st = self.provider_stats.get(provider.name, {})
            st["total_queries"] = st.get("total_queries", 0) + 1
            if res.status == "match":
                st["matches"] = st.get("matches", 0) + 1
            if res.status == "unavailable":
                st["errors"] = st.get("errors", 0) + 1
            if res.status in ("match", "clean"):
                st["last_success"] = _now_iso()
            self.provider_stats[provider.name] = st

        self._cache[ck] = (now, results)
        return results

    def get_provider_statuses(self) -> dict:
        """Return provider configuration and health metadata for the dashboard."""
        return {
            name: {
                "configured": (
                    bool(os.getenv("VIRUSTOTAL_API_KEY")) if name == "VirusTotal"
                    else bool(os.getenv("SAFEBROWSING_API_KEY")) if name == "Google Safe Browsing"
                    else True
                ),
                "total_queries": stats.get("total_queries", 0),
                "matches": stats.get("matches", 0),
                "errors": stats.get("errors", 0),
                "last_success": stats.get("last_success"),
            }
            for name, stats in self.provider_stats.items()
        }


# Singleton manager instance
threat_intel_manager = ThreatIntelManager()
