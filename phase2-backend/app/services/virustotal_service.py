"""
VirusTotal API service — external threat intelligence layer.

Called only when the ONNX model confidence is below the defined threshold
(i.e. the model is uncertain). Results are cached in memory to avoid
duplicate API calls for the same URL within the server's lifetime.

Average response latency: ~1800ms (per paper benchmarks).
"""
import base64
import hashlib
import logging
import time
from typing import Optional
from threading import Lock

import requests

from config.settings import settings

logger = logging.getLogger("app.services.virustotal")


class VirusTotalResult:
    """Parsed result from a VirusTotal URL analysis."""

    def __init__(
        self,
        malicious_count: int,
        suspicious_count: int,
        total_engines: int,
        threat_names: list[str],
        permalink: str,
    ):
        self.malicious_count = malicious_count
        self.suspicious_count = suspicious_count
        self.total_engines = total_engines
        self.threat_names = threat_names
        self.permalink = permalink

    @property
    def is_phishing(self) -> bool:
        """True if enough engines flagged the URL as malicious."""
        return self.malicious_count >= settings.VIRUSTOTAL_MALICIOUS_THRESHOLD

    @property
    def confidence(self) -> float:
        """Normalised confidence score based on engine votes."""
        if self.total_engines == 0:
            return 0.5
        return self.malicious_count / self.total_engines

    def to_dict(self) -> dict:
        return {
            "malicious_count": self.malicious_count,
            "suspicious_count": self.suspicious_count,
            "total_engines": self.total_engines,
            "threat_names": self.threat_names,
            "permalink": self.permalink,
            "is_phishing": self.is_phishing,
        }


class VirusTotalService:
    """
    Queries VirusTotal for URL reputation data.

    Uses an in-memory LRU-style cache (url_hash → result) so each
    unique URL is queried at most once per server session.
    """

    def __init__(self):
        self._cache: dict[str, Optional[VirusTotalResult]] = {}
        self._cache_lock = Lock()
        self._api_key = settings.VIRUSTOTAL_API_KEY
        self._base_url = settings.VIRUSTOTAL_BASE_URL
        self._timeout = settings.VIRUSTOTAL_TIMEOUT_SEC

        if not self._api_key:
            logger.warning(
                "VIRUSTOTAL_API_KEY not set. "
                "VirusTotal checks will be skipped."
            )

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    # ── Public API ─────────────────────────────────────────────────────────────

    def check(self, url: str) -> Optional[VirusTotalResult]:
        """
        Check a URL against VirusTotal.

        Checks the in-memory cache first. If not cached, submits the URL
        for analysis and polls for results.

        Args:
            url: Normalised URL string.

        Returns:
            VirusTotalResult or None if VT is unavailable.
        """
        if not self.is_configured:
            return None

        url_hash = hashlib.sha256(url.encode()).hexdigest()

        # Cache hit
        with self._cache_lock:
            if url_hash in self._cache:
                logger.debug(f"VirusTotal cache hit: {url[:60]}")
                return self._cache[url_hash]

        # Cache miss — query VT
        result = self._query_virustotal(url)

        with self._cache_lock:
            self._cache[url_hash] = result

        return result

    def cache_size(self) -> int:
        """Return number of URLs cached in memory."""
        with self._cache_lock:
            return len(self._cache)

    # ── VirusTotal API calls ───────────────────────────────────────────────────

    def _query_virustotal(self, url: str) -> Optional[VirusTotalResult]:
        """
        Submit URL to VT and retrieve analysis results.

        Flow:
          1. POST /urls to submit URL for analysis → get analysis_id.
          2. GET /analyses/{id} to retrieve results (poll once with short wait).
          3. If still queued, GET /urls/{url_id} for cached results.
        """
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}

        # Step 1: Submit URL
        try:
            resp = requests.post(
                f"{self._base_url}/urls",
                headers=headers,
                data={"url": url},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            analysis_id = resp.json()["data"]["id"]
            logger.debug(f"VirusTotal submitted: {url[:60]} → analysis_id={analysis_id}")
        except Exception as exc:
            logger.error(f"VirusTotal submission error: {exc}")
            return None

        # Step 2: Poll for analysis results (give VT 5 seconds to process)
        time.sleep(5)
        try:
            resp = requests.get(
                f"{self._base_url}/analyses/{analysis_id}",
                headers=headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            status = data.get("data", {}).get("attributes", {}).get("status", "")

            if status == "completed":
                return self._parse_analysis(data)
        except Exception as exc:
            logger.warning(f"VirusTotal analysis poll error: {exc}")

        # Step 3: Fallback — fetch by URL ID (base64 encoded URL)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            resp = requests.get(
                f"{self._base_url}/urls/{url_id}",
                headers=headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return self._parse_url_report(resp.json())
        except Exception as exc:
            logger.error(f"VirusTotal URL report error: {exc}")
            return None

    # ── Response parsing ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_analysis(data: dict) -> Optional[VirusTotalResult]:
        """Parse a /analyses/{id} response."""
        try:
            stats = data["data"]["attributes"]["stats"]
            results = data["data"]["attributes"].get("results", {})
            threat_names = [
                v.get("result", "")
                for v in results.values()
                if v.get("category") in {"malicious", "suspicious"} and v.get("result")
            ]
            return VirusTotalResult(
                malicious_count=stats.get("malicious", 0),
                suspicious_count=stats.get("suspicious", 0),
                total_engines=sum(stats.values()),
                threat_names=list(set(threat_names))[:10],
                permalink=data.get("data", {}).get("links", {}).get("self", ""),
            )
        except (KeyError, TypeError) as exc:
            logger.error(f"VirusTotal analysis parse error: {exc}")
            return None

    @staticmethod
    def _parse_url_report(data: dict) -> Optional[VirusTotalResult]:
        """Parse a /urls/{id} response."""
        try:
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            threat_names = [
                v.get("result", "")
                for v in results.values()
                if v.get("category") in {"malicious", "suspicious"} and v.get("result")
            ]
            return VirusTotalResult(
                malicious_count=stats.get("malicious", 0),
                suspicious_count=stats.get("suspicious", 0),
                total_engines=sum(stats.values()),
                threat_names=list(set(threat_names))[:10],
                permalink=data.get("data", {}).get("links", {}).get("self", ""),
            )
        except (KeyError, TypeError) as exc:
            logger.error(f"VirusTotal URL report parse error: {exc}")
            return None
