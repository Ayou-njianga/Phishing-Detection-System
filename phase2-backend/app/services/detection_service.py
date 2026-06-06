"""
Detection service — orchestrates the 3-layer phishing detection pipeline.

Pipeline (in order):
  Layer 0 — Trusted-domain allowlist (~0ms)  : short-circuit for known-good TLDs
  Layer 1 — MongoDB cache            (~3ms)  : instant hit for known phishing URLs
  Layer 2 — ONNX model              (~12ms) : ML inference for unclassified URLs
  Layer 3 — VirusTotal             (~1800ms): external verification for low-confidence predictions

Only layers 1 and 2 run for every request. Layer 3 fires only when the
model confidence is below CONFIDENCE_THRESHOLD (default 0.75).
"""
import logging
import time
from typing import Optional
from urllib.parse import urlparse

from app.models.url_record import UrlRecord
from app.services.mongodb_service import MongoDBService
from app.services.onnx_service import OnnxService
from app.services.virustotal_service import VirusTotalService
from app.utils.url_parser import normalise, UrlParseError
from config.settings import settings

logger = logging.getLogger("app.services.detection")

# Registered domain (SLD + TLD only, no subdomain) allowlist.
# Real phishing never uses the exact legitimate domain — it always uses
# a different TLD or subdomain (e.g. youtube.com.evil.tk, youtubelogin.tk).
# Blocking these at Layer 0 avoids ML over-generalisation from brand-name
# substrings in training phishing data (e.g. buatduityoutube.com).
_TRUSTED_DOMAINS: frozenset[str] = frozenset({
    # Google
    "google.com", "youtube.com", "gmail.com", "googlemail.com",
    "googleapis.com", "gstatic.com", "google.co.uk", "google.fr",
    "google.de", "google.ca", "google.com.au", "google.co.in",
    "googlevideo.com", "googleusercontent.com",
    # Meta
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
    "meta.com", "fbcdn.net",
    # Microsoft
    "microsoft.com", "outlook.com", "live.com", "hotmail.com",
    "office.com", "office365.com", "onedrive.com", "sharepoint.com",
    "bing.com", "msn.com", "azure.com", "windows.com",
    # Apple
    "apple.com", "icloud.com", "itunes.com",
    # Amazon / AWS
    "amazon.com", "amazon.co.uk", "amazon.fr", "amazon.de",
    "amazonaws.com", "aws.amazon.com", "awsstatic.com",
    # GitHub / GitLab
    "github.com", "githubusercontent.com", "gitlab.com",
    # Twitter/X
    "twitter.com", "x.com", "t.co",
    # LinkedIn
    "linkedin.com",
    # Netflix / Spotify / Disney
    "netflix.com", "spotify.com", "disneyplus.com",
    # Finance / payments
    "paypal.com", "stripe.com", "square.com", "cash.app",
    "venmo.com", "wise.com", "revolut.com",
    # Cloudflare / CDN
    "cloudflare.com", "cloudfront.net",
    # Wikipedia
    "wikipedia.org", "wikimedia.org",
    # Reddit
    "reddit.com", "redd.it",
    # Yahoo
    "yahoo.com", "yahoo.fr", "yahoo.co.uk",
    # Samsung / Android
    "samsung.com", "android.com",
    # Misc popular
    "tiktok.com", "snapchat.com", "pinterest.com", "tumblr.com",
    "wordpress.com", "blogspot.com", "medium.com",
    "dropbox.com", "box.com", "drive.google.com",
    "zoom.us", "slack.com", "discord.com",
    "adobe.com", "canva.com", "figma.com",
})


def _root_domain(url: str) -> str:
    """Return the registered domain (SLD.TLD) from a URL, lower-cased."""
    try:
        host = urlparse(url).hostname or ""
        host = host.lower()
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""


class DetectionResult:
    """Full result returned to the route layer."""

    def __init__(
        self,
        record: UrlRecord,
        latency_ms: float,
        pipeline_stages: list[str],
    ):
        self.record = record
        self.latency_ms = latency_ms
        self.pipeline_stages = pipeline_stages  # which layers ran

    def to_response(self) -> dict:
        resp = self.record.to_response()
        resp["latency_ms"] = round(self.latency_ms, 2)
        resp["pipeline_stages"] = self.pipeline_stages
        return resp


class DetectionService:
    """Orchestrates URL classification through all pipeline layers."""

    def __init__(
        self,
        mongodb: MongoDBService,
        onnx: OnnxService,
        virustotal: VirusTotalService,
    ):
        self._mongo = mongodb
        self._onnx = onnx
        self._vt = virustotal
        self._threshold = settings.CONFIDENCE_THRESHOLD

    # ── Main entry point ───────────────────────────────────────────────────────

    def analyse(
        self,
        raw_url: str,
        sender_app: Optional[str] = None,
        sender_id: Optional[str] = None,
    ) -> DetectionResult:
        """
        Analyse a URL through the full detection pipeline.

        Args:
            raw_url: Raw URL string from the Android notification.
            sender_app: Source app identifier (e.g. "whatsapp").
            sender_id: Hashed sender identifier for context.

        Returns:
            DetectionResult with classification and timing info.

        Raises:
            UrlParseError: If the URL cannot be parsed.
        """
        t_start = time.perf_counter()
        stages: list[str] = []

        # ── Normalise ──────────────────────────────────────────────────────────
        url = normalise(raw_url)

        # ── Layer 0: Trusted-domain allowlist ──────────────────────────────────
        root = _root_domain(url)
        if root in _TRUSTED_DOMAINS:
            stages.append("allowlist")
            record = UrlRecord(
                url=url,
                is_phishing=False,
                confidence=0.01,
                detection_source="allowlist",
                sender_app=sender_app,
                sender_id=sender_id,
            )
            elapsed = (time.perf_counter() - t_start) * 1000
            logger.info(f"[ALLOWLIST] {url[:70]} | root={root} | safe | {elapsed:.1f}ms")
            return DetectionResult(record, elapsed, stages)

        # ── Layer 1: MongoDB cache ─────────────────────────────────────────────
        cached = self._mongo.lookup(url)
        if cached is not None:
            stages.append("mongodb_cache")
            self._mongo.update_last_seen(cached.url_hash)
            elapsed = (time.perf_counter() - t_start) * 1000
            logger.info(
                f"[MONGO HIT] {url[:70]} | "
                f"phishing={cached.is_phishing} | {elapsed:.1f}ms"
            )
            return DetectionResult(cached, elapsed, stages)

        # ── Layer 2: ONNX model inference ──────────────────────────────────────
        stages.append("onnx_model")
        confidence: Optional[float] = self._onnx.predict(url)

        if confidence is None:
            # Model unavailable — fall through to VT or return uncertain result
            confidence = 0.5
            logger.warning(f"ONNX model unavailable for: {url[:70]}")

        is_phishing = confidence >= self._threshold
        detection_source = "onnx_model"

        logger.debug(
            f"[ONNX] {url[:70]} | confidence={confidence:.4f} | "
            f"threshold={self._threshold} | phishing={is_phishing}"
        )

        # ── Layer 3: VirusTotal (conditional) ─────────────────────────────────
        vt_malicious = None
        vt_total = None
        vt_threats = None

        low_confidence = confidence < self._threshold and confidence > (1 - self._threshold)
        # Fire VT when model is uncertain (score in the middle band)
        should_query_vt = (
            self._vt.is_configured
            and low_confidence
        )

        if should_query_vt:
            stages.append("virustotal")
            logger.info(f"[VT] Querying VirusTotal for uncertain URL: {url[:70]}")
            vt_result = self._vt.check(url)

            if vt_result is not None:
                # VT overrides the model decision for uncertain cases
                is_phishing = vt_result.is_phishing
                confidence = vt_result.confidence if vt_result.is_phishing else (1 - vt_result.confidence)
                detection_source = "virustotal"
                vt_malicious = vt_result.malicious_count
                vt_total = vt_result.total_engines
                vt_threats = vt_result.threat_names
                logger.info(
                    f"[VT] {url[:70]} | malicious={vt_malicious}/{vt_total} | "
                    f"phishing={is_phishing}"
                )

        # ── Build and cache the result ─────────────────────────────────────────
        record = UrlRecord(
            url=url,
            is_phishing=is_phishing,
            confidence=confidence,
            detection_source=detection_source,
            vt_malicious_count=vt_malicious,
            vt_total_engines=vt_total,
            vt_threat_names=vt_threats,
            sender_app=sender_app,
            sender_id=sender_id,
        )

        # Only cache confirmed phishing URLs to keep the collection targeted
        if is_phishing:
            self._mongo.insert(record)

        elapsed = (time.perf_counter() - t_start) * 1000
        logger.info(
            f"[RESULT] {url[:70]} | phishing={is_phishing} | "
            f"source={detection_source} | stages={stages} | {elapsed:.1f}ms"
        )

        return DetectionResult(record, elapsed, stages)

    # ── Batch analysis ─────────────────────────────────────────────────────────

    def analyse_batch(
        self,
        raw_urls: list[str],
        sender_app: Optional[str] = None,
    ) -> list[DetectionResult]:
        """
        Analyse multiple URLs from a single notification payload.

        Runs MongoDB lookups individually (fast), then batches the
        ONNX inference for URLs not in the cache.

        Args:
            raw_urls: List of raw URL strings.
            sender_app: Source app for all URLs in this batch.

        Returns:
            List of DetectionResult in the same order as input.
        """
        results: list[Optional[DetectionResult]] = [None] * len(raw_urls)
        unresolved_indices: list[int] = []
        unresolved_urls: list[str] = []

        # Pass 1: normalise + MongoDB lookup
        normalised: list[Optional[str]] = []
        for i, raw in enumerate(raw_urls):
            try:
                url = normalise(raw)
                normalised.append(url)
                cached = self._mysql.lookup(url)
                if cached:
                    results[i] = DetectionResult(cached, 0, ["mongodb_cache"])
                else:
                    unresolved_indices.append(i)
                    unresolved_urls.append(url)
            except UrlParseError:
                normalised.append(None)
                logger.warning(f"Invalid URL in batch (index {i}): {raw[:60]}")

        # Pass 2: batch ONNX inference for unresolved URLs
        if unresolved_urls:
            t0 = time.perf_counter()
            confidences = self._onnx.predict_batch(unresolved_urls)
            onnx_ms = (time.perf_counter() - t0) * 1000

            for idx, url, conf in zip(unresolved_indices, unresolved_urls, confidences):
                if conf is None:
                    conf = 0.5
                is_phishing = conf >= self._threshold
                record = UrlRecord(
                    url=url,
                    is_phishing=is_phishing,
                    confidence=conf,
                    detection_source="onnx_model",
                    sender_app=sender_app,
                )
                if is_phishing:
                    self._mysql.insert(record)
                results[idx] = DetectionResult(record, onnx_ms / len(unresolved_urls), ["onnx_model"])

        return [r for r in results if r is not None]
