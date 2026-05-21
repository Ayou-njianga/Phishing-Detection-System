"""
Data model for a URL classification record stored in MongoDB.

Kept as a plain dataclass (no ODM) to avoid heavy dependencies
and keep the data layer simple and fast.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class UrlRecord:
    """
    Represents one analysed URL and its classification result.

    Stored in MongoDB phishing_urls collection.
    Used as the canonical data structure throughout the pipeline.
    """
    url: str
    is_phishing: bool
    confidence: float                      # Model output probability (0.0 – 1.0)
    detection_source: str                  # "mongodb_cache" | "onnx_model" | "virustotal"
    url_hash: str = field(default="")     # SHA-256 of the URL for fast indexed lookup

    # VirusTotal supplementary data (populated only when VT was queried)
    vt_malicious_count: Optional[int] = None
    vt_total_engines: Optional[int] = None
    vt_threat_names: Optional[list[str]] = None

    # Timestamps
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Sender metadata forwarded from the Android app
    sender_app: Optional[str] = None      # e.g. "whatsapp", "instagram", "sms"
    sender_id: Optional[str] = None       # Hashed sender identifier

    def __post_init__(self):
        if not self.url_hash:
            self.url_hash = hashlib.sha256(self.url.encode()).hexdigest()

    def to_dict(self) -> dict:
        """Serialise to a MongoDB-compatible dictionary."""
        d = asdict(self)
        # Convert datetime to ISO string for JSON serialisation
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d

    def to_response(self) -> dict:
        """
        Produce the JSON response body sent back to the Android client.
        Excludes internal fields not needed by the mobile app.
        """
        return {
            "url": self.url,
            "is_phishing": self.is_phishing,
            "confidence": round(self.confidence, 4),
            "detection_source": self.detection_source,
            "vt_malicious_count": self.vt_malicious_count,
            "vt_total_engines": self.vt_total_engines,
            "sender_app": self.sender_app,
        }

    @staticmethod
    def url_hash_for(url: str) -> str:
        """Compute the SHA-256 hash of a URL (used for MongoDB queries)."""
        return hashlib.sha256(url.encode()).hexdigest()
