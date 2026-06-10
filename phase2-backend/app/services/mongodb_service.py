"""
MongoDB service — fast phishing URL cache.

Responsibilities:
  - Connect to MongoDB at startup (with retry logic).
  - Provide O(1) hash-indexed lookup for known phishing URLs.
  - Insert newly confirmed phishing URLs to grow the cache.
  - Ensure required indexes exist on the collection.

Average lookup latency: ~3ms (per paper benchmarks).
"""
import logging
from datetime import datetime, timezone
from typing import Optional

import pymongo
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure, OperationFailure

from app.models.url_record import UrlRecord
from config.settings import settings

logger = logging.getLogger("app.services.mongodb")


class MongoDBService:
    """Wraps all MongoDB interactions for the phishing URL cache."""

    def __init__(self):
        self._client: Optional[MongoClient] = None
        self._collection: Optional[Collection] = None
        self._connect()

    # ── Connection ─────────────────────────────────────────────────────────────

    def _connect(self):
        """Establish connection and ensure indexes exist."""
        try:
            self._client = MongoClient(
                settings.MONGO_URI,
                serverSelectionTimeoutMS=settings.MONGO_TIMEOUT_MS,
                connectTimeoutMS=settings.MONGO_TIMEOUT_MS,
            )
            # Trigger actual connection check
            self._client.admin.command("ping")

            db = self._client[settings.MONGO_DB_NAME]
            self._collection = db[settings.MONGO_COLLECTION_PHISHING]
            self._ensure_indexes()

            logger.info(
                f"MongoDB connected | db={settings.MONGO_DB_NAME} "
                f"| collection={settings.MONGO_COLLECTION_PHISHING}"
            )
        except ConnectionFailure as exc:
            logger.error(f"MongoDB connection failed: {exc}")
            # Don't crash the server — the detection pipeline degrades gracefully
            self._collection = None

    def _ensure_indexes(self):
        """Create indexes required for fast URL lookups."""
        if self._collection is None:
            return
        # Primary lookup: hash index (unique, used for dedup and cache hits)
        self._collection.create_index(
            [("url_hash", pymongo.ASCENDING)],
            unique=True,
            name="idx_url_hash",
        )
        # Secondary: lookup by raw URL string
        self._collection.create_index(
            [("url", pymongo.ASCENDING)],
            name="idx_url",
        )
        # TTL index: optionally expire very old entries (90 days)
        self._collection.create_index(
            [("first_seen", pymongo.ASCENDING)],
            expireAfterSeconds=60 * 60 * 24 * 90,
            name="idx_ttl_first_seen",
        )
        logger.debug("MongoDB indexes ensured")

    @property
    def is_connected(self) -> bool:
        return self._collection is not None

    # ── Lookup ─────────────────────────────────────────────────────────────────

    def lookup(self, url: str) -> Optional[UrlRecord]:
        """
        Check the cache for a previously classified URL.

        Uses the SHA-256 hash for O(1) indexed lookup.

        Args:
            url: Normalised URL string.

        Returns:
            UrlRecord if the URL is in the cache, None otherwise.
        """
        if not self.is_connected:
            logger.warning("MongoDB not connected — skipping cache lookup")
            return None

        url_hash = UrlRecord.url_hash_for(url)
        try:
            doc = self._collection.find_one({"url_hash": url_hash})
            if doc:
                logger.debug(f"MongoDB cache hit: {url[:60]}")
                return self._doc_to_record(doc)
        except OperationFailure as exc:
            logger.error(f"MongoDB lookup error: {exc}")
        return None

    # ── Insert ─────────────────────────────────────────────────────────────────

    def insert(self, record: UrlRecord) -> bool:
        """
        Insert a new phishing URL record into the cache.

        Silently ignores duplicate URLs (upsert on url_hash).

        Args:
            record: UrlRecord to store.

        Returns:
            True if inserted or updated, False on error.
        """
        if not self.is_connected:
            return False

        try:
            doc = record.to_dict()
            # Exclude first_seen from $set — it must only appear in $setOnInsert.
            # MongoDB rejects the same field in both operators (error code 40).
            update_fields = {k: v for k, v in doc.items() if k != "first_seen"}
            self._collection.update_one(
                {"url_hash": record.url_hash},
                {
                    "$set": update_fields,
                    "$setOnInsert": {"first_seen": record.first_seen.isoformat()},
                },
                upsert=True,
            )
            logger.debug(f"MongoDB upserted: {record.url[:60]}")
            return True
        except Exception as exc:
            logger.error(f"MongoDB insert error: {exc}")
            return False

    def update_last_seen(self, url_hash: str):
        """Update the last_seen timestamp for an existing record."""
        if not self.is_connected:
            return
        try:
            self._collection.update_one(
                {"url_hash": url_hash},
                {"$set": {"last_seen": datetime.now(timezone.utc).isoformat()}},
            )
        except Exception as exc:
            logger.warning(f"MongoDB update_last_seen error: {exc}")

    # ── Stats ──────────────────────────────────────────────────────────────────

    def count(self) -> int:
        """Return total number of records in the cache."""
        if not self.is_connected:
            return -1
        try:
            return self._collection.count_documents({})
        except Exception:
            return -1

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _doc_to_record(doc: dict) -> UrlRecord:
        """Convert a raw MongoDB document to a UrlRecord."""
        return UrlRecord(
            url=doc.get("url", ""),
            is_phishing=doc.get("is_phishing", True),
            confidence=doc.get("confidence", 1.0),
            detection_source="mongodb_cache",
            url_hash=doc.get("url_hash", ""),
            vt_malicious_count=doc.get("vt_malicious_count"),
            vt_total_engines=doc.get("vt_total_engines"),
            vt_threat_names=doc.get("vt_threat_names"),
            sender_app=doc.get("sender_app"),
            sender_id=doc.get("sender_id"),
        )
