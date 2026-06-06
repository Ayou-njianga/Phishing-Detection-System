"""
MySQL service — fast phishing URL cache.

Responsibilities:
  - Connect to MySQL at startup using a connection pool.
  - Provide hash-indexed lookup for known phishing URLs (Layer 1 cache).
  - Insert newly confirmed phishing URLs to grow the cache.
  - Create the table and indexes on first connect if they don't exist.

Average lookup latency: ~3–5ms on localhost.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

import mysql.connector
from mysql.connector import pooling, Error as MySQLError

from app.models.url_record import UrlRecord
from config.settings import settings

logger = logging.getLogger("app.services.mysql")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS phishing_urls (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    url                 TEXT            NOT NULL,
    url_hash            VARCHAR(64)     NOT NULL,
    is_phishing         TINYINT(1)      NOT NULL DEFAULT 1,
    confidence          FLOAT           NOT NULL,
    detection_source    VARCHAR(50)     NOT NULL,
    vt_malicious_count  INT,
    vt_total_engines    INT,
    vt_threat_names     TEXT,
    first_seen          DATETIME        NOT NULL,
    last_seen           DATETIME        NOT NULL,
    sender_app          VARCHAR(100),
    sender_id           VARCHAR(100),
    UNIQUE KEY idx_url_hash (url_hash),
    INDEX      idx_url     (url(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


class MySQLService:
    """Wraps all MySQL interactions for the phishing URL cache."""

    def __init__(self):
        self._pool: Optional[pooling.MySQLConnectionPool] = None
        self._connect()

    # ── Connection ─────────────────────────────────────────────────────────────

    def _connect(self):
        try:
            self._pool = pooling.MySQLConnectionPool(
                pool_name="phishguard",
                pool_size=5,
                host=settings.MYSQL_HOST,
                port=settings.MYSQL_PORT,
                database=settings.MYSQL_DB,
                user=settings.MYSQL_USER,
                password=settings.MYSQL_PASSWORD,
                connection_timeout=settings.MYSQL_TIMEOUT_SEC,
                autocommit=True,
            )
            # Verify connection and create table + indexes on first run
            conn = self._pool.get_connection()
            cursor = conn.cursor()
            cursor.execute(_CREATE_TABLE)
            cursor.close()
            conn.close()
            logger.info(
                f"MySQL connected | host={settings.MYSQL_HOST}:{settings.MYSQL_PORT}"
                f" | db={settings.MYSQL_DB}"
            )
        except MySQLError as exc:
            logger.error(f"MySQL connection failed: {exc}")
            self._pool = None

    @property
    def is_connected(self) -> bool:
        return self._pool is not None

    # ── Lookup ─────────────────────────────────────────────────────────────────

    def lookup(self, url: str) -> Optional[UrlRecord]:
        """
        Check the cache for a previously classified URL.
        Uses SHA-256 url_hash for indexed O(1) lookup.
        """
        if not self.is_connected:
            logger.warning("MySQL not connected — skipping cache lookup")
            return None

        url_hash = UrlRecord.url_hash_for(url)
        try:
            conn = self._pool.get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM phishing_urls WHERE url_hash = %s LIMIT 1",
                (url_hash,),
            )
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            if row:
                logger.debug(f"MySQL cache hit: {url[:60]}")
                return self._row_to_record(row)
        except MySQLError as exc:
            logger.error(f"MySQL lookup error: {exc}")
        return None

    # ── Insert ─────────────────────────────────────────────────────────────────

    def insert(self, record: UrlRecord) -> bool:
        """
        Insert or update a phishing URL record.
        Uses INSERT … ON DUPLICATE KEY UPDATE to handle re-detections.
        """
        if not self.is_connected:
            return False

        try:
            conn = self._pool.get_connection()
            cursor = conn.cursor()
            vt_names = (
                ",".join(record.vt_threat_names) if record.vt_threat_names else None
            )
            cursor.execute(
                """
                INSERT INTO phishing_urls
                    (url, url_hash, is_phishing, confidence, detection_source,
                     vt_malicious_count, vt_total_engines, vt_threat_names,
                     first_seen, last_seen, sender_app, sender_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    is_phishing      = VALUES(is_phishing),
                    confidence       = VALUES(confidence),
                    detection_source = VALUES(detection_source),
                    last_seen        = VALUES(last_seen),
                    sender_app       = VALUES(sender_app)
                """,
                (
                    record.url[:2048],
                    record.url_hash,
                    int(record.is_phishing),
                    record.confidence,
                    record.detection_source,
                    record.vt_malicious_count,
                    record.vt_total_engines,
                    vt_names,
                    record.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                    record.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                    record.sender_app,
                    record.sender_id,
                ),
            )
            cursor.close()
            conn.close()
            logger.debug(f"MySQL upserted: {record.url[:60]}")
            return True
        except MySQLError as exc:
            logger.error(f"MySQL insert error: {exc}")
            return False

    def update_last_seen(self, url_hash: str):
        """Update the last_seen timestamp for an existing record."""
        if not self.is_connected:
            return
        try:
            conn = self._pool.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE phishing_urls SET last_seen = %s WHERE url_hash = %s",
                (
                    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    url_hash,
                ),
            )
            cursor.close()
            conn.close()
        except MySQLError as exc:
            logger.warning(f"MySQL update_last_seen error: {exc}")

    # ── Stats ──────────────────────────────────────────────────────────────────

    def count(self) -> int:
        """Return total number of records in the cache."""
        if not self.is_connected:
            return -1
        try:
            conn = self._pool.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM phishing_urls")
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            return result[0] if result else 0
        except MySQLError:
            return -1

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_record(row: dict) -> UrlRecord:
        """Convert a MySQL row dict to a UrlRecord."""
        vt_names_raw = row.get("vt_threat_names")
        return UrlRecord(
            url=row.get("url", ""),
            is_phishing=bool(row.get("is_phishing", True)),
            confidence=float(row.get("confidence", 1.0)),
            detection_source="mysql_cache",
            url_hash=row.get("url_hash", ""),
            vt_malicious_count=row.get("vt_malicious_count"),
            vt_total_engines=row.get("vt_total_engines"),
            vt_threat_names=(
                vt_names_raw.split(",") if vt_names_raw else None
            ),
            sender_app=row.get("sender_app"),
            sender_id=row.get("sender_id"),
        )
