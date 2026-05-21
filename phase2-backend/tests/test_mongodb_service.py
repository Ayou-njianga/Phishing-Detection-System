"""
Unit tests for MongoDBService.

Uses mongomock to simulate MongoDB without a real server.
"""
import pytest
from unittest.mock import MagicMock, patch
from app.models.url_record import UrlRecord


class TestUrlRecord:
    """Test the UrlRecord model independently."""

    def test_url_hash_computed_on_init(self):
        record = UrlRecord(
            url="http://phish.com",
            is_phishing=True,
            confidence=0.95,
            detection_source="onnx_model",
        )
        assert record.url_hash != ""
        assert len(record.url_hash) == 64  # SHA-256 hex

    def test_same_url_same_hash(self):
        h1 = UrlRecord.url_hash_for("http://phish.com")
        h2 = UrlRecord.url_hash_for("http://phish.com")
        assert h1 == h2

    def test_different_urls_different_hash(self):
        h1 = UrlRecord.url_hash_for("http://phish.com")
        h2 = UrlRecord.url_hash_for("http://legit.com")
        assert h1 != h2

    def test_to_response_excludes_internal_fields(self):
        record = UrlRecord(
            url="http://phish.com",
            is_phishing=True,
            confidence=0.95,
            detection_source="onnx_model",
        )
        resp = record.to_response()
        assert "url_hash" not in resp
        assert "first_seen" not in resp
        assert "is_phishing" in resp
        assert "confidence" in resp

    def test_confidence_rounded_in_response(self):
        record = UrlRecord(
            url="http://phish.com",
            is_phishing=True,
            confidence=0.94123456789,
            detection_source="onnx_model",
        )
        resp = record.to_response()
        # Should be rounded to 4 decimal places
        assert resp["confidence"] == round(0.94123456789, 4)

    def test_to_dict_contains_all_fields(self):
        record = UrlRecord(
            url="http://phish.com",
            is_phishing=True,
            confidence=0.9,
            detection_source="onnx_model",
        )
        d = record.to_dict()
        for field in ["url", "is_phishing", "confidence", "detection_source",
                      "url_hash", "first_seen", "last_seen"]:
            assert field in d


class TestMongoDBServiceWithMock:
    """Test MongoDBService logic with a mocked collection."""

    def _make_service(self):
        """Create a MongoDBService with a mocked internal collection."""
        from app.services.mongodb_service import MongoDBService
        svc = MongoDBService.__new__(MongoDBService)
        svc._collection = MagicMock()
        svc._client = MagicMock()
        return svc

    def test_lookup_returns_none_on_miss(self):
        svc = self._make_service()
        svc._collection.find_one.return_value = None
        result = svc.lookup("http://unknown.com")
        assert result is None

    def test_lookup_returns_record_on_hit(self):
        svc = self._make_service()
        svc._collection.find_one.return_value = {
            "url": "http://phish.com",
            "is_phishing": True,
            "confidence": 0.99,
            "detection_source": "mongodb_cache",
            "url_hash": UrlRecord.url_hash_for("http://phish.com"),
        }
        result = svc.lookup("http://phish.com")
        assert result is not None
        assert result.is_phishing is True
        assert result.detection_source == "mongodb_cache"

    def test_insert_calls_update_one(self):
        svc = self._make_service()
        record = UrlRecord(
            url="http://phish.com",
            is_phishing=True,
            confidence=0.95,
            detection_source="onnx_model",
        )
        svc.insert(record)
        svc._collection.update_one.assert_called_once()

    def test_count_returns_integer(self):
        svc = self._make_service()
        svc._collection.count_documents.return_value = 42
        assert svc.count() == 42

    def test_is_connected_true_when_collection_exists(self):
        svc = self._make_service()
        assert svc.is_connected is True

    def test_is_connected_false_when_collection_is_none(self):
        svc = self._make_service()
        svc._collection = None
        assert svc.is_connected is False

    def test_lookup_returns_none_when_not_connected(self):
        svc = self._make_service()
        svc._collection = None
        result = svc.lookup("http://phish.com")
        assert result is None
