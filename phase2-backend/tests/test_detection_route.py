"""
Integration tests for the /api/v1/detect endpoint.

Uses Flask test client with mocked services so no real MongoDB,
ONNX model, or VirusTotal API key is required.
"""
import pytest
from unittest.mock import MagicMock, patch
from app import create_app
from app.models.url_record import UrlRecord
from app.services.detection_service import DetectionResult


@pytest.fixture
def app():
    """Create app with test config and mocked services."""
    application = create_app(test_config={
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "ONNX_MODEL_PATH": "/nonexistent/model.onnx",
        "VIRUSTOTAL_API_KEY": "",
    })

    # Replace real services with mocks
    mock_record = UrlRecord(
        url="http://phish.example.com",
        is_phishing=True,
        confidence=0.94,
        detection_source="onnx_model",
    )
    mock_result = DetectionResult(mock_record, latency_ms=45.2, pipeline_stages=["onnx_model"])

    mock_detection = MagicMock()
    mock_detection.analyse.return_value = mock_result
    mock_detection.analyse_batch.return_value = [mock_result]

    application.extensions["detection"] = mock_detection
    application.extensions["mongodb"] = MagicMock(is_connected=True, count=lambda: 10)
    application.extensions["onnx"] = MagicMock(is_loaded=True)
    application.extensions["virustotal"] = MagicMock(is_configured=False, cache_size=lambda: 0)

    return application


@pytest.fixture
def client(app):
    return app.test_client()


class TestDetectEndpoint:
    def test_detect_returns_200_for_valid_url(self, client):
        resp = client.post("/api/v1/detect", json={"url": "http://phish.example.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "is_phishing" in data["data"]

    def test_detect_returns_400_for_missing_url(self, client):
        resp = client.post("/api/v1/detect", json={})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["status"] == "error"
        assert data["error"]["code"] == "missing_url"

    def test_detect_returns_400_for_empty_body(self, client):
        resp = client.post("/api/v1/detect", data="", content_type="application/json")
        assert resp.status_code == 400

    def test_detect_returns_400_for_empty_url(self, client):
        resp = client.post("/api/v1/detect", json={"url": "   "})
        assert resp.status_code == 400

    def test_detect_includes_latency_ms(self, client):
        resp = client.post("/api/v1/detect", json={"url": "http://phish.example.com"})
        data = resp.get_json()
        assert "latency_ms" in data
        assert data["latency_ms"] >= 0

    def test_detect_accepts_sender_metadata(self, client):
        resp = client.post("/api/v1/detect", json={
            "url": "http://phish.example.com",
            "sender_app": "whatsapp",
            "sender_id": "abc123",
        })
        assert resp.status_code == 200


class TestDetectBatchEndpoint:
    def test_batch_returns_200_for_valid_urls(self, client):
        resp = client.post("/api/v1/detect/batch", json={
            "urls": ["http://phish.example.com", "https://google.com"]
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "results" in data["data"]

    def test_batch_returns_400_for_missing_urls(self, client):
        resp = client.post("/api/v1/detect/batch", json={})
        assert resp.status_code == 400

    def test_batch_returns_400_for_too_many_urls(self, client):
        urls = [f"http://example{i}.com" for i in range(21)]
        resp = client.post("/api/v1/detect/batch", json={"urls": urls})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"]["code"] == "too_many_urls"

    def test_batch_returns_total_count(self, client):
        resp = client.post("/api/v1/detect/batch", json={
            "urls": ["http://phish.example.com"]
        })
        data = resp.get_json()
        assert "total" in data["data"]
        assert "phishing_count" in data["data"]


class TestHealthEndpoints:
    def test_health_returns_200(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_health_detail_returns_services(self, client):
        resp = client.get("/api/v1/health/detail")
        data = resp.get_json()
        assert "services" in data
        assert "mongodb" in data["services"]
        assert "onnx_model" in data["services"]
        assert "virustotal" in data["services"]
