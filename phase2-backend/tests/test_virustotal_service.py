"""
Unit tests for VirusTotalService.

Uses the `responses` library to mock HTTP calls to the VT API
so no real API key is needed.
"""
import pytest
import responses as responses_lib
from app.services.virustotal_service import VirusTotalService, VirusTotalResult
from config.settings import settings


class TestVirusTotalResult:
    def test_is_phishing_true_when_malicious_count_above_threshold(self):
        result = VirusTotalResult(
            malicious_count=10,
            suspicious_count=2,
            total_engines=70,
            threat_names=["PhishURL"],
            permalink="",
        )
        assert result.is_phishing is True

    def test_is_phishing_false_when_below_threshold(self):
        result = VirusTotalResult(
            malicious_count=1,
            suspicious_count=0,
            total_engines=70,
            threat_names=[],
            permalink="",
        )
        assert result.is_phishing is False

    def test_confidence_proportional_to_engine_votes(self):
        result = VirusTotalResult(
            malicious_count=7,
            suspicious_count=0,
            total_engines=70,
            threat_names=[],
            permalink="",
        )
        assert abs(result.confidence - 0.1) < 1e-6

    def test_confidence_is_zero_when_no_engines(self):
        result = VirusTotalResult(
            malicious_count=0,
            suspicious_count=0,
            total_engines=0,
            threat_names=[],
            permalink="",
        )
        assert result.confidence == 0.5  # Default when no data

    def test_to_dict_has_required_keys(self):
        result = VirusTotalResult(5, 1, 70, ["Phish"], "http://vt.com")
        d = result.to_dict()
        for key in ["malicious_count", "total_engines", "is_phishing", "threat_names"]:
            assert key in d


class TestVirusTotalServiceConfiguration:
    def test_is_not_configured_when_no_api_key(self):
        svc = VirusTotalService.__new__(VirusTotalService)
        svc._api_key = ""
        svc._cache = {}
        from threading import Lock
        svc._cache_lock = Lock()
        assert svc.is_configured is False

    def test_is_configured_when_api_key_present(self):
        svc = VirusTotalService.__new__(VirusTotalService)
        svc._api_key = "fake-api-key-12345"
        svc._cache = {}
        from threading import Lock
        svc._cache_lock = Lock()
        assert svc.is_configured is True

    def test_check_returns_none_when_not_configured(self):
        svc = VirusTotalService.__new__(VirusTotalService)
        svc._api_key = ""
        svc._cache = {}
        from threading import Lock
        svc._cache_lock = Lock()
        result = svc.check("http://phish.com")
        assert result is None

    def test_cache_deduplication(self):
        """Same URL should only be queried once; second call hits cache."""
        from unittest.mock import MagicMock
        svc = VirusTotalService.__new__(VirusTotalService)
        svc._api_key = "fake-key"
        svc._base_url = settings.VIRUSTOTAL_BASE_URL
        svc._timeout = 5
        svc._cache = {}
        from threading import Lock
        svc._cache_lock = Lock()

        mock_result = VirusTotalResult(5, 0, 70, [], "")
        svc._query_virustotal = MagicMock(return_value=mock_result)

        svc.check("http://phish.com")
        svc.check("http://phish.com")  # Second call should hit cache

        svc._query_virustotal.assert_called_once()
        assert svc.cache_size() == 1

    def test_cache_size_increments(self):
        from unittest.mock import MagicMock
        svc = VirusTotalService.__new__(VirusTotalService)
        svc._api_key = "fake-key"
        svc._base_url = settings.VIRUSTOTAL_BASE_URL
        svc._timeout = 5
        svc._cache = {}
        from threading import Lock
        svc._cache_lock = Lock()
        svc._query_virustotal = MagicMock(return_value=None)

        svc.check("http://phish1.com")
        svc.check("http://phish2.com")
        assert svc.cache_size() == 2
