"""
Unit tests for OnnxService.

The ONNX model file won't exist in the test environment,
so we test the graceful-degradation behaviour and feature extraction.
"""
import numpy as np
import pytest
from unittest.mock import MagicMock, patch
from app.utils.feature_extractor import extract, FEATURE_NAMES


class TestFeatureExtractor:
    """Test the runtime feature extractor used by OnnxService."""

    PHISHING_URL = "http://192.168.1.1/verify/login-account@paypal.com"
    LEGIT_URL = "https://www.google.com/search?q=test"

    def test_returns_correct_number_of_features(self):
        features = extract(self.LEGIT_URL)
        assert len(features) == len(FEATURE_NAMES)

    def test_all_features_are_floats(self):
        features = extract(self.LEGIT_URL)
        for i, f in enumerate(features):
            assert isinstance(f, float), f"Feature {FEATURE_NAMES[i]} is not float: {f}"

    def test_phishing_url_has_ip_address_feature(self):
        features = extract(self.PHISHING_URL)
        ip_idx = FEATURE_NAMES.index("has_ip_address")
        assert features[ip_idx] == 1.0

    def test_legit_url_has_https_feature(self):
        features = extract(self.LEGIT_URL)
        https_idx = FEATURE_NAMES.index("has_https")
        assert features[https_idx] == 1.0

    def test_suspicious_keywords_detected(self):
        url = "http://bank.com/verify/login"
        features = extract(url)
        kw_idx = FEATURE_NAMES.index("has_suspicious_keywords")
        assert features[kw_idx] == 1.0

    def test_no_nan_or_inf_values(self):
        features = extract(self.LEGIT_URL)
        arr = np.array(features)
        assert not np.any(np.isnan(arr)), "NaN in features"
        assert not np.any(np.isinf(arr)), "Inf in features"

    def test_malformed_url_returns_zeros(self):
        features = extract("not-a-url-at-all!!!")
        arr = np.array(features)
        # Should not crash and should return some valid values
        assert len(features) == len(FEATURE_NAMES)


class TestOnnxServiceDegradation:
    """Test that OnnxService degrades gracefully when the model file is missing."""

    def test_is_loaded_false_when_model_missing(self):
        from app.services.onnx_service import OnnxService
        with patch("app.services.onnx_service.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            svc = OnnxService.__new__(OnnxService)
            svc._session = None
            svc._input_name = None
            assert svc.is_loaded is False

    def test_predict_returns_none_when_not_loaded(self):
        from app.services.onnx_service import OnnxService
        svc = OnnxService.__new__(OnnxService)
        svc._session = None
        svc._input_name = None
        result = svc.predict("http://phish.com")
        assert result is None

    def test_predict_batch_returns_none_list_when_not_loaded(self):
        from app.services.onnx_service import OnnxService
        svc = OnnxService.__new__(OnnxService)
        svc._session = None
        svc._input_name = None
        urls = ["http://a.com", "http://b.com"]
        results = svc.predict_batch(urls)
        assert results == [None, None]

    def test_predict_with_mock_session(self):
        """Simulate a loaded session and verify predict() runs correctly."""
        from app.services.onnx_service import OnnxService
        svc = OnnxService.__new__(OnnxService)

        mock_session = MagicMock()
        mock_session.run.return_value = [np.array([[0.92]])]
        svc._session = mock_session
        svc._input_name = "url_features"

        result = svc.predict("http://phish.com")
        assert result is not None
        assert 0.0 <= result <= 1.0
        assert abs(result - 0.92) < 1e-6
