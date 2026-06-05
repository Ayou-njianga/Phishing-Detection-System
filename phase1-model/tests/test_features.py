"""Tests for feature extraction modules."""
import pandas as pd
from src.features import lexical, structural
from src.features.extractor import extract_url


PHISHING_URL = "http://192.168.1.1/verify/login-account@paypal.com?update=true"
LEGIT_URL = "https://www.google.com/search?q=hello"
SHORT_URL = "http://bit.ly/abc123"


class TestLexical:
    def test_phishing_url_high_length(self):
        feat = lexical.extract(PHISHING_URL)
        assert feat["url_length"] > 40

    def test_phishing_url_has_suspicious_keywords(self):
        feat = lexical.extract(PHISHING_URL)
        assert feat["has_suspicious_keywords"] == 1

    def test_phishing_url_has_at_symbol(self):
        feat = lexical.extract(PHISHING_URL)
        assert feat["num_at_symbols"] == 1

    def test_legit_url_has_https(self):
        feat = lexical.extract(LEGIT_URL)
        assert feat["has_https"] == 1

    def test_url_shortener_detected(self):
        feat = lexical.extract(SHORT_URL)
        assert feat["uses_url_shortener"] == 1

    def test_ip_address_detected(self):
        feat = lexical.extract(PHISHING_URL)
        assert feat["has_ip_address"] == 1

    def test_all_values_are_numeric(self):
        feat = lexical.extract(LEGIT_URL)
        for k, v in feat.items():
            assert isinstance(v, (int, float)), f"{k} is not numeric: {v}"


class TestStructural:
    def test_ip_instead_of_domain(self):
        feat = structural.extract(PHISHING_URL)
        assert feat["uses_ip_instead_of_domain"] == 1

    def test_legit_url_no_brand_impersonation(self):
        feat = structural.extract(LEGIT_URL)
        assert feat["domain_has_brand_impersonation"] == 0

    def test_brand_impersonation_detected(self):
        fake = "http://paypal-login.evil.com/verify"
        feat = structural.extract(fake)
        assert feat["subdomain_has_brand"] == 1 or feat["domain_has_brand_impersonation"] == 1

    def test_all_values_are_numeric(self):
        feat = structural.extract(LEGIT_URL)
        for k, v in feat.items():
            assert isinstance(v, (int, float)), f"{k} is not numeric: {v}"


class TestExtractor:
    def test_extract_url_returns_dict(self):
        feat = extract_url(LEGIT_URL)
        assert isinstance(feat, dict)
        assert len(feat) == 36

    def test_extract_url_feature_names_match_phase2(self):
        """Feature keys must match FEATURE_NAMES in phase2-backend exactly."""
        from src.features.extractor import EXPECTED_FEATURE_COUNT
        feat = extract_url(LEGIT_URL)
        assert len(feat) == EXPECTED_FEATURE_COUNT
        expected_keys = [
            "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
            "num_underscores", "num_slashes", "num_at_symbols", "num_question_marks",
            "num_equals", "num_ampersands", "num_digits", "num_subdomains",
            "subdomain_count", "has_ip_address", "has_https", "has_port",
            "has_suspicious_keywords", "suspicious_keyword_count", "tld_in_suspicious_list",
            "url_entropy", "domain_entropy", "path_contains_exe", "has_double_slash_in_path",
            "uses_url_shortener", "uses_ip_instead_of_domain", "has_port_structural",
            "redirect_depth", "tld_is_high_risk", "domain_has_brand_impersonation",
            "subdomain_has_brand", "domain_is_numeric", "path_depth",
            "query_param_count", "has_fragment", "domain_part_count",
        ]
        assert list(feat.keys()) == expected_keys, (
            f"Feature key mismatch.\nGot:      {list(feat.keys())}\nExpected: {expected_keys}"
        )

    def test_extract_dataframe_shape(self):
        df = pd.DataFrame({"url": [LEGIT_URL, PHISHING_URL], "label": [0, 1]})
        from src.features.extractor import extract_dataframe
        result = extract_dataframe(df)
        assert len(result) == 2
        assert "label" in result.columns
        assert len(result.columns) == 38  # url + label + 36 features

    def test_no_nan_features(self):
        feat = extract_url(LEGIT_URL)
        for k, v in feat.items():
            assert v is not None, f"Feature {k} is None"
