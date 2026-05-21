"""Tests for URL preprocessing."""
import pandas as pd
import pytest
from src.utils.preprocessor import clean, normalise_url, _is_valid_url


class TestNormalise:
    def test_lowercases_url(self):
        assert normalise_url("HTTP://GOOGLE.COM/") == "http://google.com"

    def test_strips_trailing_slash(self):
        assert normalise_url("https://example.com/") == "https://example.com"

    def test_strips_whitespace(self):
        assert normalise_url("  https://example.com  ") == "https://example.com"


class TestValidUrl:
    def test_valid_http(self):
        assert _is_valid_url("http://google.com") is True

    def test_valid_https(self):
        assert _is_valid_url("https://bank.com/login") is True

    def test_invalid_no_scheme(self):
        assert _is_valid_url("google.com") is False

    def test_invalid_ftp(self):
        assert _is_valid_url("ftp://files.example.com") is False


class TestClean:
    def _make_df(self, urls, labels=None):
        if labels is None:
            labels = [1] * len(urls)
        return pd.DataFrame({"url": urls, "label": labels})

    def test_removes_duplicates(self):
        df = self._make_df(["http://phish.com", "http://phish.com"])
        result = clean(df)
        assert len(result) == 1

    def test_removes_invalid_urls(self):
        df = self._make_df(["not-a-url", "http://valid.com"])
        result = clean(df)
        assert len(result) == 1
        assert result.iloc[0]["url"] == "http://valid.com"

    def test_removes_placeholder_urls(self):
        df = self._make_df(["http://example.com/phish", "http://phish.com"])
        result = clean(df)
        assert len(result) == 1

    def test_normalises_urls(self):
        df = self._make_df(["HTTP://PHISH.COM/"])
        result = clean(df)
        assert result.iloc[0]["url"] == "http://phish.com"
