"""
Runtime feature extractor for the backend.

Mirrors the feature set from Phase 1 so the ONNX model receives
identically structured input vectors at inference time.

This file is intentionally self-contained (no imports from phase1-model)
so the backend can be deployed without the training codebase.
"""
import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract


# ── Constants (kept in sync with phase1-model/src/features/) ──────────────────

SUSPICIOUS_KEYWORDS = [
    "verify", "login", "secure", "account", "update", "banking",
    "confirm", "password", "credential", "signin", "paypal", "ebay",
    "amazon", "apple", "google", "microsoft", "support", "free",
    "click", "alert", "suspend", "access", "billing",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".loan", ".win", ".download", ".stream",
}

HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
    "loan", "win", "download", "stream", "racing", "review",
    "science", "party", "faith", "date", "men",
}

LEGITIMATE_DOMAINS = {
    "google", "facebook", "youtube", "amazon", "twitter",
    "instagram", "linkedin", "microsoft", "apple", "github",
}

URL_SHORTENERS = re.compile(r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly)", re.I)
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# ── Helper functions ───────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def _has_ip(netloc: str) -> int:
    host = netloc.split(":")[0]
    return int(bool(IP_PATTERN.match(host)))


def _count_redirects(path: str) -> int:
    return max(0, len(re.findall(r"https?://", path, re.I)) - 1)


# ── Main extraction function ───────────────────────────────────────────────────

def extract(url: str) -> list[float]:
    """
    Extract the full feature vector from a URL.

    The order and count of features MUST match what the ONNX model was
    trained on. Do not reorder without retraining the model.

    Args:
        url: Normalised URL string.

    Returns:
        List of floats representing the feature vector.
    """
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
    except Exception:
        return [0.0] * len(FEATURE_NAMES)

    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    lower_url = url.lower()

    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    subdomain = ext.subdomain.lower()

    domain_parts = netloc.split(".")
    kw_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)
    tld_str = "." + domain_parts[-1] if domain_parts else ""

    features = [
        # ── Lexical features ──────────────────────────────────────────────────
        float(len(url)),                                            # url_length
        float(len(domain)),                                         # domain_length
        float(len(path)),                                           # path_length
        float(url.count(".")),                                      # num_dots
        float(url.count("-")),                                      # num_hyphens
        float(url.count("_")),                                      # num_underscores
        float(url.count("/")),                                      # num_slashes
        float(url.count("@")),                                      # num_at_symbols
        float(url.count("?")),                                      # num_question_marks
        float(url.count("=")),                                      # num_equals
        float(url.count("&")),                                      # num_ampersands
        float(sum(c.isdigit() for c in url)),                       # num_digits
        float(len(subdomain.split(".")) if subdomain else 0),       # num_subdomains
        float(len(subdomain.split(".")) if subdomain else 0),       # subdomain_count
        float(_has_ip(netloc)),                                     # has_ip_address
        float(parsed.scheme == "https"),                            # has_https
        float(bool(parsed.port) and parsed.port not in {80, 443}), # has_port
        float(kw_hits > 0),                                         # has_suspicious_keywords
        float(kw_hits),                                             # suspicious_keyword_count
        float(tld_str in SUSPICIOUS_TLDS),                          # tld_in_suspicious_list
        float(round(_entropy(url), 4)),                             # url_entropy
        float(round(_entropy(domain), 4)),                          # domain_entropy
        float(bool(re.search(r"\.(exe|bat|cmd|sh|php|asp|js|jar)$", path.lower()))),  # path_contains_exe
        float("//" in path),                                        # has_double_slash_in_path
        float(bool(URL_SHORTENERS.search(lower_url))),              # uses_url_shortener

        # ── Structural features ───────────────────────────────────────────────
        float(_has_ip(netloc)),                                     # uses_ip_instead_of_domain
        float(bool(parsed.port) and parsed.port not in {80, 443}), # has_port (structural)
        float(_count_redirects(path)),                              # redirect_depth
        float(suffix in HIGH_RISK_TLDS),                            # tld_is_high_risk
        float(any(b in domain and domain != b for b in LEGITIMATE_DOMAINS)),  # domain_has_brand_impersonation
        float(any(b in subdomain for b in LEGITIMATE_DOMAINS)),     # subdomain_has_brand
        float(bool(re.match(r"^\d+$", domain))),                    # domain_is_numeric
        float(path.count("/")),                                     # path_depth
        float(len(query.split("&")) if query else 0),               # query_param_count
        float(bool(parsed.fragment)),                               # has_fragment
        float(len(ext.registered_domain.split(".")) if ext.registered_domain else 0),  # domain_part_count
    ]

    return features


# Ordered list of feature names — used for validation and debugging
FEATURE_NAMES = [
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
