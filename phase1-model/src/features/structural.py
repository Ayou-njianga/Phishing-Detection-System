"""
Structural feature extraction.

Structural features examine domain properties and URL architecture.
These do not make external network calls (WHOIS is in contextual.py).
"""
import re
from urllib.parse import urlparse

import tldextract

HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
    "loan", "win", "download", "stream", "racing", "review",
    "science", "party", "faith", "date", "men",
}

LEGITIMATE_DOMAINS = {
    "google", "facebook", "youtube", "amazon", "twitter",
    "instagram", "linkedin", "microsoft", "apple", "github",
}


def _count_redirects(path: str) -> int:
    """Estimate redirect depth by counting occurrences of http in the path."""
    return len(re.findall(r"https?://", path, re.I)) - 1


def _uses_ip(netloc: str) -> int:
    host = netloc.split(":")[0]
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    return int(bool(ip_pattern.match(host)))


def extract(url: str) -> dict:
    """
    Extract structural features from a URL.

    Args:
        url: Normalised URL string.

    Returns:
        Dictionary of feature name → numeric value.
    """
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
    except Exception:
        return {k: 0 for k in _feature_keys()}

    netloc = parsed.netloc or ""
    path = parsed.path or ""

    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    subdomain = ext.subdomain.lower()

    # Subdomain impersonation: subdomain contains a known brand name
    brand_in_subdomain = int(
        any(brand in subdomain for brand in LEGITIMATE_DOMAINS)
    )

    # Brand impersonation in domain (lookalike domains)
    brand_in_domain = int(
        any(brand in domain and domain != brand for brand in LEGITIMATE_DOMAINS)
    )

    return {
        "uses_ip_instead_of_domain": _uses_ip(netloc),
        "has_port": int(bool(parsed.port) and parsed.port not in {80, 443}),
        "redirect_depth": max(0, _count_redirects(path)),
        "tld_is_high_risk": int(suffix in HIGH_RISK_TLDS),
        "domain_has_brand_impersonation": brand_in_domain,
        "subdomain_has_brand": brand_in_subdomain,
        "domain_is_numeric": int(bool(re.match(r"^\d+$", domain))),
        "path_depth": path.count("/"),
        "query_param_count": len(parsed.query.split("&")) if parsed.query else 0,
        "has_fragment": int(bool(parsed.fragment)),
        "domain_part_count": len(ext.registered_domain.split(".")) if ext.registered_domain else 0,
    }


def _feature_keys():
    return extract("http://example.com").keys()
