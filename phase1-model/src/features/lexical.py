"""
Lexical feature extraction.

Lexical features are derived purely from the URL string itself,
without making any network requests.
"""
import math
import re
from collections import Counter
from urllib.parse import urlparse

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


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def _has_ip_address(netloc: str) -> int:
    """Return 1 if the host part looks like an IP address."""
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    host = netloc.split(":")[0]  # strip port
    return int(bool(ip_pattern.match(host)))


def extract(url: str) -> dict:
    """
    Extract lexical features from a single URL string.

    Args:
        url: Normalised URL string.

    Returns:
        Dictionary of feature name → numeric value.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return _zero_features()

    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = url

    domain_parts = netloc.split(".")
    domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else netloc
    subdomains = domain_parts[:-2] if len(domain_parts) > 2 else []

    lower_url = full.lower()
    kw_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)

    tld = "." + domain_parts[-1] if domain_parts else ""

    return {
        "url_length": len(full),
        "domain_length": len(domain),
        "path_length": len(path),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_underscores": full.count("_"),
        "num_slashes": full.count("/"),
        "num_at_symbols": full.count("@"),
        "num_question_marks": full.count("?"),
        "num_equals": full.count("="),
        "num_ampersands": full.count("&"),
        "num_digits": sum(c.isdigit() for c in full),
        "num_subdomains": len(subdomains),
        "subdomain_count": len(subdomains),
        "has_ip_address": _has_ip_address(netloc),
        "has_https": int(parsed.scheme == "https"),
        "has_port": int(":" in netloc and not netloc.endswith(":443") and not netloc.endswith(":80")),
        "has_suspicious_keywords": int(kw_hits > 0),
        "suspicious_keyword_count": kw_hits,
        "tld_in_suspicious_list": int(tld in SUSPICIOUS_TLDS),
        "url_entropy": round(_entropy(full), 4),
        "domain_entropy": round(_entropy(domain), 4),
        "path_contains_exe": int(
            bool(re.search(r"\.(exe|bat|cmd|sh|php|asp|js|jar)$", path.lower()))
        ),
        "has_double_slash_in_path": int("//" in path),
        "uses_url_shortener": int(
            bool(re.search(r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly)", lower_url))
        ),
    }


def _zero_features() -> dict:
    """Return a dict of zeros for a URL that cannot be parsed."""
    return {k: 0 for k in extract("http://example.com").keys()}
