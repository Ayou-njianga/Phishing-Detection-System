"""
Contextual feature extraction.

Contextual features require external lookups (WHOIS).
These are cached to avoid hammering WHOIS servers during bulk processing.
"""
import datetime
from functools import lru_cache
from urllib.parse import urlparse

import tldextract
import whois

from src.utils.logger import get_logger

logger = get_logger(__name__)

_RECENTLY_REGISTERED_THRESHOLD_DAYS = 30
_VERY_NEW_THRESHOLD_DAYS = 7


@lru_cache(maxsize=4096)
def _whois_lookup(domain: str) -> dict:
    """
    Perform a WHOIS lookup for a domain and return relevant fields.
    Results are cached per domain to minimise network calls.
    """
    result = {
        "domain_age_days": -1,
        "recently_registered": 1,
        "very_new_domain": 1,
        "whois_available": 0,
    }
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime.datetime):
            age = (datetime.datetime.utcnow() - creation_date).days
            result["domain_age_days"] = age
            result["recently_registered"] = int(age < _RECENTLY_REGISTERED_THRESHOLD_DAYS)
            result["very_new_domain"] = int(age < _VERY_NEW_THRESHOLD_DAYS)
            result["whois_available"] = 1
    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {domain}: {e}")
    return result


def extract(url: str, use_whois: bool = True) -> dict:
    """
    Extract contextual features from a URL.

    Args:
        url: Normalised URL string.
        use_whois: If False, skip WHOIS lookups (faster, less accurate).

    Returns:
        Dictionary of feature name → numeric value.
    """
    try:
        ext = tldextract.extract(url)
        registered_domain = ext.registered_domain
    except Exception:
        registered_domain = None

    if not registered_domain or not use_whois:
        return {
            "domain_age_days": -1,
            "recently_registered": 1,
            "very_new_domain": 1,
            "whois_available": 0,
        }

    return _whois_lookup(registered_domain)
