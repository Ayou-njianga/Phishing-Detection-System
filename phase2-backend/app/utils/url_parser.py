"""
URL parsing and validation utilities.

Provides a single validated entry point for URL normalisation
before any feature extraction or database lookup is performed.
"""
import re
from urllib.parse import urlparse, urlunparse


MAX_URL_LENGTH = 2048

_VALID_SCHEMES = {"http", "https"}

_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


class UrlParseError(ValueError):
    """Raised when a URL cannot be parsed or is obviously invalid."""
    pass


def normalise(url: str) -> str:
    """
    Normalise a URL to a canonical form.

    Steps:
      - Strip leading/trailing whitespace.
      - Lowercase scheme and host.
      - Remove default ports (80 for http, 443 for https).
      - Remove trailing slashes from path.

    Args:
        url: Raw URL string from the Android notification.

    Returns:
        Normalised URL string.

    Raises:
        UrlParseError: If the URL is malformed or uses an unsupported scheme.
    """
    if not url or not isinstance(url, str):
        raise UrlParseError("URL must be a non-empty string")

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        raise UrlParseError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters")

    # Add scheme if missing so urlparse works correctly
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise UrlParseError(f"URL parse failed: {exc}") from exc

    if parsed.scheme not in _VALID_SCHEMES:
        raise UrlParseError(f"Unsupported URL scheme: {parsed.scheme!r}")

    if not parsed.netloc:
        raise UrlParseError("URL has no host")

    # Lowercase scheme and host
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Strip trailing slashes from path
    path = parsed.path.rstrip("/") or ""

    normalised = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
    return normalised


def extract_urls_from_text(text: str) -> list[str]:
    """
    Extract all URLs found in free text (e.g. a notification body).

    Args:
        text: Raw notification text string.

    Returns:
        List of raw URL strings (not yet normalised).
    """
    url_pattern = re.compile(
        r"https?://[^\s\"'<>]+|"          # explicit http/https URLs
        r"(?<!\w)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s\"'<>]*)?",  # bare domains
        re.IGNORECASE,
    )
    return url_pattern.findall(text or "")


def is_ip_based(url: str) -> bool:
    """Return True if the URL host is a raw IP address (not a domain name)."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return bool(_IP_PATTERN.match(host))
    except Exception:
        return False
