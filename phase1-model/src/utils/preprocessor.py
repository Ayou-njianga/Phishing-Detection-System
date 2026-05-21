"""
Clean and normalise raw URL data before feature extraction.

Steps:
  1. Remove duplicate URLs.
  2. Normalise URL format (lowercase, strip trailing slashes).
  3. Drop corrupted or clearly invalid entries.
  4. Drop rows with missing values.
"""
import re
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)

# URLs that are clearly not real (used in placeholder/test datasets)
_PLACEHOLDER_PATTERN = re.compile(r"(localhost|127\.0\.0\.1|example\.com|test\.com)", re.I)


def _is_valid_url(url: str) -> bool:
    """Return True if url has a parsable scheme and netloc."""
    try:
        parsed = urlparse(str(url))
        return bool(parsed.scheme in {"http", "https"} and parsed.netloc)
    except Exception:
        return False


def normalise_url(url: str) -> str:
    """Lowercase the URL and strip trailing slashes and whitespace."""
    url = str(url).strip().lower()
    url = url.rstrip("/")
    return url


def clean(df: pd.DataFrame, processed_dir: Path = None) -> pd.DataFrame:
    """
    Apply all cleaning steps to a raw URL DataFrame.

    Args:
        df: DataFrame with columns [url, label].
        processed_dir: If provided, save the cleaned CSV here.

    Returns:
        Cleaned DataFrame.
    """
    initial_len = len(df)
    logger.info(f"Starting preprocessing: {initial_len} rows")

    # Drop nulls
    df = df.dropna(subset=["url", "label"])
    logger.info(f"After null drop: {len(df)} rows")

    # Normalise
    df["url"] = df["url"].map(normalise_url)

    # Drop duplicates (keep first occurrence)
    df = df.drop_duplicates(subset=["url"])
    logger.info(f"After dedup: {len(df)} rows")

    # Drop invalid URLs
    valid_mask = df["url"].map(_is_valid_url)
    df = df[valid_mask]
    logger.info(f"After validity filter: {len(df)} rows")

    # Drop placeholder / test URLs
    placeholder_mask = df["url"].str.contains(_PLACEHOLDER_PATTERN, na=False)
    df = df[~placeholder_mask]
    logger.info(f"After placeholder filter: {len(df)} rows")

    # Ensure label is integer
    df["label"] = df["label"].astype(int)

    logger.info(
        f"Preprocessing complete. Kept {len(df)}/{initial_len} rows. "
        f"phishing={df['label'].sum()} | legitimate={(df['label'] == 0).sum()}"
    )

    if processed_dir is not None:
        processed_dir = Path(processed_dir)
        processed_dir.mkdir(parents=True, exist_ok=True)
        out = processed_dir / "urls_clean.csv"
        df.to_csv(out, index=False)
        logger.info(f"Saved cleaned data to {out}")

    return df.reset_index(drop=True)
