"""
Master feature extractor.

Combines lexical, structural, and contextual features into a single
flat feature vector per URL.
"""
from pathlib import Path

import numpy as np
import pandas as pd
from tqdm import tqdm

from src.features import lexical, structural, contextual
from src.utils.logger import get_logger

logger = get_logger(__name__)


def extract_url(url: str, use_whois: bool = True) -> dict:
    """
    Extract all features for a single URL.

    Args:
        url: Normalised URL string.
        use_whois: Whether to perform WHOIS lookups.

    Returns:
        Flat dictionary of all features.
    """
    features = {}
    features.update(lexical.extract(url))
    features.update(structural.extract(url))
    features.update(contextual.extract(url, use_whois=use_whois))
    return features


def extract_dataframe(
    df: pd.DataFrame,
    use_whois: bool = False,
    processed_dir: Path = None,
) -> pd.DataFrame:
    """
    Extract features for every URL in a DataFrame.

    Args:
        df: DataFrame with at minimum columns [url, label].
        use_whois: Whether to run WHOIS lookups (slow; disable for fast runs).
        processed_dir: If provided, save the feature CSV here.

    Returns:
        DataFrame with original columns plus all extracted features.
    """
    logger.info(f"Extracting features for {len(df)} URLs (use_whois={use_whois})")

    feature_rows = []
    for url in tqdm(df["url"], desc="Feature extraction", unit="url"):
        feature_rows.append(extract_url(url, use_whois=use_whois))

    feat_df = pd.DataFrame(feature_rows)
    result = pd.concat([df.reset_index(drop=True), feat_df], axis=1)

    logger.info(f"Extracted {len(feat_df.columns)} features per URL")

    if processed_dir is not None:
        processed_dir = Path(processed_dir)
        processed_dir.mkdir(parents=True, exist_ok=True)
        out = processed_dir / "features.csv"
        result.to_csv(out, index=False)
        logger.info(f"Saved feature matrix to {out}")

    return result


def get_feature_columns(df: pd.DataFrame) -> list[str]:
    """Return the list of feature column names (excludes url and label)."""
    return [c for c in df.columns if c not in {"url", "label"}]


def to_numpy(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """
    Convert a feature DataFrame to X, y numpy arrays.

    Returns:
        (X, y) where X is float32 and y is int32.
    """
    feature_cols = get_feature_columns(df)
    X = df[feature_cols].values.astype(np.float32)
    y = df["label"].values.astype(np.int32)
    return X, y
