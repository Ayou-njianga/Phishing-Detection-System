"""
Master feature extractor.

Combines lexical, structural, and contextual features into a single
flat feature vector per URL.
"""
from pathlib import Path

import numpy as np
import pandas as pd
from tqdm import tqdm

from src.features import lexical, structural
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Must match FEATURE_NAMES in phase2-backend/app/utils/feature_extractor.py exactly.
EXPECTED_FEATURE_COUNT = 36


def extract_url(url: str) -> dict:
    """
    Extract all features for a single URL.

    Returns 36 lexical + structural features that match the ONNX model's
    expected input vector. WHOIS/contextual features are intentionally excluded
    because phase2-backend cannot perform WHOIS lookups within latency budget.

    Args:
        url: Normalised URL string.

    Returns:
        Flat dictionary of 36 feature name → numeric value pairs.
    """
    features = {}
    features.update(lexical.extract(url))
    features.update(structural.extract(url))
    assert len(features) == EXPECTED_FEATURE_COUNT, (
        f"Feature count mismatch: got {len(features)}, expected {EXPECTED_FEATURE_COUNT}. "
        "Check that lexical.py and structural.py keys are consistent with FEATURE_NAMES "
        "in phase2-backend/app/utils/feature_extractor.py."
    )
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
        use_whois: Deprecated — WHOIS features are excluded from the model input
            vector for runtime compatibility with phase2-backend. This parameter
            is accepted but ignored.
        processed_dir: If provided, save the feature CSV here.

    Returns:
        DataFrame with original columns plus all 36 extracted features.
    """
    if use_whois:
        logger.warning(
            "use_whois=True was requested but WHOIS features are excluded from the "
            "model input vector (phase2-backend cannot perform WHOIS lookups within "
            "the latency budget). Pass --skip-whois to suppress this warning."
        )
    logger.info(f"Extracting features for {len(df)} URLs")

    feature_rows = []
    for url in tqdm(df["url"], desc="Feature extraction", unit="url"):
        feature_rows.append(extract_url(url))

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
