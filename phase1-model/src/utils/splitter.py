"""
Stratified train / validation / test splitting.

Uses stratified sampling to preserve class ratios across all three splits,
which is critical given the class imbalance common in phishing datasets.
"""
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from src.utils.logger import get_logger

logger = get_logger(__name__)


def split(
    df: pd.DataFrame,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_seed: int = 42,
    splits_dir: Path = None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split df into train / validation / test sets.

    Args:
        df: Cleaned DataFrame with columns [url, label, ...features...].
        test_size: Fraction of total data reserved for the test set.
        val_size: Fraction of total data reserved for the validation set.
        random_seed: Random state for reproducibility.
        splits_dir: If provided, write CSVs here.

    Returns:
        (train_df, val_df, test_df)
    """
    # First split off the test set
    train_val, test = train_test_split(
        df,
        test_size=test_size,
        stratify=df["label"],
        random_state=random_seed,
    )

    # Split the remaining data into train + validation
    # val_size is expressed as fraction of total, so adjust for the remaining portion
    adjusted_val = val_size / (1 - test_size)
    train, val = train_test_split(
        train_val,
        test_size=adjusted_val,
        stratify=train_val["label"],
        random_state=random_seed,
    )

    logger.info(
        f"Split sizes — train: {len(train)} | val: {len(val)} | test: {len(test)}"
    )
    for name, subset in [("train", train), ("val", val), ("test", test)]:
        phishing_pct = subset["label"].mean() * 100
        logger.info(f"  {name}: {len(subset)} rows, {phishing_pct:.1f}% phishing")

    if splits_dir is not None:
        splits_dir = Path(splits_dir)
        splits_dir.mkdir(parents=True, exist_ok=True)
        train.to_csv(splits_dir / "train.csv", index=False)
        val.to_csv(splits_dir / "val.csv", index=False)
        test.to_csv(splits_dir / "test.csv", index=False)
        logger.info(f"Splits saved to {splits_dir}")

    return train, val, test
