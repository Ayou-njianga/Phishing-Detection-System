"""
Download and load raw phishing / legitimate URL datasets.

Sources:
  - PhishTank  : https://data.phishtank.com/data/online-valid.csv
  - OpenPhish  : https://openphish.com/feed.txt
  - Alexa top 1M : https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
"""
import io
import zipfile
from pathlib import Path

import pandas as pd
import requests

from src.utils.logger import get_logger

logger = get_logger(__name__)

PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"
OPENPHISH_URL = "https://openphish.com/feed.txt"
ALEXA_URL = "https://s3.amazonaws.com/alexa-static/top-1m.csv.zip"


def download_phishtank(raw_dir: Path, limit: int = 50_000) -> pd.DataFrame:
    """Download phishing URLs from PhishTank."""
    dest = raw_dir / "phishtank.csv"
    if dest.exists():
        logger.info("PhishTank file already present, loading from disk.")
        df = pd.read_csv(dest)
    else:
        logger.info("Downloading PhishTank dataset...")
        resp = requests.get(PHISHTANK_URL, timeout=60)
        resp.raise_for_status()
        df = pd.read_csv(io.StringIO(resp.text))
        df.to_csv(dest, index=False)
        logger.info(f"Saved {len(df)} PhishTank rows to {dest}")

    df = df[["url"]].dropna().rename(columns={"url": "url"})
    df["label"] = 1
    return df.head(limit)


def download_openphish(raw_dir: Path, limit: int = 20_000) -> pd.DataFrame:
    """Download phishing URLs from OpenPhish."""
    dest = raw_dir / "openphish.txt"
    if dest.exists():
        logger.info("OpenPhish file already present, loading from disk.")
        urls = dest.read_text().splitlines()
    else:
        logger.info("Downloading OpenPhish feed...")
        resp = requests.get(OPENPHISH_URL, timeout=30)
        resp.raise_for_status()
        urls = resp.text.strip().splitlines()
        dest.write_text("\n".join(urls))
        logger.info(f"Saved {len(urls)} OpenPhish URLs to {dest}")

    df = pd.DataFrame({"url": urls[:limit], "label": 1})
    return df


def download_alexa(raw_dir: Path, limit: int = 70_000) -> pd.DataFrame:
    """Download legitimate URLs from Alexa top-1M list."""
    dest = raw_dir / "alexa_top1m.csv"
    if dest.exists():
        logger.info("Alexa file already present, loading from disk.")
        df = pd.read_csv(dest, header=None, names=["rank", "domain"])
    else:
        logger.info("Downloading Alexa Top 1M...")
        resp = requests.get(ALEXA_URL, timeout=60)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            with z.open("top-1m.csv") as f:
                df = pd.read_csv(f, header=None, names=["rank", "domain"])
        df.to_csv(dest, index=False)
        logger.info(f"Saved {len(df)} Alexa domains to {dest}")

    df = df.head(limit).copy()
    df["url"] = "http://" + df["domain"]
    df["label"] = 0
    return df[["url", "label"]]


def load_all(raw_dir: Path) -> pd.DataFrame:
    """
    Load or download all datasets, combine, and return a single DataFrame.

    Returns:
        DataFrame with columns [url, label] where label=1 is phishing, 0 is legitimate.
    """
    raw_dir = Path(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

    phishtank = download_phishtank(raw_dir)
    openphish = download_openphish(raw_dir)
    alexa = download_alexa(raw_dir)

    combined = pd.concat([phishtank, openphish, alexa], ignore_index=True)
    logger.info(
        f"Combined dataset: {len(combined)} rows | "
        f"phishing={combined['label'].sum()} | "
        f"legitimate={(combined['label'] == 0).sum()}"
    )
    return combined
