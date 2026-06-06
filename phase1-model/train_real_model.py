"""
Real-data phishing detection model trainer.

Data sources (all free, no API key required):
  Phishing:   OpenPhish  — https://openphish.com/feed.txt      (~2 000 live URLs)
              PhishTank  — https://data.phishtank.com/data/online-valid.csv  (needs free account)
              URLhaus    — https://urlhaus.abuse.ch/downloads/csv_recent/    (~10 000 recent)
  Legitimate: Majestic Million — https://downloads.majestic.com/majestic_million.csv

Fallback: If every download fails the script falls back to synthetic data
          so the model file is always produced.

Output: phase1-model/outputs/models/phishing_detector_quantized.onnx
        (previous file is kept as phishing_detector_synthetic.onnx backup)

Usage:
    cd Phishing-Detection-System
    python phase1-model/train_real_model.py

    # Skip downloads and use cached CSVs:
    python phase1-model/train_real_model.py --skip-download
"""
import argparse
import io
import sys
import time
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
import requests
import urllib3

# ── suppress SSL warnings (Avast MITM intercepts HTTPS on this machine) ───────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── add phase2-backend to path so we reuse the canonical feature extractor ────
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "phase2-backend"))

try:
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, roc_auc_score
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    from app.utils.feature_extractor import extract, FEATURE_NAMES
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install scikit-learn skl2onnx")
    sys.exit(1)

# ── paths ─────────────────────────────────────────────────────────────────────
MODELS_DIR   = Path(__file__).parent / "outputs" / "models"
DATA_DIR     = Path(__file__).parent / "data" / "raw"
REAL_MODEL   = MODELS_DIR / "phishing_detector_quantized.onnx"
SYNTH_BACKUP = MODELS_DIR / "phishing_detector_synthetic.onnx"

N_FEATURES   = len(FEATURE_NAMES)
RANDOM_SEED  = 42
MAX_PHISHING = 250_000  # cap total phishing (all sources combined)
MAX_LEGIT    = 350_000  # cap legitimate URLs (use all available)

# ── download helpers ──────────────────────────────────────────────────────────

def _legit_urls_from_domains(domains: list[str], paths: list[str] = None) -> list[str]:
    """
    Build realistic legitimate URL variants from bare domain names.

    Uses a 75% HTTPS / 25% HTTP split and alternates www./no-www so the
    model cannot use scheme or subdomain alone as a phishing signal.
    """
    rng = np.random.RandomState(RANDOM_SEED)
    default_paths = [
        "/about", "/contact", "/products", "/services", "/login",
        "/search", "/news", "/help", "/support", "/privacy",
        "/terms", "/blog", "/faq", "/careers", "/home",
    ]
    path_list = paths or default_paths
    urls = []
    for i, d in enumerate(domains):
        scheme = "https" if rng.rand() > 0.25 else "http"   # 75% https, 25% http
        www    = "www." if rng.rand() > 0.5 else ""          # 50% www prefix
        urls.append(f"{scheme}://{www}{d}")
        # Add one path variant per domain for extra diversity
        if i % 3 == 0:
            scheme2 = "https" if rng.rand() > 0.25 else "http"
            urls.append(f"{scheme2}://{www}{d}{path_list[i % len(path_list)]}")
    return urls


def _get(url: str, timeout: int = 30) -> requests.Response:
    """GET with SSL verification disabled (Avast intercepts HTTPS)."""
    return requests.get(url, verify=False, timeout=timeout,
                        headers={"User-Agent": "PhishGuard-Trainer/1.0"})


def download_openphish() -> list[str]:
    """OpenPhish community feed — free, ~1 500–2 500 live phishing URLs."""
    print("  Downloading OpenPhish feed...")
    try:
        r = _get("https://openphish.com/feed.txt", timeout=20)
        r.raise_for_status()
        urls = [u.strip() for u in r.text.splitlines() if u.strip().startswith("http")]
        print(f"  OpenPhish: {len(urls)} URLs")
        return urls[:MAX_PHISHING]
    except Exception as e:
        print(f"  OpenPhish failed: {e}")
        return []


def download_urlhaus() -> list[str]:
    """URLhaus recent feed — handles both zip and plain-text CSV formats."""
    print("  Downloading URLhaus feed...")
    try:
        r = _get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=30)
        r.raise_for_status()
        content = r.content

        # Try zip first, fall back to raw CSV if format changed
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                name = [n for n in z.namelist() if n.endswith(".csv")][0]
                with z.open(name) as f:
                    raw = f.read().decode("utf-8", errors="ignore")
        except zipfile.BadZipFile:
            raw = content.decode("utf-8", errors="ignore")

        df = pd.read_csv(
            io.StringIO(raw), comment="#",
            names=["id","dateadded","url","url_status",
                   "last_online","threat","tags","urlhaus_link","reporter"],
            on_bad_lines="skip",
        )
        urls = df[df["url_status"] == "online"]["url"].dropna().tolist()
        print(f"  URLhaus: {len(urls)} online URLs")
        return urls[:MAX_PHISHING]
    except Exception as e:
        print(f"  URLhaus failed: {e}")
        return []


# Built-in fallback list of popular legitimate domains (used when downloads fail)
_BUILTIN_LEGIT_DOMAINS = [
    "google.com","youtube.com","facebook.com","twitter.com","instagram.com",
    "linkedin.com","microsoft.com","apple.com","amazon.com","wikipedia.org",
    "reddit.com","netflix.com","github.com","stackoverflow.com","yahoo.com",
    "bing.com","whatsapp.com","tiktok.com","pinterest.com","tumblr.com",
    "dropbox.com","paypal.com","ebay.com","adobe.com","salesforce.com",
    "zoom.us","slack.com","discord.com","twitch.tv","spotify.com",
    "airbnb.com","uber.com","lyft.com","shopify.com","wordpress.com",
    "blogger.com","medium.com","quora.com","imdb.com","cnn.com",
    "bbc.com","nytimes.com","theguardian.com","reuters.com","bloomberg.com",
    "wsj.com","forbes.com","techcrunch.com","wired.com","arstechnica.com",
    "mozilla.org","python.org","nodejs.org","reactjs.org","vuejs.org",
    "docker.com","kubernetes.io","aws.amazon.com","cloud.google.com","azure.microsoft.com",
    "cloudflare.com","godaddy.com","namecheap.com","hostgator.com","bluehost.com",
    "stripe.com","twilio.com","sendgrid.com","mailchimp.com","hubspot.com",
    "bitbucket.org","gitlab.com","npm.js.org","pypi.org","rubygems.org",
    "stackoverflow.com","superuser.com","askubuntu.com","serverfault.com","unix.stackexchange.com",
    "google.fr","google.de","google.co.uk","google.co.jp","google.com.br",
    "amazon.co.uk","amazon.de","amazon.fr","amazon.co.jp","amazon.ca",
    "bbc.co.uk","theguardian.com","lemonde.fr","spiegel.de","corriere.it",
    "gov.uk","usa.gov","canada.ca","europa.eu","un.org",
    "who.int","unicef.org","worldbank.org","imf.org","nato.int",
    "harvard.edu","mit.edu","stanford.edu","oxford.ac.uk","cambridge.org",
    "nih.gov","nasa.gov","noaa.gov","cdc.gov","fda.gov",
    "apple.com","samsung.com","sony.com","lg.com","panasonic.com",
    "toyota.com","bmw.com","mercedes-benz.com","volkswagen.com","ford.com",
    "visa.com","mastercard.com","americanexpress.com","chase.com","wellsfargo.com",
    "bankofamerica.com","citibank.com","hsbc.com","barclays.com","lloydsbank.com",
    "ups.com","fedex.com","dhl.com","usps.com","royalmail.com",
    "emirates.com","delta.com","united.com","aa.com","lufthansa.com",
    "booking.com","hotels.com","expedia.com","tripadvisor.com","kayak.com",
    "walmart.com","target.com","bestbuy.com","costco.com","homedepot.com",
    "ikea.com","zara.com","hm.com","uniqlo.com","gap.com",
    "mcdonalds.com","starbucks.com","subway.com","dominos.com","pizzahut.com",
    "coca-cola.com","pepsi.com","nestle.com","unilever.com","pg.com",
    "pfizer.com","johnson.com","abbott.com","medtronic.com","siemens.com",
    "oracle.com","sap.com","ibm.com","hp.com","dell.com",
    "intel.com","amd.com","nvidia.com","qualcomm.com","broadcom.com",
    "verizon.com","att.com","tmobile.com","sprint.com","comcast.com",
    "twitter.com","snapchat.com","telegram.org","signal.org","viber.com",
    "wordpress.org","joomla.org","drupal.org","magento.com","wix.com",
    "squarespace.com","weebly.com","godaddy.com","bluehost.com","siteground.com",
]


def download_tranco() -> list[str]:
    """Tranco top-1M list — smaller and faster than Majestic. Falls back to built-in list."""
    print("  Downloading Tranco top domains...")
    try:
        # Tranco provides a stable 'top-1m' redirect — CSV is ~10 MB (not 856 MB)
        r = _get("https://tranco-list.eu/download/X5PKJ/1000000", timeout=40)
        r.raise_for_status()
        lines = r.text.strip().splitlines()
        domains = [l.split(",")[1].strip() for l in lines if "," in l]
        urls = _legit_urls_from_domains(domains[:MAX_LEGIT])
        print(f"  Tranco: {len(urls)} URLs")
        return urls[:MAX_LEGIT]
    except Exception as e:
        print(f"  Tranco failed: {e}")

    # Second attempt: Cisco Umbrella top-1M (HTTP, so no SSL issues)
    print("  Trying Cisco Umbrella top-1M (fallback)...")
    try:
        r = _get("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
                 timeout=40)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            with z.open("top-1m.csv") as f:
                df = pd.read_csv(f, names=["rank", "domain"])
        domains = df["domain"].dropna().tolist()[:MAX_LEGIT]
        urls = _legit_urls_from_domains(domains)
        print(f"  Cisco Umbrella: {len(urls)} URLs (http+https mixed)")
        return urls[:MAX_LEGIT]
    except Exception as e:
        print(f"  Cisco Umbrella failed: {e}")

    # Final fallback: built-in curated list (always available, no network needed)
    print("  Using built-in legitimate domain list (no download needed)")
    extra_paths = ["/about", "/contact", "/products", "/services", "/login",
                   "/search", "/news", "/help", "/support", "/privacy",
                   "/terms", "/blog", "/faq", "/careers", "/home",
                   "/account", "/settings", "/dashboard", "/profile", "/explore"]
    urls = _legit_urls_from_domains(_BUILTIN_LEGIT_DOMAINS, extra_paths)
    urls = list(dict.fromkeys(urls))
    print(f"  Built-in list: {len(urls)} URLs (http+https mixed)")
    return urls


def load_phishtank(data_dir: Path) -> list[str]:
    """
    Load PhishTank verified_online.csv if it exists in the raw data directory.

    PhishTank CSV columns:
      phish_id, url, phish_detail_url, submission_time, verified,
      verification_time, online, target

    Only rows with verified=yes and online=yes are used — these are
    confirmed, currently-active phishing pages.
    """
    pt_file = data_dir / "verified_online.csv"
    if not pt_file.exists():
        return []

    print(f"  Loading PhishTank dataset ({pt_file.name})...")
    try:
        df = pd.read_csv(pt_file, on_bad_lines="skip")
        # Keep only verified + online rows
        mask = (df["verified"].str.strip().str.lower() == "yes") & \
               (df["online"].str.strip().str.lower() == "yes")
        urls = df.loc[mask, "url"].dropna().tolist()
        # Basic sanity filter
        urls = [u for u in urls if isinstance(u, str) and u.startswith("http")]
        print(f"  PhishTank: {len(urls):,} verified-online URLs "
              f"(from {len(df):,} total rows)")
        return urls
    except Exception as e:
        print(f"  PhishTank load failed: {e}")
        return []


def load_cached(data_dir: Path) -> tuple[list[str], list[str]]:
    """Load previously cached CSVs if they exist."""
    ph_file  = data_dir / "phishing_urls.csv"
    leg_file = data_dir / "legit_urls.csv"
    phishing, legit = [], []
    if ph_file.exists():
        phishing = pd.read_csv(ph_file)["url"].dropna().tolist()
        print(f"  Loaded {len(phishing)} cached phishing URLs")
    if leg_file.exists():
        legit = pd.read_csv(leg_file)["url"].dropna().tolist()
        print(f"  Loaded {len(legit)} cached legitimate URLs")
    return phishing, legit


def save_cache(data_dir: Path, phishing: list[str], legit: list[str]):
    data_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame({"url": phishing}).to_csv(data_dir / "phishing_urls.csv", index=False)
    pd.DataFrame({"url": legit}).to_csv(data_dir / "legit_urls.csv", index=False)
    print(f"  Cached {len(phishing)} phishing + {len(legit)} legit URLs")


def _expand_legit_variants(urls: list[str]) -> list[str]:
    """
    Expand each legitimate URL into all scheme × www variants.

    For https://www.example.com/path we generate:
      https://www.example.com/path  (original)
      http://www.example.com/path   (http variant)
      https://example.com/path      (no-www variant)
      http://example.com/path       (http + no-www variant)

    This guarantees the model sees every legitimate domain in all
    format combinations so it cannot use scheme or www-prefix alone
    as a near-perfect proxy for the phishing label.
    """
    seen: set = set()
    result: list[str] = []

    def _add(u: str):
        if u not in seen:
            seen.add(u)
            result.append(u)

    for url in urls:
        _add(url)
        # Build (scheme, rest_after_scheme) pairs
        if url.startswith("https://"):
            after = url[8:]
            _add("http://" + after)                    # http variant
            if after.startswith("www."):
                bare = after[4:]
                _add("https://" + bare)                # no-www https
                _add("http://"  + bare)                # no-www http
        elif url.startswith("http://"):
            after = url[7:]
            _add("https://" + after)                   # https variant
            if after.startswith("www."):
                bare = after[4:]
                _add("http://"  + bare)                # no-www http
                _add("https://" + bare)                # no-www https

    return result


def load_local_datasets(data_dir: Path) -> tuple[list[str], list[str]]:
    """
    Load phishing and legitimate URLs from all CSV files found in data_dir.

    Recognised files and their formats:
      phishing_urls.csv    — url column (existing cache from OpenPhish/URLhaus)
      Phishing URLs.csv    — url + Type columns (Type == "Phishing")
      URL dataset.csv      — url + type columns (type in {"Phishing","phishing","legitimate"})
      verified_online.csv  — handled separately by load_phishtank()

    Legitimate URLs get 25% of their https:// links flipped to http:// so
    the model cannot use the scheme as a near-perfect proxy for legitimacy.
    """
    phishing: list[str] = []
    legit:    list[str] = []

    # ── phishing_urls.csv (OpenPhish + URLhaus cache) ──────────────────────────
    f = data_dir / "phishing_urls.csv"
    if f.exists():
        urls = pd.read_csv(f)["url"].dropna().tolist()
        phishing.extend(u for u in urls if isinstance(u, str) and u.startswith("http"))
        print(f"  phishing_urls.csv         : {len(urls):>7,} phishing URLs")

    # ── Phishing URLs.csv (user-supplied phishing dataset) ────────────────────
    f = data_dir / "Phishing URLs.csv"
    if f.exists():
        df = pd.read_csv(f, on_bad_lines="skip")
        # Column may be "Type" (capital T)
        type_col = next((c for c in df.columns if c.lower() == "type"), None)
        url_col  = next((c for c in df.columns if c.lower() == "url"),  None)
        if url_col:
            if type_col:
                mask = df[type_col].str.strip().str.lower() == "phishing"
                urls = df.loc[mask, url_col].dropna().tolist()
            else:
                urls = df[url_col].dropna().tolist()
            phishing.extend(u for u in urls if isinstance(u, str) and u.startswith("http"))
            print(f"  Phishing URLs.csv         : {len(urls):>7,} phishing URLs")

    # ── URL dataset.csv (combined labelled dataset) ────────────────────────────
    f = data_dir / "URL dataset.csv"
    if f.exists():
        df = pd.read_csv(f, on_bad_lines="skip")
        type_col = next((c for c in df.columns if c.lower() == "type"), None)
        url_col  = next((c for c in df.columns if c.lower() == "url"),  None)
        if url_col and type_col:
            df["_type_norm"] = df[type_col].str.strip().str.lower()

            ph_mask  = df["_type_norm"] == "phishing"
            lg_mask  = df["_type_norm"] == "legitimate"

            ph_urls  = df.loc[ph_mask, url_col].dropna().tolist()
            lg_urls  = df.loc[lg_mask, url_col].dropna().tolist()

            phishing.extend(u for u in ph_urls if isinstance(u, str) and u.startswith("http"))
            legit.extend(   u for u in lg_urls if isinstance(u, str) and u.startswith("http"))

            print(f"  URL dataset.csv  phishing : {len(ph_urls):>7,} URLs")
            print(f"  URL dataset.csv  legit    : {len(lg_urls):>7,} URLs")

    # De-duplicate within each class
    phishing = list(dict.fromkeys(phishing))
    legit    = list(dict.fromkeys(legit))

    # Expand to all scheme × www variants so the model sees every domain
    # in all format combinations (http/https, with/without www).
    if legit:
        legit = _expand_legit_variants(legit)

    return phishing, legit


# ── synthetic fallback data ────────────────────────────────────────────────────

def _col(arr):
    return np.array(arr, dtype=np.float32).reshape(-1, 1)


def generate_synthetic(n: int = 20_000) -> tuple[np.ndarray, np.ndarray]:
    """Generate realistic synthetic URL features when real data is unavailable."""
    print("  Generating synthetic data as fallback...")
    rng = np.random.RandomState(RANDOM_SEED)
    half = n // 2

    def phishing_block(k):
        return np.hstack([
            _col(rng.randint(80, 220, k)),  _col(rng.randint(15, 45, k)),
            _col(rng.randint(20, 120, k)),  _col(rng.randint(4, 14, k)),
            _col(rng.randint(2, 9, k)),     _col(rng.randint(0, 5, k)),
            _col(rng.randint(3, 11, k)),    _col(rng.choice([0,1,2],k,p=[.7,.2,.1])),
            _col(rng.randint(0, 4, k)),     _col(rng.randint(0, 6, k)),
            _col(rng.randint(0, 5, k)),     _col(rng.randint(4, 18, k)),
            _col(rng.randint(1, 5, k)),     _col(rng.randint(1, 5, k)),
            _col(rng.choice([0,1],k,p=[.65,.35])), _col(rng.choice([0,1],k,p=[.55,.45])),
            _col(rng.choice([0,1],k,p=[.65,.35])), _col(rng.choice([0,1],k,p=[.15,.85])),
            _col(rng.randint(1, 6, k)),     _col(rng.choice([0,1],k,p=[.35,.65])),
            _col(rng.uniform(3.6,5.1,k)),   _col(rng.uniform(3.0,4.6,k)),
            _col(rng.choice([0,1],k,p=[.78,.22])), _col(rng.choice([0,1],k,p=[.68,.32])),
            _col(rng.choice([0,1],k,p=[.78,.22])), _col(rng.choice([0,1],k,p=[.65,.35])),
            _col(rng.choice([0,1],k,p=[.65,.35])), _col(rng.randint(0, 4, k)),
            _col(rng.choice([0,1],k,p=[.28,.72])), _col(rng.choice([0,1],k,p=[.35,.65])),
            _col(rng.choice([0,1],k,p=[.45,.55])), _col(rng.choice([0,1],k,p=[.68,.32])),
            _col(rng.randint(2, 9, k)),     _col(rng.randint(0, 6, k)),
            _col(rng.choice([0,1],k,p=[.68,.32])), _col(rng.choice([1,2],k)),
        ])

    def legit_block(k):
        return np.hstack([
            _col(rng.randint(18, 75, k)),  _col(rng.randint(4, 16, k)),
            _col(rng.randint(0, 35, k)),   _col(rng.randint(1, 5, k)),
            _col(rng.randint(0, 2, k)),    _col(np.zeros(k)),
            _col(rng.randint(1, 5, k)),    _col(np.zeros(k)),
            _col(rng.choice([0,1],k,p=[.65,.35])), _col(rng.randint(0,3,k)),
            _col(rng.randint(0, 2, k)),    _col(rng.randint(0, 6, k)),
            _col(rng.choice([0,1],k,p=[.65,.35])), _col(rng.choice([0,1],k,p=[.65,.35])),
            _col(np.zeros(k)), _col(np.ones(k)),
            _col(np.zeros(k)), _col(rng.choice([0,1],k,p=[.92,.08])),
            _col(rng.choice([0,1],k,p=[.92,.08])), _col(np.zeros(k)),
            _col(rng.uniform(2.4,3.9,k)),  _col(rng.uniform(1.8,3.4,k)),
            _col(np.zeros(k)), _col(np.zeros(k)),
            _col(np.zeros(k)), _col(np.zeros(k)),
            _col(np.zeros(k)), _col(np.zeros(k)),
            _col(np.zeros(k)), _col(np.zeros(k)),
            _col(np.zeros(k)), _col(np.zeros(k)),
            _col(rng.randint(1,5,k)),      _col(rng.randint(0,3,k)),
            _col(np.zeros(k)),             _col(rng.choice([2,3],k)),
        ])

    X = np.vstack([phishing_block(half), legit_block(n - half)]).astype(np.float32)
    y = np.array([1] * half + [0] * (n - half), dtype=np.int64)
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


# ── feature extraction ────────────────────────────────────────────────────────

def extract_features(urls: list[str], label: int) -> tuple[list, list]:
    """Extract feature vectors from a list of URLs with progress output."""
    X, y = [], []
    failed = 0
    for i, url in enumerate(urls):
        if i % 500 == 0:
            print(f"    [{i}/{len(urls)}] extracted...", end="\r")
        try:
            feats = extract(url)
            if len(feats) == N_FEATURES and not any(
                    v != v for v in feats):   # check for NaN
                X.append(feats)
                y.append(label)
            else:
                failed += 1
        except Exception:
            failed += 1
    print(f"    Done — {len(X)} ok, {failed} failed")
    return X, y


# ── model training + ONNX export ──────────────────────────────────────────────

def train_and_export(X: np.ndarray, y: np.ndarray, note: str):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y)

    print(f"\nTraining HistGradientBoostingClassifier on {len(X_train):,} samples ({note})...")
    clf = HistGradientBoostingClassifier(
        max_iter=300,
        max_depth=8,
        learning_rate=0.05,
        min_samples_leaf=20,
        class_weight="balanced",
        random_state=RANDOM_SEED,
    )
    t0 = time.time()
    clf.fit(X_train, y_train)
    print(f"  Training done in {time.time()-t0:.1f}s")

    print("\nEvaluation on held-out test set:")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print(f"  ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")

    print("\nExporting to ONNX...")
    initial_type = [("float_input", FloatTensorType([None, N_FEATURES]))]
    onnx_model = convert_sklearn(
        clf, initial_types=initial_type,
        options={type(clf): {"zipmap": False}},
    )
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(REAL_MODEL, "wb") as f:
        f.write(onnx_model.SerializeToString())
    size_kb = REAL_MODEL.stat().st_size // 1024
    print(f"  Saved -> {REAL_MODEL}  ({size_kb} KB)  [{note}]")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-download", action="store_true",
                        help="Use cached CSVs instead of downloading fresh data")
    args = parser.parse_args()

    print("=" * 60)
    print("PhishGuard — Real Data Model Trainer")
    print("=" * 60)

    # ── Step 1: gather URLs ────────────────────────────────────────────────────
    phishing_urls: list[str] = []
    legit_urls:    list[str] = []

    print("\n[1/4] Loading datasets...")

    # ── Primary: local CSV files in data/raw/ ──────────────────────────────────
    ph_local, lg_local = load_local_datasets(DATA_DIR)
    phishing_urls.extend(ph_local)
    legit_urls.extend(lg_local)

    # ── PhishTank (always loaded from disk when present) ───────────────────────
    pt_urls = load_phishtank(DATA_DIR)
    if pt_urls:
        phishing_urls.extend(pt_urls)
        print(f"  PhishTank verified_online : {len(pt_urls):>7,} phishing URLs")

    # ── Optional: supplement with downloaded data (skipped when --skip-download)
    if not args.skip_download:
        print("  Downloading supplementary datasets...")
        phishing_urls += download_openphish()
        phishing_urls += download_urlhaus()
        # Only download legit if local CSVs gave us none
        if not legit_urls:
            legit_urls += download_tranco()

    # ── Deduplicate and cap ────────────────────────────────────────────────────
    phishing_urls = list(dict.fromkeys(phishing_urls))
    legit_urls    = list(dict.fromkeys(legit_urls))

    # ── Last-resort fallback: built-in domain list ─────────────────────────────
    if not legit_urls:
        print("  No legitimate URLs found — generating from built-in domain list...")
        extra_paths = [
            "", "/about", "/contact", "/login", "/search", "/news", "/help",
            "/support", "/privacy", "/terms", "/blog", "/faq", "/careers",
            "/home", "/account", "/products", "/services", "/dashboard",
            "/profile", "/settings", "/explore", "/user/profile", "/docs/api",
            "/shop/cart", "/wiki/home", "/en/about", "/category/all",
        ]
        rng_legit = np.random.RandomState(RANDOM_SEED + 1)
        built = []
        for d in _BUILTIN_LEGIT_DOMAINS:
            for path in extra_paths:
                scheme = "https" if rng_legit.rand() > 0.25 else "http"
                www    = "www." if rng_legit.rand() > 0.5 else ""
                built.append(f"{scheme}://{www}{d}{path}")
        legit_urls = list(dict.fromkeys(built))
        rng_legit.shuffle(legit_urls)
        print(f"  Built-in fallback: {len(legit_urls):,} URLs (http+https mixed)")

    # Cap to MAX_LEGIT — keep a random sample so all domains are represented
    if len(legit_urls) > MAX_LEGIT:
        rng_cap = np.random.RandomState(RANDOM_SEED)
        idx = rng_cap.choice(len(legit_urls), MAX_LEGIT, replace=False)
        legit_urls = [legit_urls[i] for i in sorted(idx)]

    use_real = len(phishing_urls) >= 50 and len(legit_urls) >= 50

    if use_real:
        print(f"\n  Total: {len(phishing_urls):,} phishing + {len(legit_urls):,} legitimate URLs")
    else:
        print(f"\n  Not enough real data ({len(phishing_urls)} phishing, {len(legit_urls)} legit).")
        print("  Falling back to synthetic data.")

    # ── Step 2: extract features ───────────────────────────────────────────────
    print("\n[2/4] Extracting features...")
    if use_real:
        print(f"  Phishing ({len(phishing_urls):,} URLs):")
        X_ph, y_ph = extract_features(phishing_urls, label=1)
        print(f"  Legitimate ({len(legit_urls):,} URLs):")
        X_lg, y_lg = extract_features(legit_urls,    label=0)

        if len(X_ph) < 50 or len(X_lg) < 50:
            print("  Feature extraction produced too few samples — using synthetic.")
            use_real = False

    if use_real:
        X = np.array(X_ph + X_lg, dtype=np.float32)
        y = np.array(y_ph + y_lg, dtype=np.int64)
        rng = np.random.RandomState(RANDOM_SEED)
        idx = rng.permutation(len(X))
        X, y = X[idx], y[idx]
        data_note = f"real data  ({len(X):,} samples)"
    else:
        X, y = generate_synthetic(20_000)
        data_note = "synthetic fallback  (20 000 samples)"

    print(f"\n[3/4] Training model on {len(X):,} samples...")

    # ── Step 3: train + export ─────────────────────────────────────────────────
    train_and_export(X, y, data_note)

    # ── Step 4: ensure synthetic backup exists ─────────────────────────────────
    print("\n[4/4] Checking synthetic backup...")
    if SYNTH_BACKUP.exists():
        print(f"  Backup exists: {SYNTH_BACKUP}")
    else:
        print("  Synthetic backup not found — generating it now...")
        X_s, y_s = generate_synthetic(20_000)
        # Temporarily train a quick synthetic model for the backup
        from sklearn.ensemble import RandomForestClassifier
        clf_s = RandomForestClassifier(n_estimators=100, random_state=RANDOM_SEED, n_jobs=-1)
        clf_s.fit(X_s, y_s)
        initial_type = [("float_input", FloatTensorType([None, N_FEATURES]))]
        onnx_s = convert_sklearn(clf_s, initial_types=initial_type,
                                 options={type(clf_s): {"zipmap": False}})
        with open(SYNTH_BACKUP, "wb") as f:
            f.write(onnx_s.SerializeToString())
        print(f"  Synthetic backup saved: {SYNTH_BACKUP}")

    print("\nDone. Restart the backend to load the new model.")
    print(f"  Primary : {REAL_MODEL}")
    print(f"  Fallback: {SYNTH_BACKUP}")


if __name__ == "__main__":
    main()
