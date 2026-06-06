"""
Quick model generator — creates a functional phishing detection model
using scikit-learn (no TensorFlow needed) and exports it to ONNX.

Generates synthetic training data that mirrors realistic phishing vs.
legitimate URL feature distributions, trains a RandomForestClassifier,
and exports to the path expected by phase2-backend.

Usage:
    python phase1-model/create_quick_model.py

For production-quality accuracy, run the full pipeline instead:
    python phase1-model/run_pipeline.py
"""
import sys
from pathlib import Path

import numpy as np

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install scikit-learn skl2onnx")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
OUTPUT_PATH = Path(__file__).parent / "outputs" / "models" / "phishing_detector_quantized.onnx"
N_SAMPLES   = 20_000
RANDOM_SEED = 42

FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_at_symbols", "num_question_marks",
    "num_equals", "num_ampersands", "num_digits", "num_subdomains",
    "subdomain_count", "has_ip_address", "has_https", "has_port",
    "has_suspicious_keywords", "suspicious_keyword_count", "tld_in_suspicious_list",
    "url_entropy", "domain_entropy", "path_contains_exe", "has_double_slash_in_path",
    "uses_url_shortener", "uses_ip_instead_of_domain", "has_port_structural",
    "redirect_depth", "tld_is_high_risk", "domain_has_brand_impersonation",
    "subdomain_has_brand", "domain_is_numeric", "path_depth",
    "query_param_count", "has_fragment", "domain_part_count",
]
N_FEATURES = len(FEATURE_NAMES)


# ── Synthetic data generation ─────────────────────────────────────────────────

def _col(arr):
    return np.array(arr, dtype=np.float32).reshape(-1, 1)


def generate_data(n: int, rng: np.random.RandomState):
    half = n // 2
    ph = _phishing(half, rng)
    lg = _legit(n - half, rng)
    X  = np.vstack([ph, lg]).astype(np.float32)
    y  = np.array([1] * half + [0] * (n - half), dtype=np.int64)
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


def _phishing(n, rng):
    return np.hstack([
        _col(rng.randint(80, 220, n)),                          # url_length
        _col(rng.randint(15, 45, n)),                           # domain_length
        _col(rng.randint(20, 120, n)),                          # path_length
        _col(rng.randint(4, 14, n)),                            # num_dots
        _col(rng.randint(2, 9, n)),                             # num_hyphens
        _col(rng.randint(0, 5, n)),                             # num_underscores
        _col(rng.randint(3, 11, n)),                            # num_slashes
        _col(rng.choice([0, 1, 2], n, p=[0.7, 0.2, 0.1])),    # num_at_symbols
        _col(rng.randint(0, 4, n)),                             # num_question_marks
        _col(rng.randint(0, 6, n)),                             # num_equals
        _col(rng.randint(0, 5, n)),                             # num_ampersands
        _col(rng.randint(4, 18, n)),                            # num_digits
        _col(rng.randint(1, 5, n)),                             # num_subdomains
        _col(rng.randint(1, 5, n)),                             # subdomain_count
        _col(rng.choice([0, 1], n, p=[0.65, 0.35])),           # has_ip_address
        _col(rng.choice([0, 1], n, p=[0.55, 0.45])),           # has_https
        _col(rng.choice([0, 1], n, p=[0.65, 0.35])),           # has_port
        _col(rng.choice([0, 1], n, p=[0.15, 0.85])),           # has_suspicious_keywords
        _col(rng.randint(1, 6, n)),                             # suspicious_keyword_count
        _col(rng.choice([0, 1], n, p=[0.35, 0.65])),           # tld_in_suspicious_list
        _col(rng.uniform(3.6, 5.1, n)),                         # url_entropy
        _col(rng.uniform(3.0, 4.6, n)),                         # domain_entropy
        _col(rng.choice([0, 1], n, p=[0.78, 0.22])),           # path_contains_exe
        _col(rng.choice([0, 1], n, p=[0.68, 0.32])),           # has_double_slash_in_path
        _col(rng.choice([0, 1], n, p=[0.78, 0.22])),           # uses_url_shortener
        _col(rng.choice([0, 1], n, p=[0.65, 0.35])),           # uses_ip_instead_of_domain
        _col(rng.choice([0, 1], n, p=[0.65, 0.35])),           # has_port_structural
        _col(rng.randint(0, 4, n)),                             # redirect_depth
        _col(rng.choice([0, 1], n, p=[0.28, 0.72])),           # tld_is_high_risk
        _col(rng.choice([0, 1], n, p=[0.35, 0.65])),           # domain_has_brand_impersonation
        _col(rng.choice([0, 1], n, p=[0.45, 0.55])),           # subdomain_has_brand
        _col(rng.choice([0, 1], n, p=[0.68, 0.32])),           # domain_is_numeric
        _col(rng.randint(2, 9, n)),                             # path_depth
        _col(rng.randint(0, 6, n)),                             # query_param_count
        _col(rng.choice([0, 1], n, p=[0.68, 0.32])),           # has_fragment
        _col(rng.choice([1, 2], n)),                            # domain_part_count
    ])


def _legit(n, rng):
    return np.hstack([
        _col(rng.randint(18, 75, n)),                           # url_length
        _col(rng.randint(4, 16, n)),                            # domain_length
        _col(rng.randint(0, 35, n)),                            # path_length
        _col(rng.randint(1, 5, n)),                             # num_dots
        _col(rng.randint(0, 2, n)),                             # num_hyphens
        _col(np.zeros(n)),                                      # num_underscores
        _col(rng.randint(1, 5, n)),                             # num_slashes
        _col(np.zeros(n)),                                      # num_at_symbols
        _col(rng.choice([0, 1], n, p=[0.65, 0.35])),           # num_question_marks
        _col(rng.randint(0, 3, n)),                             # num_equals
        _col(rng.randint(0, 2, n)),                             # num_ampersands
        _col(rng.randint(0, 6, n)),                             # num_digits
        _col(rng.choice([0, 1], n, p=[0.65, 0.35])),           # num_subdomains
        _col(rng.choice([0, 1], n, p=[0.65, 0.35])),           # subdomain_count
        _col(np.zeros(n)),                                      # has_ip_address
        _col(np.ones(n)),                                       # has_https
        _col(np.zeros(n)),                                      # has_port
        _col(rng.choice([0, 1], n, p=[0.92, 0.08])),           # has_suspicious_keywords
        _col(rng.choice([0, 1], n, p=[0.92, 0.08])),           # suspicious_keyword_count
        _col(np.zeros(n)),                                      # tld_in_suspicious_list
        _col(rng.uniform(2.4, 3.9, n)),                         # url_entropy
        _col(rng.uniform(1.8, 3.4, n)),                         # domain_entropy
        _col(np.zeros(n)),                                      # path_contains_exe
        _col(np.zeros(n)),                                      # has_double_slash_in_path
        _col(np.zeros(n)),                                      # uses_url_shortener
        _col(np.zeros(n)),                                      # uses_ip_instead_of_domain
        _col(np.zeros(n)),                                      # has_port_structural
        _col(np.zeros(n)),                                      # redirect_depth
        _col(np.zeros(n)),                                      # tld_is_high_risk
        _col(np.zeros(n)),                                      # domain_has_brand_impersonation
        _col(np.zeros(n)),                                      # subdomain_has_brand
        _col(np.zeros(n)),                                      # domain_is_numeric
        _col(rng.randint(1, 5, n)),                             # path_depth
        _col(rng.randint(0, 3, n)),                             # query_param_count
        _col(np.zeros(n)),                                      # has_fragment
        _col(rng.choice([2, 3], n)),                            # domain_part_count
    ])


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"Generating {N_SAMPLES:,} synthetic URL samples …")
    rng = np.random.RandomState(RANDOM_SEED)
    X, y = generate_data(N_SAMPLES, rng)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    print(f"Training RandomForestClassifier on {len(X_train):,} samples …")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_SEED,
    )
    clf.fit(X_train, y_train)

    print("\nEvaluation on held-out test set:")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    print("Exporting to ONNX …")
    initial_type = [("float_input", FloatTensorType([None, N_FEATURES]))]
    onnx_model = convert_sklearn(
        clf,
        initial_types=initial_type,
        options={type(clf): {"zipmap": False}},
    )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "wb") as f:
        f.write(onnx_model.SerializeToString())

    size_kb = OUTPUT_PATH.stat().st_size // 1024
    print(f"\nModel saved -> {OUTPUT_PATH}  ({size_kb} KB)")
    print("Backend will pick it up on next restart.")


if __name__ == "__main__":
    main()
