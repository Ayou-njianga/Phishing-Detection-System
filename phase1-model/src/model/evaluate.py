"""
Model evaluation on the held-out test set.

Computes accuracy, precision, recall, F1-score, AUC,
and saves a confusion matrix plot.
"""
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from src.features.extractor import to_numpy
from src.utils.logger import get_logger

logger = get_logger(__name__)


def evaluate(
    model,
    splits_dir: Path,
    metrics_dir: Path,
    plots_dir: Path,
    confidence_threshold: float = 0.5,
) -> dict:
    """
    Evaluate the model on the test split and save results.

    Args:
        model: Trained Keras model.
        splits_dir: Directory containing test.csv.
        metrics_dir: Directory to save metrics JSON.
        plots_dir: Directory to save plots.
        confidence_threshold: Decision threshold for binary classification.

    Returns:
        Dictionary of computed metrics.
    """
    splits_dir = Path(splits_dir)
    metrics_dir = Path(metrics_dir)
    plots_dir = Path(plots_dir)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    plots_dir.mkdir(parents=True, exist_ok=True)

    test_df = pd.read_csv(splits_dir / "test.csv")
    X_test, y_test = to_numpy(test_df)

    # Predict
    y_proba = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_proba >= confidence_threshold).astype(int)

    # Metrics
    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1_score": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "auc_roc": round(roc_auc_score(y_test, y_proba), 4),
        "threshold": confidence_threshold,
        "test_samples": len(y_test),
    }

    logger.info("Test Set Metrics:")
    for k, v in metrics.items():
        logger.info(f"  {k}: {v}")

    logger.info("\nClassification Report:\n" + classification_report(y_test, y_pred))

    # Save metrics JSON
    metrics_path = metrics_dir / "test_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Metrics saved to {metrics_path}")

    # Confusion matrix plot
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Legitimate", "Phishing"],
        yticklabels=["Legitimate", "Phishing"],
        ax=ax,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix (threshold={confidence_threshold})")
    fig.tight_layout()
    cm_path = plots_dir / "confusion_matrix.png"
    fig.savefig(cm_path, dpi=150)
    plt.close(fig)
    logger.info(f"Confusion matrix saved to {cm_path}")

    return metrics
