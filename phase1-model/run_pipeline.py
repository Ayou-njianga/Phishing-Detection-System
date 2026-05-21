"""
Master pipeline runner for Phase 1.

Executes all steps in order:
  1. Download / load raw data
  2. Preprocess (clean + normalise)
  3. Extract features
  4. Split into train / val / test
  5. Train neural network
  6. Evaluate on test set
  7. Export to ONNX

Run: python run_pipeline.py
     python run_pipeline.py --skip-whois     # faster, skips WHOIS lookups
     python run_pipeline.py --config custom.yaml
"""
import argparse
import sys
from pathlib import Path

import yaml

from src.utils.logger import get_logger
from src.utils.data_loader import load_all
from src.utils.preprocessor import clean
from src.utils.splitter import split
from src.features.extractor import extract_dataframe
from src.model.train import train
from src.model.evaluate import evaluate
from src.model.export_onnx import export

logger = get_logger(__name__, log_file="outputs/pipeline.log")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Phase 1: Model training pipeline")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--skip-whois", action="store_true", help="Skip WHOIS lookups")
    parser.add_argument(
        "--steps",
        nargs="+",
        choices=["data", "preprocess", "features", "split", "train", "evaluate", "export"],
        default=None,
        help="Run only specific steps (default: all)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    steps = set(args.steps) if args.steps else None
    use_whois = not args.skip_whois

    raw_dir = Path(cfg["data"]["raw_dir"])
    processed_dir = Path(cfg["data"]["processed_dir"])
    splits_dir = Path(cfg["data"]["splits_dir"])
    models_dir = Path(cfg["outputs"]["models_dir"])
    metrics_dir = Path(cfg["outputs"]["metrics_dir"])
    plots_dir = Path(cfg["outputs"]["plots_dir"])

    # Step 1: Download data
    if steps is None or "data" in steps:
        logger.info("=== STEP 1: Loading data ===")
        raw_df = load_all(raw_dir)
    else:
        import pandas as pd
        raw_df = pd.read_csv(processed_dir / "urls_clean.csv")

    # Step 2: Preprocess
    if steps is None or "preprocess" in steps:
        logger.info("=== STEP 2: Preprocessing ===")
        clean_df = clean(raw_df, processed_dir=processed_dir)
    else:
        import pandas as pd
        clean_df = pd.read_csv(processed_dir / "urls_clean.csv")

    # Step 3: Feature extraction
    if steps is None or "features" in steps:
        logger.info("=== STEP 3: Feature extraction ===")
        feat_df = extract_dataframe(clean_df, use_whois=use_whois, processed_dir=processed_dir)
    else:
        import pandas as pd
        feat_df = pd.read_csv(processed_dir / "features.csv")

    # Step 4: Split
    if steps is None or "split" in steps:
        logger.info("=== STEP 4: Splitting ===")
        train_df, val_df, test_df = split(
            feat_df,
            test_size=cfg["data"]["test_size"],
            val_size=cfg["data"]["val_size"],
            random_seed=cfg["data"]["random_seed"],
            splits_dir=splits_dir,
        )

    # Step 5: Train
    if steps is None or "train" in steps:
        logger.info("=== STEP 5: Training ===")
        model = train(
            splits_dir=splits_dir,
            models_dir=models_dir,
            hidden_layers=cfg["model"]["hidden_layers"],
            dropout_rate=cfg["model"]["dropout_rate"],
            learning_rate=cfg["model"]["learning_rate"],
            batch_size=cfg["model"]["batch_size"],
            epochs=cfg["model"]["epochs"],
            early_stopping_patience=cfg["model"]["early_stopping_patience"],
        )

    # Step 6: Evaluate
    if steps is None or "evaluate" in steps:
        logger.info("=== STEP 6: Evaluating ===")
        if "model" not in dir():
            import tensorflow as tf
            model = tf.keras.models.load_model(
                str(models_dir / "phishing_detector_tf")
            )
        metrics = evaluate(
            model=model,
            splits_dir=splits_dir,
            metrics_dir=metrics_dir,
            plots_dir=plots_dir,
            confidence_threshold=cfg["model"]["confidence_threshold"],
        )
        logger.info(f"Final F1-score: {metrics['f1_score']}")

    # Step 7: Export to ONNX
    if steps is None or "export" in steps:
        logger.info("=== STEP 7: Exporting to ONNX ===")
        onnx_path = export(
            tf_model_path=models_dir / "phishing_detector_tf",
            models_dir=models_dir,
            model_name=cfg["outputs"]["model_name"],
        )
        logger.info(f"ONNX model ready at: {onnx_path}")

    logger.info("=== Pipeline complete ===")


if __name__ == "__main__":
    main()
