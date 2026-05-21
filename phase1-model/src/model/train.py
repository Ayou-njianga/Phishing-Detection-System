"""
Model training script.

Reads split CSVs, fits the neural network with early stopping,
and saves the best weights to disk.
"""
from pathlib import Path

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras

from src.features.extractor import get_feature_columns, to_numpy
from src.model.neural_net import build_model
from src.utils.logger import get_logger

logger = get_logger(__name__)


def train(
    splits_dir: Path,
    models_dir: Path,
    hidden_layers: list[int] = (256, 128, 64),
    dropout_rate: float = 0.3,
    learning_rate: float = 0.001,
    batch_size: int = 512,
    epochs: int = 50,
    early_stopping_patience: int = 5,
) -> keras.Model:
    """
    Load splits, train model, save best weights.

    Args:
        splits_dir: Directory containing train.csv, val.csv.
        models_dir: Directory to save the trained model.
        hidden_layers: Architecture of the hidden layers.
        dropout_rate: Dropout rate.
        learning_rate: Adam LR.
        batch_size: Mini-batch size.
        epochs: Max epochs.
        early_stopping_patience: Stop if val_loss doesn't improve.

    Returns:
        Trained Keras model.
    """
    splits_dir = Path(splits_dir)
    models_dir = Path(models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)

    # Load data
    train_df = pd.read_csv(splits_dir / "train.csv")
    val_df = pd.read_csv(splits_dir / "val.csv")
    logger.info(f"Train: {len(train_df)} | Val: {len(val_df)}")

    X_train, y_train = to_numpy(train_df)
    X_val, y_val = to_numpy(val_df)

    # Class weights to handle imbalance
    n_phishing = y_train.sum()
    n_legit = len(y_train) - n_phishing
    class_weight = {0: 1.0, 1: n_legit / max(n_phishing, 1)}
    logger.info(f"Class weights: {class_weight}")

    # Build model
    model = build_model(
        input_dim=X_train.shape[1],
        hidden_layers=hidden_layers,
        dropout_rate=dropout_rate,
        learning_rate=learning_rate,
    )

    # Callbacks
    best_weights_path = models_dir / "best_weights.keras"
    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=early_stopping_patience,
            restore_best_weights=True,
            verbose=1,
        ),
        keras.callbacks.ModelCheckpoint(
            filepath=str(best_weights_path),
            monitor="val_loss",
            save_best_only=True,
            verbose=1,
        ),
        keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=3,
            min_lr=1e-6,
            verbose=1,
        ),
        keras.callbacks.CSVLogger(str(models_dir / "training_log.csv")),
    ]

    # Train
    history = model.fit(
        X_train,
        y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=1,
    )

    # Save full model
    saved_model_path = models_dir / "phishing_detector_tf"
    model.save(str(saved_model_path))
    logger.info(f"Full model saved to {saved_model_path}")

    return model
