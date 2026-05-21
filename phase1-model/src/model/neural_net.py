"""
TensorFlow neural network definition for phishing URL detection.

Architecture (from paper):
  - Hidden layers: [256, 128, 64]
  - Dropout: 0.3 between each hidden layer
  - Output: single sigmoid neuron (binary classification)
  - Optimizer: Adam
  - Loss: binary cross-entropy
"""
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from src.utils.logger import get_logger

logger = get_logger(__name__)


def build_model(
    input_dim: int,
    hidden_layers: list[int] = (256, 128, 64),
    dropout_rate: float = 0.3,
    learning_rate: float = 0.001,
) -> keras.Model:
    """
    Build and compile the phishing detection neural network.

    Args:
        input_dim: Number of input features.
        hidden_layers: List of neuron counts for each hidden layer.
        dropout_rate: Dropout probability applied after each hidden layer.
        learning_rate: Adam optimiser learning rate.

    Returns:
        Compiled Keras model.
    """
    inputs = keras.Input(shape=(input_dim,), name="url_features")
    x = inputs

    for i, units in enumerate(hidden_layers):
        x = layers.Dense(
            units,
            activation="relu",
            kernel_initializer="he_normal",
            name=f"hidden_{i + 1}",
        )(x)
        x = layers.BatchNormalization(name=f"bn_{i + 1}")(x)
        x = layers.Dropout(dropout_rate, name=f"dropout_{i + 1}")(x)

    outputs = layers.Dense(1, activation="sigmoid", name="output")(x)

    model = keras.Model(inputs=inputs, outputs=outputs, name="phishing_detector")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall"),
            keras.metrics.AUC(name="auc"),
        ],
    )

    logger.info(f"Model built: input_dim={input_dim}, params={model.count_params():,}")
    model.summary(print_fn=logger.info)
    return model
