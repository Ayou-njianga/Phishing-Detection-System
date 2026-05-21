"""
Export the trained TensorFlow model to ONNX format.

Steps:
  1. Load the saved TF model.
  2. Convert with tf2onnx.
  3. Apply quantization (float32 → int8) to reduce model size.
  4. Validate the ONNX model produces identical outputs to TF.
  5. Save to outputs/models/.
"""
import os
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
import tensorflow as tf
import tf2onnx
from onnxruntime.quantization import QuantType, quantize_dynamic

from src.utils.logger import get_logger

logger = get_logger(__name__)


def export(
    tf_model_path: Path,
    models_dir: Path,
    model_name: str = "phishing_detector",
    opset: int = 13,
    quantize: bool = True,
) -> Path:
    """
    Convert a TensorFlow SavedModel to ONNX and optionally quantize it.

    Args:
        tf_model_path: Path to the TF SavedModel directory.
        models_dir: Output directory for ONNX files.
        model_name: Base name for the output files.
        opset: ONNX opset version.
        quantize: Whether to apply int8 quantization for mobile deployment.

    Returns:
        Path to the final (possibly quantized) ONNX model file.
    """
    tf_model_path = Path(tf_model_path)
    models_dir = Path(models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)

    onnx_path = models_dir / f"{model_name}.onnx"
    quantized_path = models_dir / f"{model_name}_quantized.onnx"

    # Load TF model
    logger.info(f"Loading TF model from {tf_model_path}")
    model = tf.saved_model.load(str(tf_model_path))

    # Convert to ONNX
    logger.info("Converting TF model to ONNX...")
    input_signature = [
        tf.TensorSpec(shape=[None, None], dtype=tf.float32, name="url_features")
    ]
    onnx_model, _ = tf2onnx.convert.from_function(
        model.signatures["serving_default"],
        input_signature=input_signature,
        opset=opset,
        output_path=str(onnx_path),
    )
    logger.info(f"ONNX model saved to {onnx_path} ({onnx_path.stat().st_size / 1024:.1f} KB)")

    # Optional quantization
    final_path = onnx_path
    if quantize:
        logger.info("Applying dynamic int8 quantization...")
        quantize_dynamic(
            model_input=str(onnx_path),
            model_output=str(quantized_path),
            weight_type=QuantType.QInt8,
        )
        logger.info(
            f"Quantized model saved to {quantized_path} "
            f"({quantized_path.stat().st_size / 1024:.1f} KB)"
        )
        final_path = quantized_path

    # Validation: compare TF and ONNX outputs
    logger.info("Validating ONNX model outputs...")
    _validate(tf_model_path, final_path)

    return final_path


def _validate(tf_model_path: Path, onnx_path: Path, n_samples: int = 100):
    """Run a quick sanity check that TF and ONNX produce similar predictions."""
    tf_model = tf.keras.models.load_model(str(tf_model_path))
    sess = ort.InferenceSession(str(onnx_path))
    input_name = sess.get_inputs()[0].name

    dummy_input = np.random.rand(n_samples, 36).astype(np.float32)

    tf_out = tf_model.predict(dummy_input, verbose=0).flatten()
    onnx_out = sess.run(None, {input_name: dummy_input})[0].flatten()

    max_diff = np.max(np.abs(tf_out - onnx_out))
    logger.info(f"Validation — max output difference TF vs ONNX: {max_diff:.6f}")
    assert max_diff < 0.01, f"ONNX outputs deviate too much from TF: max_diff={max_diff}"
    logger.info("ONNX validation passed.")
