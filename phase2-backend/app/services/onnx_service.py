"""
ONNX inference service.

Loads the quantized ONNX model once at startup and provides
thread-safe, low-latency URL classification.

Average inference latency: ~12ms (per paper benchmarks).
"""
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import onnxruntime as ort

from app.utils.feature_extractor import extract, FEATURE_NAMES
from config.settings import settings

logger = logging.getLogger("app.services.onnx")


class OnnxService:
    """Wraps the ONNX Runtime session for phishing URL inference."""

    def __init__(self):
        self._session: Optional[ort.InferenceSession] = None
        self._input_name: Optional[str] = None
        self._load_model()

    # ── Startup ────────────────────────────────────────────────────────────────

    def _load_model(self):
        """Load the ONNX model from disk into an ORT InferenceSession."""
        model_path = Path(settings.ONNX_MODEL_PATH)

        if not model_path.exists():
            logger.error(
                f"ONNX model not found at {model_path}. "
                "Run phase1-model/run_pipeline.py first."
            )
            return

        try:
            # Use CPU execution provider for maximum compatibility
            # Switch to ["CUDAExecutionProvider", "CPUExecutionProvider"] for GPU
            opts = ort.SessionOptions()
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            opts.intra_op_num_threads = 2  # Keep low for server with many workers

            self._session = ort.InferenceSession(
                str(model_path),
                sess_options=opts,
                providers=["CPUExecutionProvider"],
            )
            self._input_name = self._session.get_inputs()[0].name

            logger.info(
                f"ONNX model loaded | path={model_path.name} "
                f"| input={self._input_name} "
                f"| features={len(FEATURE_NAMES)}"
            )
        except Exception as exc:
            logger.error(f"Failed to load ONNX model: {exc}")
            self._session = None

    @property
    def is_loaded(self) -> bool:
        return self._session is not None

    # ── Inference ──────────────────────────────────────────────────────────────

    def predict(self, url: str) -> Optional[float]:
        """
        Run model inference on a single URL.

        Args:
            url: Normalised URL string.

        Returns:
            Phishing probability (0.0 – 1.0), or None if the model is unavailable.
        """
        if not self.is_loaded:
            logger.warning("ONNX model not loaded — cannot predict")
            return None

        try:
            features = extract(url)
            X = np.array([features], dtype=np.float32)
            outputs = self._session.run(None, {self._input_name: X})
            # Output shape: [[probability]]
            probability = float(outputs[0][0][0])
            logger.debug(f"ONNX inference: {url[:60]} → {probability:.4f}")
            return probability
        except Exception as exc:
            logger.error(f"ONNX inference error for {url[:60]!r}: {exc}")
            return None

    def predict_batch(self, urls: list[str]) -> list[Optional[float]]:
        """
        Run model inference on a batch of URLs for throughput efficiency.

        Args:
            urls: List of normalised URL strings.

        Returns:
            List of phishing probabilities in the same order as input.
        """
        if not self.is_loaded:
            return [None] * len(urls)

        try:
            features_batch = [extract(url) for url in urls]
            X = np.array(features_batch, dtype=np.float32)
            outputs = self._session.run(None, {self._input_name: X})
            return [float(p[0]) for p in outputs[0]]
        except Exception as exc:
            logger.error(f"ONNX batch inference error: {exc}")
            return [None] * len(urls)
