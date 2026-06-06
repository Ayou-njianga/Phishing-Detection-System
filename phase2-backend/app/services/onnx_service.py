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
        self._model_kind: str = "none"
        self._load_model()

    # ── Startup ────────────────────────────────────────────────────────────────

    def _load_model(self):
        """
        Load the ONNX model, trying the real model first and the synthetic
        backup second. The backend always has a working model available.
        """
        candidates = [
            (Path(settings.ONNX_MODEL_PATH),          "real"),
            (Path(settings.ONNX_FALLBACK_MODEL_PATH), "synthetic-fallback"),
        ]

        for model_path, kind in candidates:
            if not model_path.exists():
                logger.warning(f"ONNX {kind} model not found at {model_path}")
                continue
            try:
                opts = ort.SessionOptions()
                opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                opts.intra_op_num_threads = 2

                self._session = ort.InferenceSession(
                    str(model_path),
                    sess_options=opts,
                    providers=["CPUExecutionProvider"],
                )
                self._input_name = self._session.get_inputs()[0].name
                self._model_kind = kind

                logger.info(
                    f"ONNX model loaded | path={model_path.name} "
                    f"| kind={kind} | input={self._input_name} "
                    f"| features={len(FEATURE_NAMES)}"
                )
                return  # loaded successfully — stop trying
            except Exception as exc:
                logger.error(f"Failed to load ONNX {kind} model ({model_path.name}): {exc}")
                self._session = None

        logger.error(
            "No ONNX model could be loaded. "
            "Run phase1-model/train_real_model.py to generate one."
        )

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
            probability = self._parse_probability(outputs, index=0)
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
            return [self._parse_probability(outputs, index=i) for i in range(len(urls))]
        except Exception as exc:
            logger.error(f"ONNX batch inference error: {exc}")
            return [None] * len(urls)

    @staticmethod
    def _parse_probability(outputs, index: int) -> float:
        """
        Parse phishing probability from ONNX output.

        Handles two formats:
        - TensorFlow/Keras: outputs[0] shape (N, 1) — raw sigmoid probability
        - sklearn/skl2onnx: outputs[0] shape (N,) labels, outputs[1] shape (N, 2) proba
        """
        if (len(outputs) >= 2
                and hasattr(outputs[1], 'ndim')
                and outputs[1].ndim == 2
                and outputs[1].shape[1] == 2):
            # sklearn format: outputs[1][:, 1] is probability of class 1 (phishing)
            return float(outputs[1][index][1])
        # TensorFlow format: outputs[0][index][0]
        return float(outputs[0][index][0])
