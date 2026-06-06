"""
Health-check and status routes.

Used by Docker, load balancers, and the Android app to verify
the backend is running and all services are operational.

Endpoints:
  GET /api/v1/health        — lightweight liveness probe
  GET /api/v1/health/detail — full status of all subsystems
"""
import logging

from flask import Blueprint, current_app, jsonify

logger = logging.getLogger("app.routes.health")

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health():
    """
    Lightweight liveness probe.

    Returns HTTP 200 immediately if the Flask process is alive.
    Used by Docker HEALTHCHECK and load balancer ping.
    """
    return jsonify({"status": "ok"}), 200


@health_bp.route("/health/detail", methods=["GET"])
def health_detail():
    """
    Detailed status check of all backend subsystems.

    Returns:
      {
        "status": "ok" | "degraded",
        "services": {
          "mongodb":    { "connected": true,  "cached_urls": 1024 },
          "onnx_model": { "loaded": true,     "model": "phishing_detector_quantized.onnx" },
          "virustotal": { "configured": true, "cache_size": 87 }
        }
      }

    HTTP 200 if all services are operational.
    HTTP 503 if any critical service (ONNX model) is unavailable.
    """
    mysql = current_app.extensions.get("mysql")
    onnx = current_app.extensions.get("onnx")
    vt = current_app.extensions.get("virustotal")

    from config.settings import settings
    from pathlib import Path

    mysql_ok = mysql is not None and mysql.is_connected
    onnx_ok = onnx is not None and onnx.is_loaded

    services = {
        "mysql": {
            "connected": mysql_ok,
            "cached_urls": mysql.count() if mysql_ok else -1,
        },
        "onnx_model": {
            "loaded": onnx_ok,
            "model": Path(settings.ONNX_MODEL_PATH).name if onnx_ok else None,
            "kind": onnx._model_kind if onnx_ok else "none",
        },
        "virustotal": {
            "configured": vt.is_configured if vt else False,
            "cache_size": vt.cache_size() if vt else 0,
        },
    }

    overall_status = "ok" if onnx_ok else "degraded"
    http_status = 200 if onnx_ok else 503

    return jsonify({"status": overall_status, "services": services}), http_status
