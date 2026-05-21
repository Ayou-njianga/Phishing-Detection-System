"""
Standardised JSON response builder.

All API responses go through these helpers so the mobile client
can rely on a consistent envelope structure:

Success:
  { "status": "ok", "data": { ... }, "latency_ms": 42 }

Error:
  { "status": "error", "error": { "code": "...", "message": "..." } }
"""
import time
from typing import Any

from flask import jsonify, Response


def success(data: dict, latency_ms: float = None) -> Response:
    """
    Build a successful JSON response.

    Args:
        data: Payload to include under the "data" key.
        latency_ms: Optional processing time to include in the response.

    Returns:
        Flask JSON response with HTTP 200.
    """
    body = {"status": "ok", "data": data}
    if latency_ms is not None:
        body["latency_ms"] = round(latency_ms, 2)
    return jsonify(body), 200


def error(code: str, message: str, http_status: int = 400) -> Response:
    """
    Build an error JSON response.

    Args:
        code: Machine-readable error code (e.g. "invalid_url", "model_error").
        message: Human-readable description.
        http_status: HTTP status code.

    Returns:
        Flask JSON response with the given HTTP status.
    """
    body = {
        "status": "error",
        "error": {
            "code": code,
            "message": message,
        },
    }
    return jsonify(body), http_status


class Timer:
    """Simple context-manager timer for measuring request latency."""

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000

    @property
    def ms(self) -> float:
        return getattr(self, "elapsed_ms", 0.0)
