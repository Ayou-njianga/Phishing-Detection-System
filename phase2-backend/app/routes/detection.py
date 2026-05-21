"""
Detection API routes.

Endpoints:
  POST /api/v1/detect       — analyse a single URL
  POST /api/v1/detect/batch — analyse up to 20 URLs from one notification
"""
import logging

from flask import Blueprint, current_app, request

from app.utils.response_builder import success, error, Timer
from app.utils.url_parser import UrlParseError

logger = logging.getLogger("app.routes.detection")

detection_bp = Blueprint("detection", __name__)


# ── POST /api/v1/detect ────────────────────────────────────────────────────────

@detection_bp.route("/detect", methods=["POST"])
def detect():
    """
    Analyse a single URL extracted from a mobile notification.

    Request body (JSON):
      {
        "url":        "https://suspicious-link.com/verify",   // required
        "sender_app": "whatsapp",                             // optional
        "sender_id":  "abc123hash"                            // optional
      }

    Response (JSON):
      {
        "status": "ok",
        "data": {
          "url":             "https://suspicious-link.com/verify",
          "is_phishing":     true,
          "confidence":      0.9412,
          "detection_source":"onnx_model",
          "vt_malicious_count": null,
          "vt_total_engines":   null,
          "sender_app":     "whatsapp",
          "latency_ms":     58.3,
          "pipeline_stages": ["onnx_model"]
        }
      }
    """
    body = request.get_json(silent=True)
    if not body or "url" not in body:
        return error("missing_url", "Request body must include a 'url' field")

    raw_url = body.get("url", "").strip()
    sender_app = body.get("sender_app")
    sender_id = body.get("sender_id")

    if not raw_url:
        return error("empty_url", "The 'url' field must not be empty")

    detection_svc = current_app.extensions["detection"]

    with Timer() as t:
        try:
            result = detection_svc.analyse(
                raw_url=raw_url,
                sender_app=sender_app,
                sender_id=sender_id,
            )
        except UrlParseError as exc:
            logger.warning(f"Invalid URL rejected: {raw_url[:80]} — {exc}")
            return error("invalid_url", str(exc))
        except Exception as exc:
            logger.error(f"Detection error for {raw_url[:80]}: {exc}", exc_info=True)
            return error("detection_error", "Internal error during URL analysis", 500)

    return success(result.to_response(), latency_ms=t.ms)


# ── POST /api/v1/detect/batch ─────────────────────────────────────────────────

@detection_bp.route("/detect/batch", methods=["POST"])
def detect_batch():
    """
    Analyse multiple URLs from a single notification (e.g. a WhatsApp message
    containing several links).

    Request body (JSON):
      {
        "urls":       ["https://url1.com", "https://url2.com"],  // required, max 20
        "sender_app": "whatsapp"                                 // optional
      }

    Response (JSON):
      {
        "status": "ok",
        "data": {
          "results": [ { ...detection result... }, ... ],
          "total":   2,
          "phishing_count": 1
        },
        "latency_ms": 72.1
      }
    """
    body = request.get_json(silent=True)
    if not body or "urls" not in body:
        return error("missing_urls", "Request body must include a 'urls' array")

    raw_urls = body.get("urls", [])
    sender_app = body.get("sender_app")

    if not isinstance(raw_urls, list) or len(raw_urls) == 0:
        return error("empty_urls", "The 'urls' array must contain at least one URL")

    if len(raw_urls) > 20:
        return error("too_many_urls", "A maximum of 20 URLs can be analysed per batch request")

    detection_svc = current_app.extensions["detection"]

    with Timer() as t:
        try:
            results = detection_svc.analyse_batch(
                raw_urls=raw_urls,
                sender_app=sender_app,
            )
        except Exception as exc:
            logger.error(f"Batch detection error: {exc}", exc_info=True)
            return error("detection_error", "Internal error during batch URL analysis", 500)

    response_results = [r.to_response() for r in results]
    phishing_count = sum(1 for r in results if r.record.is_phishing)

    data = {
        "results": response_results,
        "total": len(response_results),
        "phishing_count": phishing_count,
    }

    return success(data, latency_ms=t.ms)
