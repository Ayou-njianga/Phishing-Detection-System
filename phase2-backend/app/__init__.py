"""
Flask application factory.

Using the factory pattern lets us create multiple app instances
(e.g. one for tests with a mock DB, one for production) without
global state leaking between them.
"""
import logging
import logging.config
import os
from pathlib import Path

import yaml
from flask import Flask
from flask_cors import CORS

from config.settings import settings


def create_app(test_config: dict = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        test_config: Optional dict of config overrides (used in testing).

    Returns:
        Configured Flask app instance.
    """
    app = Flask(__name__, instance_relative_config=False)

    # ── Core config ────────────────────────────────────────────────────────────
    app.config.from_mapping(
        SECRET_KEY=settings.SECRET_KEY,
        DEBUG=settings.DEBUG,
        MYSQL_HOST=settings.MYSQL_HOST,
        ONNX_MODEL_PATH=settings.ONNX_MODEL_PATH,
        CONFIDENCE_THRESHOLD=settings.CONFIDENCE_THRESHOLD,
        VIRUSTOTAL_API_KEY=settings.VIRUSTOTAL_API_KEY,
    )

    if test_config is not None:
        app.config.update(test_config)

    # ── CORS (Android app calls the API over HTTPS) ────────────────────────────
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ── Logging ────────────────────────────────────────────────────────────────
    _configure_logging()

    # ── Services (initialised once at startup) ─────────────────────────────────
    from app.services.mysql_service import MySQLService
    from app.services.onnx_service import OnnxService
    from app.services.virustotal_service import VirusTotalService
    from app.services.detection_service import DetectionService

    mysql = MySQLService()
    onnx = OnnxService()
    virustotal = VirusTotalService()
    detection = DetectionService(mysql=mysql, onnx=onnx, virustotal=virustotal)

    # Attach services to app context so routes can access them
    app.extensions["mysql"] = mysql
    app.extensions["onnx"] = onnx
    app.extensions["virustotal"] = virustotal
    app.extensions["detection"] = detection

    # ── Blueprints ─────────────────────────────────────────────────────────────
    from app.routes.detection import detection_bp
    from app.routes.health import health_bp

    app.register_blueprint(detection_bp, url_prefix="/api/v1")
    app.register_blueprint(health_bp, url_prefix="/api/v1")

    logging.getLogger("app").info(
        f"Phishing Detection Backend started | "
        f"env={settings.FLASK_ENV} | "
        f"model={Path(settings.ONNX_MODEL_PATH).name}"
    )

    return app


def _configure_logging():
    """Load logging config from YAML and create logs directory."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    log_config_path = Path(__file__).parent.parent / "config" / "logging.yaml"
    if log_config_path.exists():
        with open(log_config_path) as f:
            config = yaml.safe_load(f)
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=logging.INFO)
