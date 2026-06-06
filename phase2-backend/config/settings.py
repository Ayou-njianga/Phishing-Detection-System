"""
Centralised application settings loaded from environment variables.

All configuration is read here and nowhere else, so changing the .env
file is the only action needed to reconfigure the server.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if present (dev/staging). In production, env vars are injected.
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")


class Settings:
    # ── Flask ──────────────────────────────────────────────────────────────────
    FLASK_ENV: str = os.getenv("FLASK_ENV", "production")
    DEBUG: bool = os.getenv("FLASK_DEBUG", "0") == "1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-do-not-use-in-prod")

    # ── MongoDB ────────────────────────────────────────────────────────────────
    MONGO_URI: str        = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME: str    = os.getenv("MONGO_DB", "phishing_detector")
    MONGO_COLLECTION_PHISHING: str = os.getenv("MONGO_COLLECTION", "phishing_urls")
    MONGO_TIMEOUT_MS: int = int(os.getenv("MONGO_TIMEOUT_MS", "5000"))

    # ── ONNX model ─────────────────────────────────────────────────────────────
    _models_dir = Path(__file__).parent.parent.parent / "phase1-model" / "outputs" / "models"
    ONNX_MODEL_PATH: str = os.getenv(
        "ONNX_MODEL_PATH",
        str(_models_dir / "phishing_detector_quantized.onnx"),
    )
    # Synthetic model used as fallback when the real model is missing or fails
    ONNX_FALLBACK_MODEL_PATH: str = os.getenv(
        "ONNX_FALLBACK_MODEL_PATH",
        str(_models_dir / "phishing_detector_synthetic.onnx"),
    )
    # Predictions below this score trigger a VirusTotal lookup
    CONFIDENCE_THRESHOLD: float = float(os.getenv("CONFIDENCE_THRESHOLD", "0.75"))

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_TIMEOUT_SEC: int = int(os.getenv("VIRUSTOTAL_TIMEOUT_SEC", "10"))
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"

    # ── Server ─────────────────────────────────────────────────────────────────
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "5000"))
    WORKERS: int = int(os.getenv("WORKERS", "4"))

    # ── Internal thresholds ────────────────────────────────────────────────────
    # Max URL length we'll accept for analysis
    MAX_URL_LENGTH: int = 2048
    # How many VT results flag a URL as phishing (out of ~70 engines)
    VIRUSTOTAL_MALICIOUS_THRESHOLD: int = 3


settings = Settings()
