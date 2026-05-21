# Mobile Phishing Link Detection System

AI-powered phishing detection for mobile users via real-time notification monitoring.

## Architecture

```
phase1-model/        # ML model training, feature engineering, ONNX export
phase2-backend/      # Flask REST API + MongoDB + VirusTotal integration
phase3-android/      # Android app (NotificationListenerService + UI)
phase4-testing/      # End-to-end and performance tests
docs/                # Architecture, API reference, setup guide
scripts/             # Environment setup and test runners
```

## Quick Start

```bash
# 1. Set up Python environment
bash scripts/setup_env.sh

# 2. Train and export the model (Phase 1)
cd phase1-model
python run_pipeline.py

# 3. Start the backend (Phase 2)
cd ../phase2-backend
docker-compose up

# 4. Build and install the Android app (Phase 3)
cd ../phase3-android/PhishingDetector
./gradlew installDebug
```

## Detection Pipeline

| Step | Component             | Avg Latency |
|------|-----------------------|-------------|
| 1    | MongoDB lookup        | 3ms         |
| 2    | ONNX model inference  | 12ms        |
| 3    | VirusTotal API        | ~1800ms     |
| —    | Total (without VT)    | ~60ms       |

## Model Performance

| Model           | Accuracy | F1-Score  |
|-----------------|----------|-----------|
| Random Forest   | 91.2%    | 90.1%     |
| SVM             | 88.5%    | 86.3%     |
| ONNX Neural Net | 94.6%    | 93.1%     |

## Reference Paper

Based on: *AI-Oriented Phishing Detection System for the Strengthening of Security in Social Networks*,
Journal of Neonatal Surgery, Vol. 14, Issue 25s (2025), pp. 800-808.
