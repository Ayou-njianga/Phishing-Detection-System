# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="phishingdetector@example.com"
LABEL description="Mobile Phishing Link Detection — Flask Backend"

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Copy ONNX model from Phase 1 outputs (adjust path if needed)
# The model is expected at the path defined in ONNX_MODEL_PATH env var

# Create logs directory with correct permissions
RUN mkdir -p logs && chown -R appuser:appuser /app

USER appuser

# Health check — pings the /health endpoint every 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/v1/health')"

EXPOSE 5000

# Start Gunicorn with 4 workers
CMD ["gunicorn", "wsgi:app", \
     "--workers", "4", \
     "--bind", "0.0.0.0:5000", \
     "--timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info"]
