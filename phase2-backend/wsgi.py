"""
WSGI entry point for production deployment with Gunicorn.

Run in development:
  python wsgi.py

Run in production (Gunicorn):
  gunicorn wsgi:app --workers 4 --bind 0.0.0.0:5000 --timeout 30

Or via Docker:
  docker-compose up
"""
import os
from app import create_app
from config.settings import settings

app = create_app()

if __name__ == "__main__":
    app.run(
        host=settings.HOST,
        port=settings.PORT,
        debug=settings.DEBUG,
    )
