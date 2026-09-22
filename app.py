"""
TRINETRA AI — Application Entry Point
========================================
Smart Third-Eye Cyber Scam Detection System

Local development:
    python app.py

Production (example):
    gunicorn -w 4 -b 0.0.0.0:8000 "app:app"
"""

import os

from backend import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = app.config.get("DEBUG", True)
    # Heavy CUDA-backed models should not be initialized twice by Flask's
    # development auto-reloader on Windows.
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
