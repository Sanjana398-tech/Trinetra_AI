FROM python:3.12-slim

# System dependencies for Whisper and OCR
RUN apt-get update && apt-get install -y \
    ffmpeg \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

# Whisper model load + transcription can take up to ~90 s on a CPU-only
# instance.  The worker timeout must be long enough that gunicorn does not
# SIGKILL the worker before Flask sends its response.
# Render's nginx proxy has its own ~30 s idle timeout; the threading fix in
# voice_transcribe.py ensures Flask responds within 85 s regardless, so
# gunicorn only needs to cover the DistilBERT + Whisper startup time.
CMD gunicorn -w 1 --timeout 300 -b 0.0.0.0:$PORT "app:app"