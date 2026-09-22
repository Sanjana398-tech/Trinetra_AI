FROM python:3.11-slim

# System dependencies for Whisper and OCR
RUN apt-get update && apt-get install -y \
    ffmpeg \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD gunicorn -w 1 --timeout 120 -b 0.0.0.0:$PORT "app:app"