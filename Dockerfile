# Dockerfile för huvudapplikationen
FROM python:3.9-slim

# Installera systempaket och build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    docker.io \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libssl-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Uppgradera pip först
RUN pip install --upgrade pip

# Skapa applikationsmapp
WORKDIR /app

# Kopiera requirements först för bättre caching
COPY requirements.txt .

# Installera Python-dependencies med timeout och retries
RUN pip install --no-cache-dir --timeout 120 --retries 3 -r requirements.txt

# Kopiera applikationskod från app/ mappen
COPY app/ ./app/

# Skapa nödvändiga mappar
RUN mkdir -p /app/results /app/logs /app/static/reports

# Sätt rättigheter
RUN chmod +x /app/app/app.py

# Exponera port
EXPOSE 5001

# Miljövariabler
ENV FLASK_APP=app/app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Hälsokontroll
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5001/api/health || exit 1

# Starta applikationen från app mappen
WORKDIR /app/app
CMD ["python", "app.py"]