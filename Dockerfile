# Build stage
FROM python:3.11-bullseye as builder

# Installera build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpango1.0-dev \
    libharfbuzz-dev \
    libfribidi-dev \
    libpangoft2-1.0-0 \
    libgdk-pixbuf2.0-dev \
    libcairo2-dev \
    libffi-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Kopiera requirements och installera alla Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-bullseye

# Installera runtime dependencies
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libcairo2 \
    libffi7 \
    fontconfig \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Kopiera Python packages från builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app
COPY . .

EXPOSE 5001
CMD ["python", "app/app.py"]