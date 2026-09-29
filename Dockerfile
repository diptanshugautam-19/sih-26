# ==============================================================================
# Multi-Stage Dockerfile for Predictive Cyber Defence World Model
# ==============================================================================

FROM python:3.11-slim AS base

# Install system dependencies & Node.js
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    libpcap-dev \
    tcpdump \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install Frontend dependencies
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm install

# Copy application source code
COPY . .

# Expose ports
# Port 3000: React Web UI & Express Ingestion Server
# Port 8000: FastAPI Neural World Model Server
EXPOSE 3000 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=3000
ENV BACKEND_PORT=8000

# Default entrypoint starts the full stack
CMD ["sh", "-c", "cd frontend && npm run dev"]
