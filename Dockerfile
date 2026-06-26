# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (including nmap and curl for healthcheck)
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements
COPY backend/requirements.txt ./requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY backend/ ./backend/
COPY docs/ ./docs/

# Expose FastAPI port
EXPOSE 8000

# Health check
HEALTHCHECK CMD curl --fail http://localhost:8000/api/health || exit 1

# Run FastAPI app
CMD ["uvicorn", "backend.app_fastapi:app", "--host", "0.0.0.0", "--port", "8000"]
