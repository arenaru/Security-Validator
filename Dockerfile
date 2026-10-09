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

# Run FastAPI app.
# --reload is required because docker-compose mounts ./backend into the
# container: without it uvicorn keeps serving the code it loaded at startup, so
# edits to mounted files never take effect until the container is recreated.
# NOTE: --reload is a development setting (it spawns a file watcher and restarts
# on partial writes). Remove it before shipping this image to production.
CMD ["uvicorn", "backend.app_fastapi:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
