# -- Stage 1: dependency builder ---------------------------------------------
# Use a full Python image to compile wheels; avoids build tools in final image.
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies needed by database/client libraries.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first so dependency installation stays cached unless deps change.
COPY requirements.txt .

# Install into a separate prefix that will be copied to the final stage.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# -- Stage 2: runtime image ---------------------------------------------------
FROM python:3.12-slim AS runtime

# Install only runtime system dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user; the app should not run as root in production.
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

# Copy installed Python packages from builder stage.
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code and assign ownership at layer creation time.
COPY --chown=appuser:appgroup . .

# Switch to non-root runtime user.
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# --host 0.0.0.0 is required so the port is reachable outside the container.
CMD ["sh", "-c", "uvicorn iam_guardian.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
