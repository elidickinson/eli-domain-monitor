FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies that might be needed for python-whois
RUN apt-get update && apt-get install -y \
    whois \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster dependency installation
RUN pip install uv

# Copy pyproject.toml and README first for better caching
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen

# Copy application code
COPY domain_monitor.py .
COPY src/ ./src/

# Create directories for logs and data
RUN mkdir -p /app/logs /app/data

# Copy example config
COPY config.yaml.example .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command - show help
CMD ["uv", "run", "python", "domain_monitor.py", "--help"]