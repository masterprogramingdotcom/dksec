FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip install --no-cache-dir semgrep

WORKDIR /app

# Copy application files
COPY . /app

# Install dependencies and DKSec
RUN pip install --no-cache-dir -e .

EXPOSE 8080

ENTRYPOINT ["dksec"]
CMD ["ui", "--host", "0.0.0.0", "--port", "8080"]
