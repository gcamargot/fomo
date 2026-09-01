FROM python:3.12-slim-bookworm

# Prevent prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.foundry/bin:/root/.local/share/solana/install/active_release/bin:/usr/local/bin:${PATH}"

# Install core system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    procps \
    supervisor \
    bzip2 \
    tar \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (forge, cast, anvil, chisel)
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup

# Install Solana CLI
RUN sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)" || true

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

# Pre-install common Solidity compiler versions using solc-select
RUN solc-select install 0.8.20 && \
    solc-select install 0.8.24 && \
    solc-select use 0.8.20

# Copy application source code
COPY . /app/

# Create contracts and logs directory
RUN mkdir -p /app/contracts /var/log/supervisor && \
    chmod +x /app/entrypoint.sh /app/manage_daemons.sh

# Declare persistence volume for contracts dataset & database
VOLUME ["/app/contracts"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["daemon"]
