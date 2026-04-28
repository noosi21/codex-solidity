FROM node:20-slim

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    bash -c "source /root/.bashrc && foundryup" && \
    ln -s /root/.foundry/bin/forge /usr/local/bin/forge && \
    ln -s /root/.foundry/bin/cast /usr/local/bin/cast && \
    ln -s /root/.foundry/bin/anvil /usr/local/bin/anvil

# Install Slither
RUN pip3 install slither-analyzer --break-system-packages 2>/dev/null || pip3 install slither-analyzer

WORKDIR /app

# Install dependencies first (cache layer)
COPY package*.json ./
RUN npm install --production

# Copy source
COPY . .

# Make CLI globally available
RUN npm link

# Default: run audit
ENTRYPOINT ["codex-sol"]
CMD ["--help"]
