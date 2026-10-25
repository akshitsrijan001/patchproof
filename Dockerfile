# PatchProof — isolated test runner
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip install --no-cache-dir semgrep

# Set up work directory
WORKDIR /app
COPY pyproject.toml .
COPY patchproof/ patchproof/
COPY rules/ rules/
COPY templates/ templates/
COPY payloads/ payloads/
COPY target/ target/
COPY fixes/ fixes/
COPY tests/ tests/

# Install PatchProof
RUN pip install --no-cache-dir -e .

# Verify Semgrep installation
RUN semgrep --version

ENTRYPOINT ["patchproof"]
CMD ["demo"]
