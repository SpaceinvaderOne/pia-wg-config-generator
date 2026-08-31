# Pinned to 3.11: Python 3.13 onwards verifies certificates in strict mode,
# which rejects PIA's CA and breaks key registration for every region.
FROM python:3.11-slim

WORKDIR /app

# Install OS-level dependencies
RUN apt-get update \
 && apt-get install -y wireguard-tools nginx --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into a venv
COPY requirements.txt /app/
RUN python3 -m venv venv \
 && ./venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy the pia-wg source files
COPY . /app

# Expose port 80 for web UI
EXPOSE 80

# Run supervisord to manage nginx and flask
ENTRYPOINT ["/app/venv/bin/supervisord", "-c", "/app/supervisord.conf"]
