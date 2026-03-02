#!/bin/bash
set -e

# Version can be pinned via env var or defaults to latest
SCANROOK_VERSION="${SCANROOK_VERSION:-latest}"

# Always download/upgrade scanrook on startup
echo "Installing scanrook ${SCANROOK_VERSION}..."
curl -fsSL https://scanrook.sh/install | SCANROOK_VERSION="${SCANROOK_VERSION}" INSTALL_DIR=/usr/local/bin bash

# Verify it works
scanrook --version || echo "WARNING: scanrook binary not functional"

# Start the Go worker
exec /usr/local/bin/worker "$@"
