#!/bin/bash
set -e

# Version can be pinned via env var or defaults to latest
SCANROOK_VERSION="${SCANROOK_VERSION:-latest}"

# Auto-update scanner to latest (fall back to baked-in version on failure)
echo "Upgrading scanrook ${SCANROOK_VERSION}..."
curl -fsSL https://scanrook.sh/install | SCANROOK_VERSION="${SCANROOK_VERSION}" INSTALL_DIR=/usr/local/bin bash || echo "WARNING: scanrook upgrade failed, using baked-in version"

# Verify it works
scanrook --version || echo "WARNING: scanrook binary not functional"

# Run the single-job binary
exec /usr/local/bin/runjob "$@"
