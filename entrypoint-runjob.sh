#!/bin/bash
set -e

# Auto-update scanner on startup (pulls latest from GitHub releases).
# Set SCANROOK_AUTO_UPDATE=false to skip and use the baked-in version.
if [ "${SCANROOK_AUTO_UPDATE}" != "false" ]; then
  SCANROOK_VERSION="${SCANROOK_VERSION:-latest}"
  echo "Upgrading scanrook to ${SCANROOK_VERSION}..."
  curl -fsSL --max-time 30 https://scanrook.sh/install | SCANROOK_VERSION="${SCANROOK_VERSION}" INSTALL_DIR=/usr/local/bin bash || echo "WARNING: scanrook upgrade failed, using baked-in version"
fi

# Verify it works
scanrook --version || echo "WARNING: scanrook binary not functional"

# Run the single-job binary
exec /usr/local/bin/runjob "$@"
