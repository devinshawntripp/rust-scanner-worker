#!/bin/bash
set -e

# Skip scanner self-update by default in K8s Job context (scanner is baked in).
# Set SCANROOK_AUTO_UPDATE=true to enable.
if [ "${SCANROOK_AUTO_UPDATE}" = "true" ]; then
  SCANROOK_VERSION="${SCANROOK_VERSION:-latest}"
  echo "Upgrading scanrook ${SCANROOK_VERSION}..."
  curl -fsSL --max-time 30 https://scanrook.sh/install | SCANROOK_VERSION="${SCANROOK_VERSION}" INSTALL_DIR=/usr/local/bin bash || echo "WARNING: scanrook upgrade failed, using baked-in version"
fi

# Verify it works
scanrook --version || echo "WARNING: scanrook binary not functional"

# Run the single-job binary
exec /usr/local/bin/runjob "$@"
