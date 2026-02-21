# syntax=docker/dockerfile:1.6

############################
# 1) Build the worker
############################
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

############################
# 2) Build the scanner from external repo (scanner_src build context)
############################
FROM rust:1.87-slim AS scanner-build
WORKDIR /src

# optional proxy support
ARG http_proxy
ARG https_proxy
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}

# Bring in the scanner repo via a separate build context
COPY --from=scanner_src / /src

# HARD FAIL if the external context didn't arrive
RUN test -f Cargo.toml || (echo >&2 "ERROR: scanner_src context missing (no Cargo.toml). Did you pass --build-context scanner_src=?"; exit 1)

# Build deps (+ file so we can validate the binary)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates build-essential curl file \
    && rm -rf /var/lib/apt/lists/*

# Warm the Cargo index/deps for the current scanner source tree.
# Some local scanner branches intentionally drift from Cargo.lock.
RUN cargo fetch

# Build and install to /usr/local/bin/scanner
RUN cargo install --path . --root /usr/local

# Sanity checks: exists, x86_64 ELF, and > 500KB
RUN set -e; \
    test -x /usr/local/bin/scanner || { echo "scanner missing"; exit 1; }; \
    file /usr/local/bin/scanner | grep -E 'ELF 64-bit.*x86-64' >/dev/null || { echo "scanner not amd64 ELF"; exit 1; }; \
    BYTES=$(wc -c </usr/local/bin/scanner || echo 0); \
    if [ "$BYTES" -lt 500000 ]; then echo "scanner too small ($BYTES bytes) — likely a stub"; exit 1; fi; \
    /usr/local/bin/scanner --help >/dev/null 2>&1 || echo "note: scanner ran (non-zero exit, ok)"

############################
# 3) Final image
############################
FROM devintripp/rust-scanner-worker:latest
WORKDIR /app

COPY --from=build        /out/worker            /usr/local/bin/worker
COPY --from=scanner-build /usr/local/bin/scanner /usr/local/bin/scanner

# runtime dirs (emptyDir in k8s will be mounted here; still fine locally)
ENV SCRATCH_DIR=/scratch \
    SCANNER_PATH=/usr/local/bin/scanner

# align ownership of replaced binaries
USER root
RUN mkdir -p /scratch \
    && chown -R appuser:nogroup /scratch /usr/local/bin/worker /usr/local/bin/scanner
USER appuser

ENTRYPOINT ["/usr/local/bin/worker"]
