# syntax=docker/dockerfile:1.6

############################
# 1) Build the Go worker
############################
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/backfill ./cmd/backfill

############################
# 2) Minimal runtime image
# No scanner binary baked in — downloaded on startup via entrypoint
############################
FROM debian:trixie-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl gawk libssl3 rpm libarchive-tools p7zip-full hfsprogs && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=build /out/backfill /usr/local/bin/worker-backfill
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV SCRATCH_DIR=/scratch \
    SCANNER_PATH=/usr/local/bin/scanrook

RUN mkdir -p /scratch && \
    chmod 1777 /usr/local/bin

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
