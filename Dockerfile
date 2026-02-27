# syntax=docker/dockerfile:1.6

ARG BASE_IMAGE=devintripp/rust-scanner-worker:scanner-latest

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
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/backfill ./cmd/backfill

############################
# 2) Final image
############################
FROM ${BASE_IMAGE}
WORKDIR /app

COPY --from=build        /out/worker            /usr/local/bin/worker
COPY --from=build        /out/backfill          /usr/local/bin/worker-backfill

# runtime dirs (emptyDir in k8s will be mounted here; still fine locally)
ENV SCRATCH_DIR=/scratch \
    SCANNER_PATH=/usr/local/bin/scanner

# Ensure runtime scratch path exists; keep root here because scanner base may not define appuser.
USER root
RUN mkdir -p /scratch

ENTRYPOINT ["/usr/local/bin/worker"]
