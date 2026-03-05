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
# 1b) Build hfsutils from source with GCC-13
# hfsutils is blocked from Debian Trixie (GCC-14 build failure, bug #1075067).
# GCC-13 is still available in Trixie and compiles the ancient C code fine.
############################
FROM debian:trixie-slim AS hfsutils
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-13 make libc6-dev curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fsSL https://fossies.org/linux/misc/old/hfsutils-3.2.6.tar.gz | tar xz
WORKDIR /build/hfsutils-3.2.6
RUN CC=gcc-13 ./configure --prefix=/usr/local --without-tcl --without-tk && \
    make CC=gcc-13 && \
    mkdir -p /usr/local/man/man1 && \
    make install

############################
# 2) Minimal runtime image
# No scanner binary baked in — downloaded on startup via entrypoint
############################
FROM debian:trixie-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl gawk libssl3 rpm libarchive-tools p7zip-full && \
    rm -rf /var/lib/apt/lists/*

COPY --from=hfsutils /usr/local/bin/hmount /usr/local/bin/hmount
COPY --from=hfsutils /usr/local/bin/hcopy /usr/local/bin/hcopy
COPY --from=hfsutils /usr/local/bin/humount /usr/local/bin/humount

COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=build /out/backfill /usr/local/bin/worker-backfill
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV SCRATCH_DIR=/scratch \
    SCANNER_PATH=/usr/local/bin/scanrook

RUN mkdir -p /scratch && \
    chmod 1777 /usr/local/bin

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
