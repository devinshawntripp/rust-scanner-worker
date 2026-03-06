# syntax=docker/dockerfile:1.6

############################
# 1) Build the Go worker
############################
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/backfill ./cmd/backfill
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/runjob ./cmd/runjob
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/dispatcher ./cmd/dispatcher

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
# 1c) Install scanner binary at build time
############################
FROM debian:trixie-slim AS scanner-install
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl ca-certificates && rm -rf /var/lib/apt/lists/*
ENV INSTALL_DIR=/usr/local/bin
RUN curl -fsSL https://scanrook.sh/install | bash

############################
# 2) Minimal runtime image
# Scanner binary baked in, auto-updates on startup
############################
FROM debian:trixie-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl gawk libssl3 rpm libarchive-tools p7zip-full && \
    rm -rf /var/lib/apt/lists/*

COPY --from=hfsutils /usr/local/bin/hmount /usr/local/bin/hmount
COPY --from=hfsutils /usr/local/bin/hcopy /usr/local/bin/hcopy
COPY --from=hfsutils /usr/local/bin/humount /usr/local/bin/humount

COPY --from=scanner-install /usr/local/bin/scanrook /usr/local/bin/scanrook
COPY --from=build /out/worker /usr/local/bin/worker
COPY --from=build /out/backfill /usr/local/bin/worker-backfill
COPY --from=build /out/runjob /usr/local/bin/runjob
COPY --from=build /out/dispatcher /usr/local/bin/dispatcher
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY entrypoint-runjob.sh /usr/local/bin/entrypoint-runjob.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint-runjob.sh

ENV SCRATCH_DIR=/scratch \
    SCANNER_PATH=/usr/local/bin/scanrook

RUN mkdir -p /scratch && \
    chmod 1777 /usr/local/bin

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
