# syntax=docker/dockerfile:1.6

############################
# 1) Build the worker
############################
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/worker ./cmd/worker

############################
# 2) Bring in the scanner binary
#    Option A: copy from your UI image (already contains /usr/local/bin/scanner)
############################
# ARG SCANNER_FROM_IMAGE=devintripp/deltaguard-ui:1.0.11
FROM devintripp/deltaguard-ui:1.0.11 AS scannerimage

############################
# 3) Final image
############################
FROM gcr.io/distroless/static:nonroot
WORKDIR /app

COPY --from=build        /out/worker                /usr/local/bin/worker
COPY --from=scannerimage /usr/local/bin/scanner     /usr/local/bin/scanner

# runtime dirs (emptyDir in k8s will be mounted here; still fine locally)
ENV SCRATCH_DIR=/scratch \
    SCANNER_PATH=/usr/local/bin/scanner

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/worker"]
