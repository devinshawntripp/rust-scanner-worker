FROM --platform=linux/amd64 golang:1.25-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /registry-puller ./cmd/registry-puller/

FROM --platform=linux/amd64 gcr.io/distroless/static:nonroot
COPY --from=builder /registry-puller /registry-puller
ENTRYPOINT ["/registry-puller"]
