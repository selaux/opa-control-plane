ARG GOVERSION=
FROM golang:${GOVERSION} AS builder

# Install build dependencies for CGO and make
RUN apt-get update && apt-get install -y --no-install-recommends build-essential make ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Set environment variables for CGO and build cache
ENV CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64 \
    GOCACHE=/go/cache


# Build using the Makefile, output to /src/lighthouse_linux_amd64
RUN --mount=type=cache,target=/go/cache make build BIN=/src/lighthouse_linux_amd64

# Final minimal image (Chainguard glibc)
FROM cgr.dev/chainguard/glibc-dynamic:latest
WORKDIR /app
COPY --from=builder /src/lighthouse_linux_amd64 ./lighthouse_linux_amd64
ENTRYPOINT ["/app/lighthouse_linux_amd64"]
