# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

# Install templ code generator
RUN go install github.com/a-h/templ/cmd/templ@latest

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Generate templ components, then build
RUN templ generate && \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /wicket \
    ./cmd/wicket

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache \
    ca-certificates \
    wireguard-tools \
    iptables \
    ip6tables

RUN mkdir -p /data /etc/wicket /var/run/wicket

COPY --from=builder /wicket /usr/local/bin/wicket
COPY config.example.yaml /etc/wicket/config.example.yaml

# Static files must be available at runtime for file serving
COPY web/ /app/web/

WORKDIR /app

EXPOSE 8080
EXPOSE 51820/udp

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/wicket"]
CMD ["serve", "--config", "/etc/wicket/config.yaml"]
