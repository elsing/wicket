# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

# Set by buildx per target platform, e.g. "linux"/"arm64" — do not hardcode,
# this stage is built once per platform in --platforms.
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# templ is a go.mod tool dependency (pinned version) — `go tool templ` uses
# exactly that version, no separate install needed.
RUN go tool templ generate && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -o /wicket ./cmd/wicket && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -o /wicket-agent ./cmd/wicket-agent

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache \
    ca-certificates \
    wireguard-tools \
    iptables \
    ip6tables

RUN mkdir -p /data /etc/wicket /var/run/wicket

COPY --from=builder /wicket /usr/local/bin/wicket
COPY --from=builder /wicket-agent /usr/local/bin/wicket-agent
COPY web/ /app/web/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 8080
EXPOSE 51820/udp

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["serve", "--config", "/etc/wicket/config.yaml"]