# Multi-stage build for the LMbox Bridge.
#
# Final image is distroless (no shell, no apt, no nothing) — about
# 20 MB. The Bridge is a single static binary, so this is the cheapest
# auditable container we can ship to a customer's container platform.
#
# Operator notes:
#   - Config is expected at /etc/lmbox-bridge/config.yaml (mount as
#     a read-only volume).
#   - Audit chain is written to /var/lib/lmbox-bridge (mount as a
#     persistent volume).
#   - Default listening port 8443 (mTLS).
#   - Metrics on 9090 (plain HTTP, bind to localhost in the config
#     by default — expose via a sidecar if you want external access).

# ─── builder ────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w \
        -X main.Version=${VERSION} \
        -X main.Commit=${COMMIT} \
        -X main.BuildDate=${BUILD_DATE}" \
    -o /out/lmbox-bridge ./cmd/lmbox-bridge

# ─── runtime ────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/lmbox-bridge /usr/local/bin/lmbox-bridge
USER nonroot:nonroot
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/lmbox-bridge"]
CMD ["serve", "--config", "/etc/lmbox-bridge/config.yaml"]
