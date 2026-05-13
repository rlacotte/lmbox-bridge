# LMbox Bridge

Single-egress relay for [LMbox](https://lmbox.eu) appliances.
**One binary in the customer's DMZ. One firewall rule.
N boxes auto-served on the LAN.**

The Bridge replaces the per-box conversation between the customer's
RSSI and the LMbox CTO. Instead of negotiating outbound rules for
each appliance shipped, the RSSI installs `lmbox-bridge` once on a
small VM (4 GB RAM, no GPU, no inbound exposure), and every LMbox
box on the customer's LAN reaches the LMbox cloud through it.

## Why this exists

On-prem appliances historically die on the **second** installation
at a customer. The first box is exciting; the second is "yet another
firewall ticket". At a target of 60 boxes installed by M+18, every
hour of RSSI×CTO conversation per box is a ~480 k€ founder-time tax.

The Bridge eliminates that tax by construction :

- **One binary, one firewall rule.** The RSSI opens `Bridge → *.lmbox.eu:443`
  once. Every future box on that customer's LAN is invisible to the
  firewall — they connect to the Bridge on a private port (8443
  mTLS) inside the LAN.
- **mTLS in both directions.** Boxes authenticate to the Bridge with
  client certs issued at factory provisioning. The Bridge
  authenticates to the LMbox cloud with its own cert issued at
  customer enrolment.
- **Path allowlist.** Even a compromised box can't reach arbitrary
  cloud endpoints — the Bridge forwards only `/api/heartbeats/…`
  and `/api/agents/…` (configurable).
- **SHA-256 audit chain.** Every request, accepted or denied, is
  appended to a tamper-evident log the RSSI can re-walk with one
  command (`lmbox-bridge verify`) to prove nothing has been
  silently changed.

## Features

| | |
|---|---|
| **Auth** | mTLS client cert validation with regex CN allowlist + CRL revocation, reloaded periodically from disk |
| **Rate limit** | Token bucket per-box (default 10 req/s, burst 100) + global bucket (1000 req/s, burst 5000) |
| **Audit chain** | Tamper-evident SHA-256-chained JSON log, opposable to a regulator. Matches the LMbox portal's chain genesis convention |
| **Proxy** | HTTP/2 reverse proxy with hop-by-hop scrubbing, cookie/auth header stripping, X-Forwarded-For injection |
| **Observability** | Prometheus metrics on a separate listener (default 127.0.0.1:9090), health + readiness probes |
| **Hardening** | systemd `DynamicUser=yes`, capability-bound, namespaced filesystem, no shell in the Docker image (distroless) |
| **Deploy** | Single static binary (~ 12 MB), systemd unit, distroless OCI image |

## Quick start

```bash
# 1. Build (optional — pre-built binaries on GitHub Releases)
make build

# 2. Drop the binary, config, certs in place
sudo install -m 0755 bin/lmbox-bridge /usr/local/bin/
sudo mkdir -p /etc/lmbox-bridge/certs /var/lib/lmbox-bridge
sudo cp examples/config.yaml /etc/lmbox-bridge/
#  → drop your own certs into /etc/lmbox-bridge/certs/
sudo cp deploy/systemd/lmbox-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lmbox-bridge

# 3. Verify the audit chain at any time
lmbox-bridge verify \
  --audit /var/lib/lmbox-bridge/audit.log \
  --genesis "acme-industries-2026|2026-05-13T09:00:00Z"
```

For the RSSI-facing 1-page procedure, see [INSTALL.md](docs/INSTALL.md).
For the design rationale, see [ARCHITECTURE.md](docs/ARCHITECTURE.md)
and the [ADR](docs/adr/0001-bridge-design.md).

## Module layout

```
cmd/lmbox-bridge/        entrypoint + subcommands (serve, verify, version)
internal/config/         YAML loader + validation
internal/audit/          SHA-256 chained log + Resume / Verify
internal/ratelimit/      Token bucket per-box + global
internal/auth/           Cert validation + CRL with periodic reload
internal/proxy/          HTTPS reverse proxy with allowlist + header scrub
internal/server/         mTLS server orchestrating the middleware stack
internal/metrics/        Prometheus registry
internal/health/         Liveness + readiness probes
deploy/                  systemd unit + Dockerfile
examples/                annotated config.yaml
docs/                    INSTALL, ARCHITECTURE, ADR
```

## Status

`0.1.0` — production-grade core (mTLS in/out, audit chain, rate
limit, allowlist, audit verify CLI, systemd + Docker deploy). One
E2E test exercises every rejection path with real generated certs.

Roadmap : ACME auto-renewal of the Bridge's own cert, OCSP stapling,
metrics for per-cipher distribution, Talos Linux extension package.

## License

MIT. See [LICENSE](LICENSE).
