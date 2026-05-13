# ADR-0001 — LMbox Bridge: single-egress relay design

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-13 |
| Decider | LMbox core team |

## Context

LMbox ships an on-prem AI appliance ("box"). At seed-milestone scale
(60 boxes by M+18), every box installed at a customer would, by
default, need :

1. Its own outbound firewall rule on the customer's edge router.
2. A signed-off network configuration discussion with the
   customer's RSSI / DSI.
3. An ongoing maintenance commitment from the customer's IT team to
   keep that rule alive across firewall migrations.

This scales poorly. At 60 boxes spread across ~10-15 customers,
the CTO's calendar gets filled with "we updated our firewall and
now the box can't talk home" calls. Each such call is ~3-4 hours
of founder time. We project ~480 j-h of avoidable load on the CTO
over 18 months without an architectural fix.

## Decision

We ship a **single-egress relay** — `lmbox-bridge` — as part of the
appliance deployment kit. Each customer installs ONE Bridge in their
DMZ ; every box on the customer's LAN reaches the LMbox cloud
through it.

The Bridge is :

- A single Go static binary (no CGO, no dynamic linking)
- ~ 12 MB, runs in 4 GB RAM
- Listens on 8443/tcp for mTLS connections from boxes
- Connects outbound to `*.lmbox.eu:443` over mTLS
- Stateless except for a local SHA-256-chained audit log

### What the Bridge IS

| Aspect | Choice |
|---|---|
| Language | Go 1.20+ (single binary, predictable runtime, mature TLS stdlib) |
| Auth in | mTLS client cert + CN regex allowlist + CRL with periodic reload |
| Auth out | mTLS client cert presented to LMbox cloud |
| Allowlist | URL path prefix list (default: heartbeats + agent uploads only) |
| Rate limit | Token bucket per-box + global cap |
| Audit | SHA-256 hash-chained JSON log, fsynced per entry |
| Observability | Prometheus on separate listener (127.0.0.1:9090 default) |
| Health | `/healthz` (liveness) + `/readyz` (readiness with upstream probe) |
| Deploy | systemd unit (DynamicUser=yes) + distroless OCI image |

### What the Bridge IS NOT

- A general-purpose API gateway. Path allowlist is hard-coded to
  LMbox cloud endpoints.
- A TLS terminator for the customer's other internal traffic.
- A configuration store. All config lives in `/etc/lmbox-bridge/config.yaml` ;
  no remote control plane.
- A cryptographic security boundary against Bridge-VM root compromise.
  The audit chain detects tampering, but doesn't prevent it.

## Consequences

### Positive

- **One firewall rule per customer.** The RSSI conversation moves
  from "every box install" to "once at customer enrolment". At 60
  boxes spread across 10-15 customers, we save ~85 % of the firewall
  negotiations.
- **Auditable choke point.** Every box-to-cloud byte is observable
  at one place. The customer's compliance team can audit one binary
  + one log file rather than N boxes.
- **Single egress signature.** From the cloud's perspective, every
  customer's traffic carries that customer's Bridge cert. Cloud-side
  metrics and abuse detection have a clean per-customer aggregation
  key.
- **No inbound exposure.** The Bridge accepts NO inbound connection
  from outside the customer LAN. The customer's firewall posture
  is unchanged.
- **Self-healing on reset.** A factory-reset Bridge resumes its
  audit chain from disk on next start, preserving the historical
  record across operational maintenance.

### Negative / accepted

- **The Bridge is a single point of failure** per customer. If the
  VM dies, all boxes lose cloud connectivity until restart. We
  accept this : boxes queue heartbeats locally and re-send on Bridge
  recovery ; the SLA promise is "best-effort within 5 min of
  recovery", not "always-on".
- **Cert lifecycle complexity.** Each customer's enrolment kit
  contains 3 cert/key pairs (Bridge server cert, Bridge outbound
  cert, box CA bundle). We ship a `lmbox-bridge-enroll` tool to
  generate them, but it's still 3 more artefacts to rotate.
- **In-flight request data is in cleartext within the Bridge.** A
  Bridge-VM root compromise reveals every request body. We accept
  this : the alternative (true end-to-end encryption from box to
  cloud) would defeat the path allowlist and audit chain, which
  ARE the regulator-facing value. Defence in depth shifts the
  burden to the audit chain + cloud-side anomaly detection.

### Alternatives rejected

- **Mesh VPN (Tailscale / Headscale / WireGuard).** Adds a
  coordination layer the customer's IT team must adopt. Each box
  ends up with its own outbound connection — the "1 firewall rule"
  property disappears.
- **L4 port-forward.** Can't enforce path allowlist, can't extract
  box serial for per-box rate limit, can't audit by URL path. The
  Bridge's value is application-layer awareness.
- **Cloud-side per-customer egress proxy.** Moves the friction to
  LMbox infra : we'd run N customer-specific endpoints, each with
  its own firewall rules at our edge. The Bridge keeps that
  complexity on the customer side, where they already have
  competent IT teams.

## References

- `internal/proxy/proxy.go` — reverse proxy with header scrub + allowlist
- `internal/auth/auth.go` — cert + CRL validation
- `internal/audit/chain.go` — SHA-256 chain, parity with LMbox portal
- `internal/server/server.go` — middleware orchestration
- `internal/server/server_e2e_test.go` — full mTLS happy-path + rejections
- LMbox portal audit chain — same SHA-256 chain primitive used at
  `app.lmbox.eu` ; the cloud witnesses each Bridge's local chain so
  a customer's IT alone can't rewrite history without the cloud
  noticing.
