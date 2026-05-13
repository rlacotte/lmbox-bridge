# Architecture

The Bridge is a **deliberately small** piece of software. The entire
production behaviour fits in ~1 200 lines of Go, distributed across
8 internal packages with one responsibility each. We resist the
temptation to add features because every feature is a Tuesday-morning
incident at a customer's DMZ — and incidents at a DMZ are the
hardest to debug.

## Trust boundary

```
                    ┌─────────────────────────────────┐
                    │   Customer LAN (trusted, but    │
                    │   subject to compromise of any  │
                    │   single box)                   │
                    │                                 │
   ┌────────┐       │  ┌──────────┐   ┌──────────┐    │
   │ Other  │       │  │ LMbox    │   │ LMbox    │    │
   │ LAN    │──────►│  │ Box #1   │   │ Box #2   │  …N│
   │ traffic│       │  └────┬─────┘   └────┬─────┘    │
   └────────┘       │       │ mTLS (8443)  │           │
                    │       └──────┬───────┘           │
                    └──────────────┼───────────────────┘
                                   ▼
                    ┌─────────────────────────────────┐
                    │   Customer DMZ                  │
                    │   ┌──────────────────────┐      │
                    │   │   LMbox Bridge       │      │
                    │   │   - mTLS in          │      │
                    │   │   - regex CN allowlist│     │
                    │   │   - CRL              │      │
                    │   │   - token bucket     │      │
                    │   │   - path allowlist   │      │
                    │   │   - SHA-256 audit    │      │
                    │   └────┬─────────────────┘      │
                    │        │ mTLS (443)             │
                    └────────┼────────────────────────┘
                             ▼
                    ┌─────────────────────────────────┐
                    │   LMbox Cloud (lmbox.eu)        │
                    │   - heartbeats endpoint         │
                    │   - agent upload endpoint       │
                    │   - cloud-side audit chain      │
                    │     (witnesses Bridge chain)    │
                    └─────────────────────────────────┘
```

**Trust assumptions** :

1. Any individual box CAN be compromised at the OS level (LAN-side
   attacker, supply-chain malicious binary). The Bridge therefore
   treats every box request as untrusted input: cert allowlist,
   path allowlist, rate limit, audit.
2. The Bridge VM itself is trusted (semi-formally — see
   "Bridge compromise" below).
3. The LMbox cloud is trusted to NOT send malicious responses; we
   stream them through to the box without inspection.
4. The customer's IT admins are trusted to NOT silently rewrite the
   Bridge config or remove the audit log file. The audit chain's
   tamper evidence is the recourse if they try.

## Request flow (happy path)

```
Box                                Bridge                            Cloud
 │                                    │                                │
 │── mTLS handshake (port 8443) ─────►│                                │
 │       client cert presented        │                                │
 │                                    │                                │
 │── POST /api/heartbeats/BOX-001 ───►│                                │
 │       body: {"hb": …}              │                                │
 │                                    │ ┌── auth.Verify(cert)          │
 │                                    │ ├── ratelimit.Allow(serial)    │
 │                                    │ ├── proxy.PathAllowed(path)    │
 │                                    │ │                              │
 │                                    │ └── proxy.ServeHTTP            │
 │                                    │       │                        │
 │                                    │       │ mTLS handshake ───────►│
 │                                    │       │                        │
 │                                    │       │ POST .../heartbeats ──►│
 │                                    │       │       X-LMbox-Box: …   │
 │                                    │       │       X-Forwarded-For  │
 │                                    │       │                        │
 │                                    │       │◄── 200 {"ok": true}    │
 │                                    │       │                        │
 │                                    │ ┌─ audit.Append (intact chain) │
 │                                    │ │   bytes_in, bytes_out, dur   │
 │                                    │ └─                             │
 │◄── 200 {"ok": true} ───────────────│                                │
```

Every box request crosses the chain primitive **once**. The audit
log is the only writer on the hot path; everything else is a
read-only check.

## Files written on disk

| Path | Owner | What | Why |
|---|---|---|---|
| `/var/lib/lmbox-bridge/audit.log` | lmbox-bridge:lmbox-bridge | append-only, fsynced after each Write | SHA-256 chained for tamper evidence |
| `/etc/lmbox-bridge/config.yaml` | root:lmbox-bridge | read-only by service | operator-owned, RSSI-auditable |
| `/etc/lmbox-bridge/certs/*` | root:lmbox-bridge | read-only, mode 0600 keys | Bridge auth material |

Nothing else. No temp files, no scratch directories, no cache.

## Bridge compromise — what's the blast radius

Threat model: an attacker gets root on the Bridge VM.

| Capability | Mitigated how |
|---|---|
| Read in-flight request bodies | Yes — the attacker has the Bridge's keys; mTLS keys decrypt the boxes' sessions. **No mitigation in the Bridge itself** — we accept that with the appliance model. The cloud-side ratelimit on suspicious traffic patterns is the second line of defence. |
| Tamper with past audit entries | Detected by `lmbox-bridge verify` re-walking the SHA-256 chain. The chain doesn't PREVENT tampering, it makes it impossible to do silently. |
| Inject fake box requests upstream | The cloud accepts only client-cert-authenticated requests where the cert matches an enrolled Bridge. Stealing the Bridge's key lets the attacker impersonate the Bridge — but the cloud-side audit chain records every Bridge submission with a hash, so anomalies show up. |
| Take the Bridge offline | DoS only — the boxes queue heartbeats locally and resume on Bridge recovery. No data loss. |

The Bridge is not a security boundary in the cryptographic sense.
It is an **observable choke point** that turns box-to-cloud traffic
into auditable events. The audit chain is the contract.

## Why not a Tailscale / WireGuard mesh

We considered a mesh VPN approach where each box has a private
tunnel to the cloud through Tailscale. Two issues :

1. Each box ends up with its own outbound connection to the public
   Internet — the RSSI's "1 firewall rule" benefit goes away.
2. Tailscale's coordination server (or a self-hosted Headscale) is
   yet another piece of infrastructure the customer's IT must adopt
   and audit. We're trying to REMOVE pieces, not add.

A reverse proxy with a clearly-defined contract is the cheaper,
auditable answer for the on-prem regulated-industry target.

## Why not just port-forward 443 from the LAN

The Bridge does HTTP-application-level inspection :

- path allowlist (a port-forward forwards bytes, not paths)
- audit chain (a port-forward sees opaque TLS bytes)
- rate limit per-box (a port-forward can't extract the box serial)
- header sanitisation (a port-forward can't strip cookies)

Each of these is a real, customer-facing requirement.

## What we deliberately don't do

- **Hot config reload.** Restart is ~2 seconds; the boxes retry.
- **CRL fetched over HTTP.** Operators drop the file in place; the
  Bridge reloads from disk. Outbound HTTP for CRL fetch would add
  yet another egress rule.
- **OCSP responder.** Same reasoning. v0.2 may add OCSP stapling on
  the listener side if customer demand justifies it.
- **Distributed Bridge cluster.** A single 4 GB VM serves 60 boxes
  comfortably; series A target of 600 boxes still fits in a single
  VM. When it doesn't, we ship a stateful clustering story —
  prematurely is wrong.
- **Auth via OIDC / SSO.** The Bridge authenticates BOXES, not
  humans. SSO is an operator-side concern for the LMbox portal,
  not for the egress relay.
