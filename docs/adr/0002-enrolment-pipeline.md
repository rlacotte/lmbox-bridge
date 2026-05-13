# ADR-0002 — Enrolment pipeline (`lmbox-bridge-enroll`)

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-13 |
| Decider | LMbox core team |

## Context

The Bridge ([ADR-0001](0001-bridge-design.md)) requires 5 cert/key
artefacts at installation time, plus a CRL and a config file. Six
months ago we were generating these by hand with `openssl`,
checking outputs by eye, and producing kits as ad-hoc tarballs.
That worked for the first two customers and would have collapsed at
the third one.

The seed plan calls for **60 boxes installed by M+18**, spread
across ~10-15 customers. Each customer requires :

- 1 root CA gen
- 1 Bridge server cert mint
- 1 Bridge outbound cert mint (signed by LMbox cloud CA)
- N box client cert mints (1 per box shipped)
- 1 kit pack + HMAC sign
- Audit trail of every minted cert (inventory)

That's ~70 cert/keypair operations + 10 kit pack operations across
the seed milestone — minimum. None of it can be eyeballed without
breaking the trust chain we promise to the regulator.

## Decision

We ship `lmbox-bridge-enroll`, a separate Go CLI binary in the same
`lmbox-bridge` repo, that automates the entire pipeline. Same Go
codebase, same `go test` suite, same release artefact, but a
distinct entrypoint so the runtime Bridge and the enrolment tool
never coexist in the same process.

### Subcommand surface

| Subcommand | Effect |
|---|---|
| `customer-init` | Creates root CA + box-ca.pem + empty CRL + config.yaml + inventory metadata |
| `mint-bridge-server` | Signs the Bridge mTLS server cert (with SANs) using the customer root |
| `mint-bridge-outbound` | Signs the Bridge mTLS client cert (for cloud) using the LMbox cloud CA |
| `mint-box-cert` | Signs a box client cert using the customer root, for factory provisioning |
| `pack-kit` | Tar.gzs the shippable subset + HMAC-signs with the partner key |
| `verify-kit` | Re-checks a kit's HMAC and optionally extracts |

### Key design decisions

| Decision | Why |
|---|---|
| Pure Go stdlib `crypto/x509` (no cfssl, no vault) | Audit-friendly, single binary, no extra runtime |
| ECDSA P-256 keys everywhere | Smaller, faster, ubiquitous TLS support; PQ migration via key rotation later |
| 159-bit random cert serials | RFC 5280 §4.1.2.2 best practice — avoids collisions and DER edge cases |
| Per-customer trust domain (root CA per customer) | A compromised customer's root reveals only that customer's PKI; LMbox cloud trust is separate |
| LMbox cloud CA signs ONLY Bridge outbound certs | One cloud trust root, N customer trust roots — clean separation |
| HMAC-SHA256 for kit signing (not GPG / X.509) | Symmetric secret per integrator partner; trivial for RSSI to verify; revocation = key rotation |
| Reproducible kit builds (sorted entries, fixed mtime) | Two operators producing the same kit get byte-identical tarballs |
| inventory metadata in `enrolment.json` | Audit + rotation queries without parsing certs |
| 5-year default root CA lifetime, 1-year default leaf | Cheap renewal (`lmbox-bridge-enroll mint-bridge-server` rerun), root rotation is a deliberate event |

### What we deliberately do NOT do (v0.1)

- **Passphrase encryption of root CA key.** The enrolment machine
  is full-disk-encrypted (LUKS / FileVault). Adding a passphrase
  layer is good practice but adds UX friction and is a defence
  IN ADDITION TO disk encryption, not instead of. Deferred.
- **`revoke` subcommand.** Operator uses `openssl ca -revoke` until
  v0.2. Revocation is rare enough that the manual path is OK.
- **HSM / KMS backing for the cloud CA key.** The cloud CA key
  lives on the enrolment machine in `/etc/lmbox/cloud-ca.key`.
  v0.2 moves it to HashiCorp Vault Transit or AWS KMS for sign-
  only access. v0.1 ships with documented operator procedures
  (2-eyes, audit log, jumphost).
- **Multi-tenant root CA.** Each customer gets a fresh root. We
  considered a single LMbox CA + per-customer intermediates ;
  rejected because (a) customer wants to be able to revoke the
  whole tenant in one operation (delete the root), and (b) one CA
  compromise reveals every customer.

## Consequences

### Positive

- **Repeatable.** A new customer enrolment is 6 commands. Zero
  manual `openssl` arguments to copy-paste.
- **Auditable.** `enrolment.json` is the ledger of who-was-issued-
  what-when, signed implicitly by the fact that the CA key was
  required to produce the certs listed.
- **Reproducible kit builds.** Two operators with the same inputs
  produce byte-identical kits. Detects ALL operator drift.
- **Round-trip-tested.** E2E test
  ([cmd/lmbox-bridge-enroll/e2e_test.go](../../cmd/lmbox-bridge-enroll/e2e_test.go))
  runs `customer-init → mint → pack → verify → extract → load
  certs into a TLS listener → handshake with a box client cert`.
  If any step regresses, the test fails before the operator notices
  in production.

### Negative / accepted

- **Operator skill is single-point-of-failure.** A staff member
  who runs `customer-init` with wrong `customer-id` produces an
  un-revokable cert (we don't currently support cross-customer
  re-attribution). Mitigated by the 2-eyes review step in
  ENROLL.md.
- **Kit signing key management per-partner.** Sopra, Inetum,
  Magellan each get their own HMAC key. Compromise of one partner
  channel reveals integrity assertions about kits sent through
  that partner — but never any PKI material. Rotation procedure
  in ENROLL.md.
- **The cloud CA key is the crown jewel.** Compromise here lets
  an attacker forge Bridge outbound certs for every customer. v0.2
  HSM/KMS backing closes this.

## References

- `internal/pki/pki.go` — cert primitives + 8 tests
- `internal/kit/kit.go` — tarball pack + HMAC sign + 7 tests
- `cmd/lmbox-bridge-enroll/main.go` — CLI surface
- `cmd/lmbox-bridge-enroll/e2e_test.go` — E2E pipeline test
- [docs/ENROLL.md](../ENROLL.md) — operator runbook
- [docs/INSTALL.md](../INSTALL.md) — RSSI procedure on receiving a kit
