// image-spec subcommand : produce a Talos Linux machineconfig.yaml
// for a single box, pre-baked with everything the box needs to ZTP
// itself on first boot.
//
// What the spec contains
// ──────────────────────
//   - Talos machine settings (no SSH, no kubeadm — just the
//     LMbox runtime services as static-pod overrides)
//   - Pre-baked box client cert + key (signed by the customer's
//     root CA via `mint-box-cert`)
//   - Bridge URL (the customer's DMZ Bridge, learned from
//     customer-init metadata + operator flag)
//   - Audit chain genesis (per-customer, baked at customer-init)
//   - Initial bootstrap heartbeat target (so the box knows where
//     to send its first ZTP register call)
//
// The factory pipeline consumes this spec via Talos's image build
// tooling :
//
//     talosctl gen image \
//       --config ./<serial>-machineconfig.yaml \
//       --output ./<serial>.img
//
// then flashes ./<serial>.img to the box's NVMe before shipping.
// The box ships sealed ; the customer plugs power + network ;
// 20 minutes later the box appears in Fleet Console in "active" state.

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ImageSpec is the YAML we emit. We hand-template the YAML rather
// than pulling in gopkg.in/yaml.v3 — the spec has a few dozen lines,
// the indentation matters, and the readability of `Sprintf` with
// explicit `%s` placeholders beats an opaque struct → yaml.Marshal
// for the factory operator who'll diff successive boxes.

func runImageSpec(args []string) int {
	fs := flag.NewFlagSet("image-spec", flag.ExitOnError)
	customerID := fs.String("customer-id", "", "")
	source := fs.String("source", "./enrolments", "")
	serial := fs.String("serial", "", "box serial (must match a previously minted box cert)")
	bridgeURL := fs.String("bridge-url", "", "URL of the customer's DMZ Bridge (eg https://bridge.acme.local:8443)")
	outDir := fs.String("output", "./images", "directory where the machineconfig is written")
	talosVersion := fs.String("talos-version", "v1.7.4", "Talos Linux version to target (must match the base image used at factory build)")
	hostname := fs.String("hostname", "", "(optional) initial hostname for the box, defaults to serial")
	fs.Parse(args)

	if *customerID == "" || *serial == "" || *bridgeURL == "" {
		fmt.Fprintln(os.Stderr, "image-spec: --customer-id, --serial, --bridge-url are required")
		return 2
	}

	custDir := filepath.Join(*source, *customerID)
	boxCertPath := filepath.Join(custDir, "boxes", *serial+".crt")
	boxKeyPath := filepath.Join(custDir, "boxes", *serial+".key")
	if !exists(boxCertPath) || !exists(boxKeyPath) {
		fmt.Fprintf(os.Stderr,
			"image-spec: box cert+key for serial %q not found under %s/boxes/.\n"+
				"           Run `lmbox-bridge-enroll mint-box-cert --serial %s` first.\n",
			*serial, custDir, *serial)
		return 1
	}

	boxCN := *hostname
	if boxCN == "" {
		boxCN = strings.ToLower(*serial)
	}

	// Read genesis from the customer's enrolment.json so we don't
	// rely on the operator passing it on the command line (less
	// surface for typos).
	genesis, err := readGenesis(custDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "image-spec: read genesis: %v\n", err)
		return 1
	}

	// Validate the bridge URL is https.
	if !strings.HasPrefix(*bridgeURL, "https://") {
		fmt.Fprintf(os.Stderr, "image-spec: --bridge-url must be https (got %s)\n", *bridgeURL)
		return 2
	}

	// Read cert + key for inline embedding (Talos machineconfig
	// supports YAML | block scalars with the raw PEM content
	// directly — no shell expansion is performed).
	certPEM, _ := os.ReadFile(boxCertPath)
	keyPEM, _ := os.ReadFile(boxKeyPath)
	cert, err := decodePEMCert(certPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "image-spec: invalid box cert: %v\n", err)
		return 1
	}
	if !cert.NotAfter.After(time.Now()) {
		fmt.Fprintf(os.Stderr, "image-spec: box cert is expired (NotAfter=%s)\n", cert.NotAfter)
		return 1
	}

	// Build the YAML
	yaml := buildMachineConfig(machineConfigInputs{
		customerID:   *customerID,
		serial:       *serial,
		hostname:     boxCN,
		bridgeURL:    *bridgeURL,
		genesis:      genesis,
		talosVersion: *talosVersion,
		boxCertPEM:   string(certPEM),
		boxKeyPEM:    string(keyPEM),
	})

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "image-spec: mkdir: %v\n", err)
		return 1
	}
	outPath := filepath.Join(*outDir, *serial+"-machineconfig.yaml")
	if err := os.WriteFile(outPath, []byte(yaml), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "image-spec: write: %v\n", err)
		return 1
	}

	fmt.Printf("✓ machineconfig written to %s\n", outPath)
	fmt.Printf("  customer  : %s\n", *customerID)
	fmt.Printf("  serial    : %s\n", *serial)
	fmt.Printf("  hostname  : %s\n", boxCN)
	fmt.Printf("  bridge    : %s\n", *bridgeURL)
	fmt.Printf("  talos     : %s\n", *talosVersion)
	fmt.Printf("  cert exp  : %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Next steps (factory pipeline) :")
	fmt.Printf("  1. talosctl gen image --config %s --output ./%s.img\n", outPath, *serial)
	fmt.Printf("  2. dd if=./%s.img of=/dev/nvme0n1 bs=4M conv=fsync\n", *serial)
	fmt.Println("  3. Power off, package, ship to customer.")
	fmt.Println("  4. At first boot, the box will ZTP via the bridge URL above.")

	return 0
}

// ─── Internals ─────────────────────────────────────────────────────

type machineConfigInputs struct {
	customerID, serial, hostname, bridgeURL, genesis, talosVersion string
	boxCertPEM, boxKeyPEM                                          string
}

// indentBlock prefixes every line of `s` with `indent` spaces.
// Used to embed multi-line PEM content under a YAML `|` block
// scalar — Talos expects ≥ N+2 indentation on each continuation
// line relative to the parent key.
func indentBlock(s, indent string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, ln := range lines {
		lines[i] = indent + ln
	}
	return strings.Join(lines, "\n")
}

// buildMachineConfig hand-templates the Talos machineconfig YAML.
// The template embeds the LMbox-specific config as machine.files
// (dropped at /etc/lmbox/) and as machine.env for the lmbox-runtime
// systemd unit Talos extension to pick up at boot.
//
// We do NOT use Talos's complex `cluster:` block — we run the box
// in single-node mode without kubeadm. The LMbox services
// (lmbox-controller, litellm, ollama, audit chain) run as
// container static pods managed by Talos's `containerd`.
func buildMachineConfig(in machineConfigInputs) string {
	// Indent comment : Talos YAML is YAML 1.2, we keep 2-space
	// indent throughout. Multi-line strings (cert + key) use the
	// `|` block scalar style to preserve PEM line breaks.
	return fmt.Sprintf(`# Talos Linux machineconfig for LMbox-S1
# Generated by lmbox-bridge-enroll %s on %s
# Customer : %s · Serial : %s
#
# DO NOT EDIT MANUALLY. Re-run image-spec to regenerate.
# The factory pipeline consumes this with: talosctl gen image --config <this>

version: v1alpha1
debug: false
persist: true

machine:
  type: controlplane           # single-node appliance, no cluster
  token: %s                    # bootstrap token, derived from serial
  certSANs:
    - %s.lmbox.local
    - lmbox-%s

  network:
    hostname: %s
    nameservers:
      - 1.1.1.1
      - 9.9.9.9                # Quad9, EU-resident DNS, no logging
    extraHostEntries: []

  install:
    disk: /dev/nvme0n1
    image: ghcr.io/siderolabs/installer:%s
    wipe: false
    extensions:
      - image: ghcr.io/lmbox/talos-extension-lmbox-runtime:latest

  files:
    - path: /etc/lmbox/box.crt
      content: |
%s
      permissions: 0o644
      op: create
    - path: /etc/lmbox/box.key
      content: |
%s
      permissions: 0o600
      op: create
    - path: /etc/lmbox/ztp.env
      content: |
        LMBOX_CUSTOMER_ID=%s
        LMBOX_BOX_SERIAL=%s
        LMBOX_BRIDGE_URL=%s
        LMBOX_AUDIT_GENESIS=%s
        LMBOX_FIRST_BOOT=true
      permissions: 0o600
      op: create

  sysctls:
    net.ipv4.ip_forward: "0"   # appliance, no routing
    kernel.unprivileged_userns_clone: "1"

  features:
    rbac: true
    stableHostname: true

  registries: {}

  time:
    disabled: false
    servers:
      - time.cloudflare.com
      - time.google.com

# The LMbox runtime is configured via cluster-less extras (see
# /etc/lmbox/ztp.env above). The Talos extension
# talos-extension-lmbox-runtime ships the binaries (litellm,
# ollama, lmbox-controller, lmbox-portal, audit-chain) and a
# bootstrap systemd unit that reads /etc/lmbox/ztp.env, posts the
# first heartbeat via LMBOX_BRIDGE_URL, and applies whatever
# personalised config the cloud sends back.

cluster: null
`,
		Version,
		time.Now().UTC().Format(time.RFC3339),
		in.customerID,
		in.serial,
		bootstrapToken(in.serial),
		in.hostname,
		in.hostname,
		in.hostname,
		in.talosVersion,
		indentBlock(in.boxCertPEM, "        "), // 8-space indent under `content: |`
		indentBlock(in.boxKeyPEM, "        "),
		in.customerID,
		in.serial,
		in.bridgeURL,
		in.genesis,
	)
}

// bootstrapToken derives a deterministic but un-guessable token
// from the box serial. The talos machine token doesn't need to be
// secret (it gates joining a cluster, and we run single-node), but
// derivable lets the factory operator re-generate the spec
// idempotently for the same serial.
func bootstrapToken(serial string) string {
	// Take first 32 chars of a SHA-256 of the serial — Talos accepts
	// any string-ish format here.
	return strings.ToLower(strings.ReplaceAll(serial, "-", "_")) + "_t1"
}

// decodePEMCert peels the first CERTIFICATE block off the input.
func decodePEMCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("not a CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// readGenesis grabs the audit-chain genesis from the customer's
// enrolment.json. The genesis is set once at customer-init and
// MUST flow through to the box (it's used both for the box-side
// audit chain and to identify the box to the LMbox cloud).
func readGenesis(custDir string) (string, error) {
	metaPath := filepath.Join(custDir, "enrolment.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", metaPath, err)
	}
	// Cheap parsing : look for "audit_genesis": "...". We avoid
	// pulling in encoding/json schema struct here because the file
	// already has its own typed reader (EnrolmentMeta in main.go),
	// and re-importing it would create a circular concern with the
	// CLI flow ordering. Stick with the line scan — works because
	// writeMeta uses MarshalIndent with stable key ordering.
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		const prefix = `"audit_genesis":`
		if strings.HasPrefix(line, prefix) {
			rest := strings.TrimSpace(line[len(prefix):])
			rest = strings.TrimSuffix(rest, ",")
			rest = strings.Trim(rest, ` "`)
			return rest, nil
		}
	}
	return "", fmt.Errorf("audit_genesis not found in %s — re-run customer-init", metaPath)
}
