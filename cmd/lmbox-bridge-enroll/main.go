// Command lmbox-bridge-enroll generates a customer's PKI material
// and packages a signed enrolment kit for shipment to the customer's
// RSSI.
//
// Typical operator flow
//
//	# 1. New customer onboarded by an integrator partner.
//	lmbox-bridge-enroll customer-init \
//	    --customer-id acme-industries \
//	    --customer-name "Acme Industries SAS" \
//	    --output ./enrolments
//
//	# 2. Mint the Bridge's server cert with the SANs the customer
//	#    will use on the DMZ VM.
//	lmbox-bridge-enroll mint-bridge-server \
//	    --customer-id acme-industries \
//	    --dns bridge.acme.example.com \
//	    --ip 10.0.50.42
//
//	# 3. Mint the Bridge's outbound cert (signed by the LMbox cloud CA).
//	lmbox-bridge-enroll mint-bridge-outbound \
//	    --customer-id acme-industries \
//	    --cloud-ca-cert /etc/lmbox/cloud-ca.crt \
//	    --cloud-ca-key  /etc/lmbox/cloud-ca.key
//
//	# 4. Mint a box client cert at factory provisioning time.
//	lmbox-bridge-enroll mint-box-cert \
//	    --customer-id acme-industries \
//	    --serial BOX-ACME-001
//
//	# 5. Pack the Bridge kit (everything the customer's RSSI needs).
//	lmbox-bridge-enroll pack-kit \
//	    --customer-id acme-industries \
//	    --hmac-key /etc/lmbox/sopra-partner-hmac.key \
//	    --output ./out/acme-industries-bridge-kit.tar.gz
//
//	# 6. RSSI on the customer side, verifies the kit.
//	lmbox-bridge-enroll verify-kit \
//	    --kit acme-industries-bridge-kit.tar.gz \
//	    --hmac-key /tmp/sopra-partner-hmac.key
//
// The on-disk layout under --output is :
//
//	enrolments/<customer-id>/
//	  enrolment.json              # metadata
//	  root/root-ca.crt + .key     # customer root CA (KEEP IN VAULT)
//	  bridge/bridge-server.{crt,key}
//	  bridge/bridge-out.{crt,key}
//	  bridge/box-ca.pem           # = root-ca.crt, what the Bridge trusts
//	  boxes/BOX-ACME-001.{crt,key}
//	  crl/box-revocations.crl
//	  config.yaml                 # rendered for the customer
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rlacotte/lmbox-bridge/internal/kit"
	"github.com/rlacotte/lmbox-bridge/internal/pki"
)

// Version metadata (overridden at build time via -ldflags).
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// EnrolmentMeta is the JSON blob we write next to the certs to keep
// an inventory of who-was-enrolled-when. Operators tail this to
// audit the partner channel.
type EnrolmentMeta struct {
	CustomerID    string       `json:"customer_id"`
	CustomerName  string       `json:"customer_name"`
	CreatedAt     time.Time    `json:"created_at"`
	ToolVersion   string       `json:"tool_version"`
	RootCA        CertSummary  `json:"root_ca"`
	BridgeServer  *CertSummary `json:"bridge_server,omitempty"`
	BridgeOut     *CertSummary `json:"bridge_outbound,omitempty"`
	Boxes         []CertSummary `json:"boxes,omitempty"`
	GenesisString string       `json:"audit_genesis"`
}

// CertSummary is the metadata we record per cert. We do NOT include
// the private key fingerprint — only the cert serial + CN + lifetime.
type CertSummary struct {
	Serial    string    `json:"serial"`
	CN        string    `json:"cn"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "customer-init":
		os.Exit(runCustomerInit(os.Args[2:]))
	case "mint-bridge-server":
		os.Exit(runMintBridgeServer(os.Args[2:]))
	case "mint-bridge-outbound":
		os.Exit(runMintBridgeOutbound(os.Args[2:]))
	case "mint-box-cert":
		os.Exit(runMintBoxCert(os.Args[2:]))
	case "pack-kit":
		os.Exit(runPackKit(os.Args[2:]))
	case "verify-kit":
		os.Exit(runVerifyKit(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("lmbox-bridge-enroll %s (commit=%s, built=%s, %s)\n",
			Version, Commit, BuildDate, runtime.Version())
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `lmbox-bridge-enroll — provision a customer's Bridge PKI + kit

Subcommands:
  customer-init          Create customer root CA + initialize on-disk layout
  mint-bridge-server     Mint the Bridge's mTLS server cert (faces boxes)
  mint-bridge-outbound   Mint the Bridge's mTLS client cert (faces cloud)
  mint-box-cert          Mint a box client cert (factory provisioning)
  pack-kit               Tar.gz + HMAC-sign the deliverable for the RSSI
  verify-kit             Re-check a kit's HMAC against the partner key
  version                Print version

Run `+"`"+`lmbox-bridge-enroll <subcmd> --help`+"`"+` for subcommand flags.
`)
}

// ─── Subcommands ─────────────────────────────────────────────────

func runCustomerInit(args []string) int {
	fs := flag.NewFlagSet("customer-init", flag.ExitOnError)
	customerID := fs.String("customer-id", "", "short id used for paths (e.g. acme-industries)")
	customerName := fs.String("customer-name", "", "legal name of the customer (appears on cert subject Org)")
	output := fs.String("output", "./enrolments", "root directory for all customer enrolments")
	lifetimeStr := fs.String("ca-lifetime", "3650d", "root CA validity (e.g. 3650d, 5y, 87600h)")
	fs.Parse(args)

	if *customerID == "" || *customerName == "" {
		fmt.Fprintln(os.Stderr, "customer-init: --customer-id and --customer-name are required")
		return 2
	}
	lifetime, err := parseDuration(*lifetimeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: invalid ca-lifetime: %v\n", err)
		return 2
	}

	custDir := filepath.Join(*output, *customerID)
	if exists(custDir) {
		fmt.Fprintf(os.Stderr, "customer-init: %s already exists — refusing to overwrite\n", custDir)
		return 1
	}

	root, err := pki.NewRootCA(*customerName, lifetime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: %v\n", err)
		return 1
	}
	rootDir := filepath.Join(custDir, "root")
	if _, _, err := root.SavePEM(rootDir, "root-ca"); err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: %v\n", err)
		return 1
	}

	// box-ca.pem under bridge/ is the same cert the Bridge configures
	// as `listen.client_ca_file`. Keep it explicitly separated so the
	// kit packager doesn't have to dig under root/.
	if err := pki.SaveCertOnly(root, filepath.Join(custDir, "bridge", "box-ca.pem")); err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: %v\n", err)
		return 1
	}

	// Empty CRL — operators replace this when they revoke a box.
	crlPEM, err := pki.NewCRL(root, 90*24*time.Hour)
	if err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Join(custDir, "crl"), 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: %v\n", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(custDir, "crl", "box-revocations.crl"), crlPEM, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: %v\n", err)
		return 1
	}

	// Audit genesis : <customer-id>|<iso8601-now>. Stable, unique,
	// human-readable in case it ever lands in a regulator's hands.
	genesis := fmt.Sprintf("%s|%s", *customerID, time.Now().UTC().Format(time.RFC3339))
	meta := EnrolmentMeta{
		CustomerID:    *customerID,
		CustomerName:  *customerName,
		CreatedAt:     time.Now().UTC(),
		ToolVersion:   Version,
		GenesisString: genesis,
		RootCA: CertSummary{
			Serial:    root.Cert.SerialNumber.Text(16),
			CN:        root.Cert.Subject.CommonName,
			NotBefore: root.Cert.NotBefore,
			NotAfter:  root.Cert.NotAfter,
		},
	}
	if err := writeMeta(custDir, &meta); err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: %v\n", err)
		return 1
	}

	if err := renderConfig(custDir, *customerID, genesis); err != nil {
		fmt.Fprintf(os.Stderr, "customer-init: render config: %v\n", err)
		return 1
	}

	fmt.Printf("✓ customer %s initialized at %s\n", *customerID, custDir)
	fmt.Printf("  root CA serial: %s\n", meta.RootCA.Serial)
	fmt.Printf("  audit genesis : %s\n", genesis)
	fmt.Printf("  next steps    : mint-bridge-server / mint-bridge-outbound / mint-box-cert / pack-kit\n")
	return 0
}

func runMintBridgeServer(args []string) int {
	fs := flag.NewFlagSet("mint-bridge-server", flag.ExitOnError)
	customerID := fs.String("customer-id", "", "")
	output := fs.String("output", "./enrolments", "")
	cn := fs.String("cn", "lmbox-bridge", "common name for the cert")
	dnsList := fs.String("dns", "", "comma-separated DNS SANs (e.g. bridge.acme.local,bridge.acme.example.com)")
	ipList := fs.String("ip", "", "comma-separated IP SANs")
	lifetimeStr := fs.String("lifetime", "365d", "validity (e.g. 365d, 1y, 8760h)")
	fs.Parse(args)

	if *customerID == "" {
		fmt.Fprintln(os.Stderr, "--customer-id is required")
		return 2
	}
	lifetime, err := parseDuration(*lifetimeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	custDir := filepath.Join(*output, *customerID)
	root, err := pki.LoadBundle(
		filepath.Join(custDir, "root", "root-ca.crt"),
		filepath.Join(custDir, "root", "root-ca.key"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint-bridge-server: load root CA: %v\n", err)
		return 1
	}

	dns := splitCSV(*dnsList)
	ips := parseIPs(*ipList)
	if len(dns) == 0 && len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "mint-bridge-server: at least one --dns or --ip required")
		return 2
	}

	srv, err := pki.NewServerCert(root, *cn, dns, ips, lifetime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint-bridge-server: %v\n", err)
		return 1
	}
	if _, _, err := srv.SavePEM(filepath.Join(custDir, "bridge"), "bridge-server"); err != nil {
		fmt.Fprintf(os.Stderr, "mint-bridge-server: %v\n", err)
		return 1
	}

	if err := updateMeta(custDir, func(m *EnrolmentMeta) {
		m.BridgeServer = &CertSummary{
			Serial:    srv.Cert.SerialNumber.Text(16),
			CN:        srv.Cert.Subject.CommonName,
			NotBefore: srv.Cert.NotBefore,
			NotAfter:  srv.Cert.NotAfter,
		}
	}); err != nil {
		fmt.Fprintf(os.Stderr, "mint-bridge-server: meta: %v\n", err)
		return 1
	}

	fmt.Printf("✓ bridge-server cert minted\n")
	fmt.Printf("  serial : %s\n", srv.Cert.SerialNumber.Text(16))
	fmt.Printf("  dns    : %s\n", strings.Join(dns, ", "))
	fmt.Printf("  ip     : %s\n", *ipList)
	fmt.Printf("  expires: %s\n", srv.Cert.NotAfter.Format(time.RFC3339))
	return 0
}

func runMintBridgeOutbound(args []string) int {
	fs := flag.NewFlagSet("mint-bridge-outbound", flag.ExitOnError)
	customerID := fs.String("customer-id", "", "")
	output := fs.String("output", "./enrolments", "")
	cloudCert := fs.String("cloud-ca-cert", "", "path to the LMbox cloud CA cert (in PEM)")
	cloudKey := fs.String("cloud-ca-key", "", "path to the LMbox cloud CA private key (in PEM)")
	lifetimeStr := fs.String("lifetime", "365d", "")
	fs.Parse(args)

	if *customerID == "" || *cloudCert == "" || *cloudKey == "" {
		fmt.Fprintln(os.Stderr, "--customer-id, --cloud-ca-cert, --cloud-ca-key are required")
		return 2
	}
	lifetime, err := parseDuration(*lifetimeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	cloudCA, err := pki.LoadBundle(*cloudCert, *cloudKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint-bridge-outbound: load cloud CA: %v\n", err)
		return 1
	}

	cn := "bridge-" + *customerID
	out, err := pki.NewClientCert(cloudCA, cn, lifetime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint-bridge-outbound: %v\n", err)
		return 1
	}
	custDir := filepath.Join(*output, *customerID)
	if _, _, err := out.SavePEM(filepath.Join(custDir, "bridge"), "bridge-out"); err != nil {
		fmt.Fprintf(os.Stderr, "mint-bridge-outbound: %v\n", err)
		return 1
	}

	if err := updateMeta(custDir, func(m *EnrolmentMeta) {
		m.BridgeOut = &CertSummary{
			Serial:    out.Cert.SerialNumber.Text(16),
			CN:        cn,
			NotBefore: out.Cert.NotBefore,
			NotAfter:  out.Cert.NotAfter,
		}
	}); err != nil {
		fmt.Fprintf(os.Stderr, "mint-bridge-outbound: meta: %v\n", err)
		return 1
	}

	fmt.Printf("✓ bridge-out cert minted (signed by cloud CA)\n")
	fmt.Printf("  cn     : %s\n", cn)
	fmt.Printf("  serial : %s\n", out.Cert.SerialNumber.Text(16))
	fmt.Printf("  expires: %s\n", out.Cert.NotAfter.Format(time.RFC3339))
	return 0
}

func runMintBoxCert(args []string) int {
	fs := flag.NewFlagSet("mint-box-cert", flag.ExitOnError)
	customerID := fs.String("customer-id", "", "")
	output := fs.String("output", "./enrolments", "")
	serial := fs.String("serial", "", "box serial used as the cert CN (e.g. BOX-ACME-001)")
	lifetimeStr := fs.String("lifetime", "365d", "")
	fs.Parse(args)

	if *customerID == "" || *serial == "" {
		fmt.Fprintln(os.Stderr, "--customer-id and --serial are required")
		return 2
	}
	lifetime, err := parseDuration(*lifetimeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	custDir := filepath.Join(*output, *customerID)
	root, err := pki.LoadBundle(
		filepath.Join(custDir, "root", "root-ca.crt"),
		filepath.Join(custDir, "root", "root-ca.key"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint-box-cert: %v\n", err)
		return 1
	}
	box, err := pki.NewClientCert(root, *serial, lifetime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint-box-cert: %v\n", err)
		return 1
	}
	if _, _, err := box.SavePEM(filepath.Join(custDir, "boxes"), *serial); err != nil {
		fmt.Fprintf(os.Stderr, "mint-box-cert: %v\n", err)
		return 1
	}

	if err := updateMeta(custDir, func(m *EnrolmentMeta) {
		m.Boxes = append(m.Boxes, CertSummary{
			Serial:    box.Cert.SerialNumber.Text(16),
			CN:        *serial,
			NotBefore: box.Cert.NotBefore,
			NotAfter:  box.Cert.NotAfter,
		})
	}); err != nil {
		fmt.Fprintf(os.Stderr, "mint-box-cert: meta: %v\n", err)
		return 1
	}

	fmt.Printf("✓ box client cert minted\n")
	fmt.Printf("  cn     : %s\n", *serial)
	fmt.Printf("  serial : %s\n", box.Cert.SerialNumber.Text(16))
	fmt.Printf("  expires: %s\n", box.Cert.NotAfter.Format(time.RFC3339))
	return 0
}

func runPackKit(args []string) int {
	fs := flag.NewFlagSet("pack-kit", flag.ExitOnError)
	customerID := fs.String("customer-id", "", "")
	source := fs.String("source", "./enrolments", "")
	hmacKey := fs.String("hmac-key", "", "path to the partner HMAC key file (hex/base64/raw)")
	outPath := fs.String("output", "", "destination .tar.gz path (defaults to ./<customer>-bridge-kit.tar.gz)")
	fs.Parse(args)

	if *customerID == "" || *hmacKey == "" {
		fmt.Fprintln(os.Stderr, "--customer-id and --hmac-key are required")
		return 2
	}
	custDir := filepath.Join(*source, *customerID)
	if !exists(filepath.Join(custDir, "bridge", "bridge-server.crt")) {
		fmt.Fprintln(os.Stderr, "pack-kit: bridge-server cert missing; run mint-bridge-server first")
		return 1
	}
	if !exists(filepath.Join(custDir, "bridge", "bridge-out.crt")) {
		fmt.Fprintln(os.Stderr, "pack-kit: bridge-out cert missing; run mint-bridge-outbound first")
		return 1
	}

	files, err := collectKitFiles(custDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack-kit: %v\n", err)
		return 1
	}

	keyBytes, err := kit.LoadHMACKey(*hmacKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack-kit: %v\n", err)
		return 1
	}

	target := *outPath
	if target == "" {
		target = filepath.Join(".", *customerID+"-bridge-kit.tar.gz")
	}
	hex, err := kit.Build(target, files, keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack-kit: %v\n", err)
		return 1
	}

	fmt.Printf("✓ kit packed at %s\n", target)
	fmt.Printf("  HMAC-SHA256 : %s\n", hex)
	fmt.Printf("  signature   : %s.hmac\n", target)
	fmt.Println("  → ship both files to the customer's RSSI alongside the partner HMAC key (out-of-band).")
	return 0
}

func runVerifyKit(args []string) int {
	fs := flag.NewFlagSet("verify-kit", flag.ExitOnError)
	kitPath := fs.String("kit", "", "")
	hmacKey := fs.String("hmac-key", "", "")
	extract := fs.String("extract", "", "optional: extract the kit's contents into this dir")
	fs.Parse(args)

	if *kitPath == "" || *hmacKey == "" {
		fmt.Fprintln(os.Stderr, "--kit and --hmac-key are required")
		return 2
	}
	keyBytes, err := kit.LoadHMACKey(*hmacKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-kit: %v\n", err)
		return 1
	}
	if err := kit.Verify(*kitPath, keyBytes); err != nil {
		fmt.Fprintf(os.Stderr, "verify-kit: FAIL — %v\n", err)
		return 1
	}
	fmt.Printf("✓ kit %s verified (HMAC OK)\n", *kitPath)

	if *extract != "" {
		written, err := kit.Extract(*kitPath, *extract)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify-kit: extract: %v\n", err)
			return 1
		}
		fmt.Printf("  extracted %d files into %s\n", len(written), *extract)
		for _, p := range written {
			fmt.Printf("    %s\n", p)
		}
	}
	return 0
}

// ─── Helpers ─────────────────────────────────────────────────────

// parseDuration accepts the Go time.ParseDuration syntax plus the
// shorthand "Xd" (days) and "Xy" (years, 365d each), so an operator
// can write `--lifetime 5y` instead of `87600h`.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err != nil {
			return 0, fmt.Errorf("parse %q: %w", s, err)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "y") {
		var n int
		if _, err := fmt.Sscanf(s, "%dy", &n); err != nil {
			return 0, fmt.Errorf("parse %q: %w", s, err)
		}
		return time.Duration(n) * 365 * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseIPs(s string) []net.IP {
	var out []net.IP
	for _, p := range splitCSV(s) {
		ip := net.ParseIP(p)
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeMeta(custDir string, m *EnrolmentMeta) error {
	if err := os.MkdirAll(custDir, 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(custDir, "enrolment.json"), b, 0o644)
}

func updateMeta(custDir string, mutate func(*EnrolmentMeta)) error {
	path := filepath.Join(custDir, "enrolment.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read meta: %w", err)
	}
	m := &EnrolmentMeta{}
	if err := json.Unmarshal(data, m); err != nil {
		return fmt.Errorf("parse meta: %w", err)
	}
	mutate(m)
	return writeMeta(custDir, m)
}

func renderConfig(custDir, customerID, genesis string) error {
	const tmpl = `# LMbox Bridge config for %s
# Generated by lmbox-bridge-enroll %s on %s.
# Drop this file at /etc/lmbox-bridge/config.yaml on the DMZ VM.

listen:
  address: "0.0.0.0:8443"
  server_cert: certs/bridge-server.crt
  server_key: certs/bridge-server.key
  client_ca_file: certs/box-ca.pem

upstream:
  url: "https://app.lmbox.eu"
  client_cert: certs/bridge-out.crt
  client_key: certs/bridge-out.key
  allowed_paths:
    - "/api/heartbeats/"
    - "/api/agents/"

auth:
  serial_pattern: "^BOX-[A-Z0-9-]{6,40}$"
  revocation_list_file: certs/box-revocations.crl
  revocation_check_interval: 5m

audit:
  file: /var/lib/lmbox-bridge/audit.log
  genesis: %q

rate_limit:
  enabled: true
  rate: 10
  burst: 100
  global_rate: 1000
  global_burst: 5000

metrics:
  enabled: true
  address: "127.0.0.1:9090"
  path: "/metrics"

logging:
  level: info
  format: json
`
	body := fmt.Sprintf(tmpl, customerID, Version, time.Now().UTC().Format(time.RFC3339), genesis)
	return os.WriteFile(filepath.Join(custDir, "config.yaml"), []byte(body), 0o644)
}

// collectKitFiles assembles the list of files that go into the
// customer kit. Excludes the root CA (private!) and the box client
// certs (those go to factory provisioning, not the customer kit).
func collectKitFiles(custDir string) ([]kit.File, error) {
	var files []kit.File

	add := func(diskPath, archivePath string, mode int64) error {
		data, err := os.ReadFile(diskPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", diskPath, err)
		}
		files = append(files, kit.File{
			Path:    archivePath,
			Mode:    mode,
			Content: data,
		})
		return nil
	}

	// Mandatory.
	type pair struct {
		disk, arch string
		mode       int64
	}
	mandatory := []pair{
		{filepath.Join(custDir, "bridge", "bridge-server.crt"), "certs/bridge-server.crt", 0o644},
		{filepath.Join(custDir, "bridge", "bridge-server.key"), "certs/bridge-server.key", 0o600},
		{filepath.Join(custDir, "bridge", "bridge-out.crt"), "certs/bridge-out.crt", 0o644},
		{filepath.Join(custDir, "bridge", "bridge-out.key"), "certs/bridge-out.key", 0o600},
		{filepath.Join(custDir, "bridge", "box-ca.pem"), "certs/box-ca.pem", 0o644},
		{filepath.Join(custDir, "crl", "box-revocations.crl"), "certs/box-revocations.crl", 0o644},
		{filepath.Join(custDir, "config.yaml"), "config.yaml", 0o644},
	}
	for _, p := range mandatory {
		if err := add(p.disk, p.arch, p.mode); err != nil {
			return nil, err
		}
	}
	return files, nil
}

// randomKey is exposed for tests + operators who want to generate a
// fresh HMAC key without reaching for openssl.
func randomKey(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// unused but kept around for future symmetry.
var _ = hex.EncodeToString
var _ = errors.New
