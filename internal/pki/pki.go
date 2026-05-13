// Package pki encapsulates the X.509 primitives the enrolment tool
// uses to mint a customer's PKI : root CA, Bridge server cert,
// Bridge outbound cert, and box client certs.
//
// We deliberately avoid pulling in cfssl, vault, or any other PKI
// library. Stdlib crypto/x509 is enough for the small set of cert
// shapes we mint, and a dependency-free CLI makes it auditable
// line-by-line by a customer's RSSI before they accept the kit.
//
// Conventions
// ───────────
//   - Every key is ECDSA P-256. Smaller than RSA, faster, well-
//     supported by every TLS stack worth talking about. Future
//     post-quantum migration via key rotation; the cert format
//     stays the same.
//   - Every cert serial is a cryptographically random 159-bit
//     integer (per RFC 5280 §4.1.2.2 best practice). This avoids
//     accidental collisions across multiple `mint-*` invocations.
//   - PEM blocks are written with explicit type names. We never
//     ship DER-only artefacts because the customer's IT team
//     wants to `cat` and `openssl x509 -text` everything.
//   - Files are mode 0600 for keys, 0644 for certs. Operators
//     STILL need to encrypt the enrolment directory at rest;
//     this is documented in docs/ENROLL.md.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertProfile describes what to mint. Different cert kinds (CA,
// server, client) need different ExtKeyUsage + IsCA flags ; we
// encode that as a single struct so the call sites read clearly.
type CertProfile struct {
	CommonName    string
	Organization  []string
	DNSNames      []string
	IPAddresses   []net.IP
	NotBefore     time.Time
	NotAfter      time.Time
	IsCA          bool
	KeyUsage      x509.KeyUsage
	ExtKeyUsage   []x509.ExtKeyUsage
	MaxPathLenZero bool // restrict the CA from issuing further intermediate CAs
}

// Bundle holds a freshly-generated cert + private key pair.
type Bundle struct {
	Cert    *x509.Certificate
	CertDER []byte
	Key     *ecdsa.PrivateKey
}

// NewRootCA mints a self-signed root CA suitable for a customer's
// PKI. `org` is the customer name; it shows up in `openssl x509
// -text` so the RSSI can confirm at a glance that the kit they
// received is for them and not a different tenant.
func NewRootCA(org string, lifetime time.Duration) (*Bundle, error) {
	if org == "" {
		return nil, errors.New("pki: org must not be empty")
	}
	now := time.Now().UTC()
	profile := CertProfile{
		CommonName:     "lmbox-customer-root",
		Organization:   []string{org},
		NotBefore:      now,
		NotAfter:       now.Add(lifetime),
		IsCA:           true,
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		MaxPathLenZero: true, // we don't need intermediate CAs in v0.1
	}
	return mintSelfSigned(profile)
}

// NewServerCert mints a Bridge server cert (the one the Bridge
// presents on its mTLS listener to boxes on the LAN).
func NewServerCert(parent *Bundle, cn string, dnsNames []string, ips []net.IP, lifetime time.Duration) (*Bundle, error) {
	if parent == nil {
		return nil, errors.New("pki: parent CA required")
	}
	if cn == "" {
		return nil, errors.New("pki: server cn must not be empty")
	}
	now := time.Now().UTC()
	profile := CertProfile{
		CommonName:  cn,
		NotBefore:   now,
		NotAfter:    now.Add(lifetime),
		DNSNames:    dnsNames,
		IPAddresses: ips,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return mintSigned(profile, parent)
}

// NewClientCert mints a TLS client cert for a box (or, with cn set
// to "bridge-<customer-id>", the Bridge's outbound cert).
func NewClientCert(parent *Bundle, cn string, lifetime time.Duration) (*Bundle, error) {
	if parent == nil {
		return nil, errors.New("pki: parent CA required")
	}
	if cn == "" {
		return nil, errors.New("pki: client cn must not be empty")
	}
	now := time.Now().UTC()
	profile := CertProfile{
		CommonName:  cn,
		NotBefore:   now,
		NotAfter:    now.Add(lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return mintSigned(profile, parent)
}

// SavePEM writes a Bundle's cert + key to disk as PEM. Returns the
// two paths it wrote. Keys are mode 0600, certs 0644.
func (b *Bundle) SavePEM(dir, basename string) (certPath, keyPath string, err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", fmt.Errorf("pki: mkdir %s: %w", dir, err)
	}
	certPath = filepath.Join(dir, basename+".crt")
	keyPath = filepath.Join(dir, basename+".key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.CertDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("pki: write cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(b.Key)
	if err != nil {
		return "", "", fmt.Errorf("pki: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("pki: write key: %w", err)
	}
	return certPath, keyPath, nil
}

// LoadBundle reads a cert + key pair from disk. Used by the
// `mint-*` subcommands to load the customer's root CA before
// signing a new cert.
func LoadBundle(certPath, keyPath string) (*Bundle, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("pki: read cert: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("pki: cert is not a CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("pki: read key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("pki: key is not a PEM block")
	}
	var key *ecdsa.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse EC key: %w", err)
		}
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse PKCS8 key: %w", err)
		}
		var ok bool
		key, ok = k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("pki: PKCS8 key is not ECDSA")
		}
	default:
		return nil, fmt.Errorf("pki: unknown key PEM type %q", keyBlock.Type)
	}

	return &Bundle{Cert: cert, CertDER: certBlock.Bytes, Key: key}, nil
}

// SaveCertOnly writes just the cert to a PEM file. Used when the
// caller already has the cert from a previously-loaded bundle and
// wants to materialise it as a "CA bundle" file (e.g., box-ca.pem).
func SaveCertOnly(b *Bundle, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("pki: mkdir: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.CertDER})
	return os.WriteFile(path, pemBytes, 0o644)
}

// NewCRL produces a freshly-signed empty CRL. Operators replace
// this file with a non-empty version when they revoke a box cert.
// The Bridge reloads the CRL on a schedule, so a new file is
// honoured within `revocation_check_interval`.
func NewCRL(parent *Bundle, lifetime time.Duration) ([]byte, error) {
	if parent == nil {
		return nil, errors.New("pki: parent CA required for CRL")
	}
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().UTC(),
		NextUpdate: time.Now().UTC().Add(lifetime),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, parent.Cert, parent.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CRL: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// ─── Internals ───────────────────────────────────────────────────

// mintSelfSigned creates a self-signed cert (used for the root CA).
func mintSelfSigned(p CertProfile) (*Bundle, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate key: %w", err)
	}
	tmpl, err := buildTemplate(p)
	if err != nil {
		return nil, err
	}
	// Self-signed → parent = template
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("pki: create self-signed: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse created: %w", err)
	}
	return &Bundle{Cert: cert, CertDER: der, Key: priv}, nil
}

// mintSigned creates a cert signed by `parent`.
func mintSigned(p CertProfile, parent *Bundle) (*Bundle, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate key: %w", err)
	}
	tmpl, err := buildTemplate(p)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, &priv.PublicKey, parent.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse signed: %w", err)
	}
	return &Bundle{Cert: cert, CertDER: der, Key: priv}, nil
}

func buildTemplate(p CertProfile) (*x509.Certificate, error) {
	if p.NotBefore.IsZero() || p.NotAfter.IsZero() {
		return nil, errors.New("pki: NotBefore + NotAfter must be set")
	}
	if !p.NotAfter.After(p.NotBefore) {
		return nil, errors.New("pki: NotAfter must be after NotBefore")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   p.CommonName,
			Organization: p.Organization,
		},
		NotBefore:             p.NotBefore,
		NotAfter:              p.NotAfter,
		KeyUsage:              p.KeyUsage,
		ExtKeyUsage:           p.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  p.IsCA,
		DNSNames:              p.DNSNames,
		IPAddresses:           p.IPAddresses,
	}
	if p.IsCA && p.MaxPathLenZero {
		tmpl.MaxPathLen = 0
		tmpl.MaxPathLenZero = true
	}
	return tmpl, nil
}

// randomSerial generates a positive 159-bit serial. RFC 5280
// recommends at least 64 bits of entropy and avoiding the high bit
// being 1 to dodge DER encoding edge cases.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: random serial: %w", err)
	}
	return n, nil
}
