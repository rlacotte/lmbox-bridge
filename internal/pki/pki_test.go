package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewRootCA_HasCAFlag(t *testing.T) {
	b, err := NewRootCA("Acme Industries", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Cert.IsCA {
		t.Fatal("root cert should have IsCA=true")
	}
	if b.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("root cert should have CertSign key usage")
	}
	if !b.Cert.MaxPathLenZero {
		t.Fatal("root should have MaxPathLenZero")
	}
	if got := b.Cert.Subject.Organization; len(got) == 0 || got[0] != "Acme Industries" {
		t.Fatalf("subject.Org=%v, want [Acme Industries]", got)
	}
}

func TestServerCert_HasSANs(t *testing.T) {
	root, _ := NewRootCA("X", time.Hour)
	srv, err := NewServerCert(root, "lmbox-bridge",
		[]string{"bridge.acme.local"},
		[]net.IP{net.ParseIP("10.0.0.42")},
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.Cert.DNSNames) != 1 || srv.Cert.DNSNames[0] != "bridge.acme.local" {
		t.Fatalf("DNS SANs=%v", srv.Cert.DNSNames)
	}
	if len(srv.Cert.IPAddresses) != 1 {
		t.Fatalf("IP SANs=%v", srv.Cert.IPAddresses)
	}
	// Verify the chain matches.
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	if _, err := srv.Cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "bridge.acme.local",
	}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
}

func TestClientCert_HasClientAuthEKU(t *testing.T) {
	root, _ := NewRootCA("X", time.Hour)
	box, err := NewClientCert(root, "BOX-TEST-001", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gotEKU := false
	for _, eku := range box.Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			gotEKU = true
		}
	}
	if !gotEKU {
		t.Fatal("box cert should have ClientAuth EKU")
	}
	if box.Cert.Subject.CommonName != "BOX-TEST-001" {
		t.Fatalf("CN=%q, want BOX-TEST-001", box.Cert.Subject.CommonName)
	}
}

func TestSerialsAreDistinct(t *testing.T) {
	root, _ := NewRootCA("X", time.Hour)
	a, _ := NewClientCert(root, "BOX-A", time.Hour)
	b, _ := NewClientCert(root, "BOX-B", time.Hour)
	if a.Cert.SerialNumber.Cmp(b.Cert.SerialNumber) == 0 {
		t.Fatal("two minted certs share the same serial")
	}
}

func TestSavePEM_AndLoadBundle_RoundTrip(t *testing.T) {
	root, _ := NewRootCA("X", time.Hour)
	dir := t.TempDir()
	certPath, keyPath, err := root.SavePEM(dir, "root-ca")
	if err != nil {
		t.Fatal(err)
	}
	// Mode check.
	st, _ := os.Stat(keyPath)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key perm=%o, want 0600", st.Mode().Perm())
	}

	loaded, err := LoadBundle(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Cert.SerialNumber.Cmp(root.Cert.SerialNumber) != 0 {
		t.Fatal("serial mismatch after round-trip")
	}
	// Use the loaded bundle to sign something — proves the key
	// loaded correctly.
	if _, err := NewClientCert(loaded, "BOX-FROM-LOADED", time.Hour); err != nil {
		t.Fatalf("sign after load: %v", err)
	}
}

func TestNewCRL_IsEmptyByDefault(t *testing.T) {
	root, _ := NewRootCA("X", time.Hour)
	pemBytes, err := NewCRL(root, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(pemBytes) == 0 {
		t.Fatal("empty CRL PEM")
	}
	// Parse-back check — the CRL should be a valid X509 CRL.
	parsed, err := x509.ParseRevocationList(decodePEM(t, pemBytes))
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	// Use the deprecated 1.20 field name.
	if len(parsed.RevokedCertificates) != 0 {
		t.Fatalf("expected empty CRL, got %d revoked entries", len(parsed.RevokedCertificates))
	}
}

func TestBuildTemplate_RejectsBadLifetime(t *testing.T) {
	_, err := mintSelfSigned(CertProfile{
		CommonName: "x",
		NotBefore:  time.Now(),
		NotAfter:   time.Now().Add(-time.Hour),
	})
	if err == nil {
		t.Fatal("expected error on NotAfter < NotBefore")
	}
}

func TestSaveCertOnly_HandlesNestedDir(t *testing.T) {
	root, _ := NewRootCA("X", time.Hour)
	path := filepath.Join(t.TempDir(), "deep", "nested", "ca.pem")
	if err := SaveCertOnly(root, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

// decodePEM peels off the first PEM block and returns its DER bytes.
func decodePEM(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block found")
	}
	return block.Bytes
}
