// Package auth validates that a client connecting to the Bridge is a
// known LMbox box. The TLS handshake is performed by the stdlib; this
// package handles the application-level checks that happen AFTER the
// handshake has confirmed the cert chains to a known CA :
//
//  1. CN matches the expected serial pattern (default `^BOX-…$`).
//     Tight allowlist by construction.
//  2. Cert is not on the revocation list (CRL).
//  3. Cert is not expired (defence in depth — the stdlib already
//     refuses an expired cert at handshake, but we re-check so a
//     bug in the TLS config can't silently weaken this).
//
// The CRL is loaded from disk and reloaded periodically by a
// background goroutine so a freshly-revoked cert is honoured within
// `RevocationCheckInterval` of the operator dropping the new CRL
// file in place. We do not fetch CRL over HTTP — the customer's DMZ
// often blocks outbound to arbitrary URLs and we'd rather have a
// boring local file the customer's IT team can audit.
package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"sync/atomic"
	"time"
)

// Validator checks an incoming client cert against the configured
// rules. It is safe to call Verify concurrently from many goroutines.
type Validator struct {
	pattern *regexp.Regexp
	// crl is updated atomically by the reload goroutine so the hot
	// path never blocks on a mutex. The pointer points to a frozen
	// snapshot; replacing it is the only mutation.
	crl atomic.Pointer[crlSnapshot]

	// reloadPath and reloadInterval are kept for the background
	// goroutine. If reloadPath is empty, revocation is disabled and
	// crl points to an empty snapshot.
	reloadPath     string
	reloadInterval time.Duration

	stopCh chan struct{}
	doneCh chan struct{}
}

// crlSnapshot is an immutable revocation list. Once loaded we only
// read it; reloads produce a new snapshot and atomically swap.
type crlSnapshot struct {
	// serials is keyed by the hex-encoded raw subject + serial number
	// from the revoked cert entry. We use the (issuer subject, serial)
	// pair because serial alone is not globally unique across CAs.
	serials map[string]time.Time
}

// New builds a Validator. `pattern` is a Go regexp the cert's CN must
// match. `crlPath` (optional) is a PEM-encoded X.509 CRL file. When
// non-empty, the file is reloaded every `interval`.
func New(pattern, crlPath string, interval time.Duration) (*Validator, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("auth: compile pattern %q: %w", pattern, err)
	}
	v := &Validator{
		pattern:        re,
		reloadPath:     crlPath,
		reloadInterval: interval,
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}
	// Initial load. If the path is empty, we install an empty
	// snapshot so the hot path treats it uniformly.
	if err := v.reload(); err != nil {
		// Soft-fail on initial load: warn the caller via the error,
		// but install an empty snapshot so the Bridge can still
		// boot. The caller decides whether to refuse to start.
		v.crl.Store(&crlSnapshot{serials: map[string]time.Time{}})
		return v, fmt.Errorf("auth: initial CRL load: %w", err)
	}
	return v, nil
}

// Start kicks off the background CRL reload goroutine. Caller MUST
// call Stop on shutdown for graceful exit.
func (v *Validator) Start() {
	go v.reloadLoop()
}

// Stop signals the reload goroutine to exit and waits for it.
func (v *Validator) Stop() {
	close(v.stopCh)
	<-v.doneCh
}

// Verify checks a single client cert. Returns the validated serial
// (CN) on success.
//
// Preconditions: the TLS handshake has already verified the cert
// chains to a trusted CA. Verify ONLY enforces the application-level
// allowlist + revocation. If `cert` is nil, we return an error
// rather than panicking — a misconfigured server might omit
// VerifiedChains.
func (v *Validator) Verify(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("auth: nil cert")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return "", fmt.Errorf("auth: cert not yet valid (NotBefore=%s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return "", fmt.Errorf("auth: cert expired (NotAfter=%s)", cert.NotAfter)
	}

	cn := cert.Subject.CommonName
	if cn == "" {
		return "", fmt.Errorf("auth: cert has empty CN")
	}
	if !v.pattern.MatchString(cn) {
		return "", fmt.Errorf("auth: cert CN %q does not match required pattern %q",
			cn, v.pattern.String())
	}

	snap := v.crl.Load()
	if snap != nil {
		key := revocationKey(cert.RawIssuer, cert.SerialNumber)
		if revokedAt, ok := snap.serials[key]; ok {
			return "", fmt.Errorf("auth: cert revoked at %s", revokedAt)
		}
	}
	return cn, nil
}

// reload reads the CRL file and atomically installs the new snapshot.
// Called once at startup and periodically by reloadLoop. Returns
// nil if reloadPath is empty (revocation disabled).
func (v *Validator) reload() error {
	if v.reloadPath == "" {
		v.crl.Store(&crlSnapshot{serials: map[string]time.Time{}})
		return nil
	}
	data, err := os.ReadFile(v.reloadPath)
	if err != nil {
		return fmt.Errorf("read CRL %s: %w", v.reloadPath, err)
	}

	snap := &crlSnapshot{serials: map[string]time.Time{}}
	// A file may contain multiple concatenated PEM blocks (CRL list).
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CRL block: %w", err)
		}
		issuer := crl.RawIssuer
		// Go 1.20 stdlib API. The field is renamed to
		// RevokedCertificateEntries in 1.21+. When we move our
		// floor to 1.21 we'll switch over.
		for _, revoked := range crl.RevokedCertificates {
			snap.serials[revocationKey(issuer, revoked.SerialNumber)] = revoked.RevocationTime
		}
	}

	v.crl.Store(snap)
	return nil
}

// reloadLoop reloads the CRL on the configured interval. Logged
// errors are surfaced via the application logger by the caller —
// here we just write to stderr if anything goes wrong to keep this
// package free of logger dependencies.
func (v *Validator) reloadLoop() {
	defer close(v.doneCh)
	if v.reloadPath == "" || v.reloadInterval == 0 {
		// Nothing to reload; exit immediately so Stop() doesn't block.
		<-v.stopCh
		return
	}
	t := time.NewTicker(v.reloadInterval)
	defer t.Stop()
	for {
		select {
		case <-v.stopCh:
			return
		case <-t.C:
			if err := v.reload(); err != nil {
				fmt.Fprintf(os.Stderr, "lmbox-bridge: CRL reload failed: %v\n", err)
			}
		}
	}
}

// revocationKey combines issuer subject DN + serial number into a
// stable lookup key. Equivalent to RFC 5280's identification of a
// revoked cert by (issuer, serial).
func revocationKey(issuerRawSubject []byte, serial *big.Int) string {
	if serial == nil {
		return ""
	}
	// Format: hex(issuerRawSubject):serial.Text(16)
	// Cheap and human-readable for grep-ability.
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(issuerRawSubject)*2+1+len(serial.Bytes())*2)
	for _, b := range issuerRawSubject {
		out = append(out, hex[b>>4], hex[b&0x0f])
	}
	out = append(out, ':')
	return string(out) + serial.Text(16)
}
