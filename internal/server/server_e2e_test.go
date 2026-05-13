// End-to-end test for the LMbox Bridge.
//
// Wire up :
//
//	  fake box (mTLS client cert)
//	         │
//	         ▼
//	  httptest TLS server holding the Bridge handler
//	         │
//	         ▼
//	  httptest TLS server holding a mock upstream
//
// We verify the happy path + the three rejection paths (auth,
// rate-limit, path allowlist), plus the audit chain captured every
// request and the upstream actually received the X-LMbox-Box header
// injected by the Bridge.

package server_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rlacotte/lmbox-bridge/internal/audit"
	"github.com/rlacotte/lmbox-bridge/internal/auth"
	"github.com/rlacotte/lmbox-bridge/internal/proxy"
	"github.com/rlacotte/lmbox-bridge/internal/ratelimit"
	"github.com/rlacotte/lmbox-bridge/internal/server"
)

func TestE2E_HappyPathPlusRejections(t *testing.T) {
	pki := newPKI(t)

	// ─── 1. Mock upstream (https — what the cloud presents) ────
	var upstreamRecv []recordedReq
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRecv = append(upstreamRecv, recordedReq{
			path:    r.URL.Path,
			boxHdr:  r.Header.Get("X-LMbox-Box"),
			cookie:  r.Header.Get("Cookie"),
			authHdr: r.Header.Get("Authorization"),
		})
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	// ─── 2. Proxy that trusts the upstream's self-signed cert ──
	dir := t.TempDir()
	// Write proxy outbound cert (signed by our root) to disk so
	// proxy.New can LoadX509KeyPair.
	proxyCertPath, proxyKeyPath := pki.writeClientCert(t, dir, "lmbox-bridge-out")
	// Trust the upstream's self-signed cert via a file.
	upstreamCAPath := filepath.Join(dir, "upstream-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	if err := os.WriteFile(upstreamCAPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write upstream CA: %v", err)
	}

	prx, err := proxy.New(proxy.Options{
		UpstreamURL:    upstream.URL,
		ClientCertPath: proxyCertPath,
		ClientKeyPath:  proxyKeyPath,
		RootCAPath:     upstreamCAPath,
		AllowedPaths:   []string{"/api/heartbeats/", "/api/agents/"},
		DialTimeout:    3 * time.Second,
		UserAgent:      "lmbox-bridge-e2e/0.0",
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	authV, err := auth.New(`^BOX-[A-Z0-9-]+$`, "", time.Minute)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	defer authV.Stop()
	authV.Start()

	limiter := ratelimit.NewMulti(1000, 1000, 0, 0) // permissive on happy path

	var auditBuf bytes.Buffer
	chain := audit.New(&auditBuf, "e2e-test")

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    pki.pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	srv, err := server.New(server.Options{
		Addr:      "127.0.0.1:0",
		TLSConfig: tlsCfg,
		Auth:      authV,
		Limiter:   limiter,
		Proxy:     prx,
		Chain:     chain,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// ─── 3. Bind the Bridge handler on an httptest TLS listener ──
	bridge := httptest.NewUnstartedServer(srv.Handler())
	bridge.TLS = tlsCfg
	bridge.StartTLS()
	defer bridge.Close()

	boxOK := pki.newBoxClient(t, "BOX-TEST-001")
	boxRogue := pki.newBoxClient(t, "ROGUE-001") // doesn't match BOX-…

	// ─── 4. Happy path : POST heartbeat ─────────────────────────
	resp, err := boxOK.Post(bridge.URL+"/api/heartbeats/BOX-TEST-001",
		"application/json", strings.NewReader(`{"hb":1}`))
	if err != nil {
		t.Fatalf("happy POST: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("happy path status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	if got := len(upstreamRecv); got != 1 {
		t.Fatalf("upstream received %d requests, want 1", got)
	}
	if upstreamRecv[0].boxHdr != "BOX-TEST-001" {
		t.Fatalf("upstream X-LMbox-Box header = %q, want BOX-TEST-001",
			upstreamRecv[0].boxHdr)
	}
	if upstreamRecv[0].cookie != "" || upstreamRecv[0].authHdr != "" {
		t.Fatalf("upstream saw Cookie/Authorization headers (should be stripped)")
	}

	// ─── 5. Path-not-allowed : 403 ───────────────────────────────
	resp, err = boxOK.Get(bridge.URL + "/admin/secret")
	if err != nil {
		t.Fatalf("path-deny GET: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("path-deny status=%d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// ─── 6. Auth rejection : CN doesn't match pattern ────────────
	resp, err = boxRogue.Get(bridge.URL + "/api/heartbeats/whatever")
	if err != nil {
		t.Fatalf("rogue GET: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("rogue status=%d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// ─── 7. Audit chain captured every request ──────────────────
	auditLines := bytes.Count(auditBuf.Bytes(), []byte{'\n'})
	if auditLines < 3 {
		t.Fatalf("audit chain has %d lines, want >= 3 (got %q)",
			auditLines, auditBuf.String())
	}

	// ─── 8. Rate-limit rejection : tight bucket → 429 ───────────
	tightLimiter := ratelimit.NewMulti(0.0001, 1, 0, 0) // 1 burst, ~no refill
	tightChain := audit.New(nil, "e2e-tight")
	tightSrv, _ := server.New(server.Options{
		Addr:      "127.0.0.1:0",
		TLSConfig: tlsCfg,
		Auth:      authV,
		Limiter:   tightLimiter,
		Proxy:     prx,
		Chain:     tightChain,
	})
	tightBridge := httptest.NewUnstartedServer(tightSrv.Handler())
	tightBridge.TLS = tlsCfg
	tightBridge.StartTLS()
	defer tightBridge.Close()

	// 1st request consumes the only token.
	r1, err := boxOK.Get(tightBridge.URL + "/api/heartbeats/burst")
	if err != nil {
		t.Fatalf("burst req 1: %v", err)
	}
	r1.Body.Close()
	if r1.StatusCode != 200 {
		t.Fatalf("burst req 1 status=%d, want 200", r1.StatusCode)
	}
	// 2nd request: empty bucket → 429.
	r2, err := boxOK.Get(tightBridge.URL + "/api/heartbeats/burst")
	if err != nil {
		t.Fatalf("burst req 2: %v", err)
	}
	r2.Body.Close()
	if r2.StatusCode != 429 {
		t.Fatalf("rate-limit status=%d, want 429", r2.StatusCode)
	}
}

// ─── PKI helpers ─────────────────────────────────────────────────

type recordedReq struct {
	path, boxHdr, cookie, authHdr string
}

type pki struct {
	rootCert   *x509.Certificate
	rootKey    *ecdsa.PrivateKey
	serverCert tls.Certificate
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "lmbox-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "lmbox-bridge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, rootCert, &srvKey.PublicKey, rootKey)
	srvCert := tls.Certificate{
		Certificate: [][]byte{srvDER, rootDER},
		PrivateKey:  srvKey,
	}
	return &pki{rootCert: rootCert, rootKey: rootKey, serverCert: srvCert}
}

func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.rootCert)
	return pool
}

// newBoxClient returns an http.Client presenting a client cert with
// CN=cn, signed by the test root. Trusts the test root for server
// cert verification.
func (p *pki) newBoxClient(t *testing.T, cn string) *http.Client {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.rootCert, &key.PublicKey, p.rootKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: p.pool(),
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{der},
					PrivateKey:  key,
				}},
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}
}

// writeClientCert writes a fresh cert+key signed by the test root
// to disk and returns the file paths. Used to feed proxy.New's
// LoadX509KeyPair requirement.
func (p *pki) writeClientCert(t *testing.T, dir, cn string) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, p.rootCert, &key.PublicKey, p.rootKey)
	certPath = filepath.Join(dir, cn+".crt")
	keyPath = filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
