// Package proxy implements the request-forwarding logic from the box
// side to the LMbox cloud. We deliberately do NOT use
// httputil.ReverseProxy because :
//
//  1. We need fine-grained control over which headers cross the
//     trust boundary (strip cookies, hop-by-hop, X-Forwarded-For
//     rewrite, inject box serial).
//  2. We need response body size accounting for the audit chain
//     (BytesIn / BytesOut on every entry).
//  3. The set of forwardable paths is a deny-by-default allowlist
//     enforced before we even touch upstream — easier to reason
//     about than chaining filters around ReverseProxy.
//
// The proxy is the ONLY thing inside the Bridge that talks to the
// cloud. All other components (audit, rate limit, auth) feed into
// the decision to call ServeHTTP or to reject with 4xx.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Proxy forwards an incoming request to the configured upstream URL.
// Goroutine-safe via the underlying http.Client.
type Proxy struct {
	upstream     *url.URL
	httpClient   *http.Client
	allowedPaths []string
	// userAgent is set on every outbound request so the cloud-side
	// access log distinguishes Bridge-mediated traffic from a
	// direct box connection (the latter shouldn't happen, but the
	// telemetry is useful when triaging customer firewall issues).
	userAgent string
}

// Options configures the upstream connection. All TLS material is
// loaded once at construction; the proxy holds the resulting
// http.Client for the lifetime of the process.
type Options struct {
	UpstreamURL     string
	ClientCertPath  string
	ClientKeyPath   string
	RootCAPath      string // optional; system roots are used when empty
	AllowedPaths    []string
	DialTimeout     time.Duration
	ResponseTimeout time.Duration
	UserAgent       string
}

// New builds a Proxy from Options. Returns an error if any cert is
// missing or unreadable — the caller MUST fail boot rather than
// allow the Bridge to run with broken mTLS to cloud.
func New(opts Options) (*Proxy, error) {
	u, err := url.Parse(opts.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse upstream URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("proxy: upstream must be https, got %s", u.Scheme)
	}

	cert, err := tls.LoadX509KeyPair(opts.ClientCertPath, opts.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("proxy: load client cert: %w", err)
	}

	var rootCAs *x509.CertPool
	if opts.RootCAPath != "" {
		pem, err := os.ReadFile(opts.RootCAPath)
		if err != nil {
			return nil, fmt.Errorf("proxy: read root CA: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("proxy: no certs in root CA file")
		}
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs, // nil means use system roots
		MinVersion:   tls.VersionTLS12,
		// Pin to modern cipher suites. TLS 1.3 ignores this list
		// (suites are mandatory), so this only matters for the 1.2
		// fallback path.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.ResponseTimeout == 0 {
		opts.ResponseTimeout = 30 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: (&net.Dialer{
			Timeout:   opts.DialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   opts.DialTimeout,
		ResponseHeaderTimeout: opts.ResponseTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	ua := opts.UserAgent
	if ua == "" {
		ua = "lmbox-bridge/0.1"
	}

	return &Proxy{
		upstream:     u,
		httpClient:   &http.Client{Transport: transport, Timeout: 0}, // per-request deadlines via ctx
		allowedPaths: append([]string(nil), opts.AllowedPaths...),
		userAgent:    ua,
	}, nil
}

// HealthCheck performs a lightweight request through the same mTLS
// transport the proxy uses for traffic. Returns the raw response on
// success — the caller closes the body. Used by the readiness probe
// to confirm the upstream is reachable WITH the Bridge's actual
// cert + cipher config (so we detect cert expiry / mTLS regressions,
// not just generic network reachability).
func (p *Proxy) HealthCheck(req *http.Request) (*http.Response, error) {
	return p.httpClient.Do(req)
}

// PathAllowed reports whether the request path matches one of the
// configured allowlist prefixes. Empty allowlist means deny everything
// (safe default) — the caller config defaults a sane allowlist.
func (p *Proxy) PathAllowed(path string) bool {
	for _, prefix := range p.allowedPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// ServeHTTP forwards the request to upstream. The caller is
// responsible for having validated auth + rate limit BEFORE calling
// ServeHTTP — this layer assumes the request is admissible.
//
// Returns the bytes in (request body length sent) and bytes out
// (response body length received) so the caller can stamp the
// audit chain entry with accurate accounting.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, boxSerial string) (bytesIn, bytesOut int64, status int, err error) {
	// Reconstruct the upstream URL. The incoming path is preserved
	// verbatim — the cloud routes by path, the host header is
	// rewritten to the upstream host.
	target := *p.upstream
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	// We're inside a hot path: avoid io.ReadAll on the body, just
	// pipe it through. http.NewRequestWithContext preserves the
	// reader so the round-trip streams the bytes.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		return 0, 0, http.StatusInternalServerError, fmt.Errorf("build upstream req: %w", err)
	}

	// Copy + sanitise headers. We strip hop-by-hop headers (per
	// RFC 7230 §6.1) and explicitly remove cookie + auth headers
	// the box should never propagate — the only authentication
	// upstream cares about is the Bridge's own mTLS, not whatever
	// the box happens to send.
	copyHeaders(r.Header, outReq.Header)
	stripHopHeaders(outReq.Header)
	outReq.Header.Del("Cookie")
	outReq.Header.Del("Authorization")
	outReq.Header.Set("User-Agent", p.userAgent)
	// Bridge-injected provenance headers. The cloud uses these for
	// audit (which box, via which Bridge) without trusting any
	// header the box itself sent.
	outReq.Header.Set("X-LMbox-Box", boxSerial)
	outReq.Header.Set("X-Forwarded-For", clientIP(r))
	outReq.Header.Set("X-Forwarded-Proto", "https")
	// Use the upstream's host as the Host header.
	outReq.Host = p.upstream.Host

	resp, err := p.httpClient.Do(outReq)
	if err != nil {
		// Map common transport errors to readable upstream-failure
		// HTTP status codes for the audit chain.
		if isTimeout(err) {
			return 0, 0, http.StatusGatewayTimeout, err
		}
		return 0, 0, http.StatusBadGateway, err
	}
	defer resp.Body.Close()

	// Copy response headers (minus hop-by-hop) before writing the
	// status. http.ResponseWriter Write() flushes the header
	// implicitly on first write.
	copyHeaders(resp.Header, w.Header())
	stripHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)

	// Stream the body. countingWriter tracks bytes for audit.
	cw := &countingWriter{w: w}
	n, copyErr := io.Copy(cw, resp.Body)
	bytesOut = n
	bytesIn = outReq.ContentLength // approximate; -1 for chunked

	if copyErr != nil {
		return bytesIn, bytesOut, resp.StatusCode, fmt.Errorf("copy response: %w", copyErr)
	}
	return bytesIn, bytesOut, resp.StatusCode, nil
}

// ─── Helpers ─────────────────────────────────────────────────────

// hopByHopHeaders lists the headers that MUST NOT be forwarded
// per RFC 7230 §6.1.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeaders(src, dst http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func stripHopHeaders(h http.Header) {
	// Also strip whatever the Connection header lists as connection-
	// specific (per RFC 7230 §6.1).
	if c := h.Get("Connection"); c != "" {
		for _, name := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isTimeout(err error) bool {
	type timeoutError interface{ Timeout() bool }
	if t, ok := err.(timeoutError); ok && t.Timeout() {
		return true
	}
	return false
}

// countingWriter wraps an http.ResponseWriter to count bytes written.
// We don't need a full interface bridge (Hijacker/Flusher) because
// the proxy never streams server-sent events from the cloud — every
// response is a finite body that fits within the per-request timeout.
type countingWriter struct {
	w http.ResponseWriter
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
