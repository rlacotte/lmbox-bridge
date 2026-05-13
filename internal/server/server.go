// Package server is the orchestrator that combines auth, rate limit,
// audit, and proxy behind a single mTLS listener. It owns the
// HTTP server lifecycle and wires the middleware chain. Every
// request taken by Handler goes through:
//
//	mTLS handshake (stdlib)
//	  → recordingMiddleware (start timer)
//	    → authMiddleware (validate cert via auth.Validator)
//	      → rateLimitMiddleware (token bucket per box + global)
//	        → pathAllowMiddleware (proxy.PathAllowed)
//	          → proxyHandler (forward to cloud, count bytes)
//	        ← audit.Append (status + bytes + duration)
//
// Each rejection short-circuits the chain with a clean 4xx + audit
// entry. The audit chain ALWAYS sees the request, even when denied
// — that's the whole point of an opposable log to the regulator.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rlacotte/lmbox-bridge/internal/audit"
	"github.com/rlacotte/lmbox-bridge/internal/auth"
	"github.com/rlacotte/lmbox-bridge/internal/metrics"
	"github.com/rlacotte/lmbox-bridge/internal/proxy"
	"github.com/rlacotte/lmbox-bridge/internal/ratelimit"
)

// Server is the top-level facade. Build one with New, then call
// Start (non-blocking) and Stop (graceful drain).
type Server struct {
	addr         string
	tlsConfig    *tls.Config
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration

	auth      *auth.Validator
	limiter   *ratelimit.Multi
	proxy     *proxy.Proxy
	chain     *audit.Chain
	registry  *metrics.Registry
	logger    Logger

	httpServer *http.Server

	// activeBoxes tracks distinct box serials in the last 5 minutes
	// for the lmbox_bridge_active_boxes gauge.
	activeMu    sync.Mutex
	activeBoxes map[string]time.Time
}

// Logger is the minimal logging contract the server needs. We don't
// import a specific lib here — main.go picks a logger and adapts.
type Logger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

// Options bundles the dependencies. Every field is required except
// Logger (defaults to a no-op).
type Options struct {
	Addr         string
	TLSConfig    *tls.Config
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	Auth     *auth.Validator
	Limiter  *ratelimit.Multi
	Proxy    *proxy.Proxy
	Chain    *audit.Chain
	Registry *metrics.Registry
	Logger   Logger
}

// New builds a Server from Options. Does NOT bind the listener — that
// happens in Start, so a config error doesn't leave a dangling socket.
func New(opts Options) (*Server, error) {
	if opts.TLSConfig == nil {
		return nil, errors.New("server: TLSConfig required")
	}
	if opts.Auth == nil || opts.Limiter == nil || opts.Proxy == nil || opts.Chain == nil {
		return nil, errors.New("server: auth/limiter/proxy/chain are required")
	}
	if opts.Logger == nil {
		opts.Logger = noopLogger{}
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 30 * time.Second
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 60 * time.Second
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 120 * time.Second
	}
	return &Server{
		addr:         opts.Addr,
		tlsConfig:    opts.TLSConfig,
		readTimeout:  opts.ReadTimeout,
		writeTimeout: opts.WriteTimeout,
		idleTimeout:  opts.IdleTimeout,
		auth:         opts.Auth,
		limiter:      opts.Limiter,
		proxy:        opts.Proxy,
		chain:        opts.Chain,
		registry:     opts.Registry,
		logger:       opts.Logger,
		activeBoxes:  map[string]time.Time{},
	}, nil
}

// Start binds the listener and serves in a background goroutine.
// Returns once the listener accepts connections (or fails to bind).
// Use the returned error channel to observe a fatal server exit.
func (s *Server) Start() (<-chan error, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle) // catch-all : everything goes through the middleware chain
	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		TLSConfig:    s.tlsConfig,
		ReadTimeout:  s.readTimeout,
		WriteTimeout: s.writeTimeout,
		IdleTimeout:  s.idleTimeout,
		// Silence stdlib's noisy http.Server.ErrorLog by routing
		// it to our structured logger.
		ErrorLog: nil,
	}
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server listening", "addr", s.addr)
		// ListenAndServeTLS with empty file paths uses the certs
		// already loaded into s.tlsConfig.
		err := s.httpServer.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	return errCh, nil
}

// Handler returns the http.Handler the Server uses internally. Used
// by end-to-end tests that drive the Bridge via httptest. The
// production Start() path doesn't call this — it builds its own
// http.Server with the handler attached.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	return mux
}

// Stop drains in-flight requests up to `timeout`, then forcibly
// closes everything. Idempotent — calling twice is a no-op.
func (s *Server) Stop(timeout time.Duration) error {
	if s.httpServer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

// handle is the catch-all entry point. It owns the request's lifecycle :
// authenticate, rate-limit, allowlist, proxy, and audit. Every branch
// must end with auditAndRespond so the chain has a record.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// 1. mTLS validation. The handshake has already happened by the
	//    time Go invokes this handler; we only re-check the peer
	//    cert chain that stdlib resolved. If empty, that means the
	//    TLS config is misconfigured (ClientAuth not set strictly).
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.deny(w, r, "", "auth", http.StatusUnauthorized, start, "no client cert presented")
		return
	}
	serial, err := s.auth.Verify(r.TLS.PeerCertificates[0])
	if err != nil {
		s.deny(w, r, "", "auth", http.StatusUnauthorized, start, err.Error())
		return
	}

	// 2. Rate limit.
	if allowed, by := s.limiter.Allow(serial); !allowed {
		s.deny(w, r, serial, "rate_limit", http.StatusTooManyRequests, start,
			"throttled by "+by+" bucket")
		return
	}

	// 3. Path allowlist.
	if !s.proxy.PathAllowed(r.URL.Path) {
		s.deny(w, r, serial, "path_not_allowed", http.StatusForbidden, start,
			"path "+r.URL.Path+" not in allowlist")
		return
	}

	// 4. Proxy.
	bytesIn, bytesOut, status, perr := s.proxy.ServeHTTP(w, r, serial)
	s.audit(serial, r, status, bytesIn, bytesOut, time.Since(start), perr)
	s.trackActive(serial)
	if s.registry != nil {
		s.registry.RequestsTotal.WithLabelValues(strconv.Itoa(status)).Inc()
		s.registry.RequestDuration.WithLabelValues(strconv.Itoa(status)).Observe(time.Since(start).Seconds())
		s.registry.RequestBodyBytes.Add(float64(bytesIn))
		s.registry.ResponseBodyBytes.Add(float64(bytesOut))
		if perr != nil {
			kind := "network"
			if status == http.StatusGatewayTimeout {
				kind = "timeout"
			} else if status >= 500 {
				kind = "5xx"
			}
			s.registry.UpstreamErrors.WithLabelValues(kind).Inc()
		}
	}
}

// deny writes the rejection response and stamps the audit chain with
// the failure reason. Common path for every 4xx the Bridge emits
// before proxying upstream.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, serial, reason string, status int, start time.Time, detail string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	body := fmt.Sprintf(`{"error":%q,"reason":%q}`, http.StatusText(status), reason)
	bytesOut, _ := w.Write([]byte(body))

	s.audit(serial, r, status, r.ContentLength, int64(bytesOut), time.Since(start),
		errors.New(detail))
	if s.registry != nil {
		s.registry.DeniedRequests.WithLabelValues(reason).Inc()
		s.registry.RequestsTotal.WithLabelValues(strconv.Itoa(status)).Inc()
		s.registry.RequestDuration.WithLabelValues(strconv.Itoa(status)).Observe(time.Since(start).Seconds())
	}
	s.logger.Warn("request denied", "serial", serial, "reason", reason, "status", status, "detail", detail)
}

// audit appends an entry to the chain. Errors here are logged but
// never fail the request — the chain breakage will be visible at
// the next `lmbox-bridge verify` run.
func (s *Server) audit(serial string, r *http.Request, status int, bytesIn, bytesOut int64, duration time.Duration, perr error) {
	entry := audit.Entry{
		BoxSerial:  serial,
		Method:     r.Method,
		Path:       r.URL.Path,
		Status:     status,
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
		DurationMS: duration.Milliseconds(),
		ClientIP:   clientIP(r),
	}
	if perr != nil {
		entry.Error = perr.Error()
	}
	if _, err := s.chain.Append(entry); err != nil {
		s.logger.Error("audit append failed", "err", err)
	}
	if s.registry != nil {
		s.registry.AuditChainLength.Set(float64(s.chain.Len()))
		s.registry.SetLastHash(s.chain.LastHash())
	}
}

// trackActive bumps the in-memory active-boxes gauge.
func (s *Server) trackActive(serial string) {
	s.activeMu.Lock()
	s.activeBoxes[serial] = time.Now()
	// Eviction: remove entries older than 5 minutes. Cheap to do
	// inline since the map size is bounded by N boxes (~60-600).
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, t := range s.activeBoxes {
		if t.Before(cutoff) {
			delete(s.activeBoxes, k)
		}
	}
	count := len(s.activeBoxes)
	s.activeMu.Unlock()
	if s.registry != nil {
		s.registry.ActiveBoxesGauge.Set(float64(count))
	}
}

func clientIP(r *http.Request) string {
	// Strip the port off RemoteAddr. We don't trust X-Forwarded-For
	// here — the Bridge sits directly in front of the boxes.
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// NewTLSConfig builds the mTLS server config from PEM files on disk.
// Verifies that the cert + key match and that the client CA file
// contains at least one CA cert.
func NewTLSConfig(serverCertPath, serverKeyPath, clientCAPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("server: load server cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("server: read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("server: no certs in client CA file")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // mTLS REQUIRED — refuses TLS without client cert
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}, nil
}

// noopLogger keeps the package buildable in tests without forcing
// callers to wire a real logger.
type noopLogger struct{}

func (noopLogger) Info(msg string, kv ...any)  {}
func (noopLogger) Warn(msg string, kv ...any)  {}
func (noopLogger) Error(msg string, kv ...any) {}
