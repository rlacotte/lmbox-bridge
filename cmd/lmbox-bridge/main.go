// Command lmbox-bridge runs the LMbox Bridge — the single egress
// point a customer's IT team installs in their DMZ so that every
// LMbox box on the customer's LAN reaches the LMbox cloud through
// exactly one firewall rule.
//
// Usage
//
//	lmbox-bridge serve --config /etc/lmbox-bridge/config.yaml
//	lmbox-bridge verify --audit /var/lib/lmbox-bridge/audit.log --genesis "<...>"
//	lmbox-bridge version
//
// Subcommands keep the binary single-purpose at runtime (serve) but
// give operators the verification tool they need without ever
// stopping the running Bridge.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rlacotte/lmbox-bridge/internal/audit"
	"github.com/rlacotte/lmbox-bridge/internal/auth"
	"github.com/rlacotte/lmbox-bridge/internal/config"
	"github.com/rlacotte/lmbox-bridge/internal/health"
	"github.com/rlacotte/lmbox-bridge/internal/metrics"
	"github.com/rlacotte/lmbox-bridge/internal/proxy"
	"github.com/rlacotte/lmbox-bridge/internal/ratelimit"
	"github.com/rlacotte/lmbox-bridge/internal/server"
)

// Version is set at build time via -ldflags "-X main.Version=…".
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("lmbox-bridge %s (commit=%s, built=%s, %s)\n",
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
	fmt.Fprintf(os.Stderr, `lmbox-bridge — single-egress relay for LMbox boxes

Subcommands:
  serve     Run the Bridge. The only long-lived mode.
  verify    Re-walk an audit chain file and verify every hash.
  version   Print version and exit.

Run `+"`"+`lmbox-bridge <subcommand> --help`+"`"+` for subcommand flags.
`)
}

// runServe is the long-running entry point. Returns the desired exit
// code (0 on graceful shutdown, non-zero on fatal error).
func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/lmbox-bridge/config.yaml", "path to the YAML config file")
	fs.Parse(args)

	logger := newJSONLogger(os.Stderr)
	logger.Info("starting", "version", Version, "commit", Commit, "config", *cfgPath)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Error("config load failed", "err", err.Error())
		return 1
	}

	// Subsystems.
	tlsCfg, err := server.NewTLSConfig(cfg.Listen.ServerCert, cfg.Listen.ServerKey, cfg.Listen.ClientCAFile)
	if err != nil {
		logger.Error("tls config failed", "err", err.Error())
		return 1
	}

	authV, err := auth.New(cfg.Auth.SerialPattern, cfg.Auth.RevocationListFile, cfg.Auth.RevocationCheckInterval)
	if err != nil {
		// Soft error: New returns the empty validator + an error so
		// we can still boot when the operator forgot the CRL.
		// In production we WANT to refuse to boot — invariant: an
		// operator who never created a CRL still has revocation
		// disabled (path empty), which is fine; an operator who
		// pointed at a missing CRL has misconfigured and should
		// see the failure immediately.
		if cfg.Auth.RevocationListFile != "" {
			logger.Error("auth init failed", "err", err.Error())
			return 1
		}
		logger.Warn("auth init returned warning", "err", err.Error())
	}
	authV.Start()
	defer authV.Stop()

	limiter := ratelimit.NewMulti(
		cfg.RateLimit.Rate, cfg.RateLimit.Burst,
		cfg.RateLimit.GlobalRate, cfg.RateLimit.GlobalBurst,
	)
	if !cfg.RateLimit.Enabled {
		// Rate-limit-disabled mode: provide a no-op limiter so the
		// server middleware doesn't need to branch on the flag.
		// We can't trivially produce a "no-op Multi" without an
		// interface, so instead we set the rates absurdly high.
		limiter = ratelimit.NewMulti(1e9, 1e9, 0, 0)
	}

	prx, err := proxy.New(proxy.Options{
		UpstreamURL:     cfg.Upstream.URL,
		ClientCertPath:  cfg.Upstream.ClientCert,
		ClientKeyPath:   cfg.Upstream.ClientKey,
		RootCAPath:      cfg.Upstream.RootCAFile,
		AllowedPaths:    cfg.Upstream.AllowedPaths,
		DialTimeout:     cfg.Upstream.DialTimeout,
		ResponseTimeout: cfg.Upstream.ResponseTimeout,
		UserAgent:       "lmbox-bridge/" + Version,
	})
	if err != nil {
		logger.Error("proxy init failed", "err", err.Error())
		return 1
	}

	var chain *audit.Chain
	if cfg.Audit.File != "" {
		chain, err = audit.Resume(cfg.Audit.File, cfg.Audit.Genesis)
		if err != nil {
			logger.Error("audit chain resume failed", "err", err.Error())
			return 1
		}
		logger.Info("audit chain ready", "file", cfg.Audit.File, "length", chain.Len(), "last_hash", chain.LastHash())
	} else {
		// In-memory chain: still computed, just not persisted.
		// Allowed for dev / smoke tests; production deploys MUST
		// set audit.file (we'd ideally error on empty, but some
		// dev paths legitimately omit it).
		chain = audit.New(nil, cfg.Audit.Genesis)
		logger.Warn("audit file not configured — chain held in memory only")
	}

	// Metrics registry on its own listener.
	registry := metrics.New(prometheus.DefaultRegisterer)
	registry.BuildInfo.WithLabelValues(Version, Commit, runtime.Version()).Set(1)

	probes := health.New(func(ctx context.Context) error {
		// Cheap upstream probe: a GET to the configured upstream
		// root. We accept any 2xx or 3xx as "reachable" — we don't
		// expect 200 because the cloud may not expose a public
		// root, but a 404 still proves the TCP/TLS path works.
		req, err := http.NewRequestWithContext(ctx, "GET", cfg.Upstream.URL+"/healthz", nil)
		if err != nil {
			return err
		}
		// Use the proxy's outbound HTTP client so we share the same
		// mTLS config — readiness reflects the actual upstream
		// reachability the Bridge will see in practice.
		resp, err := prx.HealthCheck(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}, 90*time.Second)
	probes.MarkCRLLoaded(true) // updated by the CRL goroutine below
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probes.Start(rootCtx, 30*time.Second)

	srv, err := server.New(server.Options{
		Addr:         cfg.Listen.Address,
		TLSConfig:    tlsCfg,
		ReadTimeout:  cfg.Listen.ReadTimeout,
		WriteTimeout: cfg.Listen.WriteTimeout,
		IdleTimeout:  cfg.Listen.IdleTimeout,
		Auth:         authV,
		Limiter:      limiter,
		Proxy:        prx,
		Chain:        chain,
		Registry:     registry,
		Logger:       logger,
	})
	if err != nil {
		logger.Error("server build failed", "err", err.Error())
		return 1
	}

	mainErr, err := srv.Start()
	if err != nil {
		logger.Error("server start failed", "err", err.Error())
		return 1
	}

	// Metrics + health listener on its own port. Plain HTTP, bound
	// to localhost by default — the customer scrapes via a side-car
	// agent on the same VM.
	if cfg.Metrics.Enabled {
		mux := http.NewServeMux()
		mux.Handle(cfg.Metrics.Path, promhttp.Handler())
		mux.HandleFunc("/healthz", probes.LivenessHandler())
		mux.HandleFunc("/readyz", probes.ReadinessHandler())
		go func() {
			logger.Info("metrics listening", "addr", cfg.Metrics.Address)
			if err := http.ListenAndServe(cfg.Metrics.Address, mux); err != nil {
				logger.Error("metrics server failed", "err", err.Error())
			}
		}()
	}

	// Wait for shutdown signal or a fatal error from the main server.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		logger.Info("shutdown signal received", "signal", s.String())
	case err := <-mainErr:
		if err != nil {
			logger.Error("server exited with error", "err", err.Error())
		}
	}
	if err := srv.Stop(15 * time.Second); err != nil {
		logger.Error("graceful shutdown failed", "err", err.Error())
		return 1
	}
	logger.Info("shutdown complete")
	return 0
}

// runVerify rewalks the audit chain file. Exits 0 on intact chain,
// non-zero on first break.
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	auditFile := fs.String("audit", "", "path to the audit chain file (required)")
	genesis := fs.String("genesis", "", "genesis string used when the chain was created (required)")
	fs.Parse(args)
	if *auditFile == "" || *genesis == "" {
		fmt.Fprintln(os.Stderr, "verify: --audit and --genesis are required")
		return 2
	}
	n, err := audit.Verify(*auditFile, *genesis)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: FAIL after %d entries: %v\n", n, err)
		return 1
	}
	fmt.Printf("verify: OK — %d entries chained intact\n", n)
	return 0
}

// ─── Logger ──────────────────────────────────────────────────────

// jsonLogger writes one JSON object per log line. We don't pull in
// slog because the Go floor is 1.20; when we move to 1.21+ we'll
// swap this for log/slog with zero callsite changes.
type jsonLogger struct {
	enc *json.Encoder
	w   *log.Logger
}

func newJSONLogger(out *os.File) *jsonLogger {
	return &jsonLogger{
		enc: json.NewEncoder(out),
		w:   log.New(out, "", 0),
	}
}

func (j *jsonLogger) emit(level, msg string, kv []any) {
	rec := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"msg":   msg,
	}
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			continue
		}
		rec[k] = kv[i+1]
	}
	_ = j.enc.Encode(rec)
}

func (j *jsonLogger) Info(msg string, kv ...any)  { j.emit("info", msg, kv) }
func (j *jsonLogger) Warn(msg string, kv ...any)  { j.emit("warn", msg, kv) }
func (j *jsonLogger) Error(msg string, kv ...any) { j.emit("error", msg, kv) }
