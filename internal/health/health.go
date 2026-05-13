// Package health exposes liveness + readiness HTTP endpoints.
//
// Convention follows the Kubernetes probe model used everywhere now:
//
//	GET /healthz   →  200 if the process is alive. Always.
//	GET /readyz    →  200 if the process is ready to serve traffic.
//	                  503 if upstream is unreachable or CRL load
//	                  failed and revocation is enabled.
//
// The systemd unit hits /healthz for restart decisions; the
// customer's load balancer (if any sits in front of multiple
// Bridge replicas) hits /readyz.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// Probes wraps the readiness state. The Bridge's main loop calls
// Update* methods periodically (or on event); the HTTP handlers
// read atomic snapshots so probes never block on a contended lock.
type Probes struct {
	startedAt     time.Time
	upstreamReady atomic.Bool
	crlLoaded     atomic.Bool
	// lastUpstreamCheck is monotonic; we flip upstreamReady to false
	// if no successful check has happened in `staleAfter`.
	lastUpstreamCheck atomic.Int64 // unix nanos
	staleAfter        time.Duration
	upstreamCheck     func(ctx context.Context) error
}

// New constructs the probe registry. `upstreamCheck` is a function
// the readiness goroutine calls to verify the upstream is reachable;
// typically a HEAD or GET to a known cheap path. Pass nil to skip
// upstream readiness (the probe will only check CRL state).
func New(upstreamCheck func(ctx context.Context) error, staleAfter time.Duration) *Probes {
	if staleAfter == 0 {
		staleAfter = 90 * time.Second
	}
	p := &Probes{
		startedAt:     time.Now(),
		staleAfter:    staleAfter,
		upstreamCheck: upstreamCheck,
	}
	// Default to "ready" if no upstream check is wired. The CRL
	// flag is false until the first successful load by the caller.
	if upstreamCheck == nil {
		p.upstreamReady.Store(true)
	}
	return p
}

// MarkCRLLoaded is called by the auth package after a successful
// CRL load. Without this, /readyz reports 503 — better to be
// loud about a missing revocation list than silently allow
// revoked certs.
func (p *Probes) MarkCRLLoaded(ok bool) {
	p.crlLoaded.Store(ok)
}

// Start spawns the background goroutine that periodically pings
// upstream. Caller MUST call Stop on shutdown.
func (p *Probes) Start(ctx context.Context, interval time.Duration) {
	if p.upstreamCheck == nil {
		return
	}
	if interval == 0 {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		// One immediate check so /readyz answers correctly right
		// after Start (instead of being stuck at "not ready" until
		// the first tick).
		p.runCheck(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.runCheck(ctx)
			}
		}
	}()
}

func (p *Probes) runCheck(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := p.upstreamCheck(checkCtx)
	p.upstreamReady.Store(err == nil)
	if err == nil {
		p.lastUpstreamCheck.Store(time.Now().UnixNano())
	}
}

// LivenessHandler always returns 200. The point of /healthz is to
// report "the process is up and responding to HTTP" — anything
// fancier belongs in /readyz.
func (p *Probes) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"status":        "ok",
			"uptime_seconds": int(time.Since(p.startedAt).Seconds()),
		}
		writeJSON(w, http.StatusOK, body)
	}
}

// ReadinessHandler returns 200 only when every dependency is
// healthy. The body is a JSON breakdown so an operator hitting
// `curl -s /readyz | jq` sees exactly which check failed.
func (p *Probes) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		upOK := p.upstreamReady.Load()
		// Stale-check : if the upstream check hasn't fired in
		// staleAfter, mark not ready (defensive — protects against
		// a goroutine deadlock that froze the periodic check).
		if p.upstreamCheck != nil {
			lastNanos := p.lastUpstreamCheck.Load()
			if lastNanos > 0 {
				if time.Since(time.Unix(0, lastNanos)) > p.staleAfter {
					upOK = false
				}
			} else {
				upOK = false
			}
		}
		crlOK := p.crlLoaded.Load()
		ok := upOK && crlOK
		status := http.StatusOK
		if !ok {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]any{
			"ready":    ok,
			"upstream": upOK,
			"crl":      crlOK,
			"uptime_seconds": int(time.Since(p.startedAt).Seconds()),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
