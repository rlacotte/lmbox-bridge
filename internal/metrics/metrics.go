// Package metrics defines the Prometheus metrics the Bridge exposes
// on a separate listener (default 127.0.0.1:9090). We keep the
// metrics endpoint OFF the public mTLS listener for two reasons :
//
//  1. /metrics is a known source of memory pressure under scraping;
//     isolating it on its own port + listener limits blast radius.
//  2. The RSSI's Prometheus probably scrapes from the customer's
//     monitoring VLAN, not from the LMbox boxes' VLAN. Different
//     listeners → different firewall rules.
//
// Metric naming follows Prometheus best practices :
//   - prefix `lmbox_bridge_` for namespacing
//   - `_total` suffix on monotonic counters
//   - `_seconds` suffix on duration histograms
//   - labels stay low-cardinality: status_code (max ~10),
//     deny_reason (max 5), box_serial label is INTENTIONALLY ABSENT
//     because 60+ boxes × labels = cardinality explosion. We surface
//     per-box state via the audit log instead.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registry bundles every metric in a single struct so the rest of
// the Bridge wires them up by composition, not by reaching into
// package-level globals.
type Registry struct {
	RequestsTotal      *prometheus.CounterVec
	RequestDuration    *prometheus.HistogramVec
	RequestBodyBytes   prometheus.Counter
	ResponseBodyBytes  prometheus.Counter
	DeniedRequests     *prometheus.CounterVec
	ActiveBoxesGauge   prometheus.Gauge
	AuditChainLength   prometheus.Gauge
	AuditChainLastHash *prometheus.GaugeVec // labels: prefix=<first8>, value always 1 — exposes the hash to scrapers
	UpstreamErrors     *prometheus.CounterVec
	CRLEntries         prometheus.Gauge
	BuildInfo          *prometheus.GaugeVec
}

// New constructs the full Registry and registers every metric on
// the given prometheus.Registerer.
func New(reg prometheus.Registerer) *Registry {
	r := &Registry{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lmbox_bridge_requests_total",
			Help: "Total number of requests handled, by HTTP status code.",
		}, []string{"status_code"}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "lmbox_bridge_request_duration_seconds",
			Help:    "End-to-end request handling latency in seconds (server-side).",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"status_code"}),

		RequestBodyBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lmbox_bridge_request_body_bytes_total",
			Help: "Cumulative bytes received from box clients.",
		}),

		ResponseBodyBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lmbox_bridge_response_body_bytes_total",
			Help: "Cumulative bytes returned to box clients.",
		}),

		DeniedRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lmbox_bridge_denied_total",
			Help: "Requests denied before reaching upstream, by reason (auth, rate-limit, path-not-allowed).",
		}, []string{"reason"}),

		ActiveBoxesGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lmbox_bridge_active_boxes",
			Help: "Distinct box serials with a request in the last 5 minutes.",
		}),

		AuditChainLength: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lmbox_bridge_audit_chain_length",
			Help: "Number of entries in the audit chain since process start (does not include resumed entries).",
		}),

		AuditChainLastHash: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lmbox_bridge_audit_chain_last_hash",
			Help: "Constant 1, with the label `prefix` carrying the first 8 hex chars of the most recent chain hash. Lets scrapers detect tamper/restore.",
		}, []string{"prefix"}),

		UpstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lmbox_bridge_upstream_errors_total",
			Help: "Errors from upstream HTTPS calls, by kind (timeout, network, tls, 5xx).",
		}, []string{"kind"}),

		CRLEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lmbox_bridge_crl_entries",
			Help: "Number of revoked cert entries currently loaded.",
		}),

		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lmbox_bridge_build_info",
			Help: "Build metadata as labels, value always 1.",
		}, []string{"version", "commit", "go_version"}),
	}

	reg.MustRegister(
		r.RequestsTotal,
		r.RequestDuration,
		r.RequestBodyBytes,
		r.ResponseBodyBytes,
		r.DeniedRequests,
		r.ActiveBoxesGauge,
		r.AuditChainLength,
		r.AuditChainLastHash,
		r.UpstreamErrors,
		r.CRLEntries,
		r.BuildInfo,
	)
	return r
}

// SetLastHash extracts the first 8 hex chars of the audit chain's
// current hash and exposes them as a Prometheus label. Doing this
// on every Append would balloon cardinality, so we expect callers
// to update it periodically (every ~30 s).
func (r *Registry) SetLastHash(fullHash string) {
	prefix := fullHash
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	// Reset to drop the previous prefix label and avoid cardinality
	// drift over the process lifetime.
	r.AuditChainLastHash.Reset()
	r.AuditChainLastHash.WithLabelValues(prefix).Set(1)
}
