// Package config defines, loads, and validates the LMbox Bridge runtime
// configuration. The Bridge is configured by exactly one YAML file
// (default /etc/lmbox-bridge/config.yaml). All paths in the file are
// resolved relative to the config file's directory unless absolute.
//
// Why YAML and not env vars
// ─────────────────────────
// The Bridge runs in a customer's DMZ on a VM the customer's IT team
// controls. They expect a single config file they can audit, version
// in their CMDB, and diff against the previous release. Env vars
// are fine for credentials passed by an orchestrator, but for an
// appliance that exists explicitly to be inspectable by a RSSI,
// YAML is the right surface.
//
// The config is loaded once at startup and fully validated. We do
// not hot-reload — a restart of the Bridge takes < 2 seconds and
// re-establishes all connections cleanly. Hot reload adds enough
// edge cases (mid-flight requests, cert swap timing) that it's not
// worth the complexity at this maturity level.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration object loaded from YAML.
type Config struct {
	Listen    ListenConfig    `yaml:"listen"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	Auth      AuthConfig      `yaml:"auth"`
	Audit     AuditConfig     `yaml:"audit"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Logging   LoggingConfig   `yaml:"logging"`
}

// ListenConfig — the inbound mTLS listener facing the customer's
// LMbox boxes. Defaults to 8443 because 443 is usually claimed by
// the customer's existing reverse proxy in the DMZ.
type ListenConfig struct {
	Address      string        `yaml:"address"`        // e.g. "0.0.0.0:8443"
	ServerCert   string        `yaml:"server_cert"`    // path to PEM
	ServerKey    string        `yaml:"server_key"`     // path to PEM
	ClientCAFile string        `yaml:"client_ca_file"` // PEM bundle of CAs that issued box client certs
	ReadTimeout  time.Duration `yaml:"read_timeout"`   // request read deadline, default 30s
	WriteTimeout time.Duration `yaml:"write_timeout"`  // response write deadline, default 60s
	IdleTimeout  time.Duration `yaml:"idle_timeout"`   // keep-alive idle deadline, default 120s
}

// UpstreamConfig — the outbound HTTPS relay to LMbox cloud.
type UpstreamConfig struct {
	URL          string        `yaml:"url"`            // e.g. "https://app.lmbox.eu"
	ClientCert   string        `yaml:"client_cert"`    // Bridge's own client cert for mTLS to cloud
	ClientKey    string        `yaml:"client_key"`     // matching key
	RootCAFile   string        `yaml:"root_ca_file"`   // PEM bundle for cloud cert verification (system roots if empty)
	DialTimeout  time.Duration `yaml:"dial_timeout"`   // TCP dial deadline, default 10s
	ResponseTimeout time.Duration `yaml:"response_timeout"` // response header deadline, default 30s
	// AllowedPaths lists the URL path prefixes the Bridge will forward
	// upstream. Anything else is rejected with 403. This is the second
	// line of defence after auth — even a compromised box can't reach
	// arbitrary cloud endpoints through us.
	AllowedPaths []string `yaml:"allowed_paths"`
}

// AuthConfig — how the Bridge authenticates incoming boxes.
type AuthConfig struct {
	// SerialPattern is a regular expression every box client cert CN
	// must match. Default: ^BOX-[A-Z0-9-]{6,40}$. Tightens the surface
	// so a CA-issued cert with an unexpected CN can't sneak in.
	SerialPattern string `yaml:"serial_pattern"`
	// RevocationListFile (CRL) is consulted on each request. The CRL
	// is reloaded from disk every RevocationCheckInterval. Empty path
	// disables revocation checking (for dev only — strongly recommended
	// in production to ship a CRL even if empty).
	RevocationListFile      string        `yaml:"revocation_list_file"`
	RevocationCheckInterval time.Duration `yaml:"revocation_check_interval"`
}

// AuditConfig — the SHA-256 chained audit log.
type AuditConfig struct {
	// File path where audit entries are written, one JSON object per
	// line. Empty disables file output (chain still computed in memory
	// for chained verification).
	File string `yaml:"file"`
	// Genesis is mixed into the chain's genesis hash so two customers'
	// chains never share a prefix. Must be a non-empty string unique
	// to this Bridge enrolment.
	Genesis string `yaml:"genesis"`
	// SyslogAddress, when set, forwards each audit entry to a syslog
	// daemon (RFC 5424 over UDP). Lets the customer ingest the chain
	// into their SIEM (Splunk, QRadar, etc.).
	SyslogAddress string `yaml:"syslog_address"`
}

// RateLimitConfig — token-bucket rate limit per box serial.
type RateLimitConfig struct {
	Enabled bool    `yaml:"enabled"`
	Rate    float64 `yaml:"rate"`  // tokens per second per box, default 10
	Burst   float64 `yaml:"burst"` // bucket capacity, default 100
	// GlobalRate caps total throughput across all boxes. Belt-and-
	// braces against a runaway client flooding the cloud.
	GlobalRate  float64 `yaml:"global_rate"`  // tokens per second, default 1000
	GlobalBurst float64 `yaml:"global_burst"` // default 5000
}

// MetricsConfig — Prometheus metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"` // e.g. "127.0.0.1:9090"
	// Path defaults to "/metrics".
	Path string `yaml:"path"`
}

// LoggingConfig — structured logging configuration.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
	Format string `yaml:"format"` // "json" or "text"
}

// Load reads and validates the config at path. Relative paths inside
// the config are rebased against the config file's directory so the
// operator can drop the bundle anywhere (e.g. /opt/lmbox-bridge/conf/).
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve path: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", abs, err)
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(bytesReader(data))
	dec.KnownFields(true) // strict: unknown keys are errors, not warnings
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", abs, err)
	}

	baseDir := filepath.Dir(abs)
	cfg.applyDefaults()
	cfg.rebasePaths(baseDir)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// applyDefaults fills in unset fields with safe production defaults.
// We prefer explicit defaults visible here over magic numbers buried
// in the consumer code — every operational knob is in one place.
func (c *Config) applyDefaults() {
	if c.Listen.Address == "" {
		c.Listen.Address = "0.0.0.0:8443"
	}
	if c.Listen.ReadTimeout == 0 {
		c.Listen.ReadTimeout = 30 * time.Second
	}
	if c.Listen.WriteTimeout == 0 {
		c.Listen.WriteTimeout = 60 * time.Second
	}
	if c.Listen.IdleTimeout == 0 {
		c.Listen.IdleTimeout = 120 * time.Second
	}
	if c.Upstream.DialTimeout == 0 {
		c.Upstream.DialTimeout = 10 * time.Second
	}
	if c.Upstream.ResponseTimeout == 0 {
		c.Upstream.ResponseTimeout = 30 * time.Second
	}
	if len(c.Upstream.AllowedPaths) == 0 {
		// Conservative default: only the heartbeat + agent upload
		// surfaces the LMbox cloud exposes today. Operators add to
		// this list explicitly when a new endpoint goes live.
		c.Upstream.AllowedPaths = []string{
			"/api/heartbeats/",
			"/api/agents/",
		}
	}
	if c.Auth.SerialPattern == "" {
		c.Auth.SerialPattern = `^BOX-[A-Z0-9-]{6,40}$`
	}
	if c.Auth.RevocationCheckInterval == 0 {
		c.Auth.RevocationCheckInterval = 5 * time.Minute
	}
	if c.RateLimit.Rate == 0 {
		c.RateLimit.Rate = 10
	}
	if c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = 100
	}
	if c.RateLimit.GlobalRate == 0 {
		c.RateLimit.GlobalRate = 1000
	}
	if c.RateLimit.GlobalBurst == 0 {
		c.RateLimit.GlobalBurst = 5000
	}
	if c.Metrics.Address == "" {
		c.Metrics.Address = "127.0.0.1:9090"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
}

// rebasePaths converts every relative file path in the config into an
// absolute path relative to the config file's directory.
func (c *Config) rebasePaths(baseDir string) {
	rebase := func(p *string) {
		if *p == "" || filepath.IsAbs(*p) {
			return
		}
		*p = filepath.Join(baseDir, *p)
	}
	rebase(&c.Listen.ServerCert)
	rebase(&c.Listen.ServerKey)
	rebase(&c.Listen.ClientCAFile)
	rebase(&c.Upstream.ClientCert)
	rebase(&c.Upstream.ClientKey)
	rebase(&c.Upstream.RootCAFile)
	rebase(&c.Auth.RevocationListFile)
	rebase(&c.Audit.File)
}

// Validate ensures every required field is set and every consistency
// invariant holds. Called after applyDefaults so we only check truly
// missing inputs, not absent-but-defaulted fields.
func (c *Config) Validate() error {
	var errs []string
	require := func(name, val string) {
		if val == "" {
			errs = append(errs, name+" is required")
		}
	}

	require("listen.server_cert", c.Listen.ServerCert)
	require("listen.server_key", c.Listen.ServerKey)
	require("listen.client_ca_file", c.Listen.ClientCAFile)
	require("upstream.url", c.Upstream.URL)
	require("upstream.client_cert", c.Upstream.ClientCert)
	require("upstream.client_key", c.Upstream.ClientKey)
	require("audit.genesis", c.Audit.Genesis)

	if c.RateLimit.Enabled {
		if c.RateLimit.Rate <= 0 {
			errs = append(errs, "rate_limit.rate must be > 0 when enabled")
		}
		if c.RateLimit.Burst < c.RateLimit.Rate {
			errs = append(errs, "rate_limit.burst must be >= rate")
		}
	}

	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, "logging.level must be one of debug/info/warn/error")
	}
	switch c.Logging.Format {
	case "json", "text":
	default:
		errs = append(errs, "logging.format must be json or text")
	}

	if len(errs) > 0 {
		return errors.New("invalid: " + joinErrs(errs))
	}
	return nil
}
