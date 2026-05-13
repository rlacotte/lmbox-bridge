package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, content string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// Create stub files so path-existence checks (if any) succeed.
	for _, name := range []string{"server.crt", "server.key", "client-ca.pem", "bridge.crt", "bridge.key"} {
		os.WriteFile(filepath.Join(dir, name), []byte("stub"), 0o600)
	}
	return dir, path
}

func TestLoad_MinimalValidConfig(t *testing.T) {
	_, path := writeTempConfig(t, `
listen:
  address: "0.0.0.0:8443"
  server_cert: server.crt
  server_key: server.key
  client_ca_file: client-ca.pem
upstream:
  url: "https://app.lmbox.eu"
  client_cert: bridge.crt
  client_key: bridge.key
audit:
  genesis: "test-customer-2026"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen.Address != "0.0.0.0:8443" {
		t.Fatalf("address=%q", cfg.Listen.Address)
	}
	if cfg.RateLimit.Rate != 10 {
		t.Fatalf("rate=%v, expected default 10", cfg.RateLimit.Rate)
	}
	if len(cfg.Upstream.AllowedPaths) == 0 {
		t.Fatal("expected default allowed_paths")
	}
}

func TestLoad_RejectsUnknownKeys(t *testing.T) {
	_, path := writeTempConfig(t, `
listen:
  address: "0.0.0.0:8443"
  server_cert: server.crt
  server_key: server.key
  client_ca_file: client-ca.pem
  unknown_key: "oops"
upstream:
  url: "https://app.lmbox.eu"
  client_cert: bridge.crt
  client_key: bridge.key
audit:
  genesis: "x"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "unknown_key") {
		t.Fatalf("error doesn't mention unknown_key: %v", err)
	}
}

func TestLoad_RequiresMandatoryFields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing server_cert",
			yaml: `
listen:
  server_key: k
  client_ca_file: ca
upstream:
  url: "https://x"
  client_cert: c
  client_key: k
audit:
  genesis: g
`,
			want: "listen.server_cert is required",
		},
		{
			name: "missing upstream.url",
			yaml: `
listen:
  server_cert: c
  server_key: k
  client_ca_file: ca
upstream:
  client_cert: c
  client_key: k
audit:
  genesis: g
`,
			want: "upstream.url is required",
		},
		{
			name: "missing audit.genesis",
			yaml: `
listen:
  server_cert: c
  server_key: k
  client_ca_file: ca
upstream:
  url: "https://x"
  client_cert: c
  client_key: k
`,
			want: "audit.genesis is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, path := writeTempConfig(t, tc.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error mentioning %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestLoad_RebasesRelativePaths(t *testing.T) {
	dir, path := writeTempConfig(t, `
listen:
  server_cert: server.crt
  server_key: server.key
  client_ca_file: client-ca.pem
upstream:
  url: "https://x"
  client_cert: bridge.crt
  client_key: bridge.key
audit:
  genesis: g
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := filepath.Join(dir, "server.crt")
	if cfg.Listen.ServerCert != want {
		t.Fatalf("server_cert=%s, want %s", cfg.Listen.ServerCert, want)
	}
}

func TestLoad_RateLimitInvariants(t *testing.T) {
	_, path := writeTempConfig(t, `
listen:
  server_cert: server.crt
  server_key: server.key
  client_ca_file: client-ca.pem
upstream:
  url: "https://x"
  client_cert: bridge.crt
  client_key: bridge.key
audit:
  genesis: g
rate_limit:
  enabled: true
  rate: 10
  burst: 5
`)
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected burst<rate validation error")
	}
	if !strings.Contains(err.Error(), "burst") {
		t.Fatalf("error doesn't mention burst: %v", err)
	}
}
