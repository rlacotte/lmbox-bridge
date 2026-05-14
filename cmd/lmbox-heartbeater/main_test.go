package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMeminfo(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantTotal   int64
		wantAvail   int64
	}{
		{
			name: "standard",
			input: "MemTotal:       16234112 kB\n" +
				"MemFree:         1048576 kB\n" +
				"MemAvailable:    8388608 kB\n",
			wantTotal: 16234112 * 1024,
			wantAvail: 8388608 * 1024,
		},
		{
			name:      "empty",
			input:     "",
			wantTotal: 0,
			wantAvail: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			total, avail := parseMeminfo(tc.input)
			if total != tc.wantTotal {
				t.Errorf("total: got %d, want %d", total, tc.wantTotal)
			}
			if avail != tc.wantAvail {
				t.Errorf("avail: got %d, want %d", avail, tc.wantAvail)
			}
		})
	}
}

func TestLoadBoxIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "box.json")

	t.Run("rejects missing file", func(t *testing.T) {
		if _, err := loadBoxIdentity(filepath.Join(dir, "ghost.json")); err == nil {
			t.Fatal("expected error on missing file")
		}
	})

	t.Run("rejects empty serial", func(t *testing.T) {
		os.WriteFile(path, []byte(`{"api_key":"x"}`), 0o644)
		if _, err := loadBoxIdentity(path); err == nil {
			t.Fatal("expected error on empty serial")
		}
	})

	t.Run("rejects empty api_key", func(t *testing.T) {
		os.WriteFile(path, []byte(`{"serial":"BOX-001"}`), 0o644)
		if _, err := loadBoxIdentity(path); err == nil {
			t.Fatal("expected error on empty api_key")
		}
	})

	t.Run("defaults watched_units if missing", func(t *testing.T) {
		os.WriteFile(path, []byte(`{"serial":"BOX-001","api_key":"k"}`), 0o644)
		id, err := loadBoxIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(id.WatchedUnits) == 0 {
			t.Fatal("expected default WatchedUnits")
		}
	})

	t.Run("parses well-formed identity", func(t *testing.T) {
		os.WriteFile(path, []byte(`{
			"serial":"BOX-S1-DUPONT-001",
			"api_key":"key-xyz",
			"os_version":"v1.7.4",
			"runtime_version":"2.1.0",
			"watched_units":["ollama","lmbox-rag"]
		}`), 0o644)
		id, err := loadBoxIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		if id.Serial != "BOX-S1-DUPONT-001" {
			t.Errorf("serial: %q", id.Serial)
		}
		if len(id.WatchedUnits) != 2 {
			t.Errorf("watched_units: %v", id.WatchedUnits)
		}
	})
}

func TestFetchRAGStats(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true,"stats":{"tenant_count":1,"dataset_count":3,"chunk_count":42}}`))
		}))
		defer srv.Close()

		stats, err := fetchRAGStats(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if stats.Stats.ChunkCount != 42 {
			t.Errorf("chunk_count: %d", stats.Stats.ChunkCount)
		}
	})

	t.Run("error on 5xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(503)
		}))
		defer srv.Close()
		if _, err := fetchRAGStats(srv.URL); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestComposePayload(t *testing.T) {
	dir := t.TempDir()
	ackPath := filepath.Join(dir, "acks.jsonl")

	// Mock lmbox-rag stats endpoint.
	rag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"stats":{
			"tenant_count":2,"dataset_count":8,
			"document_count":1234,"chunk_count":5678,
			"errors_last_24h":1,"search_qps_1m":12,
			"service_version":"0.4.0"
		}}`))
	}))
	defer rag.Close()

	id := &boxIdentity{
		Serial:         "BOX-T-001",
		APIKey:         "k",
		OSVersion:      "v1.0",
		RuntimeVersion: "2.0",
		BridgeVersion:  "1.0",
		WatchedUnits:   []string{"true-unit-that-does-not-exist"}, // systemctl is-active will return "unknown"
	}
	logf := func(level, msg string, kv ...any) {}

	payload := composePayload(id, rag.URL, ackPath, logf)
	if payload.RAG["chunk_count"] != 5678 {
		t.Errorf("rag chunk_count: %v", payload.RAG["chunk_count"])
	}
	if payload.RAG["service_version"] != "0.4.0" {
		t.Errorf("rag service_version: %v", payload.RAG["service_version"])
	}
	if payload.OSVersion != "v1.0" {
		t.Errorf("os_version: %q", payload.OSVersion)
	}
}

func TestComposePayloadGracefulRAGFailure(t *testing.T) {
	dir := t.TempDir()
	ackPath := filepath.Join(dir, "acks.jsonl")

	id := &boxIdentity{
		Serial: "BOX-T-001", APIKey: "k",
		WatchedUnits: []string{},
	}
	logf := func(level, msg string, kv ...any) {}

	payload := composePayload(id, "http://127.0.0.1:1/dead", ackPath, logf)
	// RAG should be omitted (nil) on failure — heartbeat still composes.
	if payload.RAG != nil {
		t.Errorf("expected nil RAG, got %v", payload.RAG)
	}
	if payload.OSVersion == "" && payload.ReportedAt == "" {
		t.Error("payload should still be composed without RAG")
	}
}

func TestDrainAcks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acks.jsonl")
	logf := func(level, msg string, kv ...any) {}

	t.Run("no file → nil", func(t *testing.T) {
		acks := drainAcks(filepath.Join(dir, "ghost.jsonl"), logf)
		if acks != nil {
			t.Errorf("expected nil, got %v", acks)
		}
	})

	t.Run("reads JSONL + truncates", func(t *testing.T) {
		os.WriteFile(path, []byte(`{"id":1,"ok":true}
{"id":2,"ok":false,"error":"x"}
`), 0o644)
		acks := drainAcks(path, logf)
		if len(acks) != 2 {
			t.Fatalf("expected 2 acks, got %d", len(acks))
		}
		// File must be empty after drain.
		b, _ := os.ReadFile(path)
		if len(strings.TrimSpace(string(b))) != 0 {
			t.Errorf("file not truncated: %q", string(b))
		}
	})
}

func TestPostHeartbeat(t *testing.T) {
	var received map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"ok":true,"heartbeat_id":42}`))
	}))
	defer srv.Close()

	id := &boxIdentity{Serial: "BOX-X", APIKey: "key-1"}
	payload := heartbeatPayload{OSVersion: "v1"}

	if err := postHeartbeat(payload, id, srv.URL, ""); err != nil {
		t.Fatal(err)
	}
	if received["os_version"] != "v1" {
		t.Errorf("received: %v", received)
	}
}

func TestPostHeartbeatPrefersBridge(t *testing.T) {
	cloudHit := false
	bridgeHit := false
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cloudHit = true
		w.WriteHeader(201)
		w.Write([]byte(`{}`))
	}))
	defer cloud.Close()
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridgeHit = true
		w.WriteHeader(201)
		w.Write([]byte(`{}`))
	}))
	defer bridge.Close()

	id := &boxIdentity{Serial: "BOX-Y", APIKey: "k"}
	if err := postHeartbeat(heartbeatPayload{}, id, cloud.URL, bridge.URL); err != nil {
		t.Fatal(err)
	}
	if !bridgeHit {
		t.Error("bridge should be hit when configured")
	}
	if cloudHit {
		t.Error("cloud should be skipped when bridge is configured")
	}
}
