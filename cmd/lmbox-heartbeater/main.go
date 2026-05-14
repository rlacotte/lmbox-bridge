// Command lmbox-heartbeater compose et émet périodiquement le
// heartbeat de la box vers le cloud LMbox (gbox-web). Tourne en
// daemon sur la box, démarré par systemd.
//
// Source du payload heartbeat :
//
//   - Identité box        : /etc/lmbox/box.json (serial, API key,
//                            os_version, runtime_version,
//                            bridge_version, modules_versions)
//   - Métriques système   : /proc/meminfo, /proc/stat, /proc/diskstats
//   - Métriques RAG       : GET http://127.0.0.1:3300/api/v1/health/stats
//                            (sans auth — endpoint local non-tenant-scoped)
//   - Services status     : systemctl is-active <unit> pour les units
//                            critiques (ollama, lmbox-rag, openclaw, …)
//   - Commands ack        : /var/lib/lmbox/box/commands-ack.json
//                            (déposé par OpenClaw quand il a fini une
//                             commande)
//
// Destination : POST <cloud_base>/api/heartbeats/<serial> via le Bridge
// DMZ. Bearer = la box's API key. Le Bridge a déjà l'auth mTLS au
// niveau réseau ; l'API key est l'auth applicative côté gbox-web.
//
// Intervalle par défaut : 60s. Configurable via --interval ou env
// LMBOX_HEARTBEAT_INTERVAL_SECONDS.
//
// Doctrine appliquée :
//   - Aucune donnée business (chunks, prompts, réponses agent) ne
//     part au cloud — uniquement des compteurs agrégés et le status.
//   - Aucune persistence locale du payload — chaque tick est composé
//     à frais, posté, oublié. Si le post échoue, on retry au tick
//     suivant (pas de queue locale pour éviter d'accumuler un
//     backlog quand le réseau revient).
//   - Logs JSON structurés vers stdout, captés par journald.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Version est injecté au build via -ldflags "-X main.Version=...".
var (
	Version   = "0.1.0-dev"
	BuildDate = "unknown"
)

const (
	defaultInterval     = 60 * time.Second
	defaultCloudBase    = "https://api.lmbox.eu"
	defaultBridgeURL    = ""        // si vide : POST direct (pas de Bridge en dev)
	defaultRAGStatsURL  = "http://127.0.0.1:3300/api/v1/health/stats"
	defaultBoxJSONPath  = "/etc/lmbox/box.json"
	defaultAckPath      = "/var/lib/lmbox/box/commands-ack.json"
	requestTimeout      = 10 * time.Second
)

// boxIdentity = contenu de /etc/lmbox/box.json, écrit par
// lmbox-bridge-enroll au premier boot (chantier 1.2 ZTP).
type boxIdentity struct {
	Serial          string            `json:"serial"`
	APIKey          string            `json:"api_key"`
	OSVersion       string            `json:"os_version"`
	RuntimeVersion  string            `json:"runtime_version"`
	BridgeVersion   string            `json:"bridge_version"`
	ModulesVersions map[string]string `json:"modules_versions"`
	ModelsVersions  map[string]string `json:"models_versions"`
	WatchedUnits    []string          `json:"watched_units"`
	HardwareModel   string            `json:"hardware_model"`
}

// ragStats = ce que lmbox-rag /api/v1/health/stats renvoie.
type ragStats struct {
	OK    bool `json:"ok"`
	Stats struct {
		TenantCount     int    `json:"tenant_count"`
		DatasetCount    int    `json:"dataset_count"`
		DocumentCount   int    `json:"document_count"`
		ChunkCount      int    `json:"chunk_count"`
		LastIngestAt    string `json:"last_ingest_at"`
		ErrorsLast24h   int    `json:"errors_last_24h"`
		SearchQPS1m     int    `json:"search_qps_1m"`
		ServiceVersion  string `json:"service_version"`
	} `json:"stats"`
}

// heartbeatPayload = ce qu'on POST à Api::HeartbeatsController#create.
// Forme alignée avec gbox-web/app/controllers/api/heartbeats_controller.rb.
type heartbeatPayload struct {
	ReportedAt        string             `json:"reported_at"`
	OSVersion         string             `json:"os_version"`
	RuntimeVersion    string             `json:"runtime_version"`
	BridgeVersion     string             `json:"bridge_version"`
	ModulesVersions   map[string]string  `json:"modules_versions"`
	ModelsVersions    map[string]string  `json:"models_versions"`
	ServicesStatus    map[string]string  `json:"services_status"`
	Metrics           map[string]any     `json:"metrics"`
	CommandsAck       []map[string]any   `json:"commands_ack,omitempty"`
	RAG               map[string]any     `json:"rag,omitempty"`
}

func main() {
	var (
		interval     time.Duration
		cloudBase    string
		bridgeURL    string
		ragStatsURL  string
		boxJSON      string
		ackPath      string
		oneshot      bool
		showVersion  bool
	)

	flag.DurationVar(&interval, "interval", envDuration("LMBOX_HEARTBEAT_INTERVAL_SECONDS", defaultInterval),
		"Intervalle entre 2 heartbeats")
	flag.StringVar(&cloudBase, "cloud", envStr("LMBOX_CLOUD_BASE", defaultCloudBase),
		"Cloud LMbox base URL (heartbeat target)")
	flag.StringVar(&bridgeURL, "bridge", envStr("LMBOX_BRIDGE_URL", defaultBridgeURL),
		"URL du Bridge DMZ local (vide = POST direct au cloud, dev only)")
	flag.StringVar(&ragStatsURL, "rag-stats-url", envStr("LMBOX_RAG_STATS_URL", defaultRAGStatsURL),
		"URL locale de lmbox-rag /api/v1/health/stats")
	flag.StringVar(&boxJSON, "box-json", envStr("LMBOX_BOX_JSON", defaultBoxJSONPath),
		"Path vers le fichier d'identité box (écrit par lmbox-bridge-enroll au ZTP)")
	flag.StringVar(&ackPath, "ack-path", envStr("LMBOX_ACK_PATH", defaultAckPath),
		"Path vers la file d'ack commands déposée par OpenClaw")
	flag.BoolVar(&oneshot, "oneshot", false, "Tick une fois puis exit (debug)")
	flag.BoolVar(&showVersion, "version", false, "Affiche version + exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("lmbox-heartbeater %s (%s)\n", Version, BuildDate)
		return
	}

	logger := log.New(os.Stdout, "", 0)
	logf := func(level, msg string, kv ...any) {
		fields := map[string]any{
			"time":  time.Now().UTC().Format(time.RFC3339Nano),
			"level": level,
			"msg":   msg,
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if k, ok := kv[i].(string); ok {
				fields[k] = kv[i+1]
			}
		}
		b, _ := json.Marshal(fields)
		logger.Println(string(b))
	}

	if oneshot {
		runOnce(logf, cloudBase, bridgeURL, ragStatsURL, boxJSON, ackPath)
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	logf("info", "heartbeater starting",
		"version", Version,
		"interval_seconds", interval.Seconds(),
		"cloud", cloudBase,
		"via_bridge", bridgeURL != "")

	// 1er tick immédiat pour valider la config dès le boot.
	runOnce(logf, cloudBase, bridgeURL, ragStatsURL, boxJSON, ackPath)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			runOnce(logf, cloudBase, bridgeURL, ragStatsURL, boxJSON, ackPath)
		case sig := <-stop:
			logf("info", "shutdown requested", "signal", sig.String())
			return
		}
	}
}

func runOnce(logf func(string, string, ...any), cloudBase, bridgeURL, ragStatsURL, boxJSON, ackPath string) {
	id, err := loadBoxIdentity(boxJSON)
	if err != nil {
		logf("error", "load box identity failed", "err", err.Error(), "path", boxJSON)
		return
	}

	payload := composePayload(id, ragStatsURL, ackPath, logf)
	if err := postHeartbeat(payload, id, cloudBase, bridgeURL); err != nil {
		logf("error", "heartbeat POST failed", "err", err.Error(), "serial", id.Serial)
		return
	}

	logf("info", "heartbeat ok",
		"serial", id.Serial,
		"rag_chunks", payload.RAG["chunk_count"],
		"services_ok", countOK(payload.ServicesStatus))
}

func composePayload(id *boxIdentity, ragStatsURL, ackPath string, logf func(string, string, ...any)) heartbeatPayload {
	rag, err := fetchRAGStats(ragStatsURL)
	if err != nil {
		logf("warn", "rag stats unavailable",
			"err", err.Error(),
			"url", ragStatsURL)
		// On émet quand même un heartbeat sans RAG plutôt que de
		// rien envoyer — le cloud verra `rag_*` non-mis-à-jour
		// et flaggera la dérive.
	}

	services := probeServices(id.WatchedUnits)
	metrics := readSystemMetrics()
	acks := drainAcks(ackPath, logf)

	payload := heartbeatPayload{
		ReportedAt:      time.Now().UTC().Format(time.RFC3339),
		OSVersion:       id.OSVersion,
		RuntimeVersion:  id.RuntimeVersion,
		BridgeVersion:   id.BridgeVersion,
		ModulesVersions: id.ModulesVersions,
		ModelsVersions:  id.ModelsVersions,
		ServicesStatus:  services,
		Metrics:         metrics,
		CommandsAck:     acks,
	}

	if rag != nil {
		payload.RAG = map[string]any{
			"tenant_count":     rag.Stats.TenantCount,
			"dataset_count":    rag.Stats.DatasetCount,
			"document_count":   rag.Stats.DocumentCount,
			"chunk_count":      rag.Stats.ChunkCount,
			"last_ingest_at":   rag.Stats.LastIngestAt,
			"errors_last_24h":  rag.Stats.ErrorsLast24h,
			"search_qps_1m":    rag.Stats.SearchQPS1m,
			"service_version":  rag.Stats.ServiceVersion,
		}
	}

	return payload
}

func loadBoxIdentity(path string) (*boxIdentity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var id boxIdentity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if id.Serial == "" {
		return nil, errors.New("serial missing in box.json")
	}
	if id.APIKey == "" {
		return nil, errors.New("api_key missing in box.json")
	}
	if len(id.WatchedUnits) == 0 {
		id.WatchedUnits = []string{"ollama", "lmbox-rag", "lmbox-rag-worker", "openclaw"}
	}
	return &id, nil
}

func fetchRAGStats(url string) (*ragStats, error) {
	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var stats ragStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &stats, nil
}

func probeServices(units []string) map[string]string {
	status := make(map[string]string, len(units))
	for _, u := range units {
		out, err := exec.Command("systemctl", "is-active", u).Output()
		if err != nil && len(out) == 0 {
			status[u] = "unknown"
			continue
		}
		status[u] = strings.TrimSpace(string(out))
	}
	return status
}

func readSystemMetrics() map[string]any {
	m := make(map[string]any)
	if mem, err := os.ReadFile("/proc/meminfo"); err == nil {
		total, free := parseMeminfo(string(mem))
		if total > 0 {
			m["memory_total_bytes"] = total
			m["memory_used_bytes"] = total - free
			m["memory_used_pct"] = float64(total-free) / float64(total) * 100
		}
	}
	return m
}

// parseMeminfo extrait MemTotal et MemAvailable (en bytes) depuis
// le contenu de /proc/meminfo. Format ligne : "MemTotal:  16234567 kB".
func parseMeminfo(content string) (total, available int64) {
	for _, line := range strings.Split(content, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		var v int64
		fmt.Sscanf(parts[1], "%d", &v)
		v *= 1024 // kB → bytes
		switch parts[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			available = v
		}
	}
	return total, available
}

// drainAcks lit + reset le fichier d'ack des commands. OpenClaw écrit
// dans ce fichier quand il a fini une commande (install_agent,
// rotate_logs, apply_upgrade, …). On lit + truncate atomiquement
// pour ne pas re-ack 2× la même commande.
func drainAcks(path string, logf func(string, string, ...any)) []map[string]any {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("warn", "drain acks open failed", "err", err.Error(), "path", path)
		}
		return nil
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil || len(b) == 0 {
		return nil
	}

	var acks []map[string]any
	// Le fichier est un JSON Lines (un objet par ligne).
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ack map[string]any
		if err := json.Unmarshal([]byte(line), &ack); err == nil {
			acks = append(acks, ack)
		}
	}

	// Truncate — les acks sont consommés.
	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	return acks
}

func postHeartbeat(payload heartbeatPayload, id *boxIdentity, cloudBase, bridgeURL string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	// Target : Bridge DMZ si configuré, sinon direct cloud (dev only).
	target := cloudBase
	if bridgeURL != "" {
		target = bridgeURL
	}
	url := fmt.Sprintf("%s/api/heartbeats/%s", strings.TrimRight(target, "/"), id.Serial)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+id.APIKey)
	req.Header.Set("User-Agent", fmt.Sprintf("lmbox-heartbeater/%s", Version))

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, string(out))
	}
	return nil
}

func countOK(services map[string]string) int {
	ok := 0
	for _, s := range services {
		if s == "active" {
			ok++
		}
	}
	return ok
}

func envStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v + "s")
	if err != nil {
		return def
	}
	return d
}
