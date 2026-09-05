package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// pluginConfig is the JSON configuration file format for yggss.
// It is loaded with the -c flag (or the "config" SIP003 option) and provides
// defaults for the corresponding command-line flags. Explicit flags and
// SIP003 environment variables take precedence over the config file.
type pluginConfig struct {
	// Server selects the server role (same as the -s flag).
	Server bool `json:"server"`
	// Bind is the listen address (STANDALONE RUN ONLY):
	//   client: local address for ss-local to connect to (e.g. 127.0.0.1:1080)
	//   server: public address for the yggdrasil link listener (e.g. :4440)
	// When running under shadowsocks (SIP003), bind/destination are taken
	// from the SS_LOCAL_*/SS_REMOTE_* environment and these fields are
	// ignored.
	Bind string `json:"bind"`
	// Destination (STANDALONE RUN ONLY):
	//   client: public host:port of the server node (direct peering target)
	//   server: host:port of the local shadowsocks server to forward to
	Destination string `json:"destination"`
	// Key is the ed25519 private key of the local node (hex, see -genkey).
	Key string `json:"key"`
	// ServerKey is the ed25519 public key of the server node (hex, client only).
	ServerKey string `json:"server_key"`
	// ClientKey is a single allowed client node public key (hex, server only).
	// Kept for backward compatibility; use ClientKeys for multiple clients.
	ClientKey string `json:"client_key"`
	// ClientKeys is the list of allowed client node public keys (hex, server
	// only). Combined with ClientKey. Empty list means any node may connect.
	ClientKeys []string `json:"client_keys"`
	// Peers is a list of extra yggdrasil peering URIs for mesh reachability.
	Peers []string `json:"peers"`
	// Password is the yggdrasil group password (must match on both sides).
	Password string `json:"password"`
	// Scheme is the yggdrasil link scheme for the direct server connection:
	// tls (default), tcp, quic, ws, wss.
	Scheme string `json:"scheme"`
	// Mode selects the tunnel transport: "mesh" (default) routes the QUIC
	// tunnel through the yggdrasil packet session (works over the mesh,
	// slower), "direct" runs it over plain UDP between the client and the
	// server endpoint (faster, requires direct UDP reachability).
	Mode string `json:"mode"`
	// SNI is a fake domain name placed into the ClientHello of the direct
	// TLS link to the server (client only). Useful when destination comes
	// from the shadowsocks environment and cannot carry "?sni=" itself.
	// Example: "www.example.com".
	SNI string `json:"sni"`
	// DirectDialTimeout caps how long a direct (UDP) dial may take before
	// falling back to the mesh, in seconds (client only). Short values
	// reduce stalls when UDP is blocked; default 5.
	DirectDialTimeout int `json:"direct_dial_timeout_sec"`
	// DirectRetry is the interval in seconds between retries of the direct
	// tunnel while it is down (client only). Default 30.
	DirectRetry int `json:"direct_retry_sec"`
	// Timeout is the tunnel dial timeout in seconds (client only).
	Timeout int `json:"timeout"`
	// LogInterval is the interval in seconds between periodic status log
	// lines (peers, latency, current route). 0 disables status logging.
	LogInterval int `json:"log_interval"`
	// Failover enables direct-link failover (client only): the direct link
	// to the server is preferred; when it degrades (latency above threshold)
	// it is disconnected and traffic goes through peers until the direct
	// link recovers. Default: enabled when both a direct server address and
	// peers are configured.
	Failover *bool `json:"failover"`
	// FailoverLatency is the direct-link latency threshold in milliseconds;
	// above it the link counts as degraded (default 1000).
	FailoverLatency int `json:"failover_latency_ms"`
	// FailoverCheck is the health-check interval in seconds (default 5).
	FailoverCheck int `json:"failover_check_sec"`
}

// loadConfigFile reads and validates a JSON config file.
func loadConfigFile(path string) (*pluginConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	cfg := &pluginConfig{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	cfg.Key = strings.TrimSpace(cfg.Key)
	cfg.ServerKey = strings.TrimSpace(cfg.ServerKey)
	cfg.ClientKey = strings.TrimSpace(cfg.ClientKey)
	for i, k := range cfg.ClientKeys {
		cfg.ClientKeys[i] = strings.TrimSpace(k)
	}
	cfg.Scheme = strings.TrimSpace(cfg.Scheme)
	return cfg, nil
}

// findConfigPath pre-scans the command line for the -c flag (both "-c path"
// and "-c=path" forms) before flag parsing.
func findConfigPath(args []string) string {
	for i, a := range args {
		switch {
		case a == "-c" && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(a, "-c="):
			return strings.TrimPrefix(a, "-c=")
		}
	}
	return ""
}
