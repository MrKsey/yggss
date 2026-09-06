package yggss

import (
	"net"
	"os"
	"strings"
)

// Env holds the environment variables set by a shadowsocks client or
// server when launching this program as a SIP003 plugin.
type Env struct {
	localHost  string
	localPort  string
	remoteHost string
	remotePort string
	// Options is the parsed SS_PLUGIN_OPTIONS string (key=value pairs).
	Options map[string]string
}

func (e *Env) LocalAddr() string  { return net.JoinHostPort(e.localHost, e.localPort) }
func (e *Env) RemoteAddr() string { return net.JoinHostPort(e.remoteHost, e.remotePort) }

// detectSIP003 returns the plugin environment if the process was launched by
// a shadowsocks server or client, nil otherwise.
//
// Note: the presence of SS_PLUGIN is NOT a reliable signal — the SIP003 spec
// does not define it and shadowsocks-rust never sets it. The standard way
// (used by simple-tls as well) is to look for SS_LOCAL_*/SS_REMOTE_* variables.
func detectSIP003() *Env {
	_, localHost := os.LookupEnv("SS_LOCAL_HOST")
	_, localPort := os.LookupEnv("SS_LOCAL_PORT")
	_, remoteHost := os.LookupEnv("SS_REMOTE_HOST")
	_, remotePort := os.LookupEnv("SS_REMOTE_PORT")
	_, opts := os.LookupEnv("SS_PLUGIN_OPTIONS")
	if !localHost && !localPort && !remoteHost && !remotePort && !opts {
		return nil // not launched as a SIP003 plugin
	}
	if !localHost || !localPort || !remoteHost || !remotePort {
		return nil // incomplete SIP003 environment, treat as standalone run
	}
	return &Env{
		localHost:  os.Getenv("SS_LOCAL_HOST"),
		localPort:  os.Getenv("SS_LOCAL_PORT"),
		remoteHost: os.Getenv("SS_REMOTE_HOST"),
		remotePort: os.Getenv("SS_REMOTE_PORT"),
		Options:    parsePluginOptions(os.Getenv("SS_PLUGIN_OPTIONS")),
	}
}

// parsePluginOptions parses SS_PLUGIN_OPTIONS in the "key=value;key2=value2" format.
func parsePluginOptions(s string) map[string]string {
	opts := make(map[string]string)
	for _, pair := range strings.Split(s, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		opts[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return opts
}

// configPathFromOptions extracts the path to a JSON config file from the raw
// SS_PLUGIN_OPTIONS string. Supported forms:
//
//	/etc/shadowsocks/yggss-client.json          (path directly)
//	c=/etc/shadowsocks/yggss-client.json        (short form)
//	config=/etc/shadowsocks/yggss-client.json   (long form)
//	s;c=/etc/shadowsocks/yggss-server.json      (combined with other options)
//
// Returns "" when no config path is present.
func configPathFromOptions(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// A single value that looks like a file path (no "key=value" structure,
	// ends with .json) is treated as the config path itself.
	if !strings.Contains(raw, "=") && strings.HasSuffix(strings.ToLower(raw), ".json") {
		return raw
	}
	opts := parsePluginOptions(raw)
	if p := opts["config"]; p != "" {
		return p
	}
	return opts["c"]
}
