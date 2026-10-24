// Package yggss implements a SIP003 plugin for shadowsocks that tunnels
// traffic through the Yggdrasil network.
//
// This file is the public API of the package: it exposes the small set of
// types and constructors used by cmd/yggss, keeping the rest of the
// implementation unexported.
package yggss

import (
	"crypto/ed25519"
	"time"

	"github.com/gologme/log"
)

// Default failover parameters, also used as CLI flag defaults.
const (
	DefaultFailoverLatencyMs = defaultFailoverLatencyMs
	DefaultFailoverCheckSec  = defaultFailoverCheckSec
)

// Config is the JSON configuration file format for yggss.
type Config = pluginConfig

// LoadConfig reads and validates a JSON config file.
func LoadConfig(path string) (*Config, error) {
	return loadConfigFile(path)
}

// DetectSIP003 returns the plugin environment if the process was launched by
// a shadowsocks client or server, nil otherwise.
func DetectSIP003() *Env {
	return detectSIP003()
}

// ConfigPathFromOptions extracts the path to a JSON config file from the raw
// SS_PLUGIN_OPTIONS string.
func ConfigPathFromOptions(raw string) string {
	return configPathFromOptions(raw)
}

// ClientOptions configures a client-side tunnel.
type ClientOptions struct {
	Node      *Node
	ServerKey ed25519.PublicKey
	Bind      string
	Timeout   time.Duration
	Log       *log.Logger
	// Direct, when non-nil, enables the direct (plain UDP) tunnel with the
	// mesh as a fallback.
	Direct *DirectClient
}

// Client is the client side of the plugin.
type Client = client

// NewClient builds the client-side tunnel. When Direct is set, the
// background Alt-Svc-style prober is started as well.
func NewClient(opts ClientOptions) *Client {
	c := &client{
		node:      opts.Node,
		serverKey: opts.ServerKey,
		bind:      opts.Bind,
		timeout:   opts.Timeout,
		log:       opts.Log,
		direct:    opts.Direct,
	}
	if c.direct != nil {
		c.direct.startProber(c)
	}
	return c
}

// DirectOptions configures the direct (plain UDP) client path.
type DirectOptions struct {
	Node        *Node
	ServerKey   ed25519.PublicKey
	ServerAddr  string
	Timeout     time.Duration
	RetryPeriod time.Duration
	FakeSNI     string
	Log         *log.Logger
}

// DirectClient is the client side of the direct (plain UDP) tunnel.
type DirectClient = directClient

// NewDirectClient builds the direct client path. The prober is started by
// NewClient once the path is attached to a client.
func NewDirectClient(opts DirectOptions) *DirectClient {
	return &directClient{
		node:        opts.Node,
		serverKey:   opts.ServerKey,
		serverAddr:  opts.ServerAddr,
		timeout:     opts.Timeout,
		retryPeriod: opts.RetryPeriod,
		fakeSNI:     opts.FakeSNI,
		log:         opts.Log,
	}
}

// ServerOptions configures the server-side tunnel.
type ServerOptions struct {
	Node    *Node
	Dst     string
	Allowed map[string]struct{}
	Log     *log.Logger
}

// Server is the server side of the plugin.
type Server = server

// NewServer builds the server-side tunnel.
func NewServer(opts ServerOptions) *Server {
	return &server{
		node:    opts.Node,
		dst:     opts.Dst,
		allowed: opts.Allowed,
		log:     opts.Log,
	}
}

// StartDirectServer starts the direct (plain UDP) listener on the server.
func StartDirectServer(node *Node, bind, dst string, allowed map[string]struct{}, logger *log.Logger) error {
	return startDirectServer(node, bind, dst, allowed, logger)
}

// StartStatusLogger starts periodic yggdrasil peering status logging.
func StartStatusLogger(node *Node, serverKey ed25519.PublicKey, interval time.Duration, logger *log.Logger) {
	startStatusLogger(node, serverKey, interval, logger)
}

// StartClientStatusLog starts periodic status logging with end-to-end tunnel
// traffic counters and the currently active tunnel channel.
func StartClientStatusLog(node *Node, serverKey ed25519.PublicKey, interval time.Duration, cl *Client, logger *log.Logger) {
	startStatusLoggerTun(node, serverKey, interval,
		&cl.rx, &cl.tx, func() string { return cl.PathState().String() }, logger)
}

// FailoverMonitor watches the direct link to the server and toggles it.
type FailoverMonitor = failoverMonitor

// NewFailoverMonitor builds a direct-link failover monitor. It returns nil
// when failover is not applicable (no direct endpoint).
func NewFailoverMonitor(node *Node, directURI string, serverKey ed25519.PublicKey,
	latencyMs, checkSec int, logger *log.Logger) *FailoverMonitor {
	return newFailoverMonitor(node, directURI, serverKey, latencyMs, checkSec, logger)
}
