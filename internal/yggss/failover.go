package yggss

import (
	"crypto/ed25519"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gologme/log"
)

// failover states.
const (
	failoverStateDirect = iota // direct link in use
	failoverStateMesh          // direct link disconnected, traffic via peers
)

const (
	// Consecutive bad samples before dropping the direct link.
	failoverDegradeLimit = 3
	// Consecutive good probes before restoring the direct link.
	failoverRecoverLimit = 2
	// Default health-check parameters.
	defaultFailoverLatencyMs = 1000
	defaultFailoverCheckSec  = 5
	failoverProbeTimeout     = 3 * time.Second
)

// failoverMonitor watches the direct link to the server and toggles it:
//
//	DIRECT state: the direct peering is up; if its measured latency exceeds
//	              the threshold failoverDegradeLimit times in a row (or the
//	              link goes down), the peering is removed so that yggdrasil
//	              reroutes traffic through the mesh peers.
//	MESH state:   the direct endpoint is probed out-of-band with a plain TCP
//	              connect; after failoverRecoverLimit good probes the
//	              peering is restored.
//
// While the direct link is up, yggdrasil itself prefers it (an adjacent node
// has the minimal tree distance), so no extra routing logic is needed.
type failoverMonitor struct {
	node       *Node
	directURI  string // full peering URI, e.g. tls://host:443
	directHost string // host:port for the out-of-band TCP probe
	serverKey  ed25519.PublicKey
	maxLatency time.Duration
	checkEvery time.Duration
	log        *log.Logger
}

// newFailoverMonitor validates the direct URI and builds the monitor.
// Returns nil if failover is not applicable (no direct endpoint).
func newFailoverMonitor(node *Node, directURI string, serverKey ed25519.PublicKey,
	latencyMs, checkSec int, logger *log.Logger) *failoverMonitor {
	if directURI == "" || len(serverKey) != ed25519.PublicKeySize {
		return nil
	}
	u, err := url.Parse(directURI)
	if err != nil || u.Host == "" {
		return nil
	}
	if latencyMs <= 0 {
		latencyMs = defaultFailoverLatencyMs
	}
	if checkSec <= 0 {
		checkSec = defaultFailoverCheckSec
	}
	return &failoverMonitor{
		node:       node,
		directURI:  directURI,
		directHost: u.Host,
		serverKey:  serverKey,
		maxLatency: time.Duration(latencyMs) * time.Millisecond,
		checkEvery: time.Duration(checkSec) * time.Second,
		log:        logger,
	}
}

// Run blocks and performs the health-check loop.
func (m *failoverMonitor) Run() {
	state := failoverStateDirect
	bad, good := 0, 0
	m.log.Infof("failover monitor: enabled, direct=%s, latency threshold %s, check every %s",
		m.directURI, m.maxLatency, m.checkEvery)
	ticker := time.NewTicker(m.checkEvery)
	defer ticker.Stop()
	for range ticker.C {
		switch state {
		case failoverStateDirect:
			lat, up := m.directLinkLatency()
			if up && lat <= m.maxLatency {
				bad = 0
				continue
			}
			bad++
			if !up {
				m.log.Warnf("failover: direct link is down (%d/%d)", bad, failoverDegradeLimit)
			} else {
				m.log.Warnf("failover: direct link degraded, latency %s > %s (%d/%d)",
					lat.Truncate(time.Millisecond), m.maxLatency, bad, failoverDegradeLimit)
			}
			if bad >= failoverDegradeLimit {
				if err := m.node.RemovePeer(m.directURI); err != nil {
					m.log.Warnf("failover: failed to remove direct peering: %s", err)
					continue
				}
				state = failoverStateMesh
				good = 0
				m.log.Warnln("failover: direct link disconnected, traffic goes through mesh peers")
			}
		case failoverStateMesh:
			d, ok := m.probeDirect()
			if ok {
				good++
				m.log.Infof("failover: direct endpoint reachable, connect %s (%d/%d)",
					d.Truncate(time.Millisecond), good, failoverRecoverLimit)
			} else {
				good = 0
			}
			if good >= failoverRecoverLimit {
				if err := m.node.AddPeer(m.directURI); err != nil {
					m.log.Warnf("failover: failed to restore direct peering: %s", err)
					continue
				}
				state = failoverStateDirect
				bad = 0
				m.log.Infoln("failover: direct link restored")
			}
		}
	}
}

// directLinkLatency returns the measured latency of the direct link to the
// server (identified by its node key) and whether the link is up.
func (m *failoverMonitor) directLinkLatency() (time.Duration, bool) {
	for _, p := range m.node.Peers() {
		if p.Up && p.Key.Equal(m.serverKey) {
			return p.Latency, true
		}
	}
	return 0, false
}

// probeDirect makes an out-of-band TCP connect to the server endpoint.
// It deliberately bypasses yggdrasil so that the probe measures the raw
// reachability of the direct endpoint, not the current mesh route.
func (m *failoverMonitor) probeDirect() (time.Duration, bool) {
	host := m.directHost
	if strings.HasPrefix(host, "[") { // keep IPv6 literals intact for DialTimeout
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = net.JoinHostPort(h, portOf(m.directHost))
		}
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", host, failoverProbeTimeout)
	if err != nil {
		return 0, false
	}
	_ = conn.Close()
	return time.Since(start), true
}

// portOf extracts the port from a host:port string.
func portOf(hostport string) string {
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	return port
}
