package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gologme/log"
)

// startStatusLogger periodically logs yggdrasil peering status: connected
// peers with their latency/cost/throughput and, on the client, the current
// route to the server node. interval <= 0 disables logging.
func startStatusLogger(n *Node, serverKey ed25519.PublicKey, interval time.Duration, logger *log.Logger) {
	startStatusLoggerTun(n, serverKey, interval, nil, nil, nil, logger)
}

// startStatusLoggerTun is like startStatusLogger but also reports end-to-end
// tunnel traffic counters (rx = from server to local apps, tx = to server)
// and, when tunnelPath is non-nil, which channel the tunnel currently uses.
func startStatusLoggerTun(n *Node, serverKey ed25519.PublicKey, interval time.Duration,
	tunRx, tunTx *tunnelCounters, tunnelPath func() string, logger *log.Logger) {
	if interval <= 0 {
		return
	}
	sl := &statusLogger{
		n:          n,
		serverKey:  serverKey,
		tunRx:      tunRx,
		tunTx:      tunTx,
		tunnelPath: tunnelPath,
		logger:     logger,
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			sl.report()
		}
	}()
}

// statusLogger holds the state needed to estimate mesh transit traffic
// between status reports.
type statusLogger struct {
	n            *Node
	serverKey    ed25519.PublicKey
	tunRx, tunTx *tunnelCounters
	tunnelPath   func() string
	logger       *log.Logger

	prevLink    uint64 // cumulative link bytes at the previous report
	prevSession uint64 // cumulative session bytes at the previous report
	started     bool
}

// report writes one status report to the log.
func (s *statusLogger) report() {
	var up []string
	var linkBytes uint64
	for _, p := range s.n.Peers() {
		if !p.Up {
			continue
		}
		linkBytes += p.RXBytes + p.TXBytes
		line := fmt.Sprintf("%s latency=%s cost=%d rx=%s tx=%s",
			p.URI, peerLatency(p.Latency), p.Cost, formatBytes(p.RXBytes), formatBytes(p.TXBytes))
		if len(p.Key) == ed25519.PublicKeySize {
			line += fmt.Sprintf(" key=%s", shortKey(p.Key))
		}
		up = append(up, line)
	}
	if len(up) == 0 {
		s.logger.Infoln("status: no connected peers")
		s.started = false
		return
	}
	s.logger.Infof("status: %d peer(s) up", len(up))
	for _, line := range up {
		s.logger.Infoln("  peer:", line)
	}
	s.reportTransit(linkBytes)

	if len(s.serverKey) != ed25519.PublicKeySize {
		return // server mode: no single route to report
	}

	// End-to-end tunnel traffic (the actual payload, not link protocol).
	if s.tunRx != nil && s.tunTx != nil {
		s.logger.Infof("tunnel traffic: rx=%s tx=%s (end-to-end payload)",
			formatBytes(atomic.LoadUint64(&s.tunRx.rx)), formatBytes(atomic.LoadUint64(&s.tunTx.tx)))
	}

	// The actual route to the server, in plain words. In direct mode the
	// tunnel channel (h3/QUIC vs h2/mesh) is reported first, in browser
	// Alt-Svc terms.
	if s.tunnelPath != nil {
		s.logger.Infoln("tunnel path:", s.tunnelPath())
	}
	if s.n.IsPeerOf(s.serverKey) {
		var uri string
		var latency time.Duration
		for _, p := range s.n.Peers() {
			if p.Up && p.Key.Equal(s.serverKey) {
				uri, latency = p.URI, p.Latency
				break
			}
		}
		s.logger.Infof("traffic to server: DIRECT link %s (latency %s)",
			uri, peerLatency(latency))
	} else {
		parentKey, ok := s.n.TreeParent()
		if !ok {
			s.logger.Infoln("traffic to server: via MESH (tree parent unknown)")
			return
		}
		parentURI, parentLatency := "unknown", time.Duration(0)
		for _, p := range s.n.Peers() {
			if p.Up && p.Key.Equal(parentKey) {
				parentURI, parentLatency = p.URI, p.Latency
				break
			}
		}
		hops := "unknown"
		if coords, ok := s.n.PathCoords(s.serverKey); ok {
			hops = fmt.Sprint(len(coords) + 1)
		}
		s.logger.Infof("traffic to server: via MESH, first hop %s (latency %s), ~%s hop(s) total",
			parentURI, peerLatency(parentLatency), hops)
	}
}

// transitThreshold is the minimum estimated transit volume per report
// interval before it is logged: below it the difference between link and
// session traffic is protocol overhead and measurement noise.
const transitThreshold = 1 << 20 // 1 MiB

// reportTransit estimates how much third-party (transit) traffic crossed
// the node since the previous report. Yggdrasil/ironwood forwards transit
// unconditionally and offers no switch to disable it, but transit packets
// never create end-to-end sessions - so the difference between the link
// counters (everything on the peerings) and the session counters (only
// traffic addressed to/from this node) approximates the transit volume.
// A significant estimate means the node is being used as a relay: trimming
// the public peer list is the only practical way to reduce it.
func (s *statusLogger) reportTransit(linkBytes uint64) {
	var sessionBytes uint64
	for _, ses := range s.n.Sessions() {
		sessionBytes += ses.RXBytes + ses.TXBytes
	}
	if !s.started {
		s.prevLink, s.prevSession, s.started = linkBytes, sessionBytes, true
		return
	}
	dLink := int64(linkBytes) - int64(s.prevLink)
	dSession := int64(sessionBytes) - int64(s.prevSession)
	s.prevLink, s.prevSession = linkBytes, sessionBytes
	if dLink <= 0 || dSession < 0 {
		return // counters reset or nothing moved
	}
	transit := dLink - dSession
	// Link traffic carries per-packet crypto/protocol overhead (~10%),
	// so only report clear excess.
	if transit > transitThreshold && transit > dLink/5 {
		s.logger.Warnf("mesh transit: ~%s of third-party traffic relayed in the last interval (%.0f%% of link traffic) - "+
			"yggdrasil relays transit by design; trimming the peers list reduces it",
			formatBytes(uint64(transit)), 100*float64(transit)/float64(dLink))
	}
}

func peerLatency(d time.Duration) string {
	if d <= 0 {
		return "measuring"
	}
	return d.Truncate(time.Millisecond).String()
}

// shortKey returns the first 8 bytes of a key in hex.
func shortKey(k []byte) string {
	if len(k) > 8 {
		k = k[:8]
	}
	return hex.EncodeToString(k)
}

// trimCoords formats path coordinates compactly.
func trimCoords(coords []uint64) string {
	parts := make([]string, len(coords))
	for i, c := range coords {
		parts[i] = fmt.Sprint(c)
	}
	return strings.Join(parts, " ")
}

// formatBytes renders a byte count in human-readable form.
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
