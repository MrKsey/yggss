package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gologme/log"
	"github.com/quic-go/quic-go"
)

// Direct mode: the QUIC tunnel runs over a plain UDP socket between the
// client and the server public endpoint, bypassing the yggdrasil packet
// session entirely. The yggdrasil TLS link (TCP) keeps running in parallel
// for mesh connectivity and failover.
//
// Compared to mesh mode this removes one crypto layer and all intermediate
// packet copies, which is several times faster on typical VPS hardware.
// Security is unchanged: the QUIC handshake uses the same self-signed node
// certificate, ALPN and key pinning as mesh mode.
//
// DPI profile mimics the browser Alt-Svc (h2 -> h3) upgrade pattern:
//   - the TLS-over-TCP link (the "h2" phase) always carries traffic first;
//   - the QUIC/UDP path (the "h3" phase) is only used after a background
//     prober has verified it, while the TCP channel stays alive in
//     parallel - exactly how a browser races QUIC against a live h2
//     connection after receiving the Alt-Svc hint;
//   - when verification fails, new streams instantly return to the TCP
//     channel (browser fallback), and the prober keeps re-testing in the
//     background. UDP never exists without a live TCP session alongside.

// quicConn is the subset of *quic.Conn used by the tunnel code. Keeping the
// field as an interface lets tests inject a controllable fake connection.
type quicConn interface {
	Context() context.Context
	OpenStreamSync(ctx context.Context) (*quic.Stream, error)
	CloseWithError(code quic.ApplicationErrorCode, reason string) error
}

// directFallbackCooldown is the default interval between direct-path
// re-verification probes, used when direct_retry_sec is not configured.
const directFallbackCooldown = 30 * time.Second

// parseHostPort splits "host:port" or a URI "tls://host:port" into host and
// numeric port.
func parseHostPort(s string) (string, int, error) {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
		if j := strings.IndexAny(s, "/?"); j >= 0 {
			s = s[:j]
		}
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid address %q: %w", s, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in %q: %w", s, err)
	}
	return host, port, nil
}

// resolveUDP resolves host to an IP for the UDP address.
func resolveUDP(host string, port int) (*net.UDPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("cannot resolve %q", host)
	}
	// Prefer IPv6 when available (matches typical yggdrasil endpoints).
	for _, ip := range ips {
		if ip.To4() == nil {
			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}

// startDirectServer starts the UDP QUIC listener for direct mode. bind is
// the link listen address (e.g. "tls://[::]:443" or "[::]:443"); the UDP
// port is derived from it. dst is the shadowsocks server address.
func startDirectServer(node *Node, bind, dst string, allowed map[string]struct{}, logger *log.Logger) error {
	ln, _, err := startDirectListener(node, bind, allowed, logger)
	if err != nil {
		return err
	}
	go func() {
		for {
			qconn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go serveDirectConn(qconn, dst, logger)
		}
	}()
	return nil
}

// startDirectListener opens the UDP QUIC listener and returns it together
// with the local UDP address it is bound to.
func startDirectListener(node *Node, bind string, allowed map[string]struct{},
	logger *log.Logger) (*quic.Listener, *net.UDPAddr, error) {
	host, port, err := parseHostPort(bind)
	if err != nil {
		return nil, nil, err
	}
	// Match the listener family to the bind address: a plain IPv4 bind
	// gets an IPv4 listener, everything else gets a dual-stack one.
	laddr := &net.UDPAddr{IP: net.IPv6unspecified, Port: port}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		laddr.IP = net.IPv4zero
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on udp %d: %w", port, err)
	}
	tr := &quic.Transport{Conn: conn}
	// Chrome-like parameters on the server side too (the server's transport
	// parameters are visible in its handshake response).
	ql, err := tr.Listen(directServerTLS(node, allowed), chromeTransportParams())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start direct QUIC listener: %w", err)
	}
	logger.Infof("direct tunnel: QUIC listener on udp/%d", port)
	return ql, conn.LocalAddr().(*net.UDPAddr), nil
}

// serveDirectConn accepts streams on an incoming direct QUIC connection and
// forwards each stream to dst. Liveness probes (probePing) are echoed back
// here and never reach dst.
func serveDirectConn(qconn *quic.Conn, dst string, logger *log.Logger) {
	defer qconn.CloseWithError(0, "")
	for {
		stream, err := qconn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(stream *quic.Stream) {
			defer stream.Close()
			handled, consumed := handleProbeStream(stream)
			if handled {
				return
			}
			upstream, err := net.DialTimeout("tcp", dst, 10*time.Second)
			if err != nil {
				logger.Warnf("direct: failed to connect to %s: %s", dst, err)
				return
			}
			defer upstream.Close()
			var src io.ReadWriteCloser = stream
			if len(consumed) > 0 {
				src = streamWithPrefix{io.MultiReader(bytes.NewReader(consumed), stream), stream}
			}
			pipe(src, upstream, nil, nil)
		}(stream)
	}
}

// directServerTLS builds the TLS config for the direct QUIC tunnel: same
// certificate and ALPN as mesh mode, with the optional client key whitelist.
func directServerTLS(node *Node, allowed map[string]struct{}) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*node.Certificate()},
		NextProtos:   []string{alpn},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(allowed) == 0 {
				return nil // any node with the group password may connect
			}
			if len(rawCerts) == 0 {
				return errors.New("client sent no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pk, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("client certificate key must be ed25519")
			}
			if _, ok := allowed[string(pk)]; !ok {
				return errors.New("client public key is not allowed")
			}
			return nil
		},
	}
}

// directDialTimeout caps how long a direct dial may take before falling
// back to the mesh. When UDP is silently dropped (DPI/firewall), the dial
// would otherwise block for the full tunnel timeout on every cooldown
// expiry, stalling new connections.
const directDialTimeout = 5 * time.Second

// directDial dials the server UDP endpoint from the client side. serverAddr
// is the public endpoint of the server (the same host:port as the direct
// link). fakeSNI, when non-empty, is advertised in the QUIC ClientHello so
// the handshake looks like a browser HTTP/3 connection. Returns the
// established QUIC connection. The dial timeout is capped at
// directDialTimeout unless configured shorter.
//
// Convenience wrapper for tests and diagnostics: the underlying transport is
// not returned, so this leaks one UDP socket per call. Production code must
// use directDialTransport.
func directDial(node *Node, serverKey ed25519.PublicKey, serverAddr string,
	timeout time.Duration, fakeSNI string) (*quic.Conn, error) {
	qconn, _, err := directDialTransport(node, serverKey, serverAddr, timeout, fakeSNI)
	return qconn, err
}

// directDialTransport is directDial plus the owning transport: the caller
// must keep the transport alive while the connection is used and Close it
// afterwards, otherwise every dial leaks a UDP socket and its goroutines.
func directDialTransport(node *Node, serverKey ed25519.PublicKey, serverAddr string,
	timeout time.Duration, fakeSNI string) (*quic.Conn, *quic.Transport, error) {
	if timeout <= 0 || timeout > directDialTimeout {
		timeout = directDialTimeout
	}
	host, port, err := parseHostPort(serverAddr)
	if err != nil {
		return nil, nil, err
	}
	raddr, err := resolveUDP(host, port)
	if err != nil {
		return nil, nil, err
	}
	// The local socket must match the address family of the server:
	// sending IPv4 packets from an IPv6-bound socket fails on Windows.
	var laddr *net.UDPAddr
	if raddr.IP.To4() != nil {
		laddr = &net.UDPAddr{IP: net.IPv4zero}
	} else {
		laddr = &net.UDPAddr{IP: net.IPv6unspecified}
	}
	udpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, nil, err
	}
	tr := &quic.Transport{Conn: udpConn}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // identity is pinned manually below
		NextProtos:         []string{alpn},
		Certificates:       []tls.Certificate{*node.Certificate()},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server sent no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pk, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok || !pk.Equal(serverKey) {
				return errors.New("server public key mismatch")
			}
			return nil
		},
	}
	// The SNI is visible to DPI inside the QUIC Initial packet; a fake
	// domain makes the ClientHello look like a browser h3 connection.
	if fakeSNI != "" {
		tlsCfg.ServerName = fakeSNI
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Chrome-like transport parameters: the direct tunnel's handshake must
	// not stand out against real browser h3 traffic.
	qconn, err := tr.Dial(ctx, raddr, tlsCfg, chromeTransportParams())
	if err != nil {
		_ = tr.Close()
		return nil, nil, fmt.Errorf("direct dial failed: %w", err)
	}
	return qconn, tr, nil
}

// directClient wraps a direct QUIC connection for the client side: it hands
// out streams and reconnects transparently when the connection dies.
//
// Verification follows the Alt-Svc model: user traffic never waits for the
// direct path. The mesh channel serves connections immediately, while a
// background prober "discovers" the fast path, caches it for a TTL
// (MarkVerified) and re-confirms it periodically. Failed verification
// clears the cache (MarkFailed) and traffic stays on the mesh.
type directClient struct {
	node        *Node
	serverKey   ed25519.PublicKey
	serverAddr  string
	timeout     time.Duration
	retryPeriod time.Duration // re-verification interval while verified
	fakeSNI     string        // SNI advertised in the QUIC ClientHello
	log         *log.Logger

	mu    sync.Mutex
	tr    *quic.Transport // transport owning qconn; closed together with it
	qconn quicConn        // interface: real *quic.Conn in production, fake in tests

	// failUntil is a short cooldown after a failed dial or a dead
	// connection: openStream calls arriving during it fail immediately
	// instead of stampeding into serialized 5s dials.
	failUntil time.Time

	// owner is the client this directClient serves (set by startProber);
	// used to update the Alt-Svc status state on asynchronous events.
	owner *client

	// probeRTT is the EWMA of successful probe round-trip times; a sharp
	// rise above the derived threshold means the path degrades.
	probeRTT time.Duration

	verifyMu      sync.Mutex
	verifiedUntil time.Time

	probeMu     sync.Mutex
	probeStop   chan struct{}
	probeActive bool
}

// IsVerified reports whether the direct path is currently trusted (the
// Alt-Svc cache is fresh). User streams go direct only when this is true.
func (d *directClient) IsVerified() bool {
	d.verifyMu.Lock()
	defer d.verifyMu.Unlock()
	return time.Now().Before(d.verifiedUntil)
}

// MarkVerified caches the direct path as usable for the given TTL.
func (d *directClient) MarkVerified(ttl time.Duration) {
	d.verifyMu.Lock()
	d.verifiedUntil = time.Now().Add(ttl)
	d.verifyMu.Unlock()
}

// MarkFailed clears the Alt-Svc cache: user traffic returns to the mesh
// until the prober re-verifies the direct path.
func (d *directClient) MarkFailed() {
	d.verifyMu.Lock()
	d.verifiedUntil = time.Time{}
	d.verifyMu.Unlock()
}

// verifyTTL is how long a successful probe keeps the direct path trusted.
func (d *directClient) verifyTTL() time.Duration {
	if d.retryPeriod > 0 {
		return 2 * d.retryPeriod
	}
	return 2 * directFallbackCooldown
}

// probeIntervalWhileUnverified is how often the prober retries while the
// direct path is not yet (or no longer) verified.
const probeIntervalWhileUnverified = 5 * time.Second

// directFailCooldown is how long openStream refuses to dial after a failed
// dial or a dead connection: instead of every caller serially paying the
// full dial timeout, the first failure cools the path down and the rest
// fall through to mesh instantly.
const directFailCooldown = 2 * time.Second

// probeFailStreakLimit is the number of consecutive failed probes on a
// living connection before the path is declared degraded. A single lost
// probe packet is not critical (QUIC retransmits); a streak means real
// loss growth.
const probeFailStreakLimit = 2

// errDirectCooldown is returned by openStream while the path is cooling
// down after a failure; callers fall through to mesh on it.
var errDirectCooldown = errors.New("direct path cooling down after failure")

// directPathState describes the current channel selection for status logs.
type directPathState int

const (
	pathMeshOnly     directPathState = iota // mesh, direct never verified
	pathH2H3                                // mesh link + verified direct (h2+h3 race)
	pathMeshProbing                         // mesh, direct being probed
	pathMeshFallback                        // mesh after a verified direct failed
)

// String renders the state for the status log, in browser Alt-Svc terms.
func (s directPathState) String() string {
	switch s {
	case pathH2H3:
		return "h2+h3 (direct verified)"
	case pathMeshProbing:
		return "h2 (probing h3)"
	case pathMeshFallback:
		return "h2 (h3 failed, probing)"
	default:
		return "h2"
	}
}

// PathState reports the current channel state for the status logger.
func (c *client) PathState() directPathState {
	if c.direct == nil {
		return pathMeshOnly
	}
	if c.direct.IsVerified() {
		return pathH2H3
	}
	c.probeStateMu.Lock()
	defer c.probeStateMu.Unlock()
	return c.probeState
}

// connAlive reports whether the current direct connection exists and has
// not been closed (by us, by the peer, or by an idle timeout).
func (d *directClient) connAlive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connAliveLocked()
}

// connAliveLocked is connAlive without locking (d.mu must be held).
func (d *directClient) connAliveLocked() bool {
	if d.qconn == nil {
		return false
	}
	select {
	case <-d.qconn.Context().Done():
		return false
	default:
		return true
	}
}

// dropConnLocked closes and forgets the current connection together with
// its transport (d.mu must be held). Only call this for dead connections:
// closing kills every stream running on the connection.
func (d *directClient) dropConnLocked() {
	if d.qconn != nil {
		_ = d.qconn.CloseWithError(0, "reset")
	}
	if d.tr != nil {
		_ = d.tr.Close()
	}
	d.qconn = nil
	d.tr = nil
}

// dropAndFail kills the current connection (if any) and clears the Alt-Svc
// cache: new streams go to mesh, existing streams on the killed connection
// error out immediately so their applications reconnect - over mesh, since
// the direct path is now unverified. This is the fast-switch primitive:
// it turns "direct path went bad" into an instant, visible cutover instead
// of waiting for QUIC's own timeouts.
func (d *directClient) dropAndFail(reason string) {
	d.mu.Lock()
	d.dropConnLocked()
	d.failUntil = time.Now().Add(directFailCooldown)
	d.mu.Unlock()
	d.MarkFailed()
	if d.owner != nil {
		d.owner.setProbeState(pathMeshFallback)
	}
	if reason != "" {
		d.log.Warnf("tunnel: h3 path failed (%s) - downgrading to h2, existing streams reconnect via mesh", reason)
	}
}

// watchConn waits for the connection to close (by the peer, by us, or by
// QUIC's own timeout) and, if it is still the current connection, performs
// the fast cutover: drop + MarkFailed + cooldown. Without it, streams on a
// silently dead connection would hang until QUIC's idle timeout (up to two
// minutes) instead of reconnecting over mesh right away.
func (d *directClient) watchConn(qconn *quic.Conn) {
	<-qconn.Context().Done()
	d.mu.Lock()
	current := d.qconn == qconn
	if current {
		d.dropConnLocked()
		d.failUntil = time.Now().Add(directFailCooldown)
	}
	d.mu.Unlock()
	if current {
		d.MarkFailed()
		if d.owner != nil {
			d.owner.setProbeState(pathMeshFallback)
		}
		d.log.Warnln("tunnel: h3 connection closed - downgrading to h2, streams reconnect via mesh")
	}
}

// probeHealthy records a probe RTT and reports whether the path looks
// healthy. The first successful probe establishes the baseline; afterwards
// a sharp rise (more than 3x the EWMA, at least 1s) means packet loss is
// growing - the retransmission-driven delay is exactly what a loss spike
// looks like from the outside.
func (d *directClient) probeHealthy(rtt time.Duration) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.probeRTT <= 0 {
		d.probeRTT = rtt
		return true
	}
	threshold := 3 * d.probeRTT
	if threshold < time.Second {
		threshold = time.Second
	}
	if rtt > threshold {
		return false
	}
	// EWMA update only on healthy probes: a degraded sample must not
	// drag the baseline up and hide further degradation.
	d.probeRTT = time.Duration(0.7*float64(d.probeRTT) + 0.3*float64(rtt))
	return true
}

// openStream returns a QUIC stream to the server, reusing the existing
// connection when possible and redialing otherwise. Dials are serialised:
// a caller that finds a dead connection dials under the lock, so only one
// redial happens at a time and nobody closes a connection with live
// streams. The lock is held only for the dial, not for stream opens on a
// healthy connection - concurrent streams on a working path never queue.
//
// Error handling distinguishes a dead connection from a transient failure:
// a dead connection is dropped and redialed, while a transient error (a
// burst of packet loss, the peer stream limit reached for a moment) is
// reported as-is. Killing the connection on a transient error would take
// down every healthy stream multiplexed on it.
func (d *directClient) openStream() (*quic.Stream, error) {
	d.mu.Lock()
	if time.Now().Before(d.failUntil) {
		d.mu.Unlock()
		return nil, errDirectCooldown
	}
	if d.node == nil {
		// Test-only configuration: no node, so dialing is impossible.
		// Behave like a failed dial: cool the path down and fail fast.
		d.failUntil = time.Now().Add(directFailCooldown)
		d.mu.Unlock()
		return nil, errors.New("direct: no node configured (test)")
	}
	if !d.connAliveLocked() {
		d.dropConnLocked()
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		stream, err := d.qconn.OpenStreamSync(ctx)
		cancel()
		if err == nil {
			d.mu.Unlock()
			return stream, nil
		}
		if d.connAliveLocked() {
			// Transient failure on a living connection: report it, keep
			// the connection and its healthy streams untouched.
			d.mu.Unlock()
			return nil, err
		}
		// The connection died while we were waiting: drop and redial.
		d.dropConnLocked()
	}

	// Redial under the lock. directDial is capped at directDialTimeout,
	// so worst case concurrent callers wait that long for a healthy new
	// connection instead of racing and killing each other's streams.
	qconn, tr, err := directDialTransport(d.node, d.serverKey, d.serverAddr, d.timeout, d.fakeSNI)
	if err != nil {
		// Dial failed: cool the path down so the callers already waiting
		// on the lock fall through to mesh instead of re-dialing one by
		// one, each for the full dial timeout.
		d.failUntil = time.Now().Add(directFailCooldown)
		d.mu.Unlock()
		d.MarkFailed()
		if d.owner != nil {
			d.owner.setProbeState(pathMeshFallback)
		}
		return nil, err
	}
	d.qconn = qconn
	d.tr = tr
	d.mu.Unlock()

	// Fast cutover when this connection dies later (peer restart, network
	// change): kill it, mark failed, let streams reconnect via mesh.
	go d.watchConn(qconn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return qconn.OpenStreamSync(ctx)
}

// Close shuts down the direct tunnel and stops the background prober.
func (d *directClient) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dropConnLocked()
	d.stopProber()
	return nil
}

// probeIdleLimit is how long the tunnel may stay completely idle before the
// prober stops poking the direct path: a browser does not keep testing h3
// while the user is away, so probes only make sense around real activity.
const probeIdleLimit = 10 * time.Minute

// startProber launches the background Alt-Svc-style prober. While the direct
// path is unverified it opens a short QUIC session every few seconds (the
// browser "background check"); once verified it re-confirms the path every
// retryPeriod and keeps the Alt-Svc cache fresh. The prober only runs while
// the mesh channel is active AND the tunnel has seen recent activity, so
// UDP traffic never appears without a parallel TCP session and never
// continues long after the user went idle - matching the h2->h3 upgrade
// pattern.
func (d *directClient) startProber(client *client) {
	d.probeMu.Lock()
	defer d.probeMu.Unlock()
	if d.probeActive {
		return
	}
	if d.retryPeriod <= 0 {
		d.retryPeriod = directFallbackCooldown
	}
	d.owner = client
	d.probeStop = make(chan struct{})
	d.probeActive = true
	stop := d.probeStop
	go func() {
		// First probe shortly after startup: if UDP works, the fast path is
		// advertised almost immediately (the "Alt-Svc hint").
		//
		// The one-shot timer is tracked via its channel, not the *time.Timer
		// pointer: select evaluates the channel expressions of all cases, so
		// nil-ing the timer itself would dereference nil on the next loop.
		// Receiving from a nil channel is safe (that case just never fires).
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		var timerC <-chan time.Time = timer.C
		unverifiedTicker := time.NewTicker(probeIntervalWhileUnverified)
		defer unverifiedTicker.Stop()
		verifiedTicker := time.NewTicker(d.retryPeriod)
		defer verifiedTicker.Stop()
		// Exactly one cadence is enabled at a time: fast re-probing while
		// the path is unverified, slow re-confirmation while it is verified.
		// (Both tickers used to fire unconditionally, probing the path every
		// few seconds even when verified.)
		var unverifiedC <-chan time.Time = unverifiedTicker.C
		var verifiedC <-chan time.Time
		failStreak := 0
		for {
			select {
			case <-stop:
				return
			case <-timerC:
				timerC = nil
			case <-unverifiedC:
			case <-verifiedC:
			}
			// The probe runs only on top of an active mesh session: the
			// TLS link (h2 phase) must be alive for the h3 check to look
			// like a browser upgrade race.
			if !client.meshActive() {
				continue
			}
			// Skip probes while the tunnel is idle: a browser would not
			// race h3 against h2 with no user activity.
			if time.Since(client.lastActivity()) > probeIdleLimit {
				// Long idle: drop the h3 cache, traffic will re-verify on
				// the next burst of connections.
				if d.IsVerified() {
					d.MarkFailed()
					client.setProbeState(pathMeshProbing)
					d.log.Infoln("tunnel: idle, h3 cache dropped - will re-verify on next activity")
					unverifiedC = unverifiedTicker.C
					verifiedC = nil
				}
				continue
			}
			wasVerified := d.IsVerified()
			// Sync a stale display state: the verified cache may have
			// expired between probes while the path is actually dead.
			if !wasVerified && client.PathState() == pathH2H3 {
				client.setProbeState(pathMeshProbing)
			}
			start := time.Now()
			stream, err := d.openStream()
			if err != nil {
				if err == errDirectCooldown {
					continue // another caller just failed; mesh is serving
				}
				if d.connAlive() {
					// Living connection, transient error (lost probe
					// packet or a momentary stall). A single failure is
					// not critical - QUIC retransmits; a streak means
					// packet loss is growing and the path must yield to
					// mesh.
					failStreak++
					if wasVerified && failStreak >= probeFailStreakLimit {
						d.dropAndFail(fmt.Sprintf("%d consecutive probe errors: %v", failStreak, err))
					}
					continue
				}
				// The connection is gone: fast cutover to mesh (dropAndFail
				// also kills any streams still riding the dead connection,
				// so their applications reconnect over mesh right away).
				d.dropAndFail("")
				failStreak = 0
				unverifiedC = unverifiedTicker.C
				verifiedC = nil
				continue
			}
			// End-to-end round trip: the path is only verified when data
			// actually comes back. Stream opens are local operations in
			// QUIC and succeed even on a black-holed path (NAT rebinding,
			// firewall starting to drop UDP), so open+close alone would
			// keep a dead path "verified" forever while user streams
			// silently hang in it.
			deadline := time.Now().Add(3 * time.Second)
			_ = stream.SetDeadline(deadline)
			if _, werr := stream.Write(probePing); werr == nil {
				echo := make([]byte, len(probePing))
				_, rerr := io.ReadFull(stream, echo)
				if rerr == nil && !bytes.Equal(echo, probePing) {
					rerr = errors.New("probe echo mismatch")
				}
				err = rerr
			} else {
				err = werr
			}
			_ = stream.Close()
			if err != nil {
				// The write/read round trip failed: the path does not
				// carry data. Treat exactly like a failed open below -
				// drop the dead connection and yield to mesh.
				//
				// The streak limit is checked regardless of wasVerified:
				// the verified cache may expire (its TTL is short) before
				// two 3s-timeout probes complete, and dropping a dead
				// connection is correct in the unverified probing phase
				// too - the next dial starts fresh.
				if d.connAlive() {
					failStreak++
					if failStreak >= probeFailStreakLimit {
						d.dropAndFail(fmt.Sprintf("probe round trip failed: %v", err))
					}
				} else {
					d.dropAndFail("")
					failStreak = 0
					unverifiedC = unverifiedTicker.C
					verifiedC = nil
				}
				continue
			}
			elapsed := time.Since(start)
			failStreak = 0
			if !d.probeHealthy(elapsed) {
				// The path answers, but sharply slower than its own
				// baseline - that is what growing packet loss looks like.
				// Yield to mesh; the fast cadence keeps checking and the
				// path is upgraded back as soon as probes come clean.
				if wasVerified {
					d.dropAndFail(fmt.Sprintf("probe rtt %s exceeds degradation threshold", elapsed.Truncate(time.Millisecond)))
				}
				continue
			}
			d.MarkVerified(d.verifyTTL())
			client.setProbeState(pathH2H3)
			if !wasVerified {
				d.log.Infof("tunnel: h3 path verified in %s - new streams upgrade to QUIC",
					elapsed.Truncate(time.Millisecond))
			}
			if timerC != nil { // stop the one-shot startup timer
				timer.Stop()
				timerC = nil
			}
			// Verified: probe on the slow cadence only.
			unverifiedC = nil
			verifiedTicker.Reset(d.retryPeriod)
			verifiedC = verifiedTicker.C
		}
	}()
}

// stopProber halts the background prober (idempotent).
func (d *directClient) stopProber() {
	if d.probeStop != nil {
		close(d.probeStop)
		d.probeStop = nil
		d.probeActive = false
	}
}
