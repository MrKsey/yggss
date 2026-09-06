package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Arceliar/ironwood/types"
	"github.com/gologme/log"
	"github.com/quic-go/quic-go"
)

// alpn is the application protocol negotiated inside the QUIC handshake.
// It deliberately uses the standard HTTP/3 identifier: the ALPN is visible
// to DPI (the QUIC Initial packet is encrypted with a well-known key), and
// "h3" makes the direct tunnel indistinguishable from browser HTTP/3
// traffic. Both sides must use the same value.
const alpn = "h3"

// quicSNI returns the SNI to advertise in the QUIC ClientHello. The fake
// domain (the sni option) makes the handshake look like a real browser
// connection; without it no SNI is sent.
func quicSNI(fake string) string {
	return fake
}

// quicConfig returns the QUIC settings for the mesh tunnel (inside the
// yggdrasil session, invisible to DPI, so no browser mimicry needed). Long
// timeouts give slow routers (MIPS/ARM, e.g. Keenetic with entware) enough
// time for the yggdrasil session setup before the QUIC handshake.
func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:  30 * time.Second,
		MaxIdleTimeout:        2 * time.Minute,
		KeepAlivePeriod:       15 * time.Second,
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 1024,
	}
}

// chromeTransportParams mirrors the transport parameters Chrome advertises
// in its HTTP/3 ClientHello, so that the quic-go fingerprint of the direct
// tunnel does not stand out against real browser traffic:
//   - ~100 bidirectional / ~103 unidirectional stream limits (Chrome);
//   - initial packet size ~1350 (Chrome initial datagram size).
//
// Two deliberate deviations from the browser profile, both invisible to
// passive DPI (flow control windows are transport parameters, not frames,
// and Chrome's own values vary by platform):
//   - MaxIdleTimeout 2min instead of 30s: the tunnel reuses one connection
//     for many short-lived streams, and the verification probe fires only
//     every direct_retry_sec - a 30s idle timeout kills the connection in
//     exactly the quiet gap between probes, stranding streams opened into
//     the half-dead connection. Browsers create a fresh connection per
//     page load; a proxy tunnel cannot behave that way.
//   - KeepAlivePeriod 10s: keeps the connection alive through quiet
//     periods and detects a dead path within ~2 timeouts.
//   - Large receive windows (16MB stream / 32MB connection): the quic-go
//     defaults (512KB/6MB) throttle bulk downloads on paths with RTT
//     above ~50ms - 16MB over a 100ms RTT path caps at ~130 Mbit/s per
//     stream, comfortably above typical residential uplink speeds.
//   - Stream limits 1024 instead of Chrome's ~100/103: a proxy multiplexes
//     every proxied TCP connection over ONE QUIC connection, and a busy
//     browser easily exceeds 100 concurrent streams (6+ per host, dozens of
//     hosts, long-lived keep-alive connections). At Chrome's limit new
//     stream opens stall until a slot frees - visible as periodic tunnel
//     freezes. Like the flow-control windows, stream limits are transport
//     parameters, not frames, and browsers vary them across platforms; the
//     strong browser signals (ALPN h3, SNI, initial packet size) are kept.
//
// Parameters quic-go cannot customize (versions, grease) are already close
// to Chrome by default.
func chromeTransportParams() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       2 * time.Minute,
		KeepAlivePeriod:      10 * time.Second,

		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 1024,
		InitialPacketSize:     1350,

		InitialStreamReceiveWindow:     4 << 20,  // 4MB instead of the 512KB default
		MaxStreamReceiveWindow:         16 << 20, // 16MB instead of 6MB
		InitialConnectionReceiveWindow: 8 << 20,  // 8MB instead of 512KB
		MaxConnectionReceiveWindow:     32 << 20, // 32MB instead of 6MB
	}
}

// tunnelCounters tracks end-to-end tunnel traffic for status logging.
type tunnelCounters struct {
	rx uint64
	tx uint64
}

func (c *tunnelCounters) addRx(n int) {
	if n > 0 {
		atomic.AddUint64(&c.rx, uint64(n))
	}
}

func (c *tunnelCounters) addTx(n int) {
	if n > 0 {
		atomic.AddUint64(&c.tx, uint64(n))
	}
}

// pipeBufSize is the copy buffer for tunnel streams. QUIC streams perform
// best with large writes: small buffers fragment data into tiny QUIC
// packets and multiply syscall overhead.
const pipeBufSize = 256 * 1024

// pipe copies data between two endpoints in both directions until one of
// them reaches EOF or fails, then closes both. Traffic is counted when a
// non-nil counter is supplied.
func pipe(a, b io.ReadWriteCloser, rx, tx *tunnelCounters) {
	done := make(chan struct{}, 2)
	copyCount := func(dst io.Writer, src io.Reader, cnt *tunnelCounters) {
		buf := make([]byte, pipeBufSize)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if cnt != nil {
					cnt.addTx(n)
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go copyCount(a, b, rx)
	go copyCount(b, a, tx)
	<-done
	<-done
}

// server is the server side of the plugin: it accepts QUIC streams from the
// client node over the yggdrasil mesh and forwards each stream to the local
// shadowsocks server.
type server struct {
	node    *Node
	dst     string              // host:port of the shadowsocks server
	allowed map[string]struct{} // optional set of allowed client public keys
	log     *log.Logger
	rx, tx  tunnelCounters // end-to-end tunnel traffic counters
}

// Run starts the QUIC listener on top of the yggdrasil node and blocks.
func (s *server) Run() error {
	tr := &quic.Transport{Conn: s.node.PacketConn()}
	ql, err := tr.Listen(s.tlsConfig(), quicConfig())
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener: %w", err)
	}
	s.log.Infof("tunnel is up, forwarding to %s", s.dst)

	for {
		conn, err := ql.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *server) handleConn(conn *quic.Conn) {
	defer conn.CloseWithError(0, "")
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(stream)
	}
}

func (s *server) handleStream(stream *quic.Stream) {
	defer stream.Close()
	upstream, err := net.DialTimeout("tcp", s.dst, 10*time.Second)
	if err != nil {
		s.log.Warnf("failed to connect to %s: %s", s.dst, err)
		return
	}
	defer upstream.Close()
	pipe(stream, upstream, &s.rx, &s.tx)
}

func (s *server) tlsConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*s.node.Certificate()},
		NextProtos:   []string{alpn},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(s.allowed) == 0 {
				return nil // any yggdrasil node that finished the mesh handshake may connect
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
			if _, ok := s.allowed[string(pk)]; !ok {
				return errors.New("client public key is not allowed")
			}
			return nil
		},
	}
}

// client is the client side of the plugin: it listens for ss-local
// connections and forwards each one over a QUIC stream to the server node.
type client struct {
	node      *Node
	serverKey ed25519.PublicKey
	bind      string
	timeout   time.Duration
	log       *log.Logger
	rx, tx    tunnelCounters // end-to-end tunnel traffic counters

	// direct, when non-nil, routes streams over plain UDP to the server
	// endpoint instead of the yggdrasil packet session (direct mode).
	direct *directClient

	// probeState tracks the Alt-Svc-style channel state for status logs.
	probeStateMu sync.Mutex
	probeState   directPathState

	// lastActive tracks the most recent tunnel activity (a new stream or
	// traffic through one) so the direct prober can pause while idle.
	lastActive atomic.Int64 // unix nanoseconds
	mu         sync.Mutex
	tr         *quic.Transport
	qconn      *quic.Conn
}

// touchActivity records tunnel activity (called on every new stream).
func (c *client) touchActivity() {
	c.lastActive.Store(time.Now().UnixNano())
}

// lastActivity returns the time of the most recent tunnel activity.
func (c *client) lastActivity() time.Time {
	return time.Unix(0, c.lastActive.Load())
}

// setProbeState updates the channel state shown in the status log.
func (c *client) setProbeState(s directPathState) {
	c.probeStateMu.Lock()
	c.probeState = s
	c.probeStateMu.Unlock()
}

// meshActive reports whether the mesh channel is currently carrying traffic
// (or at least ready to). The direct prober uses this to keep the UDP path
// always accompanied by a live TCP session, mimicking the browser h2->h3
// upgrade race.
func (c *client) meshActive() bool {
	// The mesh QUIC connection is dialled lazily; the yggdrasil node is up
	// from startup, so the h2 channel is always available as long as the
	// process runs and the node has at least one peering.
	return c.node.ConnectedPeerCount() > 0
}

// Run starts the local TCP listener for ss-local and blocks.
func (c *client) Run() (net.Listener, error) {
	c.tr = &quic.Transport{Conn: c.node.PacketConn()}
	ln, err := net.Listen("tcp", c.bind)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", c.bind, err)
	}
	c.log.Infoln("listening on", c.bind)
	go c.acceptLoop(ln)
	return ln, nil
}

func (c *client) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go c.handle(conn)
	}
}

func (c *client) handle(conn net.Conn) {
	defer conn.Close()
	c.touchActivity()
	stream, err := c.openStream()
	if err != nil {
		c.log.Warnf("failed to open tunnel stream: %s", err)
		return
	}
	defer stream.Close()
	pipe(stream, conn, &c.rx, &c.tx)
}

// openStream returns a QUIC stream to the server, reusing the existing QUIC
// connection when possible and dialing a new one otherwise.
//
// Channel selection follows the browser Alt-Svc model: user traffic never
// waits for the direct path. When the h3 (direct UDP) path is verified, new
// streams race to it; on failure they instantly fall back to the h2 (mesh)
// channel without any timeout. When h3 is not verified, streams go straight
// to mesh - the background prober does the discovery.
func (c *client) openStream() (*quic.Stream, error) {
	// Direct mode: use the fast path only while it is verified.
	if c.direct != nil && c.direct.IsVerified() {
		stream, err := c.direct.openStream()
		if err == nil {
			return stream, nil
		}
		// Downgrade everyone to mesh only when the direct connection is
		// really gone. A transient error on a living connection (e.g. the
		// peer stream limit reached for a moment) must not tear down the
		// verified cache - this stream is simply served over mesh.
		if !c.direct.connAlive() {
			c.direct.MarkFailed()
			c.setProbeState(pathMeshFallback)
			c.log.Warnf("tunnel: h3 path failed (%v) - downgrading to h2", err)
		} else {
			c.log.Warnf("tunnel: h3 stream failed (%v) - serving this stream over h2", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.qconn != nil {
		// A mesh connection killed by the peer or by a link flap may still
		// accept local stream opens for a while - detect it up front,
		// otherwise every new stream blocks for the full OpenStreamSync
		// timeout while serializing all other callers on the lock.
		select {
		case <-c.qconn.Context().Done():
			_ = c.qconn.CloseWithError(0, "reset")
			c.qconn = nil
		default:
		}
	}
	if c.qconn != nil {
		stream, err := c.openStreamOn(c.qconn)
		if err == nil {
			return stream, nil
		}
		_ = c.qconn.CloseWithError(0, "reset")
		c.qconn = nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	qconn, err := c.tr.Dial(ctx, types.Addr(c.serverKey), c.tlsConfig(), quicConfig())
	if err != nil {
		return nil, fmt.Errorf(
			"failed to dial server over yggdrasil: %w (check that server_key is the server node's PUBLIC key hex from -genkey, not its yggdrasil address, and that the group password is identical on both sides)", err)
	}
	stream, err := c.openStreamOn(qconn)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, err
	}
	c.qconn = qconn
	return stream, nil
}

func (c *client) openStreamOn(qconn *quic.Conn) (*quic.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return qconn.OpenStreamSync(ctx)
}

func (c *client) tlsConfig() *tls.Config {
	return &tls.Config{
		// The server identity is pinned manually below, so chain
		// verification is intentionally disabled.
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
		Certificates:       []tls.Certificate{*c.node.Certificate()},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server sent no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pk, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok || !pk.Equal(c.serverKey) {
				return errors.New("server public key mismatch")
			}
			return nil
		},
	}
}
