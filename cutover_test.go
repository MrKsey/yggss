package main

// Live cutover fault-injection test: a controllable UDP proxy sits between
// the direct client and the direct server, so the UDP path can be broken
// and healed at will while real user streams are flowing. The mesh channel
// runs over a real yggdrasil TCP peering on loopback.
//
// Scenario (TestLiveCutover):
//
//  1. both channels up: streams flow over the verified direct path;
//  2. the UDP path goes black: within a few seconds the round-trip probe
//     detects it, the direct connection is killed and new streams flow
//     over mesh - without restarting anything;
//  3. the UDP path heals: probes verify it again and streams upgrade back
//     to direct;
//  4. both channels break: user streams fail fast with an error instead of
//     hanging forever;
//  5. both channels heal: traffic resumes.

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// udpFaultProxy forwards UDP datagrams between a client-facing socket and a
// server endpoint, silently dropping everything while broken.
type udpFaultProxy struct {
	clientSock *net.UDPConn // faces the direct client
	serverSock *net.UDPConn // faces the direct server
	serverAddr *net.UDPAddr

	mu         sync.Mutex
	broken     bool
	clientAddr *net.UDPAddr
}

func startUDPFaultProxy(t *testing.T, server *net.UDPAddr) *udpFaultProxy {
	t.Helper()
	host := net.ParseIP(udpTestHost)
	clientSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: host, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serverSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: host, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	p := &udpFaultProxy{clientSock: clientSock, serverSock: serverSock, serverAddr: server}

	// Server -> client direction.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := serverSock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !raddr.IP.Equal(server.IP) || raddr.Port != server.Port {
				continue
			}
			p.mu.Lock()
			broken, ca := p.broken, p.clientAddr
			p.mu.Unlock()
			if !broken && ca != nil {
				_, _ = clientSock.WriteToUDP(buf[:n], ca)
			}
		}
	}()

	// Client -> server direction.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, caddr, err := clientSock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.clientAddr = caddr
			broken := p.broken
			p.mu.Unlock()
			if !broken {
				_, _ = serverSock.WriteToUDP(buf[:n], server)
			}
		}
	}()

	t.Cleanup(func() {
		clientSock.Close()
		serverSock.Close()
	})
	return p
}

func (p *udpFaultProxy) addr() *net.UDPAddr { return p.clientSock.LocalAddr().(*net.UDPAddr) }

func (p *udpFaultProxy) setBroken(b bool) {
	p.mu.Lock()
	p.broken = b
	p.mu.Unlock()
}

// echoRoundTrip dials the tunnel listener, sends a message and waits for the
// echo. It returns the error instead of failing the test, so callers can
// assert both success and bounded failure.
func echoRoundTrip(ln net.Listener, msg string, d time.Duration) error {
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), d)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != msg {
		return errEchoMismatch
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

const errEchoMismatch = errString("echo mismatch")

// waitForCond polls cond until it returns true or the deadline expires.
func waitForCond(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// TestLiveCutover runs the full break/heal matrix with real QUIC over real
// (loopback) UDP and a real yggdrasil mesh peering.
func TestLiveCutover(t *testing.T) {
	udpLoopbackAvailable(t)
	logger := testLogger(t)

	// 1. Echo server stands in for the shadowsocks server.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Server node: mesh listener + direct UDP listener on the same port.
	srvNode, err := NewNode("", "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srvNode.Stop()
	srvListener, err := srvNode.Listen("tcp://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, srvPort, err := net.SplitHostPort(srvListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := startDirectServer(srvNode, "tcp://127.0.0.1:"+srvPort,
		echo.Addr().String(), nil, logger); err != nil {
		t.Fatal(err)
	}
	// The mesh QUIC listener (what client mesh dials connect to), with a
	// controllable "broken" flag: while broken, accepted connections are
	// closed immediately, so mesh dials fail fast.
	var meshDown atomic.Bool
	var meshMu sync.Mutex
	var meshConns []*quic.Conn
	srv := &server{
		node:    srvNode,
		dst:     echo.Addr().String(),
		allowed: nil,
		log:     logger,
	}
	go func() {
		tr := &quic.Transport{Conn: srvNode.PacketConn()}
		ql, err := tr.Listen(srv.tlsConfig(), quicConfig())
		if err != nil {
			return
		}
		defer ql.Close()
		for {
			conn, err := ql.Accept(context.Background())
			if err != nil {
				return
			}
			if meshDown.Load() {
				_ = conn.CloseWithError(0, "mesh broken")
				continue
			}
			meshMu.Lock()
			meshConns = append(meshConns, conn)
			meshMu.Unlock()
			go srv.handleConn(conn)
		}
	}()
	breakMesh := func() {
		meshDown.Store(true)
		meshMu.Lock()
		for _, conn := range meshConns {
			_ = conn.CloseWithError(0, "mesh broken")
		}
		meshConns = nil
		meshMu.Unlock()
	}
	directUDPPort, err := strconv.Atoi(srvPort)
	if err != nil {
		t.Fatal(err)
	}
	srvUDPAddr := &net.UDPAddr{IP: net.ParseIP(udpTestHost), Port: directUDPPort}

	// The fault proxy fronts the direct UDP listener.
	proxy := startUDPFaultProxy(t, srvUDPAddr)

	// 3. Client node peered with the server node (mesh channel).
	cliNode, err := NewNode("", "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer cliNode.Stop()
	if err := cliNode.AddPeer("tcp://" + srvListener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	waitForCond(t, 10*time.Second, "mesh peering", func() bool {
		return cliNode.ConnectedPeerCount() == 1 && srvNode.ConnectedPeerCount() == 1
	})

	// 4. Plugin client: direct via the proxy, fast probe cadence.
	cli := &client{
		node:      cliNode,
		serverKey: srvNode.PublicKey(),
		bind:      "127.0.0.1:0",
		timeout:   10 * time.Second,
		log:       logger,
		direct: &directClient{
			node:        cliNode,
			serverKey:   srvNode.PublicKey(),
			serverAddr:  net.JoinHostPort(udpTestHost, strconv.Itoa(proxy.addr().Port)),
			timeout:     3 * time.Second,
			retryPeriod: 500 * time.Millisecond,
			log:         logger,
		},
	}
	cli.direct.startProber(cli)
	ln, err := cli.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const msg = "live cutover probe"

	// Phase 1: the probe verifies the direct path through the proxy and
	// streams flow over it.
	waitForCond(t, 15*time.Second, "direct path verified", func() bool {
		return cli.PathState() == pathH2H3
	})
	if err := echoRoundTrip(ln, msg, 10*time.Second); err != nil {
		t.Fatalf("phase 1 (direct healthy): %v", err)
	}

	// Phase 2: the UDP path goes black. The round-trip probe must detect
	// it within a few probe periods and the direct connection must be
	// dropped; new streams must then flow over mesh.
	proxy.setBroken(true)
	waitForCond(t, 15*time.Second, "cutover to mesh after UDP blackout", func() bool {
		return cli.PathState() == pathMeshFallback
	})
	if err := echoRoundTrip(ln, msg, 15*time.Second); err != nil {
		t.Fatalf("phase 2 (direct black, mesh must carry traffic): %v", err)
	}

	// Phase 3: the UDP path heals. Probes must verify it again and new
	// streams must upgrade back to direct.
	proxy.setBroken(false)
	waitForCond(t, 15*time.Second, "upgrade back to direct after heal", func() bool {
		return cli.PathState() == pathH2H3
	})
	if err := echoRoundTrip(ln, msg, 10*time.Second); err != nil {
		t.Fatalf("phase 3 (direct healed): %v", err)
	}

	// Phase 4: both channels break (UDP black + mesh connections killed
	// and new dials rejected). User streams must fail with a bounded
	// error, not hang forever.
	proxy.setBroken(true)
	breakMesh()
	start := time.Now()
	err = echoRoundTrip(ln, msg, 30*time.Second)
	if err == nil {
		t.Fatal("phase 4 (both channels down): stream must fail")
	}
	if elapsed := time.Since(start); elapsed > 25*time.Second {
		t.Fatalf("phase 4: stream error took too long (%s) - not fail-fast", elapsed)
	}

	// Phase 5: both channels heal (mesh accepts again + UDP back).
	// Traffic must resume without a client restart.
	proxy.setBroken(false)
	meshDown.Store(false)
	if err := echoRoundTrip(ln, msg, 20*time.Second); err != nil {
		t.Fatalf("phase 5 (both healed): %v", err)
	}
}
