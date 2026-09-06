package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gologme/log"
)

// hexPriv encodes an ed25519 private key as hex.
func hexPriv(priv ed25519.PrivateKey) string { return hex.EncodeToString(priv) }

func testLogger(t *testing.T) *log.Logger {
	t.Helper()
	l := log.New(testWriter{t}, "", log.Flags())
	l.EnableLevel("info")
	l.EnableLevel("warn")
	l.EnableLevel("error")
	return l
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

// waitFor polls cond until it returns true or the deadline expires.
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

// TestEndToEnd spins up an echo server, a plugin server node and a plugin
// client node, peers them directly over TCP and checks that data sent to the
// client listener comes back from the echo server through the tunnel.
func TestEndToEnd(t *testing.T) {
	// 1. Echo server (stands in for the shadowsocks server).
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

	logger := testLogger(t)

	// 2. Server node: yggdrasil link listener + plugin server.
	srvNode, err := NewNode("", "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srvNode.Stop()
	srvListener, err := srvNode.Listen("tcp://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	allowedKey := make(map[string]struct{}) // filled below, after client node creation
	srv := &server{
		node:    srvNode,
		dst:     echo.Addr().String(),
		allowed: allowedKey,
		log:     logger,
	}
	go func() { _ = srv.Run() }()

	// 3. Client node: peered directly with the server node.
	cliNode, err := NewNode("", "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer cliNode.Stop()
	if err := cliNode.AddPeer("tcp://" + srvListener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, func() bool {
		return cliNode.ConnectedPeerCount() == 1 && srvNode.ConnectedPeerCount() == 1
	})

	// Only now can we pin the client key on the server side.
	allowedKey[string(cliNode.PublicKey())] = struct{}{}

	// 4. Plugin client.
	cli := &client{
		node:      cliNode,
		serverKey: srvNode.PublicKey(),
		bind:      "127.0.0.1:0",
		timeout:   15 * time.Second,
		log:       logger,
	}
	ln, err := cli.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// 5. Push data through the tunnel and expect the echo back.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	msg := []byte("hello over yggdrasil")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", got, msg)
	}

	// 6. A second connection must reuse the cached QUIC connection.
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn2.Write(msg); err != nil {
		t.Fatal(err)
	}
	got2 := make([]byte, len(msg))
	if _, err := io.ReadFull(conn2, got2); err != nil {
		t.Fatal(err)
	}
	if string(got2) != string(msg) {
		t.Fatalf("echo mismatch on reused connection: got %q, want %q", got2, msg)
	}
}

// TestEndToEndDirect verifies the direct mode: the tunnel runs over plain
// UDP between the client and the server, bypassing the yggdrasil session.
func TestEndToEndDirect(t *testing.T) {
	udpLoopbackAvailable(t)
	// 1. Echo server.
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

	logger := testLogger(t)

	// 2. Server node with a UDP direct listener on the same port.
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

	// 3. Client node (mesh peering keeps the yggdrasil side alive, but the
	// tunnel itself must go over UDP).
	cliNode, err := NewNode("", "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer cliNode.Stop()

	cli := &client{
		node:      cliNode,
		serverKey: srvNode.PublicKey(),
		bind:      "127.0.0.1:0",
		timeout:   15 * time.Second,
		log:       logger,
		direct: &directClient{
			node:        cliNode,
			serverKey:   srvNode.PublicKey(),
			serverAddr:  net.JoinHostPort(udpTestHost, srvPort),
			timeout:     15 * time.Second,
			retryPeriod: 2 * time.Second,
			log:         logger,
		},
	}
	// Alt-Svc model: the direct path starts unverified; emulate a successful
	// background probe so user streams take the fast path.
	cli.direct.MarkVerified(cli.direct.verifyTTL())
	ln, err := cli.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// 4. Push data through the tunnel and expect the echo back.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	msg := []byte("hello over direct udp")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", got, msg)
	}

	// 5. Second connection reuses the cached QUIC connection.
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn2.Write(msg); err != nil {
		t.Fatal(err)
	}
	got2 := make([]byte, len(msg))
	if _, err := io.ReadFull(conn2, got2); err != nil {
		t.Fatal(err)
	}
	if string(got2) != string(msg) {
		t.Fatalf("echo mismatch on reused connection: got %q, want %q", got2, msg)
	}
}

// TestDirectDialDiagnostic checks that a bare QUIC dial over UDP loopback
// works at all, isolating direct-mode failures from the plugin logic.
func TestDirectDialDiagnostic(t *testing.T) {
	udpLoopbackAvailable(t)
	logger := testLogger(t)
	srvNode, err := NewNode("", "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer srvNode.Stop()

	ql, addr, err := startDirectListener(srvNode, net.JoinHostPort(udpTestHost, "0"), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer ql.Close()
	_ = ql

	qconn, err := directDial(srvNode, srvNode.PublicKey(), net.JoinHostPort(udpTestHost, strconv.Itoa(addr.Port)), 10*time.Second, "")
	if err != nil {
		t.Fatalf("direct dial failed: %v", err)
	}
	defer qconn.CloseWithError(0, "")
}

// TestGenKey sanity-checks key generation helpers.
func TestGenKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		t.Fatal("unexpected key sizes")
	}
	node, err := NewNode(hexPriv(priv), "", testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Stop()
	if !node.PublicKey().Equal(pub) {
		t.Fatal("node public key does not match the provided private key")
	}
}
