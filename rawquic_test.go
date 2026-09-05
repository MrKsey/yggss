package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// TestQuicLoopbackRaw checks that quic-go works over UDP loopback in this
// environment, without any yggdrasil involvement.
func TestQuicLoopbackRaw(t *testing.T) {
	udpLoopbackAvailable(t)
	cert := genSelfSigned(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"rawtest"},
	}
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"rawtest"},
	}

	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sconn.Close()
	str := &quic.Transport{Conn: sconn}
	ql, err := str.Listen(tlsCfg, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ql.Accept(context.Background())
		if err != nil {
			return
		}
		s, err := c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		n, _ := s.Read(buf)
		s.Write(buf[:n])
	}()

	cconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cconn.Close()
	ctr := &quic.Transport{Conn: cconn}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qc, err := ctr.Dial(ctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sconn.LocalAddr().(*net.UDPAddr).Port}, clientTLS, &quic.Config{})
	if err != nil {
		t.Fatalf("raw quic dial failed: %v", err)
	}
	defer qc.CloseWithError(0, "")
	s, err := qc.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("ping!")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := s.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping!" {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

// udpLoopbackAvailable probes whether UDP datagrams can travel over
// loopback in this environment (sandboxes and some CI runners block UDP).
func udpLoopbackAvailable(t *testing.T) {
	t.Helper()
	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open UDP socket: %v", err)
	}
	defer rx.Close()
	tx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open UDP socket: %v", err)
	}
	defer tx.Close()
	if _, err := tx.WriteToUDP([]byte("x"), rx.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Skipf("cannot send UDP: %v", err)
	}
	_ = rx.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := rx.Read(buf); err != nil {
		t.Skip("UDP loopback is blocked in this environment; direct-mode tests require a real network")
	}
}

// TestUDPLoopbackEcho checks plain UDP loopback in this environment.
func TestUDPLoopbackEcho(t *testing.T) {
	udpLoopbackAvailable(t)
	sconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sconn.Close()
	go func() {
		buf := make([]byte, 5)
		n, raddr, err := sconn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		sconn.WriteToUDP(buf[:n], raddr)
	}()

	cconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cconn.Close()
	if _, err := cconn.WriteToUDP([]byte("ping!"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sconn.LocalAddr().(*net.UDPAddr).Port}); err != nil {
		t.Fatal(err)
	}
	_ = cconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 5)
	if _, err := cconn.Read(buf); err != nil {
		t.Fatalf("udp loopback echo failed: %v", err)
	}
}

func genSelfSigned(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rawtest"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
