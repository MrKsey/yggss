package yggss

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// Node wraps a yggdrasil node running in library mode (no TUN adapter).
// The node serves two purposes:
//  1. mesh peering - to reach the remote side either directly or through
//     public peers / relays;
//  2. a packet carrier for the end-to-end QUIC tunnel between the two
//     node keys (the yggdrasil session provides e2e encryption keyed to
//     the ed25519 node identities).
type Node struct {
	cfg  *config.NodeConfig
	core *core.Core
	log  *log.Logger
}

// NewNode creates a yggdrasil node. If keyHex is empty, an ephemeral key is
// generated (the node identity then changes on every restart).
func NewNode(keyHex, password string, logger *log.Logger) (*Node, error) {
	var priv ed25519.PrivateKey
	if strings.TrimSpace(keyHex) == "" {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
		priv = p
		logger.Warnln("no private key configured, using an ephemeral one")
	} else {
		b, err := hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		if len(b) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("private key must be exactly %d bytes", ed25519.PrivateKeySize)
		}
		priv = ed25519.PrivateKey(b)
	}

	cfg := config.GenerateConfig()
	cfg.PrivateKey = config.KeyBytes(priv)
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	var opts []core.SetupOption
	if password != "" {
		opts = append(opts, core.GroupPassword(password))
		logger.Infoln("yggdrasil group password: enabled")
	} else {
		logger.Warnln("yggdrasil group password: disabled (must match on both sides)")
	}
	c, err := core.New(cfg.Certificate, logger, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to start yggdrasil node: %w", err)
	}
	return &Node{cfg: cfg, core: c, log: logger}, nil
}

// AddPeer registers a persistent peering, e.g. "tls://a.b.c.d:e".
func (n *Node) AddPeer(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}
	return n.core.AddPeer(u, "")
}

// RemovePeer removes a persistent peering (stops reconnect attempts and
// drops the link if established).
func (n *Node) RemovePeer(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}
	return n.core.RemovePeer(u, "")
}

// Listen starts an incoming link listener, e.g. "tls://0.0.0.0:4440".
func (n *Node) Listen(uri string) (*core.Listener, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	return n.core.Listen(u, "")
}

// ConnectedPeerCount returns the number of currently established peerings.
func (n *Node) ConnectedPeerCount() int {
	count := 0
	for _, p := range n.core.GetPeers() {
		if p.Up {
			count++
		}
	}
	return count
}

// PeerKeys returns the public keys of currently connected peers.
func (n *Node) PeerKeys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, p := range n.core.GetPeers() {
		if p.Up && len(p.Key) == ed25519.PublicKeySize {
			keys = append(keys, p.Key)
		}
	}
	return keys
}

// Peers returns detailed info about current peerings (latency, cost,
// throughput, keys).
func (n *Node) Peers() []core.PeerInfo { return n.core.GetPeers() }

// Sessions returns the end-to-end yggdrasil sessions this node participates
// in (traffic addressed to/from this node only - transit traffic relayed
// for other nodes does not create sessions).
func (n *Node) Sessions() []core.SessionInfo { return n.core.GetSessions() }

// TreeParent returns the public key of the current spanning-tree parent.
// The parent is the first hop for most traffic (everything routed up the
// tree), which includes the client-to-server direction in this plugin.
func (n *Node) TreeParent() (ed25519.PublicKey, bool) {
	self := n.core.PublicKey()
	for _, t := range n.core.GetTree() {
		if t.Key.Equal(self) {
			return t.Parent, true
		}
	}
	return nil, false
}

// PathCoords returns the tree coordinates (path from the root) of the given
// node, as currently known by the pathfinder.
func (n *Node) PathCoords(key ed25519.PublicKey) ([]uint64, bool) {
	for _, p := range n.core.GetPaths() {
		if p.Key.Equal(key) {
			return p.Path, true
		}
	}
	return nil, false
}

// IsPeerOf reports whether the given key is one of our direct link neighbors.
func (n *Node) IsPeerOf(key ed25519.PublicKey) bool {
	for _, p := range n.core.GetPeers() {
		if p.Up && p.Key.Equal(key) {
			return true
		}
	}
	return false
}

// PacketConn returns the node as a packet carrier for the QUIC tunnel.
// Core.ReadFrom filters out yggdrasil-internal proto traffic, so the QUIC
// transport only sees end-to-end session payloads.
func (n *Node) PacketConn() net.PacketConn { return &nodePacketConn{core: n.core} }

// PublicKey returns the ed25519 public key (the node identity).
func (n *Node) PublicKey() ed25519.PublicKey { return n.core.PublicKey() }

// Address returns the derived yggdrasil IPv6 address of the node.
func (n *Node) Address() net.IP { return n.core.Address() }

// Certificate returns the node self-signed TLS certificate (used for the
// QUIC handshake and client authentication).
func (n *Node) Certificate() *tls.Certificate { return n.cfg.Certificate }

// Stop shuts the node down.
func (n *Node) Stop() { n.core.Stop() }

// nodePacketConn adapts *core.Core to the net.PacketConn interface required
// by quic-go. Core itself does not implement net.PacketConn because it lacks
// plain Read/Write, but its ReadFrom/WriteTo are exactly what QUIC needs.
type nodePacketConn struct{ core *core.Core }

func (c *nodePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.core.ReadFrom(p)
}

func (c *nodePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.core.WriteTo(p, addr)
}

func (c *nodePacketConn) Close() error {
	c.core.Stop()
	return nil
}

func (c *nodePacketConn) LocalAddr() net.Addr { return c.core.LocalAddr() }

func (c *nodePacketConn) SetDeadline(t time.Time) error      { return c.core.SetDeadline(t) }
func (c *nodePacketConn) SetReadDeadline(t time.Time) error  { return c.core.SetReadDeadline(t) }
func (c *nodePacketConn) SetWriteDeadline(t time.Time) error { return c.core.SetWriteDeadline(t) }
