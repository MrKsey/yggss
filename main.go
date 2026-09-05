// yggss is a SIP003 plugin for shadowsocks that tunnels traffic through the
// Yggdrasil network (https://github.com/yggdrasil-network/yggdrasil-go).
//
// Both the client and the server run as full yggdrasil nodes. Traffic is
// carried end-to-end over QUIC streams on top of the encrypted yggdrasil
// packet session between the two node keys, so the plugin works both over a
// direct peering and through the yggdrasil mesh (public peers / relays).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

const version = "0.1.0"

func main() {
	var (
		bindAddr          string
		dstAddr           string
		isServer          bool
		keyHex            string
		serverKeyHex      string
		clientKeyHex      string
		peerList          string
		password          string
		scheme            string
		mode              string
		sni               string
		directDialSec     int
		directRetrySec    int
		timeoutSec        int
		logIntervalSec    int
		failoverFlag      bool
		failoverSet       bool
		failoverLatencyMs int
		failoverCheckSec  int
		genKey            bool
		showVersion       bool
		configPath        string
	)

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.StringVar(&bindAddr, "b", "", "[Host:Port] client: local listen address; server: public listen address")
	fs.StringVar(&dstAddr, "d", "", "client: server public address ([scheme://]Host:Port); server: [Host:Port] forward destination")
	fs.BoolVar(&isServer, "s", false, "run as server")
	fs.StringVar(&keyHex, "key", "", "ed25519 private key of the local yggdrasil node (hex)")
	fs.StringVar(&serverKeyHex, "serverkey", "", "ed25519 public key of the server node (hex, client only)")
	fs.StringVar(&clientKeyHex, "clientkey", "", "ed25519 public key of the allowed client node (hex, server only)")
	fs.StringVar(&peerList, "peers", "", "comma-separated list of extra yggdrasil peering URIs")
	fs.StringVar(&password, "password", "", "yggdrasil group password (must match on both sides)")
	fs.StringVar(&scheme, "scheme", "tls", "yggdrasil link scheme used for the direct server connection (tls, tcp, quic, ws, wss)")
	fs.StringVar(&mode, "mode", "mesh", "tunnel transport: mesh (via yggdrasil session) or direct (plain UDP, faster)")
	fs.StringVar(&sni, "sni", "", "fake SNI domain for the direct TLS link to the server (client only)")
	fs.IntVar(&directDialSec, "directdialtimeout", 5, "direct UDP dial timeout in seconds (client only)")
	fs.IntVar(&directRetrySec, "directretry", 30, "interval between direct tunnel retries in seconds (client only)")
	fs.IntVar(&timeoutSec, "t", 30, "tunnel dial timeout in seconds")
	fs.StringVar(&configPath, "c", "", "path to a JSON config file (see examples/)")
	fs.IntVar(&logIntervalSec, "loginterval", 30, "status log interval in seconds (0 = disabled)")
	fs.BoolVar(&failoverFlag, "failover", true, "direct-link failover (default: on when peers are configured)")
	fs.IntVar(&failoverLatencyMs, "failoverlatency", defaultFailoverLatencyMs, "direct-link latency threshold in ms for failover")
	fs.IntVar(&failoverCheckSec, "failovercheck", defaultFailoverCheckSec, "failover health-check interval in seconds")
	fs.BoolVar(&genKey, "genkey", false, "generate a new node key pair and exit")
	fs.BoolVar(&showVersion, "v", false, "print version and exit")
	_ = fs.Parse(os.Args[1:])

	logger := log.New(os.Stderr, "", log.Flags())
	logger.EnableLevel("info")
	logger.EnableLevel("warn")
	logger.EnableLevel("error")

	if showVersion {
		fmt.Println(version)
		return
	}
	if genKey {
		genAndPrintKey()
		return
	}

	// Apply the JSON config file (if any) for values not set explicitly
	// on the command line. SIP003 environment variables are applied later
	// and take the highest precedence.
	if configPath == "" {
		// The config path may also come from SS_PLUGIN_OPTIONS, e.g.:
		//   "plugin_opts": "/etc/shadowsocks/yggss-client.json"
		//   "plugin_opts": "c=/etc/shadowsocks/yggss-client.json"
		//   "plugin_opts": "s;c=/etc/shadowsocks/yggss-server.json"
		if env := detectSIP003(); env != nil {
			configPath = configPathFromOptions(os.Getenv("SS_PLUGIN_OPTIONS"))
		}
	}
	if configPath != "" {
		cfg, err := loadConfigFile(configPath)
		if err != nil {
			fatal(logger, "%v", err)
		}
		setFlags := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
		logger.Infoln("using config file", configPath)
		if !setFlags["s"] && cfg.Server {
			isServer = true
		}
		if !setFlags["b"] && cfg.Bind != "" {
			bindAddr = cfg.Bind
		}
		if !setFlags["d"] && cfg.Destination != "" {
			dstAddr = cfg.Destination
		}
		if !setFlags["key"] && cfg.Key != "" {
			keyHex = cfg.Key
		}
		if !setFlags["serverkey"] && cfg.ServerKey != "" {
			serverKeyHex = cfg.ServerKey
		}
		if !setFlags["clientkey"] && cfg.ClientKey != "" {
			clientKeyHex = cfg.ClientKey
		}
		if !setFlags["clientkeys"] && len(cfg.ClientKeys) > 0 {
			clientKeyHex = strings.Join(cfg.ClientKeys, ",")
		}
		if !setFlags["password"] && cfg.Password != "" {
			password = cfg.Password
		}
		if !setFlags["scheme"] && cfg.Scheme != "" {
			scheme = cfg.Scheme
		}
		if !setFlags["mode"] && cfg.Mode != "" {
			mode = cfg.Mode
		}
		if !setFlags["sni"] && cfg.SNI != "" {
			sni = cfg.SNI
		}
		if !setFlags["directdialtimeout"] && cfg.DirectDialTimeout > 0 {
			directDialSec = cfg.DirectDialTimeout
		}
		if !setFlags["directretry"] && cfg.DirectRetry > 0 {
			directRetrySec = cfg.DirectRetry
		}
		if !setFlags["t"] && cfg.Timeout > 0 {
			timeoutSec = cfg.Timeout
		}
		if !setFlags["loginterval"] && cfg.LogInterval >= 0 {
			logIntervalSec = cfg.LogInterval
		}
		if !setFlags["failover"] && cfg.Failover != nil {
			failoverFlag = *cfg.Failover
			failoverSet = true
		}
		if !setFlags["failoverlatency"] && cfg.FailoverLatency > 0 {
			failoverLatencyMs = cfg.FailoverLatency
		}
		if !setFlags["failovercheck"] && cfg.FailoverCheck > 0 {
			failoverCheckSec = cfg.FailoverCheck
		}
		if !setFlags["peers"] && len(cfg.Peers) > 0 {
			peerList = strings.Join(cfg.Peers, ",")
		}
	}

	// Overwrite flags when running as a SIP003 plugin.
	if env := detectSIP003(); env != nil {
		logger.Infoln("running as a SIP003 plugin")
		get := func(k string) string { return env.options[k] }
		if v := get("key"); v != "" {
			keyHex = v
		}
		if v := get("serverkey"); v != "" {
			serverKeyHex = v
		}
		if v := get("clientkey"); v != "" {
			clientKeyHex = v
		}
		if v := get("peers"); v != "" {
			peerList = v
		}
		if v := get("password"); v != "" {
			password = v
		}
		if v := get("scheme"); v != "" {
			scheme = v
		}
		if v := get("t"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				timeoutSec = n
			}
		}
		if v := get("loginterval"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				logIntervalSec = n
			}
		}
		if v := get("mode"); v == "mesh" || v == "direct" {
			mode = v
		}
		if v := get("sni"); v != "" {
			sni = v
		}
		if v := get("directdialtimeout"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				directDialSec = n
			}
		}
		if v := get("directretry"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				directRetrySec = n
			}
		}
		if v := get("failover"); v != "" {
			failoverFlag = v != "0" && v != "false" && v != "off" && v != "no"
			failoverSet = true
		}
		if v := get("failover_latency"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				failoverLatencyMs = n
			}
		}
		if v := get("failover_check"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				failoverCheckSec = n
			}
		}
		if _, ok := env.options["s"]; ok {
			isServer = true
		}
		if isServer {
			// The plugin must listen on the public endpoint and forward
			// decrypted streams to the shadowsocks server.
			bindAddr = env.remoteAddr()
			dstAddr = env.localAddr()
		} else {
			// The plugin listens for ss-local and tunnels to the server.
			bindAddr = env.localAddr()
			dstAddr = env.remoteAddr()
		}
		logger.Infof("SIP003 addresses: bind=%s (from SS_LOCAL_%s), destination=%s (from SS_%s)",
			bindAddr,
			map[bool]string{true: "REMOTE", false: "LOCAL"}[isServer],
			dstAddr,
			map[bool]string{true: "LOCAL", false: "REMOTE"}[isServer],
		)
		logger.Infoln("note: bind/destination from the JSON config are ignored when running under shadowsocks")
	}

	if bindAddr == "" {
		fatal(logger, "listen address (-b) is required")
	}
	timeout := time.Duration(timeoutSec) * time.Second

	// Create the local yggdrasil node (no TUN adapter, library mode only).
	node, err := NewNode(keyHex, password, logger)
	if err != nil {
		fatal(logger, "%v", err)
	}
	defer node.Stop()
	logger.Infof("yggdrasil node started, address %s, public key %s",
		node.Address(), hex.EncodeToString(node.PublicKey()))

	// Extra peers for mesh reachability (both sides may need them).
	for _, p := range splitPeers(peerList) {
		if err := node.AddPeer(p); err != nil {
			logger.Warnf("failed to add peer %q: %s", p, err)
		} else {
			logger.Infoln("peering with", p)
		}
	}

	if isServer {
		if dstAddr == "" {
			fatal(logger, "forward destination (-d) is required")
		}
		listenURI := bindAddr
		if !strings.Contains(listenURI, "://") {
			listenURI = scheme + "://" + listenURI
		}
		if _, err := node.Listen(listenURI); err != nil {
			fatal(logger, "failed to listen on %s: %v", listenURI, err)
		}
		var allowed map[string]struct{}
		if clientKeyHex != "" {
			allowed = make(map[string]struct{})
			for _, k := range strings.Split(clientKeyHex, ",") {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				pk, err := parseKey(k, ed25519.PublicKeySize)
				if err != nil {
					fatal(logger, "%v", err)
				}
				allowed[string(pk)] = struct{}{}
			}
			if len(allowed) == 0 {
				allowed = nil
			}
			logger.Infof("client whitelist: %d key(s)", len(allowed))
		}
		srv := &server{
			node:    node,
			dst:     dstAddr,
			allowed: allowed,
			log:     logger,
		}
		// Direct mode: additionally serve the tunnel over plain UDP on the
		// same port. The mesh tunnel keeps working as a fallback.
		if mode == "direct" {
			if err := startDirectServer(node, bindAddr, dstAddr, allowed, logger); err != nil {
				fatal(logger, "direct mode: %v", err)
			}
		}
		startStatusLogger(node, nil, time.Duration(logIntervalSec)*time.Second, logger)
		if err := srv.Run(); err != nil {
			fatal(logger, "server exited: %v", err)
		}
		return
	}

	// Client mode.
	if serverKeyHex == "" {
		fatal(logger, "server public key (-serverkey) is required")
	}
	if dstAddr == "" {
		fatal(logger, "server address (-d) is required")
	}
	serverKey, err := parseKey(serverKeyHex, ed25519.PublicKeySize)
	if err != nil {
		fatal(logger, "%v", err)
	}
	peerURI := dstAddr
	if !strings.Contains(peerURI, "://") {
		peerURI = scheme + "://" + peerURI
	}
	// A fake SNI can be attached to the direct server link. It matters for
	// the TLS link (TCP); the direct QUIC tunnel does not send SNI at all.
	if sni != "" && !strings.Contains(peerURI, "?") {
		peerURI += "?sni=" + url.QueryEscape(sni)
		logger.Infoln("direct link SNI:", sni)
	}
	if err := node.AddPeer(peerURI); err != nil {
		logger.Warnf("failed to add server peer %q: %s", peerURI, err)
	} else {
		logger.Infoln("peering with", peerURI)
	}

	cl := &client{
		node:      node,
		serverKey: ed25519.PublicKey(serverKey),
		bind:      bindAddr,
		timeout:   timeout,
		log:       logger,
	}
	if mode == "direct" {
		dialTimeout := time.Duration(directDialSec) * time.Second
		retryPeriod := time.Duration(directRetrySec) * time.Second
		cl.direct = &directClient{
			node:        node,
			serverKey:   ed25519.PublicKey(serverKey),
			serverAddr:  dstAddr,
			timeout:     dialTimeout,
			retryPeriod: retryPeriod,
			fakeSNI:     sni,
			log:         logger,
		}
		cl.direct.startProber(cl)
		logger.Infof("tunnel mode: direct (QUIC over UDP to %s), mesh fallback enabled, dial timeout %s, retry every %s",
			dstAddr, dialTimeout, retryPeriod)
	} else {
		logger.Infoln("tunnel mode: mesh (via yggdrasil session)")
	}

	// Direct-link failover: prefer the direct peering; when it degrades,
	// disconnect it so traffic goes through the mesh peers, and restore it
	// once the endpoint becomes reachable again.
	if failoverSet || len(splitPeers(peerList)) > 0 {
		if !failoverSet || failoverFlag {
			if fm := newFailoverMonitor(node, peerURI, ed25519.PublicKey(serverKey),
				failoverLatencyMs, failoverCheckSec, logger); fm != nil {
				go fm.Run()
			}
		} else {
			logger.Infoln("failover monitor: disabled by configuration")
		}
	}

	// Verify that the node we peered with is really the server whose key
	// is configured. A mismatch here (e.g. a yggdrasil address pasted into
	// server_key instead of the public key) makes QUIC dials time out.
	go func() {
		deadline := time.Now().Add(timeout + 10*time.Second)
		for time.Now().Before(deadline) {
			for _, k := range node.PeerKeys() {
				if k.Equal(ed25519.PublicKey(serverKey)) {
					logger.Infoln("server identity verified: peered node key matches server_key")
					return
				}
			}
			if n := node.ConnectedPeerCount(); n > 0 {
				for _, k := range node.PeerKeys() {
					logger.Warnf("peered node key %s does not match server_key %s - "+
						"QUIC dials will fail; server_key must be the server's public key (hex), not its yggdrasil address",
						hex.EncodeToString(k), serverKeyHex)
				}
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		logger.Warnf("no peering verified within %s - check network reachability of %s", timeout, dstAddr)
	}()

	startStatusLoggerTun(node, ed25519.PublicKey(serverKey), time.Duration(logIntervalSec)*time.Second,
		&cl.rx, &cl.tx, func() string { return cl.PathState().String() }, logger)

	ln, err := cl.Run()
	if err != nil {
		fatal(logger, "client exited: %v", err)
	}
	defer ln.Close()

	// Block until a termination signal arrives; cl.Run serves connections
	// in the background.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	logger.Infoln("exiting on signal")
}

func fatal(logger *log.Logger, format string, args ...any) {
	logger.Errorf(format, args...)
	os.Exit(1)
}

// genAndPrintKey prints a new node key pair and the derived yggdrasil address.
func genAndPrintKey() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Println("private key (hex): ", hex.EncodeToString(priv))
	fmt.Println("public key (hex):  ", hex.EncodeToString(pub))
	addr := address.AddrForKey(pub)
	fmt.Println("yggdrasil address: ", net.IP(addr[:]).String())
}

// parseKey decodes a hex-encoded key of the exact expected size.
func parseKey(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("key must be exactly %d bytes (%d hex chars)", size, size*2)
	}
	return b, nil
}

// splitPeers splits a comma-separated peer list and drops empty entries.
func splitPeers(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// keep runtime imported for potential GOMAXPROCS tuning in future versions.
var _ = runtime.NumCPU
