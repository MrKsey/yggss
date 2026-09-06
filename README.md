# yggss — a Shadowsocks SIP003 plugin over Yggdrasil Network

[README in Russian](README.ru.md)

**yggss** is a [SIP003](https://shadowsocks.org/en/wiki/Plugin.html) plugin for
[Shadowsocks](https://shadowsocks.org) that tunnels proxy traffic through the
[Yggdrasil Network](https://yggdrasil-network.github.io/) — a fully encrypted
end-to-end IPv6 mesh network in which every node is identified by its ed25519
public key rather than by an IP address.

Both ends of the tunnel (client and server) run as Yggdrasil nodes in library
mode — no TUN adapter, no root, no system routes. Application data is carried
over QUIC streams on top of Yggdrasil's encrypted end-to-end session:

```
apps > ss-local > yggss (client) == Yggdrasil mesh / direct UDP == yggss (server) > ss-server > internet
```

- **Addressing by node key**: the server is reached by its public key, not by
  IP. If direct reachability is blocked, traffic flows through mesh peers.
- **Masking**: to an outside observer the traffic looks like ordinary
  Yggdrasil peering — TLS, QUIC or WebSocket sessions to well-known public
  peers, plus a browser-like HTTP/3 flow to the server.
- **Layered encryption**: link-level TLS + Yggdrasil end-to-end session +
  QUIC/TLS inside.
- **Multiplexing**: one QUIC connection, one stream per proxied TCP
  connection.

Prebuilt binaries for **Linux x64, Linux arm64 and Windows x64** are attached
to every [GitHub Release](https://github.com/MrKsey/yggss/releases).

## How it works

1. **Both plugins start a Yggdrasil node** (`core.New` from yggdrasil-go,
   library mode). Each node has an ed25519 identity: a private key (secret)
   and a public key (the node's address in the mesh).
2. **The server plugin** listens for Yggdrasil link connections on the public
   endpoint (`SS_REMOTE_HOST:SS_REMOTE_PORT`) and opens a QUIC listener over
   the node's packet session. Every accepted QUIC stream is forwarded to the
   local `ss-server`.
3. **The client plugin** peers with the server (direct link to
   `SS_REMOTE_HOST:SS_REMOTE_PORT`, optionally plus public mesh peers), then
   dials the server's *key* over the mesh. Every connection from `ss-local`
   becomes one QUIC stream.
4. **Authentication**: the client pins the server's public key (checked inside
   the QUIC handshake); the server can verify client keys against a whitelist;
   an optional group password restricts who may peer at the link level at all.
5. **Data path**: `ss-local` TCP stream -> QUIC stream -> (direct UDP or
   Yggdrasil session) -> server-side QUIC accept -> TCP to `ss-server`.

## Traffic masking

Yggdrasil links already look like ordinary TLS/WebSocket sessions. On top of
that, the *direct* tunnel mode mimics a browser:

- **ALPN is fixed to `h3`** — the standard HTTP/3 identifier. The QUIC Initial
  packet is encrypted with a well-known key (RFC 9001), so DPI can read the
  ClientHello; a unique ALPN string would be an instant signature, while `h3`
  is what every browser sends.
- **Fake SNI** (the `sni` option) is placed into both the TLS link ClientHello
  and the QUIC ClientHello, so the handshake looks like a real connection to
  a popular domain.
- **Transport parameters** (stream limits, initial packet size) are matched
  to Chrome's HTTP/3 profile, so the quic-go fingerprint does not stand out.
- **h2 to h3 upgrade race (Alt-Svc model)**: user traffic never waits for the
  fast path. The mesh channel serves connections immediately while a
  background probe verifies the QUIC path *only while the mesh channel is
  active* — UDP traffic never exists without a parallel TCP session, exactly
  like a browser racing HTTP/3 against HTTP/2. When the probe succeeds, new
  streams upgrade to QUIC; when it fails, they instantly fall back to mesh.

```
tunnel: h3 path verified in 95ms (probe rtt) - new streams upgrade to QUIC
tunnel: h3 probe round trip failed (context deadline exceeded) - 1 of 2 before downgrading
tunnel: h3 path failed (2 consecutive probe errors: ...) - downgrading to h2, existing streams reconnect via mesh
tunnel path: h2+h3 (direct verified) - active: direct QUIC
tunnel path: h2 (h3 failed, probing) - active: mesh
```

### Startup summary

The first log lines always show the version and the four parameters that
define the plugin's role, so a running instance can be identified from the
log alone:

```
yggss v1.2.0
bind: [::1]:40729
destination: [2001:db8::1]:443
scheme: tls
mode: direct
```

### What the log tells you

| Log line | Meaning |
|---|---|
| `tunnel: h3 path verified in <rtt> - new streams upgrade to QUIC` | the direct path passed a real round-trip probe; new connections go over direct QUIC |
| `tunnel: h3 probe error on a living connection (...) - 1 of 2 before downgrading` | a probe hiccup (e.g. one lost packet); not critical, QUIC retransmits |
| `tunnel: h3 probe round trip failed (...) - 1 of 2 before downgrading` | the path stopped carrying data (black hole); one more failure and the channel switches |
| `tunnel: h3 path failed (...) - downgrading to h2, existing streams reconnect via mesh` | the direct channel is dropped: new streams go over mesh, streams on the dead connection error out immediately so their applications reconnect |
| `tunnel: h3 probe rtt ... exceeds the degradation threshold` | packet loss is growing (RTT spike against the path baseline); the path yields to mesh |
| `tunnel: h3 verify cache expired - probing the path again` | the verified cache TTL ran out; the path is re-checked before upgrades resume |
| `tunnel: idle, h3 cache dropped - will re-verify on next activity` | no traffic for a long time; the probe pauses and re-verifies on the next burst |
| `tunnel path: ... - active: direct QUIC` / `active: mesh` | what carries traffic right now (periodic status log) |
| `server identity verified: peered node key matches server_key` | the mesh peering with the server is up and its key matches the config |

## Tunnel modes

The `mode` option chooses what carries the tunnel streams between the client
and the server plugin:

- **`direct`** is essentially **QUIC over plain UDP, bypassing Yggdrasil
  entirely**. The client dials the server's UDP endpoint directly; packets
  travel exactly like a browser's HTTP/3 traffic — one QUIC handshake,
  TLS 1.3 inside QUIC, no mesh routing, no extra encapsulation. The Yggdrasil
  node identity is still used for authentication (the QUIC TLS certificates
  are the nodes' ed25519 keys), but the *transport* has nothing to do with
  the Yggdrasil network: no spanning tree, no transit peers, no session
  layer. This is why it is fast: one crypto layer instead of three and no
  routing overhead.
- **`mesh`** runs QUIC on top of the real Yggdrasil end-to-end session. The
  client dials the server's *public key*, and Yggdrasil routes the packets
  — directly over the TCP/TLS link when possible, otherwise through mesh
  peers. This adds two more crypto layers (link TLS + the end-to-end
  session) and routing hops, but works even when the server has no reachable
  UDP endpoint, and the route can pass through public peers.

| | `mesh` (default) | `direct` |
|---|---|---|
| Transport | QUIC over the Yggdrasil session | QUIC over plain UDP (no Yggdrasil in the data path) |
| Addressing | server's public key, routed by the mesh | server's IP:port, dialed directly |
| Crypto layers | 3 (link TLS + session + QUIC) | 1 (QUIC's built-in TLS 1.3) |
| Typical speed | lower (see below) | 2-3x higher |
| Works through mesh peers | yes | no (needs direct UDP reachability) |
| Automatic fallback to mesh | — | yes, Alt-Svc style |

In `direct` mode the server listens with QUIC/UDP on the same port as the
TLS link (TCP and UDP are independent). Authentication is unchanged: the
same node keys are checked inside the QUIC handshake.

## Why mesh speed can be low

Mesh throughput is limited by design trade-offs of Yggdrasil itself:

1. **Extra crypto and encapsulation layers.** Every payload byte is encrypted
   three times (link TLS, end-to-end session, QUIC) and wrapped in several
   packet headers. CPU cost per byte is roughly 2-3x that of direct mode.
2. **Yggdrasil routing optimizes latency, not bandwidth.** Spanning-tree
   routing picks the *closest* path, not the *widest* one. A low-latency route
   through several public peers can have far less capacity than a single
   direct link.
3. **Transit traffic.** Yggdrasil relays third-party traffic through the tree
   by design and offers no switch to disable it. Public peers (and your own
   node, if it has public peerings) may carry other people's traffic, sharing
   the same channel and CPU. yggss detects this and warns in the status log:

   ```
   mesh transit: ~30MiB of third-party traffic relayed in the last interval (100% of link traffic) - yggdrasil relays transit by design; trimming the peers list reduces it
   ```

   The only practical mitigation is a shorter `peers` list.
4. **Public peer capacity.** Community-run peers are shared by everyone and
   are often rate-limited.

**Recommendation**: use `direct` mode when the server has open UDP; keep the
mesh as the automatic fallback (it is always hot — failover is instant).

### Fast cutover on direct-path degradation

The client watches the direct path continuously and switches channels on
degradation, not on death:

- the background probe sends a real round-trip request (the server echoes
  it back); a path that swallows packets (NAT rebinding, a firewall starting
  to drop UDP) fails the probe within 3 seconds even though the QUIC
  connection formally stays "open" — the direct connection is closed
  immediately, so the streams riding it error out at once and their
  applications reconnect over mesh;
- a sharp RTT rise against the path's own baseline (or two consecutive probe
  errors) is treated as growing packet loss and switches the same way;
- when the direct connection closes (peer restart, network change), the
  cutover happens the same instant instead of waiting for QUIC timeouts;
- while degraded, the probe re-checks every few seconds; as soon as probes
  come back clean, new streams upgrade to QUIC again.

A single lost packet never triggers a switch — QUIC retransmits transparently.

## Getting started

### 1. Generate node keys

```bash
./yggss -genkey
```

```
private key (hex):  1d62c1...b71
public key (hex):   c6e500...b71
yggdrasil address:  200:7235:ff73:d8a4:a4af:224a:7649:c0d4
```

Generate one pair for the server and one for every client. The private key is
the node identity — keep it secret.

### 2. Where to put the options

Three equivalent ways, in rising priority:

1. **JSON config file** (recommended) — see [`examples/`](examples/);
2. **Command-line flags** (`-key`, `-serverkey`, ...) for standalone runs;
3. **`plugin_opts` string** when running under shadowsocks
   (`key=...;serverkey=...;password=...`).

Under shadowsocks the `bind`/`destination` addresses are taken from the
SIP003 environment automatically; the config only carries keys, peers and
tuning. Pass just the config path:

```jsonc
"plugin_opts": "/etc/shadowsocks/yggss-client.json"      // full form
"plugin_opts": "c=/etc/shadowsocks/yggss-client.json"    // short form
"plugin_opts": "s;c=/etc/shadowsocks/yggss-server.json"  // "s" = server mode
```

### 3. Config examples

Client plugin (`examples/yggss-client.json`):

```json
{
	"server": false,
	"bind": "127.0.0.1:1080",
	"destination": "<SERVER_IP>:4440",
	"key": "<CLIENT_PRIVATE_KEY_HEX>",
	"server_key": "<SERVER_PUBLIC_KEY_HEX>",
	"password": "<GROUP_SECRET>",
	"scheme": "tls",
	"mode": "direct",
	"timeout": 30,
	"log_interval": 30,
	"failover": true,
	"peers": [
		"wss://<PUBLIC_PEER_1>:443/path",
		"tls://<PUBLIC_PEER_2>:port"
	]
}
```

Server plugin (`examples/yggss-server.json`):

```json
{
	"server": true,
	"bind": ":4440",
	"destination": "127.0.0.1:8388",
	"key": "<SERVER_PRIVATE_KEY_HEX>",
	"client_keys": ["<CLIENT_PUBLIC_KEY_HEX>"],
	"password": "<GROUP_SECRET>",
	"mode": "direct",
	"log_interval": 30
}
```

Full walkthroughs, including shadowsocks-rust configs and systemd units, are
in [`examples/`](examples/).

### 4. Options reference

| Key | Side | Description |
|-----|------|-------------|
| `s` | server | Server mode |
| `key` | both | Node private key (hex, from `-genkey`) |
| `serverkey` | client | Server node public key (hex) — required |
| `clientkey` / `client_keys` | server | Allowed client public keys (whitelist; empty = any node) — optional: a matching `password` on both sides is sufficient, the whitelist only adds per-node access control |
| `peers` | both | Extra Yggdrasil peers, comma-separated (`tls://`, `tcp://`, `quic://`, `ws://`, `wss://`, `socks://`, `sockstls://`; link params `?key=`, `?priority=`, `?sni=`, `?password=`, `?maxbackoff=`) |
| `password` | both | Yggdrasil group password (shared secret) — the simplest setup is `key` + `password` on the server and `key` + `serverkey` + `password` on the client, no key whitelists needed |
| `scheme` | both | Direct link scheme: `tls` (default), `tcp`, `quic`, `ws`, `wss` |
| `t` / `timeout` | client | Tunnel dial timeout, seconds (default 30) |
| `loginterval` / `log_interval` | both | Status log interval, seconds (default 30, `0` = off) |
| `failover` | client | Direct-link failover (default on when peers are set) |
| `failover_latency` | client | Direct-link latency threshold, ms (default 1000) |
| `failover_check` | client | Health check interval, seconds (default 5) |
| `mode` | both | `mesh` (default) or `direct` |
| `sni` | client | Fake domain for the direct link ClientHello |
| `direct_dial_timeout_sec` | client | Direct UDP dial timeout (default 5) |
| `direct_retry_sec` | client | Direct path re-verification interval (default 10) |

The same options are available as CLI flags (`-s`, `-key`, `-serverkey`,
`-clientkey`, `-peers`, `-password`, `-scheme`, `-t`, `-b`, `-d`, `-sni`,
`-mode`, ...) for standalone runs.

## Where to get binaries

- **Releases**: <https://github.com/MrKsey/yggss/releases> — every release
  carries `yggss-linux-amd64`, `yggss-linux-arm64` and
  `yggss-windows-amd64.exe`, built automatically by GitHub Actions.
- **From source** (Go 1.25+):

  ```bash
  GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o yggss-linux-amd64 .
  GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o yggss-linux-arm64 .
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o yggss.exe .
  ```

One binary serves as both client and server; the role is set by the
`"server"` field of the JSON config (or the `-s` flag).

## Where to get public peers

The community-maintained list of open Yggdrasil peers is published at
<https://github.com/yggdrasil-network/public-peers> — pick 2-3 entries
geographically close to you and put them into `peers`. Avoid adding many:
every public peering is a potential transit path (see *Why mesh speed can be
low*). With a group password configured, foreign nodes cannot peer with your
listeners even if they discover them.

## Limitations

- SIP003 carries TCP only; UDP over the plugin is not possible (a protocol
  limitation of shadowsocks plugins).
- The first connection after startup may take a few seconds while Yggdrasil
  finds a route to the server key (mostly noticeable through public peers).
- Long-lived streams opened over the direct path are terminated if the QUIC
  connection dies (streams cannot migrate between transports); applications
  reconnect on their own and new streams go through mesh instantly.
- yggdrasil-go is licensed LGPLv3 (with a static-linking exception).

## Tests

```bash
go test ./...
```

- Unit and state-machine tests cover the channel-selection logic (lifecycle,
  degradation/recovery, fail-fast behavior) with injectable fake QUIC
  connections.
- `TestLiveCutover` is a fault-injection scenario: real QUIC over UDP through
  a breakable proxy plus a real Yggdrasil mesh peering. It walks the full
  break/heal matrix — direct works, UDP blackout (cutover to mesh), UDP heals
  (upgrade back), both channels break (streams fail fast), both heal (traffic
  resumes without a restart).
- Direct-mode tests automatically fall back to a LAN interface when loopback
  UDP is filtered (common on workstations with strict firewalls).
