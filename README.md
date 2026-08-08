# tunnel-suite

A tunneling-protocol test harness written in Go. One binary, two modes:

- **`server`** — listens for test sessions on every supported protocol.
- **`client`** — connects to a server and benchmarks each protocol: connection
  handshake time, round-trip latency (min/avg/max + jitter), packet loss, and
  nominal per-packet header overhead.

Results are rendered as a terminal table and written to a JSON report file.

## Protocols

| Protocol     | Kind      | How it tunnels                                    | Requires root |
|--------------|-----------|---------------------------------------------------|---------------|
| `tcp`        | stream    | plain TCP                                          | no            |
| `udp`        | datagram  | plain UDP                                          | no            |
| `tls`        | stream    | TLS over TCP (ephemeral self-signed cert)          | no            |
| `quic`       | stream    | raw QUIC bidirectional stream (quic-go)            | no            |
| `http3`      | stream    | HTTP/3 extended CONNECT, RFC 9220 (quic-go/http3)  | no            |
| `kcp`        | stream    | KCP reliable ARQ over UDP (kcp-go)                 | no            |
| `shadowsocks`| stream    | Shadowsocks AEAD AES-128-GCM stream                | no            |
| `gre`        | datagram  | GRE (RFC 2784) via raw sockets, IP protocol 47     | **yes**       |
| `ipip`       | datagram  | IP-in-IP (RFC 2003) via raw sockets, IP protocol 4 | **yes**       |
| `sit`        | datagram  | 6in4 (RFC 4213) via raw sockets, IP protocol 41    | **yes**       |
| `6to4`       | datagram  | 6to4 (RFC 3056) via raw sockets, IP protocol 41   | **yes**       |
| `geneve`     | datagram  | GENEVE (RFC 8926) over UDP (8-byte header + VNI)  | no            |
| `vxlan`      | datagram  | VXLAN (RFC 7348) over UDP (8-byte header + VNI)   | no            |
| `vxlan-gpe`  | datagram  | VXLAN-GPE over UDP (8-byte header + next protocol) | no            |
| `gue`        | datagram  | GUE over UDP (extensible header + 16-bit proto/ctype) | no            |
| `ipsec`      | datagram  | IPsec ESP-AES-GCM over UDP (RFC 3948/4106/4303)     | no            |
| `l2tp`       | datagram  | L2TPv3 data messages over UDP (RFC 3931)             | no            |
| `icmp`       | datagram  | ICMP echo (RFC 792) via raw sockets, IP protocol 1 | **yes**       |
| `icmpv6`     | datagram  | ICMPv6 (RFC 4443) via raw sockets, IP protocol 58  | **yes**       |
| `wireguard`  | datagram  | kernel WireGuard interface (`ip` + `wg` tools)     | **yes**       |
| `amnezia`    | datagram  | AmneziaWG v1 via userspace amneziawg-go over TUN   | **yes**       |
| `amnezia2`   | datagram  | AmneziaWG 2.0 (CPS concealment) via amneziawg-go  | **yes**       |
| `tap`        | datagram  | layer-2 Ethernet TAP bridged over UDP by a userspace relay | **yes** |
| `http`       | stream    | HTTP CONNECT tunnel (classic proxy tunnel)               | no            |
| `https`      | stream    | HTTP CONNECT inside TLS                                  | no            |
| `ws`         | stream    | WebSocket tunnel (RFC 6455, binary messages)             | no            |
| `wss`        | stream    | WebSocket over TLS (`wss://`)                            | no            |
| `anytls`     | stream    | AnyTLS — TLS session protocol from anytls-go             | no            |
| `naive`      | stream    | NaiveProxy — TLS + HTTP/2 CONNECT + padding (pure Go)    | no            |
| `smtp`       | stream      | SMTP tunnel — fake Postfix handshake then raw stream     | no            |
| `noise`      | stream      | Noise NNpsk0 record layer over TCP, keyed from `--password` | no          |
| `shadowtls`  | stream      | ShadowTLS v3 — TLS records tagged with a token-derived HMAC | no          |
| `trojan`     | stream      | Trojan — TLS + SHA-224(password) header, wire-compatible    | no          |

Notes:

- Layer-3 protocols (GRE/IPIP/SIT/6to4/ICMP/ICMPv6) need root/`CAP_NET_RAW`.
  The harness crafts synthetic inner IP packets with valid headers; test
  frames are the payload.
- `sit` and `6to4` share the same IPv6-in-IPv4 wire format (inner IPv6
  packet in an outer IPv4 packet, IP protocol 41) but use different inner
  addressing: `sit` (RFC 4213 6in4) stamps fixed RFC 4193 ULA addresses
  (  `fd00::1` ⇄ `fd00::2`), while `6to4` (RFC 3056) derives the inner
  addresses from the tunnel endpoints' IPv4 addresses using the well-known
  `2002::/16` prefix (`2002:V4ADDR::/48`), the classic automatic-6to4
  scheme. Both share IP protocol 41, so on a host running both servers each
  will echo the other's probes too (benign: both echo the identical frame,
  and sessions are per-client).
- `geneve` carries the test frames in GENEVE (RFC 8926) encapsulation over
  UDP. GENEVE's IANA-assigned port is 6081; the harness uses its own
  base+offset port layout so one server can host every protocol. Every
  datagram carries the 8-byte fixed GENEVE header (version/option length,
  protocol type `0x0800`, and a 24-bit VNI stamped per tunnel), and the test
  frame rides as the inner payload. Runs without root.
- `vxlan` carries the test frames in VXLAN (RFC 7348) encapsulation over
  UDP. VXLAN's IANA-assigned port is 4789; the harness uses its own
  base+offset port layout so one server can host every protocol. Every
  datagram carries the 8-byte VXLAN header (flags with the I bit set, a
  24-bit VNI stamped per tunnel), and the test frame rides in place of the
  inner Ethernet frame. Runs without root.
- `vxlan-gpe` is VXLAN with the Generic Protocol Extension
  (draft-ietf-nvo3-vxlan-gpe; RFC 9638's NVO3 encapsulation considerations
  record why GENEVE won over it): the header stays 8 bytes, but the
  24-bit reserved field becomes a 16-bit reserved field plus an 8-bit **Next
  Protocol** — the same role GENEVE's Protocol Type plays in RFC 8926, only
  encoded as an IANA registry value (IPv4 = `0x01`, IPv6 = `0x02`, Ethernet
  = `0x03`) instead of an EtherType. The I and P flags mark a valid VNI
  carrying the inner protocol; the test frame is stamped as IPv4. Runs
  without root.
- `gue` is Generic UDP Encapsulation (draft-ietf-nvo3-gue, unratified — no
  RFC): the 4-byte v0 base header `[Ver 2b][C 1b][Hlen 5b][Proto/ctype
  16b][Flags 8b]` plays the same "what is the inner payload" role as
  GENEVE's Protocol Type, but the 16-bit field holds an IANA IP protocol
  number — the draft's own data-message example stamps 94 (IPIP), and so
  does the harness. A 32-bit VNI rides in one extension word flagged by
  the first (most significant) flag bit, per the GUE extension drafts.
  Runs without root.
- `ipsec` is the only **encrypted and integrity-protected** tunnel in the
  harness: genuine ESP packets (RFC 4303) with the AES-GCM transform
  (RFC 4106) — SPI, sequence number, 8-byte IV, and a GCM tag as the ICV —
  wrapped in UDP per the NAT-Traversal scheme (RFC 3948) with the 4-byte
  non-IKE marker. Both ends share one static SA: the AES-128 key and GCM
  salt are derived from `--password` (default `tunnel-suite`), so both sides
  authenticate each other's traffic, and a wrong or missing password fails
  the handshake. No IKE is performed; the UDP encapsulation avoids raw
  sockets and the kernel's XFRM stack. Runs without root.
- `l2tp` carries the test frames in L2TPv3 (RFC 3931) data messages over
  UDP (port 1701): the session header `[flags 16b = T clear, Ver 3][reserved
  16b][Session ID 32b][Cookie 32b]`, with the cookie checked on receipt
  exactly as the RFC requires. The harness implements the data plane only —
  no control connection — so the Session ID and Cookie that real L2TPv3
  exchanges via SCCRQ/ICRQ are derived from `--password`, meaning a wrong
  password fails the session association. The test frame stands in for the
  tunneled L2 frame (the pseudowire payload). L2TPv3's direct-over-IP mode
  (protocol 115) would need raw sockets; the UDP variant runs without root.
- `icmp` looks like ordinary ping traffic: the client sends ICMP echo
  requests (type 8) carrying the test frames, and the server answers with
  echo replies (type 0) over a raw `ip4:1` socket. The kernel auto-answers
  echo requests, so the server only treats requests as client probes and the
  client only treats replies as answers; a per-tunnel id lets each end ignore
  its own transmissions, which raw loopback delivers back to the sender.
- `icmpv6` carries test frames inside ICMPv6 messages of a private type
  (200, RFC 4443 reserves 200–254 for private experimentation) over a raw
  `ip6:58` socket, so the tunnel looks like ordinary ICMPv6 control traffic.
  `--server` must resolve to an IPv6 address (or `::1`, which `127.0.0.1`
  maps to automatically for loopback runs). A per-tunnel id lets each end
  ignore its own transmissions, which raw IPv6 loopback delivers back to
  the sender.
- WireGuard uses the **kernel** implementation: both ends create a real
  `wireguard` interface, exchange keys over a control channel, and send UDP
  probes through the encrypted tunnel (internal address `10.9.0.1/24` ⇄
  `10.9.0.2/24`). Requires the `wireguard` kernel module and the
  `wireguard-tools` `wg` binary. The key exchange happens over a TCP control
  channel that client `--blind` skips entirely: both ends then use the
  **embedded known keys** and a fixed inner echo port, so the whole tunnel
  runs over UDP alone.
- AmneziaWG runs **userspace** (`amneziawg-go`): each end creates a TUN
  interface and an obfuscated AmneziaWG device, no kernel module needed. The
  obfuscation parameters (junk packets `Jc`/`Jmin`/`Jmax`, padding `S1`/`S2`,
  dynamic headers `H1`–`H4`, and for `amnezia2` the CPS concealment tags
  `I1`–`I5`/`J1`–`J3`) are fixed and identical on both ends. Internal
  addresses `10.11.0.0/24` (amnezia) and `10.12.0.0/24` (amnezia2). Like
  WireGuard, the key exchange runs over a TCP control channel that client
  `--blind` skips: both ends then use the embedded known keys and the fixed
  inner echo port, so the tunnel runs over UDP alone.
- TAP is a real **layer-2** tunnel: each end creates an Ethernet TAP
  interface (`IFF_TAP`) and a userspace relay forwards every L2 frame
  between them over UDP, forming a transparent bridge (ARP included). Test
  probes are ordinary IP packets routed through the pair of TAPs (internal
  addresses `10.13.0.1/24` ⇄ `10.13.0.2/24`). Requires root and
  `/dev/net/tun`.
- `http`/`https` are classic HTTP **CONNECT** tunnels: the client sends
  `CONNECT host:port HTTP/1.1` with a Chrome-style `User-Agent` and
  `Proxy-Connection: keep-alive`, the server answers `200 Connection
  established`, and the raw byte stream becomes the tunnel. `https` does the
  same handshake inside TLS.
- `ws`/`wss` tunnel a byte stream over WebSocket binary frames
  (`github.com/coder/websocket`); every stream write becomes one message.
- `anytls` runs the real AnyTLS session protocol in-process
  (`github.com/anytls/anytls-go`): a TLS connection carrying a custom framed
  session with a password handshake, designed to be indistinguishable from
  ordinary HTTPS. The shared password comes from `--password`.
- `naive` is a **pure-Go** reimplementation of NaiveProxy: TLS + HTTP/2
  CONNECT with Basic auth, plus the naive padding scheme (a `Padding` header
  and length-prefixed junk chunks on the first 8 chunks of each direction),
  modeled directly on the reference `caddy/forwardproxy` (naive branch)
  server. No external binaries needed.
- `smtp` is a **Go port of the smtp-tunnel-proxy** protocol: the handshake
  mimics a real Postfix submission server (`220 ... ESMTP Postfix`, EHLO
  capabilities, STARTTLS, `AUTH PLAIN` with an HMAC-SHA256 timestamped
  token, then a `BINARY` upgrade), after which the connection becomes a raw
  byte stream. It is wire-compatible with the reference Python
  implementation (username `tunnel`, secret = `--password`): a Python
  smtp-tunnel-proxy client can authenticate against the Go server and vice
  versa. The harness only exercises the echo path, not the multiplexed
  CONNECT/DATA/CLOSE proxying frames.
- `noise` is a TCP tunnel wrapped in a **Noise NNpsk0** record layer
  (`github.com/flynn/noise`, X25519 + ChaCha20-Poly1305 + SHA-256). On the
  wire the session is two short bursts of random-looking bytes (the client's
  32-byte ephemeral public key, then the server's key-and-payload message)
  followed by an encrypted byte stream that looks the same — no TLS
  ClientHello, no recognisable protocol, nothing for deep packet inspection
  to fingerprint. The 32-byte pre-shared key is derived from `--password`
  (default `tunnel-suite`), mixed into the handshake from the first message,
  so a peer without the token cannot even complete the handshake: the server
  stays silent and a port scan finds a dead port rather than a service.
  Costs a little more CPU than plain TCP for the encryption. Because the
  whole tunnel runs over plain TCP with no separate key-exchange plane, it
  works unchanged in `--blind` mode.
- `trojan` is **wire-compatible with the real Trojan protocol**: a real TLS
  handshake (ephemeral self-signed cert) followed by the classic header —
  the hex-encoded SHA-224 of `--password`, CRLF, command byte `0x01`
  (TCP connect), a SOCKS5-style address, and a trailing CRLF — after which
  the connection becomes a raw byte stream. On the wire it is
  indistinguishable from ordinary HTTPS, and a peer without the password
  fails the hash check, so the server closes without a reply and the port
  looks dead. The harness client sends a fixed `0.0.0.0:0` target (the
  forwarding plane supplies real destinations), which real Trojan servers
  accept.
- `shadowtls` implements the **ShadowTLS v3 wire format**
  (`sing-shadowtls`/`ihciah shadow-tls`): a real TLS handshake followed by
  TLS application-data records whose payloads carry a 4-byte HMAC-SHA1 tag
  and are XORed with a password-derived keystream. The v3 key-derivation
  seed (normally the decoy ServerHello random) is a 32-byte
  password-derived greeting the server sends before the TLS handshake, so
  both ends agree on the keys without a decoy site. Every post-handshake
  record is authenticated: a peer without the token fails the HMAC on the
  very first record and the server closes silently, so the port looks dead
  to scanners. Both `trojan` and `shadowtls` run over plain TCP with no
  separate key-exchange plane, so they work unchanged in `--blind` mode.
- If a protocol can't start (no privileges, no module), the server reports it
  unavailable and the client marks it **skipped** with the reason.
- `bip`, `h3`, `ss`, `wg`, `awg`/`amneziawg`, `awg2`, `l2tap`/`l2`,
  `http-connect`/`httptunnel`, `websocket`/`wstunnel`,
  `secure-websocket`/`wss-tunnel`, `any-tls`, `naiveproxy`, `icmp6`, `icmp4`,
  `ping`, `six-to-four`/`sixfour`/`six2four`, `nnpsk0`/`noisepsk`, and the
  common misspellings
  `amnesia`/`amnesia2`/`amensia`/`amensia2` are accepted as aliases
  (`awg` → `amnezia`, `awg2` → `amnezia2`, `bip` → `sit`, `icmp6` →
  `icmpv6`, `icmp4`/`ping` → `icmp`, `six-to-four` → `6to4`, `l2tap` →
  `tap`, `naiveproxy` → `naive`, `nnpsk0` → `noise`, `shadow-tls` →
  `shadowtls`, `trojangfw` → `trojan`, ...).

## Quick start

```sh
# build
go build -o tunnel-suite ./cmd/tunnel-suite

# machine A (the server)
sudo ./tunnel-suite server --listen 0.0.0.0 --protocols-base-port 10000

# machine B (the client)
./tunnel-suite client --server <server-ip> --protocols-base-port 10000
```

On the client you'll see live progress, a summary table, and a JSON report:

```
PROTOCOL  KIND  STATUS  RTT min  RTT avg  RTT max  JITTER  LOSS  HANDSHAKE  OVERHEAD
------------------------------------------------------------------------------------------------
tcp          stream    ok  0.14ms  0.32ms   2.99ms   0.24ms   0.00%  0.2ms  40B
...
wireguard    datagram  ok  0.12ms  7.75ms  43.56ms  10.86ms   0.00%  3.1ms  88B

Total: 23   OK: 23   Skipped: 0   Failed: 0

JSON report written to report-20260806-...json
```

## Usage

### Flag style

Long flags accept either a single or a double dash — `-server H`, `-tunnel-protocol
tcp`, `-blind` are the same as `--server H`, `--tunnel-protocol tcp`, `--blind`.
The generated help and shell tab-completion render the single-dash form
(`-for<TAB>` offers `-forward`; typing `--for<TAB>` still offers `--forward`).
The examples below use the conventional double-dash spelling.

### Server

```
tunnel-suite server [flags]
  --listen string            address to bind (default "0.0.0.0")
  --protocols-base-port int  base port for protocol listeners; each protocol
                             uses protocols-base-port+offset (default 10000)
  --control-port int         control/manifest port (default: the protocols base port)
  --protocols string         comma-separated subset (default: all)
  --cert, --key        TLS certificate pair (default: ephemeral self-signed)
  --ss-password string Shadowsocks password (must match the client)
  --password string    shared secret for anytls/naive/ipsec/l2tp/noise/trojan/
                       shadowtls (must match the client)
  --forward            enable relay sessions for client --mode forward|socks
```

### Client

```
tunnel-suite client [flags]
  --server string            server host or IP (required)
  --protocols-base-port int  protocols base port, must match the server (default 10000)
  --control-port int         control/manifest port (default: the protocols base
                             port; must match the server when set)
  --protocols string         comma-separated subset (default: everything the server offers)
  --pings int          probes per phase per protocol (default 50)
  --rtt-size int       latency probe size in bytes (default 64)
  --loss-size int      loss probe size in bytes (default 1200)
  --gap-ms float       pause between probes in ms (default 5)
  --timeout float      per-protocol budget in seconds (default 20)
  --json string        JSON report path (default report-<timestamp>.json)
  --ss-password string Shadowsocks password (must match the server)
  --password string    shared secret for anytls/naive/ipsec/l2tp/noise/trojan/
                       shadowtls (must match the server)
  --throughput string  comma-separated protocols to run a throughput speed
                       test against (default: none)
  --throughput-only [list]
                       run only the throughput speed tests, skipping the
                       standard benchmark; takes an optional comma-separated
                       list (--throughput-only tcp,amnezia), or bare to reuse
                       the --throughput list
  --throughput-time float  throughput test duration in seconds (default 5)
  --throughput-size int   throughput frame size in bytes (default 60000)
  --blind              probe every protocol directly, skipping the server's
                       TCP control port and the wireguard/amnezia/amnezia2
                       TCP key exchange (for servers behind a firewall that
                       blocks TCP)
  --no-color           disable ANSI colors
  --tunnel-protocol string
                      tunnel protocol for --mode forward|socks (e.g. tcp, udp, ws)
  --mode string       forward|socks: run a persistent tunnel endpoint instead
                      of the benchmark (needs --tunnel-protocol, --local-port)
  --local-port int    local listen port for forwarding mode
  --remote-host/--remote-port
                      destination for --mode forward
```

### Shell completion

The CLI is built on Cobra, so `--help` is rich and every subcommand supports
tab-completion (commands, flags and protocol names). Enable it in one step —
the command detects your shell and appends the sourcing line to its rc file
(`~/.bashrc`, `~/.zshrc`, `~/.config/fish/config.fish`, or the PowerShell
profile):

```sh
tunnel-suite completion install          # auto-detects the shell
# or explicitly: tunnel-suite completion install bash|zsh|fish|powershell
```

The managed block is idempotent (re-running only rewrites it in place) and
`tunnel-suite completion install --uninstall` removes it. You can also just
generate the script and source it manually:

```sh
source <(tunnel-suite completion bash)   # or zsh / fish / powershell
```

After that, `tunnel-suite <TAB>` completes the subcommands, and flag values
tab-complete protocol names (`--protocols=<TAB>`, `--throughput=<TAB>`,
`--throughput-only=<TAB>`).

The bash script is self-contained: it embeds the small `_get_comp_words_by_ref`
/ `_filedir` helpers it needs, so it keeps working even when the
`bash-completion` package is not installed (the script prefers the real
package when it is loaded).

### Forwarding mode

Besides benchmarking, `tunnel-suite` can carry real TCP traffic through any
of its tunnel protocols. Run the server with `--forward` (echo testing keeps
working; without the flag the server is never an open relay), then on the
client pick the tunnel protocol (`--tunnel-protocol`, any supported protocol),
how the tunnel is established and where it listens:

```sh
# fixed port forward: local 8080 -> remote 10.0.0.5:80 through a TCP tunnel
tunnel-suite client --server HOST --tunnel-protocol tcp --mode forward \
  --local-port 8080 --remote-host 10.0.0.5 --remote-port 80

# local SOCKS5 proxy through a UDP tunnel
tunnel-suite client --server HOST --tunnel-protocol udp --mode socks --local-port 1080
```

`--mode forward` forwards the local port to a fixed destination; `--mode
socks` runs a local SOCKS5 proxy whose destinations are chosen by the client
application (e.g. `curl --socks5-hostname 127.0.0.1:1080 ...`).

By default the tunnel is dialed at `--protocols-base-port` plus the chosen
protocol's offset. Add `--control-port` to instead discover the exact tunnel
port from the server's manifest — the client then dials whatever port the
server actually reports for the protocol, which is handy when the server was
configured with its own `--control-port` and a shifted base:

```sh
tunnel-suite client --server HOST --tunnel-protocol smtp --mode forward \
  --protocols-base-port 11580 --control-port 11606 \
  --local-port 2060 --remote-host 127.0.0.1 --remote-port 11612
```

### Installing as a systemd service

Use the `install` subcommand to write a systemd unit and start it with
`systemctl enable --now` (needs root; add `--user` for a per-user service,
`--dry-run` to preview the unit without touching the system):

```sh
sudo tunnel-suite install server --protocols-base-port 20000
sudo tunnel-suite install client --server HOST --tunnel-protocol tcp \
  --mode forward --local-port 8080 --remote-host 10.0.0.5 --remote-port 80
tunnel-suite install server --dry-run                    # preview only
tunnel-suite install client --uninstall                  # just the unit name
```

`install server` writes a unit that runs the server with relay enabled by
default. For the client, the tunnel protocol (`--tunnel-protocol`, any
supported protocol), the mode (`--mode forward|socks`) and the local port
(`--local-port`) are required. Add `--control-port` to make the installed
client discover the tunnel port from the server's manifest instead of
computing `--protocols-base-port` + offset. `--name` sets a custom systemd
unit name; `--uninstall` only needs that name, so the endpoint flags are not
required to remove the service again.

To remove services again, use the `uninstall` subcommand. It scans the unit
directory for the services tunnel-suite installed and **confirms before
removing anything** (the services are listed and you answer y/N):

```sh
sudo tunnel-suite uninstall                     # remove every tunnel-suite service
sudo tunnel-suite uninstall tunnel-suite-server # remove just one (or more, by name)
sudo tunnel-suite uninstall --yes               # skip the confirmation (scripts)
tunnel-suite uninstall --user                   # per-user services instead
sudo tunnel-suite uninstall --dry-run           # list what would be removed
```

The confirmation lists exactly what will be removed; `--yes` (or `-y`)
skips it for scripts, and when stdin is not a terminal the command fails
closed and asks for `--yes` instead of removing anything unattended.
Service names tab-complete from the ones actually installed
(`tunnel-suite uninstall tunnel-s<TAB>`), the `.service` suffix is optional,
and any name not installed is rejected with a hint of what is. Discovery is
by content (every installed unit references `tunnel-suite`), so custom
`--name` units and even renamed binaries are found — services belonging to
other software are never touched.

#### System vs `--user` services

`install server` and `install client` write a systemd unit and start it with
`systemctl enable --now`. Without `--user` the unit is a **system** service;
with `--user` it becomes a **per-user** service:

|                        | system (default)                   | `--user`                            |
|------------------------|------------------------------------|-------------------------------------|
| unit file              | `/etc/systemd/system/…service`     | `~/.config/systemd/user/…service`   |
| needs root             | yes (`sudo`)                       | no                                  |
| starts when            | **boot** (`multi-user.target`)     | **login** (`default.target`)        |
| controlling command    | `systemctl …`                      | `systemctl --user …`                |
| environment            | minimal, clean                     | inherits your login session         |
| logs                   | `journalctl -u …`                  | `journalctl --user -u …`            |

A `--user` service is enabled just like a system one, but the user systemd
session only exists once you log in — so after a reboot it stays dormant
until login. To make user services start at boot without a login, enable
*lingering* for the account:

```sh
loginctl enable-linger "$USER"     # user services now start at boot
loginctl disable-linger "$USER"    # revert
```

Rule of thumb: the **server** on a VPS should be a system service (no
`--user`, starts at boot, no login needed); a **client** tunnel on a machine
you log into can be either — `--user` (plus optional linger) keeps it
root-free. `--dry-run` prints the exact unit and commands either way.

### Blind mode (TCP fully blocked)

The client normally fetches the server's protocol manifest from the control
port (TCP). `--blind` skips that, probes every protocol at its standard
protocols-base-port offset, and — for `wireguard`/`amnezia`/`amnezia2` — also
skips the TCP key-exchange handshake: both ends use **embedded known keys**
and a **fixed inner echo port**, so those tunnels establish over UDP alone.
The `--throughput` speed test dials through the same path, so in blind mode
the WireGuard family's speed test also runs over UDP alone — zero TCP (the
client plumbing routes `--blind` to both the standard benchmark and the
speed test). This is meant for servers behind a firewall that filters TCP on
the control port (and often on the protocol control ports too). Protocols
whose dial or handshake cannot complete show as `skipped` with the reason,
and every dial is internally time-bounded so the run always finishes. Note
the known keys are public constants compiled into the binary — the harness
is a benchmark tool, not a secure VPN.

### Port layout

Two independent knobs place the listeners: `--protocols-base-port` anchors the
protocol ports (each protocol binds `protocols-base-port` plus its offset
below), and `--control-port` is the manifest's TCP port. The control port
defaults to the protocols base port, so the classic layout is unchanged:
manifest at `base+0`, protocols starting at `base+1`. Pass `--control-port`
to move the manifest independently — e.g. a fixed public control port while
the protocol ports shift freely, or the other way around. The server refuses
to start if the control port collides with a protocol's TCP listener, and the
JSON report records both (`protocols_base_port`, `control_port`).

| offset | use                          |
|-------:|------------------------------|
| +0     | control / manifest (TCP)     |
| +1 … +7 | tcp, udp, tls, quic, http3, kcp, shadowsocks |
| +8 … +10 | gre, ipip, sit (raw sockets; ports are bookkeeping) |
| +11    | icmpv6 (raw socket; port is bookkeeping) |
| +12 … +13 | wireguard control / data (UDP) |
| +14 … +15 | amnezia control / data (UDP) |
| +16 … +17 | amnezia2 control / data (UDP) |
| +18 … +19 | tap relay / echo (UDP)         |
| +19 … +24 | http, https, ws, wss, anytls, naive |
| +25       | smtp tunnel                    |
| +26       | icmp (raw socket; port is bookkeeping) |
| +27       | 6to4 (raw socket; port is bookkeeping)  |
| +28       | geneve (UDP)                            |
| +29       | vxlan (UDP)                            |
| +30       | vxlan-gpe (UDP)                        |
| +31       | gue (UDP)                              |
| +32       | ipsec (UDP, ESP NAT-T)                  |
| +33       | l2tp (UDP, L2TPv3 data messages)         |
| +34       | noise (TCP)                              |
| +35       | shadowtls (TCP)                          |
| +36       | trojan (TCP)                             |

## How a test works

Every protocol implements the same interface:

- **Server side** — `Listen(addr)` binds, then `Accept()` hands over one
  `Tunnel` per test session; an echo loop reflects every received frame back.
- **Client side** — `Dial(addr)` establishes the tunnel, then the benchmark
  sends probes:

  1. **Handshake** — time from dial start to the first echoed frame. For
     TLS/QUIC this includes the full cryptographic handshake; for WireGuard it
     includes the handshake ratchet; for raw datagrams it is the first round
     trip.
  2. **Latency** — `--pings` round trips of `--rtt-size` bytes; reports
     min/avg/max and jitter (mean absolute deviation between consecutive RTTs).
  3. **Loss** — `--pings` datagrams of `--loss-size` bytes; percentage of
     missing echoes. Reliable stream transports report 0% by design.
  4. **Overhead** — nominal header bytes per packet (no IP options).

Probe frames are self-describing: `[type][seq][nanosecond timestamp][padding]`,
so the echo can be matched by sequence number even on lossy datagram tunnels.

### Throughput speed test

Passing `--throughput tcp,udp,...` runs a speed test for exactly those
protocols — the speed test is never run for unlisted protocols. By default it
runs after the standard benchmark; add `--throughput-only` to run nothing but
the speed tests. `--throughput-only` can carry the list itself, so
`--throughput-only tcp,amnezia` is shorthand for
`--throughput tcp,amnezia --throughput-only`. The client blasts large frames
at the server for `--throughput-time` seconds while the server's echo loop
returns them, then
reports the achieved **upload** (client→server) and **download** (server→client
echo) rates in Mbps, plus frame loss and the volume transferred:

```
tunnel-suite client --server <ip> --protocols-base-port 10000 --throughput tcp,wireguard --throughput-time 10

THROUGHPUT — echo test, 10.0s @ 60000B frames
PROTOCOL  KIND  STATUS  UPLOAD     DOWNLOAD   LOSS    DATA
tcp       stream  ok   912.4 Mbps  910.1 Mbps  0.00%  1.1 GB up / 1.1 GB down
```

To skip the standard benchmark entirely, `--throughput-only` takes the list
directly (bare, it reuses the `--throughput` list):

```
tunnel-suite client --server <ip> --protocols-base-port 10000 --throughput-only tcp,wireguard --throughput-time 10
```

A typical full run — benchmark **all** protocols (the client default is
everything the server offers) and speed-test a chosen set:

```sh
# on the server
sudo tunnel-suite server --protocols-base-port 10000

# on the client: benchmark all protocols + speed-test a chosen set
sudo tunnel-suite client --server <server-ip> --protocols-base-port 10000 \
  --throughput tcp,udp,icmp,icmpv6,gre,ipip,sit,tls,quic \
  --throughput-time 5
```

> **Benchmark vs speed test.** The standard benchmark always runs for every
> protocol the server offers — `wireguard`, `amnezia`, and `amnezia2`
> included (pass `--protocols` only to narrow it down). The speed test is
> **opt-in per protocol**, so to speed-test the wireguard family too, add
> their names to `--throughput`:
>
> ```sh
> tunnel-suite client --server <server-ip> --protocols-base-port 10000 \
>   --throughput tcp,udp,icmp,icmpv6,gre,ipip,sit,tls,quic,wireguard,amnezia,amnezia2 \
>   --throughput-time 5
> ```
>
> `wireguard`/`amnezia`/`amnezia2` need root, `iproute2` (`ip`),
> `wireguard-tools` (`wg`), and `/dev/net/tun` — otherwise they are reported
> **skipped**. With `--blind` their speed test also runs over UDP alone, like
> the benchmark (see *Blind mode* above).
>
> **Raw protocols and the MTU:** over a real network, raw layer-3 protocols
> (`icmp`, `icmpv6`, `gre`, `ipip`, `sit`, `6to4`) send each frame as a
> single **unfragmented** raw IP packet, so a frame larger than the path MTU
> fails immediately at the socket (`sendmsg: message too long`). The client
> now **auto-clamps** the throughput frame to 1400 bytes for these protocols
> (the report notes it), so `--throughput-only gre` works out of the box;
> `--throughput-size 1400` is what the clamp uses. `--throughput-size 60000`
> still applies to everything else, and 60000-byte frames remain fine on
> loopback.
>
> **What the throughput LOSS column really measures.** The reader keeps
> counting echoed frames for a short grace period after the blast deadline
> (so frames still in flight are counted, not reported lost), read buffers
> are reused, and datagram sockets request 4 MiB kernel buffers. Two
> remaining effects are real, not artifacts: over a real network a 60000-byte
> UDP datagram is ~41 IP fragments and losing any one fragment drops the
> whole datagram (use `--throughput-size 1400` to remove the amplification),
> and on loopback the client can blast faster than the server's echo loop
> can reflect, so kernel buffer drops show up there too (on a real WAN the
> blast is capped well below the server's echo capacity). The kernel clamps
> socket buffers to `net.core.rmem_max`/`wmem_max`; on hosts where those are
> tiny (often 208 KiB) raise them for high-rate datagram tests:
>
> ```sh
> sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
> ```

Because the server echoes, the test exercises both directions at once; on an
asymmetric path the slower direction bounds both rates. Throughput results are
also included in the JSON report under `throughput`.

## Project layout

```
cmd/tunnel-suite/        CLI entry point (server/client subcommands)
internal/protocol/      Tunnel/Protocol interfaces, framing, registry,
                        and one file per protocol (tcp, udp, tls, quic,
                        h3, kcp, shadowsocks, gre, ipip, sit, 6to4, geneve,
                        vxlan, vxlan-gpe, gue, ipsec, l2tp, icmp, icmpv6,
                        wireguard, amnezia, amnezia2, tap,
                        http, https, ws, wss, anytls, naive, smtp, noise,
                        shadowtls, trojan)
internal/benchmark/     the test runner (handshake/latency/loss metrics)
internal/report/        result model, terminal table, JSON serialization
internal/server/        server orchestration: listeners, echo loops, manifest
internal/client/        client orchestration: discovery + benchmark dispatch
```

## Adding a protocol

1. Implement the `Protocol` interface (see `internal/protocol/protocol.go`):
   `Name`, `Kind` (`stream` or `datagram`), `Overhead`, `NeedsRoot`, `Listen`,
   `Dial`.
2. Register it in `All()` and give it a port offset in
   `internal/protocol/registry.go`.
3. That's it — the benchmark, reporting and CLI pick it up automatically.

## Security notes

- The harness generates an ephemeral self-signed TLS certificate and the
  client skips certificate validation — **do not use it to tunnel sensitive
  data**; it is a test instrument.
- WireGuard and raw protocols require elevated privileges and create real
  network interfaces on the host. Interfaces are removed on teardown.
- The Shadowsocks password defaults to a well-known value; pass `--ss-password`
  on both ends if you care about the encryption key.

## Requirements

- Go 1.24+
- Linux (raw sockets + kernel WireGuard require Linux)
- root or `CAP_NET_RAW` for `gre`/`ipip`/`sit`/`icmp`/`icmpv6`/`wireguard`/`amnezia`/`amnezia2`/`tap`
- `iproute2` (`ip`) for WireGuard/AmneziaWG/TAP
- `wireguard-tools` (`wg`) for the kernel WireGuard protocol
- `/dev/net/tun` for the userspace AmneziaWG protocols and the TAP tunnel
