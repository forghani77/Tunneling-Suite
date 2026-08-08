package protocol

import "encoding/hex"

// innerEchoPort is the fixed, well-known inner UDP port that the WireGuard /
// AmneziaWG servers bind their echo listener to (on each family's internal
// address: 10.9.0.1, 10.11.0.1, 10.12.0.1). In normal mode the TCP handshake
// reports it to the client; in blind mode (TCP blocked) the client uses this
// constant directly. It must match on both ends, like the keys below. Note it
// must stay outside the outer base-port range (base+0 … base+33) so the echo
// bind can never collide with a wildcard outer listener on the same host
// (with the default --base-port 10000 the outer ports are 10000–10033).
const innerEchoPort = 34567

// staticKeys holds one protocol family's embedded, well-known Curve25519
// keypair pair. Every tunnel-suite peer agrees on these without any exchange,
// exactly like the AmneziaWG obfuscation parameters and the default protocol
// password — they exist so the harness can skip its TCP control plane when
// the server sits behind a firewall that blocks TCP (client --blind).
//
// They are NOT security credentials: they are public constants compiled into
// the binary, so a determined attacker who knows them could impersonate a
// peer. The harness is a benchmark tool, not a secure VPN.
type staticKeys struct {
	serverPriv, serverPub string // hex
	clientPriv, clientPub string // hex
}

var (
	staticWg = staticKeys{
		serverPriv: "b007cc327b2bfbfe1d9a59de581317f1b0d0ab7fe7f158e836f5063b4c448a56",
		serverPub:  "3ab4e66522c936d17562d35777845d3eea38374768e3327cde6cf78126fdf413",
		clientPriv: "00e26252391ce9d9e4ad61d7218bcb409c24c99491471ad70c98b8b26123e25e",
		clientPub:  "97027102a3cb71b1600cd4edb77e1d63edacc81dc8c60d2e00a123e5fb4a286d",
	}
	staticAmnezia = staticKeys{
		serverPriv: "288ceae37bebc631c2164ab410bc7a297736575f6f5fb34db6a7ea60672ba474",
		serverPub:  "049bd5b1d114d68f263aace59c94f81d26166db468849a44dd4c1594353f4050",
		clientPriv: "98888e588592827ea03eedbd9f626e9a7ba699b59cb118d326e8a7325e8a6d4a",
		clientPub:  "1b6bc4f86a8e7967006717a8b7afe1441498bc499c4137baa8505063fde1e97b",
	}
	staticAmnezia2 = staticKeys{
		serverPriv: "081f7888e6e19b511b092130613b3b5bd2418e6c32198f8394d2a9532f3a415d",
		serverPub:  "73de07e3b8687bbd9efdfed60a796a3654eed67d3bbb5d123b771d695072f17a",
		clientPriv: "007bbb7b2b617b794e6e78fc4a75589a6562ac7dfb380cb1539d635f3ce3ec77",
		clientPub:  "d9975883f4ca5f16b553ad74b85349f83a8660432480d7a93617fb22289bff35",
	}
)

// staticKeysFor returns the embedded known keys for a WireGuard-family
// protocol, or a zero value for anything else.
func staticKeysFor(name string) staticKeys {
	switch name {
	case "wireguard":
		return staticWg
	case "amnezia":
		return staticAmnezia
	case "amnezia2":
		return staticAmnezia2
	}
	return staticKeys{}
}

func (k staticKeys) serverPrivBytes() []byte { b, _ := hex.DecodeString(k.serverPriv); return b }
func (k staticKeys) serverPubBytes() []byte  { b, _ := hex.DecodeString(k.serverPub); return b }
func (k staticKeys) clientPrivBytes() []byte { b, _ := hex.DecodeString(k.clientPriv); return b }
func (k staticKeys) clientPubBytes() []byte  { b, _ := hex.DecodeString(k.clientPub); return b }
