package protocol

import (
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestStaticKeysForCoverage ensures every WireGuard-family protocol has
// embedded known keys (used by client --blind to skip the TCP key exchange).
func TestStaticKeysForCoverage(t *testing.T) {
	for _, name := range []string{"wireguard", "amnezia", "amnezia2"} {
		k := staticKeysFor(name)
		if len(k.serverPriv) == 0 || len(k.serverPub) == 0 || len(k.clientPriv) == 0 || len(k.clientPub) == 0 {
			t.Errorf("staticKeysFor(%q) returned an incomplete key set", name)
		}
	}
	if k := staticKeysFor("tcp"); k.serverPriv != "" || k.clientPub != "" {
		t.Errorf("staticKeysFor(tcp) should return a zero value, got %+v", k)
	}
}

// TestStaticKeysAreValidPairs derives each embedded public key from its
// private key, so a typo in a hex literal can never silently break the
// blind-mode tunnel (handshakes would just fail).
func TestStaticKeysAreValidPairs(t *testing.T) {
	for name, k := range map[string]staticKeys{
		"wireguard": staticWg,
		"amnezia":   staticAmnezia,
		"amnezia2":  staticAmnezia2,
	} {
		for _, pair := range []struct {
			label  string
			privB  []byte
			pubHex string
		}{
			{"server", k.serverPrivBytes(), k.serverPub},
			{"client", k.clientPrivBytes(), k.clientPub},
		} {
			got, err := curve25519.X25519(pair.privB, curve25519.Basepoint)
			if err != nil {
				t.Fatalf("%s/%s: X25519: %v", name, pair.label, err)
			}
			want := k.serverPubBytes()
			if pair.label == "client" {
				want = k.clientPubBytes()
			}
			if string(got) != string(want) {
				t.Errorf("%s/%s: public key does not match private key", name, pair.label)
			}
		}
	}
}
