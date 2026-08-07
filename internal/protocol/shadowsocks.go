package protocol

import (
	"github.com/shadowsocks/go-shadowsocks2/core"
)

// DefaultSSPassword is used when no password is configured on either side.
const DefaultSSPassword = "tunnel-suite-test-password"

// ssProto tunnels bytes through a Shadowsocks AEAD (AES-128-GCM) stream.
type ssProto struct{}

func (ssProto) Name() string    { return "shadowsocks" }
func (ssProto) Kind() Kind      { return KindStream }
func (ssProto) Overhead() int   { return 46 } // TCP 40 + 2 length + 16 AEAD tag
func (ssProto) NeedsRoot() bool { return false }

func ssPassword(opts Options) string {
	if opts.SSPassword != "" {
		return opts.SSPassword
	}
	return DefaultSSPassword
}

func (ssProto) Listen(addr string, opts Options) (ProtoServer, error) {
	ciph, err := core.PickCipher("AEAD_AES_128_GCM", nil, ssPassword(opts))
	if err != nil {
		return nil, err
	}
	ln, err := core.Listen("tcp", addr, ciph)
	if err != nil {
		return nil, err
	}
	return &streamServer{ln: ln}, nil
}

func (ssProto) Dial(addr string, opts Options) (Tunnel, error) {
	ciph, err := core.PickCipher("AEAD_AES_128_GCM", nil, ssPassword(opts))
	if err != nil {
		return nil, err
	}
	c, err := core.Dial("tcp", addr, ciph)
	if err != nil {
		return nil, err
	}
	return newStreamTunnel(c, "shadowsocks://"+addr), nil
}
