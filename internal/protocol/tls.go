package protocol

import (
	"crypto/tls"
	"net"
)

// tlsProto tunnels bytes over TLS 1.3 (or the highest mutually supported
// version) on top of TCP.
type tlsProto struct{}

func (tlsProto) Name() string    { return "tls" }
func (tlsProto) Kind() Kind      { return KindStream }
func (tlsProto) Overhead() int   { return 45 } // 20 IP + 20 TCP + 5 TLS record
func (tlsProto) NeedsRoot() bool { return false }

func (tlsProto) Listen(addr string, opts Options) (ProtoServer, error) {
	cert, err := loadOrGenerateCert(opts)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return &streamServer{ln: ln}, nil
}

func (tlsProto) Dial(addr string, opts Options) (Tunnel, error) {
	// The harness owns both ends and uses an ephemeral self-signed cert, so
	// the client deliberately skips certificate validation. DialWithDialer
	// bounds the TCP connect and the TLS handshake together, so a service
	// squatting on the port that accepts TCP but never speaks TLS cannot
	// hang the probe forever.
	cfg := &tls.Config{InsecureSkipVerify: true}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: connTimeout}, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return newStreamTunnel(c, "tls://"+addr), nil
}
