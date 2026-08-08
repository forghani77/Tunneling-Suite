package protocol

import "strings"

// Port offsets relative to --protocols-base-port. PortControl (+0) is the
// historical manifest slot: the control port is now configured explicitly
// (--control-port, defaulting to the protocols base port), so base+PortControl
// is no longer computed — the constant stays as the +0 anchor of this iota
// sequence.
const (
	PortControl         = iota // +0: manifest / control (TCP, historical default slot)
	PortTCP                    // +1
	PortUDP                    // +2
	PortTLS                    // +3
	PortQUIC                   // +4
	PortH3                     // +5
	PortKCP                    // +6
	PortSS                     // +7
	PortGRE                    // +8: raw socket (port is bookkeeping only)
	PortIPIP                   // +9
	PortSIT                    // +10
	PortICMPv6                 // +11: raw IPv6 socket (port is bookkeeping only)
	PortWGControl              // +12: WireGuard key exchange
	PortWGData                 // +13: WireGuard UDP listener
	PortAmneziaControl         // +14: AmneziaWG key exchange
	PortAmneziaData            // +15: AmneziaWG UDP listener
	PortAmnezia2Control        // +16: AmneziaWG 2.0 key exchange
	PortAmnezia2Data           // +17: AmneziaWG 2.0 UDP listener
	PortTap                    // +18: TAP L2 relay UDP socket (+19: echo)
	PortHTTP                   // +19: HTTP CONNECT tunnel
	PortHTTPS                  // +20: HTTPS CONNECT tunnel
	PortWS                     // +21: WebSocket tunnel
	PortWSS                    // +22: WebSocket over TLS
	PortAnyTLS                 // +23: AnyTLS
	PortNaive                  // +24: NaiveProxy
	PortSMTP                   // +25: SMTP tunnel
	PortICMP                   // +26: raw IPv4 socket (port is bookkeeping only)
	PortSixToFour              // +27: raw IPv4 socket (port is bookkeeping only)
	PortGeneve                 // +28: GENEVE (UDP)
	PortVXLAN                  // +29: VXLAN (UDP)
	PortVXLANGpe               // +30: VXLAN-GPE (UDP)
	PortGUE                    // +31: GUE (UDP)
	PortIPsec                  // +32: IPsec ESP over UDP (NAT-T)
	PortL2TP                   // +33: L2TPv3 (UDP)
	PortNoise                  // +34: Noise NNpsk0 (TCP)
)

// All returns the full protocol registry in deterministic (port) order.
func All() []Protocol {
	return []Protocol{
		tcpProto{},
		udpProto{},
		tlsProto{},
		quicProto{},
		h3Proto{},
		kcpProto{},
		ssProto{},
		greProto{},
		ipipProto{},
		sitProto{},
		icmp6Proto{},
		wgProto{},
		amneziaProto{awgV1},
		amneziaProto{awgV2},
		tapProto{},
		httpProto{},
		httpsProto{},
		wsProto{},
		wssProto{},
		anytlsProto{},
		naiveProto{},
		smtpProto{},
		icmpProto{},
		sixToFourProto{},
		geneveProto{},
		vxlanProto{},
		vxlanGpeProto{},
		gueProto{},
		ipsecProto{},
		l2tpProto{},
		noiseProto{},
	}
}

// EffectiveControlPort returns the control/manifest port for a run: the
// explicitly configured port when non-zero, otherwise the protocols base port
// (preserving the classic layout where the manifest sits at base+0).
func EffectiveControlPort(controlPort, protocolsBasePort int) int {
	if controlPort != 0 {
		return controlPort
	}
	return protocolsBasePort
}

// PortOffset returns the port offset (relative to the base port) for a
// protocol's main listener. WireGuard's data listener is offset+1.
func PortOffset(p Protocol) int {
	switch p.Name() {
	case "tcp":
		return PortTCP
	case "udp":
		return PortUDP
	case "tls":
		return PortTLS
	case "quic":
		return PortQUIC
	case "http3":
		return PortH3
	case "kcp":
		return PortKCP
	case "shadowsocks":
		return PortSS
	case "gre":
		return PortGRE
	case "ipip":
		return PortIPIP
	case "sit":
		return PortSIT
	case "icmpv6":
		return PortICMPv6
	case "wireguard":
		return PortWGControl
	case "amnezia":
		return PortAmneziaControl
	case "amnezia2":
		return PortAmnezia2Control
	case "tap":
		return PortTap
	case "http":
		return PortHTTP
	case "https":
		return PortHTTPS
	case "ws":
		return PortWS
	case "wss":
		return PortWSS
	case "anytls":
		return PortAnyTLS
	case "naive":
		return PortNaive
	case "smtp":
		return PortSMTP
	case "icmp":
		return PortICMP
	case "6to4":
		return PortSixToFour
	case "geneve":
		return PortGeneve
	case "vxlan":
		return PortVXLAN
	case "vxlan-gpe":
		return PortVXLANGpe
	case "gue":
		return PortGUE
	case "ipsec":
		return PortIPsec
	case "l2tp":
		return PortL2TP
	case "noise":
		return PortNoise
	}
	return -1
}

var (
	allByName map[string]Protocol
	allOrder  []string
)

func init() {
	allByName = make(map[string]Protocol)
	for _, p := range All() {
		allByName[p.Name()] = p
		allOrder = append(allOrder, p.Name())
	}
}

// ByName resolves a protocol by name.
func ByName(name string) (Protocol, bool) {
	p, ok := allByName[strings.ToLower(name)]
	return p, ok
}

// Names returns all protocol names in registry order.
func Names() []string { return append([]string(nil), allOrder...) }

// NameAliases maps common alternative spellings to canonical names.
var NameAliases = map[string]string{
	"bip":              "sit", // SIT/6in4 is often written "bip" or "ip6ip"
	"icmp6":            "icmpv6",
	"h3":               "http3",
	"ss":               "shadowsocks",
	"wg":               "wireguard",
	"awg":              "amnezia",
	"amneziawg":        "amnezia",
	"awg2":             "amnezia2",
	"amnesia":          "amnezia", // common misspelling
	"amnesia2":         "amnezia2",
	"amensia":          "amnezia",
	"amensia2":         "amnezia2",
	"l2tap":            "tap",
	"l2":               "tap",
	"tapvpn":           "tap",
	"http-connect":     "http",
	"httptunnel":       "http",
	"secure-http":      "https",
	"websocket":        "ws",
	"wstunnel":         "ws",
	"secure-websocket": "wss",
	"wss-tunnel":       "wss", "any-tls": "anytls",
	"naiveproxy":  "naive",
	"naive-proxy": "naive",
	"smtptunnel":  "smtp",
	"smtp-tunnel": "smtp",
	"smtps":       "smtp",
	"icmp4":       "icmp",
	"icmpv4":      "icmp",
	"ping":        "icmp",
	"six-to-four": "6to4",
	"sixfour":     "6to4",
	"six2four":    "6to4",
	"rfc3056":     "6to4",
	"vxlangpe":    "vxlan-gpe",
	"vxgpe":       "vxlan-gpe",
	"gpe":         "vxlan-gpe",
	"l2tpv3":      "l2tp",
	"l2tp-v3":     "l2tp",
	"nnpsk0":      "noise",
	"nn-psk0":     "noise",
	"noisepsk":    "noise",
}

// NormalizeName canonicalizes a user-supplied protocol name.
func NormalizeName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if canon, ok := NameAliases[n]; ok {
		return canon
	}
	return n
}
