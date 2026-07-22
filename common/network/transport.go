package network

// NormalizeTransport returns tcp|udp|auto.
// dialNetwork is a legacy alias: "udp" -> udp, else empty.
func NormalizeTransport(transport, dialNetwork string) string {
	switch transport {
	case "tcp", "udp", "auto":
		return transport
	case "":
		// legacy DialNetwork
		if dialNetwork == "udp" {
			return "udp"
		}
		return "tcp"
	default:
		return "tcp"
	}
}
