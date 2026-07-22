package config

import (
	"time"

	"github.com/layou233/zbproxy/v3/common/network"
)

type Outbound struct {
	Name                 string                         `json:",omitempty"`
	Dialer               string                         `json:",omitempty"`
	TargetAddress        string                         `json:",omitempty"`
	TargetPort           uint16                         `json:",omitempty"`
	// UDPTargetPort is the peer UDP tunnel port. 0 = UDP path disabled.
	UDPTargetPort uint16 `json:"UDPTargetPort"`
	// Transport: "tcp" | "udp" | "auto". Default tcp. "auto" probes both paths.
	Transport string `json:"Transport"`
	// DialNetwork is a legacy alias: "udp" means Transport=udp when Transport empty.
	DialNetwork string `json:"DialNetwork,omitempty"`
	// TransportProbeInterval for auto mode, e.g. "10s".
	TransportProbeInterval string `json:"TransportProbeInterval"`

	Minecraft            *MinecraftService              `json:",omitempty"`
	SocketOptions        *network.OutboundSocketOptions `json:",omitempty"`
	ProxyProtocolVersion int8                           `json:",omitempty"`
	ProxyOptions         proxyOptions                   `json:",omitempty"`
	// SendAuthSecret sends Root.AuthSecret as the first stream bytes after dial.
	SendAuthSecret bool `json:"SendAuthSecret"`
}

// ResolvedTransport returns tcp|udp|auto.
func (o *Outbound) ResolvedTransport() string {
	return network.NormalizeTransport(o.Transport, o.DialNetwork)
}

// ProbeInterval parses TransportProbeInterval with defaults.
func (o *Outbound) ProbeInterval() time.Duration {
	if o.TransportProbeInterval == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(o.TransportProbeInterval)
	if err != nil || d < 3*time.Second {
		return 10 * time.Second
	}
	if d > 60*time.Second {
		return 60 * time.Second
	}
	return d
}
