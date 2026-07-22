package config

import "github.com/layou233/zbproxy/v3/common/network"

type Outbound struct {
	Name                 string                         `json:",omitempty"`
	Dialer               string                         `json:",omitempty"`
	TargetAddress        string                         `json:",omitempty"`
	TargetPort           uint16                         `json:",omitempty"`
	Minecraft            *MinecraftService              `json:",omitempty"`
	SocketOptions        *network.OutboundSocketOptions `json:",omitempty"`
	ProxyProtocolVersion int8                           `json:",omitempty"`
	ProxyOptions         proxyOptions                   `json:",omitempty"`
	// SendAuthSecret sends Root.AuthSecret as the first bytes after dial
	// (before PROXY protocol). Enable only for outbounds that target another
	// ZBProxy with RequireAuthSecret; never enable toward public game servers.
	SendAuthSecret bool `json:",omitempty"`
}
