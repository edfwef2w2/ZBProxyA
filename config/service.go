package config

import "github.com/layou233/zbproxy/v3/common/network"

type Service struct {
	Name          string
	TargetAddress string `json:",omitempty"`
	TargetPort    uint16 `json:",omitempty"`
	// Listen is the TCP listen port (legacy field name, always the TCP port).
	Listen uint16
	// ListenUDP is the UDP tunnel listen port. 0 = UDP inbound disabled.
	ListenUDP uint16 `json:"ListenUDP"`

	// EnableTCP enables TCP accept on Listen. Legacy configs with both flags false → TCP on.
	EnableTCP bool `json:"EnableTCP"`
	// EnableUDP enables UDP tunnel accept on ListenUDP (requires ListenUDP > 0).
	EnableUDP bool `json:"EnableUDP"`

	EnableProxyProtocol bool `json:",omitempty"`
	// RequireAuthSecret enables inbound pre-shared-key verification using Root.AuthSecret.
	RequireAuthSecret bool                          `json:"RequireAuthSecret"`
	IPAccess          access                        `json:",omitempty"`
	Minecraft         *MinecraftService             `json:",omitempty"`
	TLSSniffing       *tlsSniffing                  `json:",omitempty"`
	SocketOptions     *network.InboundSocketOptions `json:",omitempty"`
	Outbound          proxyOptions                  `json:",omitempty"`
}

// TCPEnabled reports whether TCP inbound should run.
// Old configs leave EnableTCP/EnableUDP false → TCP only.
func (s *Service) TCPEnabled() bool {
	if s.EnableTCP || s.EnableUDP {
		return s.EnableTCP
	}
	return true
}

// UDPEnabled reports whether UDP tunnel inbound should run.
func (s *Service) UDPEnabled() bool {
	return s.EnableUDP && s.ListenUDP > 0
}

type access struct {
	Mode      string   // 'accept' or 'deny' or empty
	ListTags  []string `json:",omitempty"`
	LowerCase bool     `json:",omitempty"`
}

type MinecraftService struct {
	EnableHostnameRewrite bool   `json:",omitempty"`
	RewrittenHostname     string `json:",omitempty"`

	OnlineCount onlineCount

	IgnoreFMLSuffix   bool `json:",omitempty"`
	IgnoreSRVRedirect bool `json:",omitempty"`

	HostnameAccess access `json:",omitempty"`
	NameAccess     access `json:",omitempty"`

	PingMode        string
	MotdFavicon     string
	MotdDescription string
}

type onlineCount struct {
	Max            int32
	Online         int32
	EnableMaxLimit bool
	Sample         any `json:",omitempty"`
}

type tlsSniffing struct {
	RejectNonTLS     bool
	RejectIfNonMatch bool     `json:",omitempty"`
	SNIAllowListTags []string `json:",omitempty"`
}

type proxyOptions struct {
	Type    string `json:",omitempty"`
	Network string `json:",omitempty"`
	Address string `json:",omitempty"`
}
