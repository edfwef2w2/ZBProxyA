package udptunnel

import "time"

const (
	// Magic is ASCII "ZB".
	Magic uint16 = 0x5A42
	// Version of the framing protocol.
	Version uint8 = 1

	HeaderSize = 2 + 1 + 1 + 8 + 4 + 4 + 2 // 22 bytes

	// MaxPayload keeps datagrams under typical Ethernet MTU with IP/UDP headers.
	MaxPayload = 1200
	// MaxInFlight is the send/recv window in frames per session (memory bound).
	MaxInFlight = 32
	// MaxSessions caps concurrent tunnels per listener (256 MiB friendly).
	MaxSessions = 256

	// DefaultIdleTimeout recycles dead sessions.
	DefaultIdleTimeout = 90 * time.Second
	// DefaultDialTimeout for SYN handshake.
	DefaultDialTimeout = 5 * time.Second
	// DefaultRTO initial retransmit timeout.
	DefaultRTO = 200 * time.Millisecond
	// MaxRTO caps exponential backoff.
	MaxRTO = 2 * time.Second
	// ProbeTimeout for PING/PONG and lightweight TCP dial probes.
	ProbeTimeout = 1500 * time.Millisecond
)

// Frame types.
const (
	TypeSYN     uint8 = 1
	TypeSYNACK  uint8 = 2
	TypeDATA    uint8 = 3
	TypeACK     uint8 = 4
	TypeFIN     uint8 = 5
	TypeRST     uint8 = 6
	TypePING    uint8 = 7
	TypePONG    uint8 = 8
)
