package udptunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Dial creates a tunnel session to address (host:port) over UDP.
func Dial(ctx context.Context, address string) (net.Conn, error) {
	return DialTimeout(ctx, address, DefaultDialTimeout)
}

// DialTimeout dials with an explicit handshake timeout.
func DialTimeout(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}

	var sid uint64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &sid)
	if sid == 0 {
		sid = 1
	}

	s := newSession(sid, pc, raddr)
	base := newConn(s, pc.LocalAddr(), raddr)

	var once sync.Once
	stop := make(chan struct{})
	shutdown := func() {
		once.Do(func() {
			close(stop)
			s.mu.Lock()
			s.forceCloseLocked()
			s.mu.Unlock()
			_ = pc.Close()
		})
	}

	go func() {
		buf := make([]byte, HeaderSize+MaxPayload+64)
		var frame Frame
		for {
			_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			select {
			case <-stop:
				return
			default:
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					s.mu.Lock()
					cl := s.closed
					s.mu.Unlock()
					if cl {
						return
					}
					s.retransmitTick()
					continue
				}
				shutdown()
				return
			}
			if Decode(buf[:n], &frame) != nil {
				continue
			}
			if frame.SessionID != sid {
				continue
			}
			if len(frame.Payload) > 0 {
				p := make([]byte, len(frame.Payload))
				copy(p, frame.Payload)
				frame.Payload = p
			}
			s.onPacket(&frame, addr)
			if frame.Type == TypeRST {
				shutdown()
				return
			}
		}
	}()

	if err := s.writePacket(TypeSYN, 0, 0, nil); err != nil {
		shutdown()
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	synTicker := time.NewTicker(DefaultRTO)
	defer synTicker.Stop()
	for {
		select {
		case <-s.handshake:
			return &clientConn{Conn: base, shutdown: shutdown}, nil
		case <-ctx.Done():
			shutdown()
			return nil, ctx.Err()
		case <-synTicker.C:
			if time.Now().After(deadline) {
				shutdown()
				return nil, fmt.Errorf("udptunnel: dial %s: handshake timeout", address)
			}
			_ = s.writePacket(TypeSYN, 0, 0, nil)
		}
	}
}

// clientConn ensures the underlying PacketConn is closed with the stream.
type clientConn struct {
	*Conn
	shutdown func()
	once     sync.Once
}

func (c *clientConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		if c.shutdown != nil {
			c.shutdown()
		}
	})
	return err
}

// ProbeRTT sends PING and waits for PONG. Returns RTT or error.
func ProbeRTT(ctx context.Context, address string) (time.Duration, error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return 0, err
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return 0, err
	}
	defer pc.Close()

	var sid uint64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &sid)
	ping := Frame{Type: TypePING, SessionID: sid, Seq: 1}
	b, err := EncodeAlloc(&ping)
	if err != nil {
		return 0, err
	}

	deadline := time.Now().Add(ProbeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = pc.SetDeadline(deadline)

	start := time.Now()
	if _, err = pc.WriteTo(b, raddr); err != nil {
		return 0, err
	}
	buf := make([]byte, HeaderSize+64)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		var f Frame
		if Decode(buf[:n], &f) != nil {
			continue
		}
		if f.Type == TypePONG && f.SessionID == sid {
			return time.Since(start), nil
		}
	}
}
