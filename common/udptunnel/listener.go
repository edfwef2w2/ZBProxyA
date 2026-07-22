package udptunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Listener accepts tunnel sessions as net.Conn.
type Listener struct {
	pc        net.PacketConn
	sessions  map[uint64]*session
	mu        sync.Mutex
	acceptCh  chan *Conn
	closed    chan struct{}
	closeOnce sync.Once
	idle      time.Duration
	localAddr net.Addr
}

// ListenPacket starts a tunnel listener on an existing PacketConn (usually UDP).
func ListenPacket(pc net.PacketConn) *Listener {
	l := &Listener{
		pc:        pc,
		sessions:  make(map[uint64]*session),
		acceptCh:  make(chan *Conn, 32),
		closed:    make(chan struct{}),
		idle:      DefaultIdleTimeout,
		localAddr: pc.LocalAddr(),
	}
	go l.readLoop()
	go l.timerLoop()
	return l
}

// ListenUDP listens on network address (e.g. ":25567").
func ListenUDP(network, address string) (*Listener, error) {
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return ListenPacket(pc), nil
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *Listener) AcceptContext(ctx context.Context) (net.Conn, error) {
	select {
	case c, ok := <-l.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *Listener) Addr() net.Addr { return l.localAddr }

func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.pc.Close()
		l.mu.Lock()
		for _, s := range l.sessions {
			s.mu.Lock()
			s.forceCloseLocked()
			s.mu.Unlock()
			s.invokeClosed()
		}
		l.sessions = nil
		l.mu.Unlock()
	})
	return err
}

func (l *Listener) removeSession(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sessions != nil {
		delete(l.sessions, id)
	}
}

func (l *Listener) readLoop() {
	buf := make([]byte, HeaderSize+MaxPayload+64)
	var frame Frame
	for {
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// copy frame payload before reuse of buf in next ReadFrom — Decode aliases buf
		if err := Decode(buf[:n], &frame); err != nil {
			continue
		}
		// snapshot payload for dispatch (storeData copies again)
		if len(frame.Payload) > 0 {
			p := make([]byte, len(frame.Payload))
			copy(p, frame.Payload)
			frame.Payload = p
		}
		l.dispatch(&frame, addr)
	}
}

func (l *Listener) dispatch(f *Frame, addr net.Addr) {
	if f.Type == TypePING {
		pong := Frame{Type: TypePONG, SessionID: f.SessionID, Seq: f.Seq, Ack: 0}
		b, err := EncodeAlloc(&pong)
		if err == nil {
			_, _ = l.pc.WriteTo(b, addr)
		}
		return
	}

	l.mu.Lock()
	if l.sessions == nil {
		l.mu.Unlock()
		return
	}
	s := l.sessions[f.SessionID]

	switch f.Type {
	case TypeSYN:
		if s == nil {
			if len(l.sessions) >= MaxSessions {
				l.mu.Unlock()
				rst := Frame{Type: TypeRST, SessionID: f.SessionID}
				b, _ := EncodeAlloc(&rst)
				_, _ = l.pc.WriteTo(b, addr)
				return
			}
			s = newSession(f.SessionID, l.pc, addr)
			s.onClosed = l.removeSession
			l.sessions[f.SessionID] = s
			c := newConn(s, l.localAddr, addr)
			select {
			case l.acceptCh <- c:
			default:
				delete(l.sessions, f.SessionID)
				s.mu.Lock()
				s.forceCloseLocked()
				s.mu.Unlock()
				l.mu.Unlock()
				rst := Frame{Type: TypeRST, SessionID: f.SessionID}
				b, _ := EncodeAlloc(&rst)
				_, _ = l.pc.WriteTo(b, addr)
				return
			}
		} else {
			s.peer = addr
		}
		l.mu.Unlock()
		_ = s.writePacket(TypeSYNACK, 0, 0, nil)
		return
	default:
		if s == nil {
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
		s.onPacket(f, addr)
	}
}

func (l *Listener) timerLoop() {
	tk := time.NewTicker(100 * time.Millisecond)
	defer tk.Stop()
	idleTk := time.NewTicker(5 * time.Second)
	defer idleTk.Stop()
	for {
		select {
		case <-l.closed:
			return
		case <-tk.C:
			l.mu.Lock()
			list := make([]*session, 0, len(l.sessions))
			for _, s := range l.sessions {
				list = append(list, s)
			}
			l.mu.Unlock()
			for _, s := range list {
				s.retransmitTick()
			}
		case <-idleTk.C:
			l.mu.Lock()
			for id, s := range l.sessions {
				if s.idle(l.idle) {
					s.mu.Lock()
					s.forceCloseLocked()
					s.mu.Unlock()
					delete(l.sessions, id)
				}
			}
			l.mu.Unlock()
		}
	}
}

// ErrListenerClosed is returned when accepting on a closed listener.
var ErrListenerClosed = errors.New("udptunnel: listener closed")
