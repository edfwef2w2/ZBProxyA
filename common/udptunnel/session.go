package udptunnel

import (
	"io"
	"net"
	"sync"
	"time"
)

type sendSlot struct {
	data     []byte
	seq      uint32
	lastSend time.Time
}

// session is one reliable stream over UDP.
type session struct {
	id     uint64
	pc     net.PacketConn
	peer   net.Addr
	mu     sync.Mutex
	closed bool

	sendNext  uint32
	sendSlots []sendSlot
	writeWait chan struct{}

	recvNext  uint32
	recvBuf   [MaxInFlight][]byte
	recvValid [MaxInFlight]bool
	readBuf   []byte
	readWait  chan struct{}
	readEOF   bool
	writeFin  bool

	lastActive time.Time
	rto        time.Duration
	encodeBuf  []byte
	handshake  chan struct{}
	hsOnce     sync.Once

	// onClosed is invoked once when the session is fully closed (optional).
	onClosed func(id uint64)
	closeCb  sync.Once
}

func newSession(id uint64, pc net.PacketConn, peer net.Addr) *session {
	return &session{
		id:         id,
		pc:         pc,
		peer:       peer,
		writeWait:  make(chan struct{}, 1),
		readWait:   make(chan struct{}, 1),
		handshake:  make(chan struct{}),
		lastActive: time.Now(),
		rto:        DefaultRTO,
		encodeBuf:  make([]byte, HeaderSize+MaxPayload),
		sendSlots:  make([]sendSlot, 0, MaxInFlight),
	}
}

func (s *session) touch() { s.lastActive = time.Now() }

func (s *session) signalHS() {
	s.hsOnce.Do(func() { close(s.handshake) })
}

func (s *session) notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *session) invokeClosed() {
	s.closeCb.Do(func() {
		if s.onClosed != nil {
			s.onClosed(s.id)
		}
	})
}

func (s *session) writePacket(typ uint8, seq, ack uint32, payload []byte) error {
	s.mu.Lock()
	if s.closed && typ != TypeRST && typ != TypeFIN && typ != TypeACK && typ != TypeSYNACK {
		s.mu.Unlock()
		return net.ErrClosed
	}
	peer := s.peer
	pc := s.pc
	f := Frame{Type: typ, SessionID: s.id, Seq: seq, Ack: ack, Payload: payload}
	b, err := Encode(s.encodeBuf, &f)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	out := make([]byte, len(b))
	copy(out, b)
	s.mu.Unlock()
	if peer == nil || pc == nil {
		return io.ErrClosedPipe
	}
	_, err = pc.WriteTo(out, peer)
	return err
}

func (s *session) onPacket(f *Frame, from net.Addr) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if from != nil {
		s.peer = from
	}
	s.touch()

	// Cumulative ACK piggybacked on most control/data frames.
	switch f.Type {
	case TypeACK, TypeDATA, TypeSYNACK, TypeFIN:
		s.consumeAckLocked(f.Ack)
	}

	switch f.Type {
	case TypeDATA:
		s.storeDataLocked(f)
		ack := s.recvNext
		s.mu.Unlock()
		_ = s.writePacket(TypeACK, 0, ack, nil)
		return
	case TypeFIN:
		s.readEOF = true
		s.notify(s.readWait)
		ack := s.recvNext
		s.mu.Unlock()
		_ = s.writePacket(TypeACK, 0, ack, nil)
		return
	case TypeRST:
		s.forceCloseLocked()
		s.mu.Unlock()
		s.invokeClosed()
		return
	case TypeSYNACK:
		s.signalHS()
		s.notify(s.writeWait)
	case TypeACK:
		s.notify(s.writeWait)
	case TypePONG:
		// probe only; ignore on stream sessions
	}
	s.mu.Unlock()
}

func (s *session) consumeAckLocked(ack uint32) {
	if len(s.sendSlots) == 0 {
		return
	}
	n := 0
	for _, slot := range s.sendSlots {
		if slot.seq < ack {
			continue
		}
		s.sendSlots[n] = slot
		n++
	}
	if n < len(s.sendSlots) {
		s.sendSlots = s.sendSlots[:n]
		s.rto = DefaultRTO
		s.notify(s.writeWait)
	}
}

func (s *session) storeDataLocked(f *Frame) {
	if f.Seq < s.recvNext {
		return
	}
	off := int(f.Seq - s.recvNext)
	if off >= MaxInFlight {
		return
	}
	if !s.recvValid[off] {
		p := make([]byte, len(f.Payload))
		copy(p, f.Payload)
		s.recvBuf[off] = p
		s.recvValid[off] = true
	}
	for s.recvValid[0] {
		s.readBuf = append(s.readBuf, s.recvBuf[0]...)
		s.recvBuf[0] = nil
		s.recvValid[0] = false
		copy(s.recvBuf[0:], s.recvBuf[1:])
		copy(s.recvValid[0:], s.recvValid[1:])
		s.recvBuf[MaxInFlight-1] = nil
		s.recvValid[MaxInFlight-1] = false
		s.recvNext++
		s.notify(s.readWait)
	}
}

func (s *session) write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		s.mu.Lock()
		for !s.closed && !s.writeFin && len(s.sendSlots) >= MaxInFlight {
			ch := s.writeWait
			s.mu.Unlock()
			<-ch
			s.mu.Lock()
		}
		if s.closed || s.writeFin {
			s.mu.Unlock()
			if total > 0 {
				return total, nil
			}
			return 0, net.ErrClosed
		}
		n := len(b)
		if n > MaxPayload {
			n = MaxPayload
		}
		payload := make([]byte, n)
		copy(payload, b[:n])
		seq := s.sendNext
		s.sendNext++
		s.sendSlots = append(s.sendSlots, sendSlot{data: payload, seq: seq, lastSend: time.Now()})
		ack := s.recvNext
		s.mu.Unlock()

		if err := s.writePacket(TypeDATA, seq, ack, payload); err != nil {
			return total, err
		}
		b = b[n:]
		total += n
	}
	return total, nil
}

func (s *session) read(p []byte) (int, error) {
	s.mu.Lock()
	for len(s.readBuf) == 0 && !s.readEOF && !s.closed {
		ch := s.readWait
		s.mu.Unlock()
		<-ch
		s.mu.Lock()
	}
	if len(s.readBuf) == 0 {
		done := s.readEOF || s.closed
		s.mu.Unlock()
		if done {
			return 0, io.EOF
		}
		return 0, io.ErrNoProgress
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	if len(s.readBuf) == 0 {
		s.readBuf = nil
	}
	s.mu.Unlock()
	return n, nil
}

func (s *session) retransmitTick() {
	s.mu.Lock()
	if s.closed || len(s.sendSlots) == 0 {
		s.mu.Unlock()
		return
	}
	now := time.Now()
	type item struct {
		seq, ack uint32
		data     []byte
	}
	var due []item
	for i := range s.sendSlots {
		if now.Sub(s.sendSlots[i].lastSend) >= s.rto {
			s.sendSlots[i].lastSend = now
			due = append(due, item{seq: s.sendSlots[i].seq, ack: s.recvNext, data: s.sendSlots[i].data})
		}
	}
	if len(due) > 0 {
		if s.rto < MaxRTO {
			s.rto *= 2
			if s.rto > MaxRTO {
				s.rto = MaxRTO
			}
		}
	}
	s.mu.Unlock()
	for _, it := range due {
		_ = s.writePacket(TypeDATA, it.seq, it.ack, it.data)
	}
}

func (s *session) forceCloseLocked() {
	if s.closed {
		return
	}
	s.closed = true
	s.readEOF = true
	s.writeFin = true
	s.signalHS()
	s.notify(s.readWait)
	s.notify(s.writeWait)
}

func (s *session) close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.writeFin = true
	ack := s.recvNext
	s.mu.Unlock()
	_ = s.writePacket(TypeFIN, 0, ack, nil)
	s.mu.Lock()
	s.forceCloseLocked()
	s.mu.Unlock()
	s.invokeClosed()
	return nil
}

func (s *session) idle(timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActive) > timeout
}
