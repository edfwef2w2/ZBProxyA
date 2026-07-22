// Package transportselect picks tcp vs udp paths for dual-tunnel outbounds.
package transportselect

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/layou233/zbproxy/v3/common/udptunnel"

	"github.com/phuslu/log"
)

const (
	ModeTCP  = "tcp"
	ModeUDP  = "udp"
	ModeAuto = "auto"
)

// StickyMs: do not flip preferred if RTT delta is below this.
const StickyMs = 5

// PathFailThreshold marks a path down after consecutive probe failures.
const PathFailThreshold = 3

// Config for a selector instance.
type Config struct {
	Host         string
	TCPPort      uint16
	UDPPort      uint16
	Mode         string // tcp | udp | auto
	Interval     time.Duration
	Logger       *log.Logger
	OutboundName string
}

// Selector tracks preferred transport for new dials.
type Selector struct {
	cfg Config

	preferred atomic.Value // string tcp|udp
	mu        sync.Mutex
	tcpRTT    time.Duration
	udpRTT    time.Duration
	tcpFails  int
	udpFails  int
	tcpUp     bool
	udpUp     bool

	stop chan struct{}
	once sync.Once
}

// New creates a selector. Call Start for auto mode.
func New(cfg Config) *Selector {
	if cfg.Interval < 3*time.Second {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Interval > 60*time.Second {
		cfg.Interval = 60 * time.Second
	}
	s := &Selector{cfg: cfg, stop: make(chan struct{})}
	// initial preference
	switch cfg.Mode {
	case ModeUDP:
		s.preferred.Store(ModeUDP)
	case ModeAuto:
		// prefer TCP until first probe if both exist
		if cfg.TCPPort > 0 {
			s.preferred.Store(ModeTCP)
		} else {
			s.preferred.Store(ModeUDP)
		}
	default:
		s.preferred.Store(ModeTCP)
	}
	return s
}

// Preferred returns tcp or udp for the next dial.
func (s *Selector) Preferred() string {
	v, _ := s.preferred.Load().(string)
	if v == "" {
		return ModeTCP
	}
	// honor hard mode
	switch s.cfg.Mode {
	case ModeTCP:
		return ModeTCP
	case ModeUDP:
		return ModeUDP
	}
	return v
}

// Start begins background probing when Mode is auto.
func (s *Selector) Start() {
	if s.cfg.Mode != ModeAuto {
		return
	}
	if s.cfg.TCPPort == 0 && s.cfg.UDPPort == 0 {
		return
	}
	go s.loop()
}

// Stop ends the probe loop.
func (s *Selector) Stop() {
	s.once.Do(func() { close(s.stop) })
}

func (s *Selector) loop() {
	// immediate first probe
	s.probeOnce()
	tk := time.NewTicker(s.cfg.Interval)
	defer tk.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tk.C:
			s.probeOnce()
		}
	}
}

func (s *Selector) probeOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), udptunnel.ProbeTimeout+500*time.Millisecond)
	defer cancel()

	var tcpRTT time.Duration
	var udpRTT time.Duration
	tcpOK, udpOK := false, false

	if s.cfg.TCPPort > 0 {
		addr := net.JoinHostPort(s.cfg.Host, strconv.FormatUint(uint64(s.cfg.TCPPort), 10))
		start := time.Now()
		d := net.Dialer{Timeout: udptunnel.ProbeTimeout}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = c.Close()
			tcpRTT = time.Since(start)
			tcpOK = true
		}
	}
	if s.cfg.UDPPort > 0 {
		addr := net.JoinHostPort(s.cfg.Host, strconv.FormatUint(uint64(s.cfg.UDPPort), 10))
		rtt, err := udptunnel.ProbeRTT(ctx, addr)
		if err == nil {
			udpRTT = rtt
			udpOK = true
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.TCPPort > 0 {
		if tcpOK {
			s.tcpFails = 0
			s.tcpUp = true
			s.tcpRTT = tcpRTT
		} else {
			s.tcpFails++
			if s.tcpFails >= PathFailThreshold {
				s.tcpUp = false
			}
		}
	} else {
		s.tcpUp = false
	}
	if s.cfg.UDPPort > 0 {
		if udpOK {
			s.udpFails = 0
			s.udpUp = true
			s.udpRTT = udpRTT
		} else {
			s.udpFails++
			if s.udpFails >= PathFailThreshold {
				s.udpUp = false
			}
		}
	} else {
		s.udpUp = false
	}

	old, _ := s.preferred.Load().(string)
	next := s.chooseLocked(old)
	if next != old {
		s.preferred.Store(next)
		if s.cfg.Logger != nil {
			s.cfg.Logger.Info().
				Str("outbound", s.cfg.OutboundName).
				Str("from", old).
				Str("to", next).
				Dur("rtt_tcp", s.tcpRTT).
				Dur("rtt_udp", s.udpRTT).
				Msg("transport preferred switched")
		}
	}
}

func (s *Selector) chooseLocked(sticky string) string {
	tcpOK := s.tcpUp && s.cfg.TCPPort > 0
	udpOK := s.udpUp && s.cfg.UDPPort > 0
	switch {
	case tcpOK && !udpOK:
		return ModeTCP
	case udpOK && !tcpOK:
		return ModeUDP
	case !tcpOK && !udpOK:
		// fall back to whatever is configured
		if s.cfg.TCPPort > 0 {
			return ModeTCP
		}
		return ModeUDP
	default:
		// both up
		diff := s.tcpRTT - s.udpRTT
		if diff < 0 {
			diff = -diff
		}
		if sticky == ModeTCP || sticky == ModeUDP {
			if diff < StickyMs*time.Millisecond {
				return sticky
			}
		}
		if s.udpRTT < s.tcpRTT {
			return ModeUDP
		}
		return ModeTCP
	}
}


