package transportselect

import "testing"

func TestChooseSticky(t *testing.T) {
	s := New(Config{Host: "127.0.0.1", TCPPort: 1, UDPPort: 2, Mode: ModeAuto})
	s.mu.Lock()
	s.tcpUp, s.udpUp = true, true
	s.tcpRTT, s.udpRTT = 20e6, 18e6 // 20ms vs 18ms — within sticky 5ms
	got := s.chooseLocked(ModeTCP)
	s.mu.Unlock()
	if got != ModeTCP {
		t.Fatalf("sticky want tcp, got %s", got)
	}

	s.mu.Lock()
	s.udpRTT = 5e6 // 5ms, clearly better
	got = s.chooseLocked(ModeTCP)
	s.mu.Unlock()
	if got != ModeUDP {
		t.Fatalf("want udp, got %s", got)
	}
}

func TestPreferredHardMode(t *testing.T) {
	s := New(Config{Mode: ModeUDP, UDPPort: 9})
	if s.Preferred() != ModeUDP {
		t.Fatal(s.Preferred())
	}
	s = New(Config{Mode: ModeTCP, TCPPort: 9})
	if s.Preferred() != ModeTCP {
		t.Fatal(s.Preferred())
	}
}
