package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/layou233/zbproxy/v3/adapter"
	"github.com/layou233/zbproxy/v3/common"
	"github.com/layou233/zbproxy/v3/common/access"
	"github.com/layou233/zbproxy/v3/common/authsecret"
	"github.com/layou233/zbproxy/v3/common/bufio"
	"github.com/layou233/zbproxy/v3/common/network"
	"github.com/layou233/zbproxy/v3/common/proxyprotocol"
	"github.com/layou233/zbproxy/v3/common/set"
	"github.com/layou233/zbproxy/v3/common/udptunnel"
	"github.com/layou233/zbproxy/v3/config"
	"github.com/layou233/zbproxy/v3/protocol/minecraft"

	"github.com/phuslu/log"
)

type Service struct {
	tcpListener *net.TCPListener
	udpListener *udptunnel.Listener
	ctx         context.Context
	router      adapter.Router
	logger      *log.Logger
	config      *config.Service
	legacyOutbound adapter.Outbound
	listenAddress  string
	ipAccessLists  []set.StringSet
	authSecret     atomic.Value // []byte
	started        bool
}

var _ adapter.Service = (*Service)(nil)

func NewService(logger *log.Logger, newConfig *config.Service) *Service {
	s := &Service{
		listenAddress: ":" + strconv.Itoa(int(newConfig.Listen)),
		logger:        logger,
		config:        newConfig,
	}
	s.authSecret.Store([]byte(nil))
	return s
}

func (s *Service) SetAuthSecret(secret string) {
	b, err := authsecret.Normalize(secret)
	if err != nil {
		s.logger.Warn().Err(err).Str("service", s.config.Name).Msg("Ignoring invalid AuthSecret")
		s.authSecret.Store([]byte(nil))
		return
	}
	if b == nil {
		s.authSecret.Store([]byte(nil))
		return
	}
	s.authSecret.Store(b)
}

func (s *Service) listenTCPLoop() {
	for {
		conn, err := s.tcpListener.AcceptTCP()
		if err != nil {
			return
		}
		go s.handleInbound(conn, "tcp")
	}
}

func (s *Service) listenUDPLoop() {
	for {
		conn, err := s.udpListener.Accept()
		if err != nil {
			return
		}
		go s.handleInbound(conn, "udp")
	}
}

func (s *Service) handleInbound(netConn net.Conn, networkKind string) {
	defer func() {
		// router/legacy owns close in some paths; best-effort
	}()

	remote := netConn.RemoteAddr()
	var ipString string
	var srcPort uint16
	switch a := remote.(type) {
	case *net.TCPAddr:
		ipString = a.IP.String()
		srcPort = uint16(a.Port)
	case *net.UDPAddr:
		ipString = a.IP.String()
		srcPort = uint16(a.Port)
	default:
		ipString = remote.String()
	}

	if s.config.RequireAuthSecret {
		secret, _ := s.authSecret.Load().([]byte)
		if len(secret) == 0 {
			if tc, ok := netConn.(*net.TCPConn); ok {
				tc.SetLinger(0)
			}
			netConn.Close()
			s.logger.Warn().Str("service", s.config.Name).Str("ip", ipString).Str("network", networkKind).
				Msg("Rejected: RequireAuthSecret set but AuthSecret is empty")
			return
		}
		if err := authsecret.Verify(netConn, secret, authsecret.DefaultTimeout); err != nil {
			if tc, ok := netConn.(*net.TCPConn); ok {
				tc.SetLinger(0)
			}
			netConn.Close()
			s.logger.Warn().Str("service", s.config.Name).Str("ip", ipString).Str("network", networkKind).
				Err(err).Msg("Rejected by auth secret")
			return
		}
	}

	if s.ipAccessLists != nil &&
		!access.Check(s.ipAccessLists, s.config.IPAccess.Mode, ipString) {
		if tc, ok := netConn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		netConn.Close()
		s.logger.Warn().Str("service", s.config.Name).Str("ip", ipString).Str("network", networkKind).
			Msg("Rejected by access control")
		return
	}

	var srcAddr netip.AddrPort
	if tcpAddr, ok := remote.(*net.TCPAddr); ok {
		srcAddr = netip.AddrPortFrom(common.MustOK(netip.AddrFromSlice(tcpAddr.IP)).Unmap(), uint16(tcpAddr.Port))
	} else if udpAddr, ok := remote.(*net.UDPAddr); ok {
		srcAddr = netip.AddrPortFrom(common.MustOK(netip.AddrFromSlice(udpAddr.IP)).Unmap(), uint16(udpAddr.Port))
	} else {
		srcAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), srcPort)
	}

	metadata := &adapter.Metadata{
		ServiceName:         s.config.Name,
		DestinationHostname: s.config.TargetAddress,
		DestinationPort:     s.config.TargetPort,
		SourceAddress:       srcAddr,
	}
	metadata.GenerateID()

	var bufConn *bufio.CachedConn
	if s.config.EnableProxyProtocol {
		bufConn = bufio.NewCachedConn(netConn)
		netConn = bufConn
		changed, err := proxyprotocol.HandleConnection(bufConn, metadata)
		if err != nil {
			bufConn.Close()
			s.logger.Warn().Str("id", metadata.ConnectionID).Str("service", s.config.Name).
				Str("ip", ipString).Str("network", networkKind).Err(err).Msg("Error when reading PROXY protocol header")
			return
		}
		if changed {
			ipString = metadata.SourceAddress.Addr().String()
		}
	}

	s.logger.Info().Str("id", metadata.ConnectionID).Str("service", s.config.Name).
		Str("ip", ipString).Str("network", networkKind).Msg("New inbound connection")

	if s.legacyOutbound != nil {
		defer s.logger.Info().Str("id", metadata.ConnectionID).Str("service", s.config.Name).
			Str("ip", ipString).Msg("Disconnected")
		defer netConn.Close()
		switch outbound := s.legacyOutbound.(type) {
		case *minecraft.Outbound:
			bufConn = bufio.NewCachedConn(netConn)
			err := minecraft.SniffClientHandshake(bufConn, metadata)
			bufConn.Release()
			if err != nil {
				s.logger.Warn().Str("id", metadata.ConnectionID).Str("service", s.config.Name).
					Str("ip", ipString).Err(err).Msg("Error when reading Minecraft handshake")
				return
			}
			err = outbound.InjectConnection(s.ctx, bufConn, metadata)
			if err != nil {
				s.logger.Info().Str("id", metadata.ConnectionID).Str("service", s.config.Name).
					Str("player", metadata.Minecraft.PlayerName).Err(err).Msg("Handling Minecraft connection")
			}
		}
	} else {
		s.router.HandleConnection(netConn, metadata)
	}
}

func (s *Service) Start(ctx context.Context) error {
	var err error
	if s.config.Minecraft != nil && s.config.TLSSniffing != nil {
		return errors.New("Minecraft and TLSSniffing are mutually exclusive in legacy mode")
	}
	if s.config.Minecraft != nil {
		s.legacyOutbound, err = minecraft.NewOutbound(s.logger, &config.Outbound{
			Name:          "legacy-" + s.config.Name,
			TargetAddress: s.config.TargetAddress,
			TargetPort:    s.config.TargetPort,
			Minecraft:     s.config.Minecraft,
			SocketOptions: network.ConvertLegacyOutboundOptions(s.config.SocketOptions),
		})
		if err != nil {
			return common.Cause("initialize legacy Minecraft outbound: ", err)
		}
		err = s.legacyOutbound.PostInitialize(s.router, s.router)
		if err != nil {
			return common.Cause("post initialize legacy Minecraft outbound: ", err)
		}
	}

	if s.config.IPAccess.Mode != access.DefaultMode {
		s.ipAccessLists, err = s.router.FindListsByTag(s.config.IPAccess.ListTags)
		if err != nil {
			return common.Cause("load access control lists: ", err)
		}
	}

	enableTCP := s.config.TCPEnabled()
	enableUDP := s.config.UDPEnabled()
	if !enableTCP && !enableUDP {
		return errors.New("service: neither TCP nor UDP inbound enabled")
	}
	if s.config.EnableUDP && s.config.ListenUDP == 0 {
		return errors.New("service: EnableUDP requires ListenUDP > 0")
	}

	s.ctx = ctx

	if enableTCP {
		listenConfig := &net.ListenConfig{
			Control: network.NewListenerControlFromOptions(s.config.SocketOptions),
		}
		if s.config.SocketOptions != nil {
			network.SetListenerTCPKeepAlive(listenConfig, s.config.SocketOptions.KeepAliveConfig())
			if s.config.SocketOptions.MultiPathTCP {
				network.SetListenerMultiPathTCP(listenConfig, true)
			}
		}
		tcpAddr := ":" + strconv.Itoa(int(s.config.Listen))
		listener, err := listenConfig.Listen(ctx, "tcp", tcpAddr)
		if err != nil {
			return common.Cause("start TCP listening: ", err)
		}
		s.tcpListener = listener.(*net.TCPListener)
		s.logger.Info().Str("service", s.config.Name).Str("network", "tcp").
			Msg("Listening on " + tcpAddr)
		go s.listenTCPLoop()
	}

	if enableUDP {
		udpAddr := ":" + strconv.Itoa(int(s.config.ListenUDP))
		ul, err := udptunnel.ListenUDP("udp", udpAddr)
		if err != nil {
			if s.tcpListener != nil {
				_ = s.tcpListener.Close()
				s.tcpListener = nil
			}
			return common.Cause("start UDP tunnel listening: ", err)
		}
		s.udpListener = ul
		s.logger.Info().Str("service", s.config.Name).Str("network", "udp").
			Msg("Listening on " + udpAddr)
		go s.listenUDPLoop()
	}

	s.started = true
	return nil
}

func (s *Service) Reload(ctx context.Context, newConfig *config.Service) error {
	if !s.started {
		return os.ErrClosed
	}
	_ = s.Close()
	s.listenAddress = ":" + strconv.Itoa(int(newConfig.Listen))
	s.config = newConfig
	s.legacyOutbound = nil
	s.ipAccessLists = nil
	return s.Start(ctx)
}

func (s *Service) UpdateRouter(router adapter.Router) {
	s.router = router
}

func (s *Service) Close() error {
	if !s.started && s.tcpListener == nil && s.udpListener == nil {
		return os.ErrClosed
	}
	var err error
	if s.tcpListener != nil {
		err = s.tcpListener.Close()
		s.tcpListener = nil
	}
	if s.udpListener != nil {
		if e := s.udpListener.Close(); e != nil && err == nil {
			err = e
		}
		s.udpListener = nil
	}
	s.started = false
	return err
}
