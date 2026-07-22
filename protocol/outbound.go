package protocol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/layou233/zbproxy/v3/adapter"
	"github.com/layou233/zbproxy/v3/common"
	"github.com/layou233/zbproxy/v3/common/authsecret"
	"github.com/layou233/zbproxy/v3/common/network"
	"github.com/layou233/zbproxy/v3/common/network/socks"
	"github.com/layou233/zbproxy/v3/common/proxyprotocol"
	"github.com/layou233/zbproxy/v3/common/transportselect"
	"github.com/layou233/zbproxy/v3/common/udptunnel"
	"github.com/layou233/zbproxy/v3/config"
	"github.com/layou233/zbproxy/v3/protocol/minecraft"

	"github.com/phuslu/log"
)

func NewOutbound(logger *log.Logger, newConfig *config.Outbound) (adapter.Outbound, error) {
	if newConfig == nil {
		return nil, os.ErrInvalid
	}
	switch {
	case newConfig.Minecraft != nil:
		return minecraft.NewOutbound(logger, newConfig)
	}
	return &Plain{
		logger: logger,
		config: newConfig,
	}, nil
}

type Plain struct {
	access     sync.RWMutex
	logger     *log.Logger
	config     *config.Outbound
	router     adapter.Router
	dialer     network.Dialer
	authSecret atomic.Value // []byte
	selector   *transportselect.Selector
}

var (
	_ adapter.Outbound           = (*Plain)(nil)
	_ adapter.MetadataOutbound   = (*Plain)(nil)
	_ adapter.AuthSecretOutbound = (*Plain)(nil)
	_ network.Dialer             = (*Plain)(nil)
)

func (o *Plain) Name() (name string) {
	o.access.RLock()
	if o.config != nil {
		name = o.config.Name
	}
	o.access.RUnlock()
	return
}

func (o *Plain) SetAuthSecret(secret string) {
	b, err := authsecret.Normalize(secret)
	if err != nil || b == nil {
		o.authSecret.Store([]byte(nil))
		return
	}
	o.authSecret.Store(b)
}

func (o *Plain) PostInitialize(router adapter.Router, provider adapter.RouteResourceProvider) error {
	var err error
	mode := o.config.ResolvedTransport()
	if mode == transportselect.ModeUDP || mode == transportselect.ModeAuto {
		if o.config.ProxyOptions.Type != "" {
			return errors.New("SOCKS proxy options are not supported with UDP/auto transport")
		}
	}
	if mode == transportselect.ModeUDP && o.config.UDPTargetPort == 0 {
		return errors.New("Transport=udp requires UDPTargetPort > 0")
	}
	if o.config.Dialer != "" {
		if o.config.SocketOptions != nil {
			return errors.New("socket options are not available when dialer is specified")
		}
		if mode == transportselect.ModeUDP {
			return errors.New("nested dialer is not supported with Transport=udp")
		}
		o.dialer, err = provider.FindOutboundByName(o.config.Dialer)
		if err != nil {
			return err
		}
	} else {
		o.dialer = network.NewSystemDialer(o.config.SocketOptions)
	}
	switch o.config.ProxyProtocolVersion {
	case proxyprotocol.VersionUnspecified,
		proxyprotocol.Version1,
		proxyprotocol.Version2:
	default:
		return fmt.Errorf("invalid proxy protocol version: %v", o.config.ProxyProtocolVersion)
	}
	switch o.config.ProxyOptions.Type {
	case "socks", "socks5", "socks4a", "socks4":
		o.dialer = &socks.Client{
			Dialer:  o.dialer,
			Version: o.config.ProxyOptions.Type,
			Network: o.config.ProxyOptions.Network,
			Address: o.config.ProxyOptions.Address,
		}
	}
	o.router = router

	// transport selector for auto / dual path
	if o.selector != nil {
		o.selector.Stop()
		o.selector = nil
	}
	if mode == transportselect.ModeAuto || mode == transportselect.ModeUDP || o.config.UDPTargetPort > 0 {
		o.selector = transportselect.New(transportselect.Config{
			Host:         o.config.TargetAddress,
			TCPPort:      o.config.TargetPort,
			UDPPort:      o.config.UDPTargetPort,
			Mode:         mode,
			Interval:     o.config.ProbeInterval(),
			Logger:       o.logger,
			OutboundName: o.config.Name,
		})
		o.selector.Start()
	}
	return nil
}

func (o *Plain) Reload(options adapter.OutboundReloadOptions) error {
	o.access.Lock()
	defer o.access.Unlock()
	if o.selector != nil {
		o.selector.Stop()
		o.selector = nil
	}
	o.config = options.Config
	return o.PostInitialize(o.router, &options)
}

func (o *Plain) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	o.access.RLock()
	defer o.access.RUnlock()
	return o.dialer.DialContext(ctx, network, address)
}

func (o *Plain) DialContextWithMetadata(ctx context.Context, network string, address string, metadata *adapter.Metadata) (net.Conn, error) {
	o.access.RLock()
	defer o.access.RUnlock()

	conn, err := o.dialTunnel(ctx, metadata)
	if err != nil {
		return nil, err
	}

	if o.config.SendAuthSecret {
		secret, _ := o.authSecret.Load().([]byte)
		if len(secret) == 0 {
			conn.Close()
			return nil, errors.New("SendAuthSecret set but AuthSecret is empty")
		}
		if err = authsecret.Write(conn, secret); err != nil {
			conn.Close()
			return nil, common.Cause("failed to write auth secret: ", err)
		}
	}

	if o.config.ProxyProtocolVersion != proxyprotocol.VersionUnspecified {
		var localAddress netip.AddrPort
		localAddress, err = netip.ParseAddrPort(conn.LocalAddr().String())
		if err != nil {
			conn.Close()
			return nil, common.Cause("failed to parse local address: ", err)
		}
		err = (&proxyprotocol.Header{
			Version:           uint8(o.config.ProxyProtocolVersion),
			Command:           proxyprotocol.CommandProxy,
			TransportProtocol: proxyprotocol.TransportProtocolByNetwork(network) | proxyprotocol.AddressFamilyByAddr(metadata.SourceAddress.Addr()),
			SourceAddress:     metadata.SourceAddress,
		}).WriteHeader(conn, localAddress)
		if err != nil {
			conn.Close()
			return nil, common.Cause("failed to write PROXY protocol header: ", err)
		}
	}
	return conn, nil
}

func (o *Plain) dialTunnel(ctx context.Context, metadata *adapter.Metadata) (net.Conn, error) {
	mode := o.config.ResolvedTransport()
	if o.selector != nil && mode == transportselect.ModeAuto {
		mode = o.selector.Preferred()
	}
	host := o.config.TargetAddress
	tunnelHop := o.config.UDPTargetPort > 0 ||
		o.config.ResolvedTransport() == transportselect.ModeUDP ||
		o.config.ResolvedTransport() == transportselect.ModeAuto

	switch mode {
	case transportselect.ModeUDP:
		if o.config.UDPTargetPort == 0 {
			return nil, errors.New("UDP path selected but UDPTargetPort is 0")
		}
		addr := net.JoinHostPort(host, strconv.FormatUint(uint64(o.config.UDPTargetPort), 10))
		return udptunnel.Dial(ctx, addr)
	default:
		destHost := host
		destPort := o.config.TargetPort
		if !tunnelHop && metadata != nil {
			if metadata.DestinationHostname != "" {
				destHost = metadata.DestinationHostname
			}
			if metadata.DestinationPort > 0 {
				destPort = metadata.DestinationPort
			}
		}
		address := net.JoinHostPort(destHost, strconv.FormatUint(uint64(destPort), 10))
		return adapter.DialContextWithMetadata(o.dialer, ctx, "tcp", address, metadata)
	}
}
