package outbound

import (
	"context"
	goerrors "errors"
	"io"
	"os"
	"time"

	"github.com/ImAubrey/acore/common/dice"

	"github.com/ImAubrey/acore/app/proxyman"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/mux"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/policy"
	"github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/proxy"
	"github.com/ImAubrey/acore/proxy/freedom"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

func getStatCounter(v *core.Instance, tag string) (stats.Counter, stats.Counter) {
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter

	policy := v.GetFeature(policy.ManagerType()).(policy.Manager)
	if len(tag) > 0 && policy.ForSystem().Stats.OutboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && policy.ForSystem().Stats.OutboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			downlinkCounter = c
		}
	}

	return uplinkCounter, downlinkCounter
}

// Handler implements outbound.Handler.
type Handler struct {
	tag             string
	senderSettings  *proxyman.SenderConfig
	freedomSettings *internet.FreedomDialerSettings
	streamSettings  *internet.MemoryStreamConfig
	proxyConfig     proto.Message
	proxy           proxy.Outbound
	outboundManager outbound.Manager
	mux             *mux.ClientManager
	xudp            *mux.ClientManager
	udp443          string
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
}

func (h *Handler) setOutboundStrategy(outbounds []*session.Outbound) {
	if h.senderSettings == nil || len(outbounds) == 0 {
		return
	}
	outbounds[len(outbounds)-1].TargetStrategy = uint8(h.effectiveStrategy())
}

// effectiveStrategy returns the domain strategy to use for target resolution.
// Priority: senderSettings.TargetStrategy > streamSettings.SocketSettings.DomainStrategy.
func (h *Handler) effectiveStrategy() internet.DomainStrategy {
	if h.senderSettings != nil && h.senderSettings.TargetStrategy.HasStrategy() {
		return h.senderSettings.TargetStrategy
	}
	if h.streamSettings != nil && h.streamSettings.SocketSettings != nil {
		if h.streamSettings.SocketSettings.DomainStrategy.HasStrategy() {
			return h.streamSettings.SocketSettings.DomainStrategy
		}
	}
	return internet.DomainStrategy_AS_IS
}

// pickPreferredIP returns a random IP from the preferred family if available.
func pickPreferredIP(ips []net.IP, preferV6 bool) net.IP {
	if len(ips) == 0 {
		return nil
	}
	var preferred []net.IP
	for _, ip := range ips {
		if preferV6 {
			if ip.To4() == nil {
				preferred = append(preferred, ip)
			}
		} else if ip.To4() != nil {
			preferred = append(preferred, ip)
		}
	}
	if len(preferred) > 0 {
		return preferred[dice.Roll(len(preferred))]
	}
	return ips[dice.Roll(len(ips))]
}

func tcpConcurrentEnabled(s *proxyman.SenderConfig) bool {
	if s == nil {
		return false
	}
	if s.TcpConcurrent == nil {
		return true
	}
	return *s.TcpConcurrent
}

// NewHandler creates a new Handler based on the given configuration.
func NewHandler(ctx context.Context, config *core.OutboundHandlerConfig) (outbound.Handler, error) {
	v := core.MustFromContext(ctx)
	uplinkCounter, downlinkCounter := getStatCounter(v, config.Tag)
	h := &Handler{
		tag:             config.Tag,
		outboundManager: v.GetFeature(outbound.ManagerType()).(outbound.Manager),
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}

	if config.SenderSettings != nil {
		senderSettings, err := config.SenderSettings.GetInstance()
		if err != nil {
			return nil, err
		}
		switch s := senderSettings.(type) {
		case *proxyman.SenderConfig:
			h.senderSettings = s
			mss, err := internet.ToMemoryStreamConfig(s.StreamSettings)
			if err != nil {
				return nil, errors.New("failed to parse stream settings").Base(err).AtWarning()
			}
			h.streamSettings = mss
			var socketSettings *internet.SocketConfig
			if mss != nil {
				socketSettings = mss.SocketSettings
			}
			h.freedomSettings = internet.BuildFreedomDialerSettings(s.Via, s.Via6, s.ViaCidr, s.Via6Cidr, s.TargetStrategy, socketSettings)
		default:
			return nil, errors.New("settings is not SenderConfig")
		}
	}

	proxyConfig, err := config.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}
	h.proxyConfig = proxyConfig

	ctx = session.ContextWithFullHandler(ctx, h)

	rawProxyHandler, err := common.CreateObject(ctx, proxyConfig)
	if err != nil {
		return nil, err
	}

	proxyHandler, ok := rawProxyHandler.(proxy.Outbound)
	if !ok {
		return nil, errors.New("not an outbound handler")
	}

	if h.senderSettings != nil && h.senderSettings.MultiplexSettings != nil {
		if config := h.senderSettings.MultiplexSettings; config.Enabled {
			if config.Concurrency < 0 {
				h.mux = &mux.ClientManager{Enabled: false}
			}
			if config.Concurrency == 0 {
				config.Concurrency = 8 // same as before
			}
			if config.Concurrency > 0 {
				h.mux = &mux.ClientManager{
					Enabled: true,
					Picker: &mux.IncrementalWorkerPicker{
						Factory: &mux.DialingWorkerFactory{
							Proxy:  proxyHandler,
							Dialer: h,
							Strategy: mux.ClientStrategy{
								MaxConcurrency: uint32(config.Concurrency),
								MaxConnection:  128,
							},
						},
					},
				}
			}
			if config.XudpConcurrency < 0 {
				h.xudp = &mux.ClientManager{Enabled: false}
			}
			if config.XudpConcurrency == 0 {
				h.xudp = nil // same as before
			}
			if config.XudpConcurrency > 0 {
				h.xudp = &mux.ClientManager{
					Enabled: true,
					Picker: &mux.IncrementalWorkerPicker{
						Factory: &mux.DialingWorkerFactory{
							Proxy:  proxyHandler,
							Dialer: h,
							Strategy: mux.ClientStrategy{
								MaxConcurrency: uint32(config.XudpConcurrency),
								MaxConnection:  128,
							},
						},
					},
				}
			}
			h.udp443 = config.XudpProxyUDP443
		}
	}

	h.proxy = proxyHandler
	return h, nil
}

// Tag implements outbound.Handler.
func (h *Handler) Tag() string {
	return h.tag
}

// Dispatch implements proxy.Outbound.Dispatch.
func (h *Handler) Dispatch(ctx context.Context, link *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	h.setOutboundStrategy(outbounds)
	content := session.ContentFromContext(ctx)
	if h.senderSettings != nil && ob.Target.Address.Family().IsDomain() && (content == nil || !content.SkipDNSResolve) {
		strategy := h.effectiveStrategy()
		if ob.ReLookup && !strategy.HasStrategy() {
			strategy = internet.DomainStrategy_USE_IP
		}
		if strategy.HasStrategy() {
			if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil {
				strategy = strategy.GetDynamicStrategy(ob.OriginalTarget.Address.Family())
			}
			unchangedDomain := ob.Target.Address.Domain()
			preferV6 := strategy.PreferIP6()
			var (
				addr net.Address
				err  error
			)
			if ob.ReLookup {
				addr, err = internet.LookupForAddressPickPreferredWithContext(ctx, unchangedDomain, strategy, nil, preferV6)
			} else {
				addr, err = internet.LookupForAddressPickWithContext(ctx, unchangedDomain, strategy, nil)
			}
			if err != nil {
				errors.LogInfoInner(ctx, err, "failed to resolve ip for target ", ob.Target.Address.Domain())
				if strategy.ForceIP() {
					err := errors.New("failed to resolve ip for target ", ob.Target.Address.Domain()).Base(err)
					session.SubmitOutboundErrorToOriginator(ctx, err)
					common.Interrupt(link.Writer)
					common.Interrupt(link.Reader)
					return
				}
			} else {
				ob.Target.Address = addr
				errors.LogInfo(ctx, "target: ", unchangedDomain, " resolved to: ", ob.Target.Address.String())
			}
		}
	}
	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}
	if conn := conntrack.ConnectionFromContext(ctx); conn != nil {
		target := ob.Target
		if ob.RouteTarget.IsValid() && ob.RouteTarget.Address.Family().IsDomain() {
			if !(ob.OriginalTarget.IsValid() && ob.OriginalTarget.Address.Family().IsDomain()) {
				target = ob.RouteTarget
			}
		}
		conn.SetTarget(target)
	}
	if h.mux != nil {
		test := func(err error) {
			if err != nil {
				err := errors.New("failed to process mux outbound traffic").Base(err)
				session.SubmitOutboundErrorToOriginator(ctx, err)
				errors.LogInfo(ctx, err.Error())
				common.Interrupt(link.Writer)
				common.Interrupt(link.Reader)
			}
		}
		if ob.Target.Network == net.Network_UDP && ob.Target.Port == 443 {
			switch h.udp443 {
			case "reject":
				test(errors.New("XUDP rejected UDP/443 traffic").AtInfo())
				return
			case "skip":
				goto out
			}
		}
		if h.xudp != nil && ob.Target.Network == net.Network_UDP {
			if !h.xudp.Enabled {
				goto out
			}
			test(h.xudp.Dispatch(ctx, link))
			return
		}
		if h.mux.Enabled {
			test(h.mux.Dispatch(ctx, link))
			return
		}
	}
out:
	err := h.proxy.Process(ctx, link, h)
	var errC error
	if err != nil {
		errC = errors.Cause(err)
		if goerrors.Is(errC, io.EOF) || goerrors.Is(errC, io.ErrClosedPipe) || goerrors.Is(errC, context.Canceled) {
			err = nil
		}
	}
	if err != nil {
		// Ensure outbound ray is properly closed.
		err := errors.New("failed to process outbound traffic").Base(err)
		session.SubmitOutboundErrorToOriginator(ctx, err)
		errors.LogInfo(ctx, err.Error())
		common.Interrupt(link.Writer)
	} else {
		if errC != nil && goerrors.Is(errC, io.ErrClosedPipe) {
			common.Interrupt(link.Writer)
		} else {
			common.Close(link.Writer)
		}
	}
	common.Interrupt(link.Reader)
}

func (h *Handler) DestIpAddress() net.IP {
	return internet.DestIpAddress()
}

func (h *Handler) dialConcurrent(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	outbounds := session.OutboundsFromContext(ctx)
	if outbounds == nil || len(outbounds) == 0 {
		return nil, os.ErrInvalid
	}
	ob := outbounds[len(outbounds)-1]
	strategy := h.effectiveStrategy()

	normalizeIPs := func(ips []net.IP, family net.AddressFamily, includeIP net.IP) []net.IP {
		if includeIP != nil {
			ips = append(ips, includeIP)
		}
		seen := make(map[string]struct{}, len(ips))
		unique := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			if family.IsIPv4() && ip.To4() == nil {
				continue
			}
			if family.IsIPv6() && ip.To4() != nil {
				continue
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			unique = append(unique, ip)
		}
		return unique
	}

	resolveIPs := func() ([]net.IP, error) {
		if len(ob.TargetIPs) > 0 {
			if dest.Address.Family().IsIP() {
				return normalizeIPs(ob.TargetIPs, dest.Address.Family(), dest.Address.IP()), nil
			}
			return normalizeIPs(ob.TargetIPs, net.AddressFamilyDomain, nil), nil
		}
		if dest.Address.Family().IsIP() {
			// Concurrency should follow the original IP family.
			targetFamily := dest.Address.Family()
			// If target is IP but we still have a domain hint (RouteTarget), prefer resolving it for concurrency.
			if ob.RouteTarget.Address != nil && ob.RouteTarget.Address.Family().IsDomain() {
				if resolved, err := internet.LookupForIPWithContext(ctx, ob.RouteTarget.Address.Domain(), strategy, nil); err == nil && len(resolved) > 0 {
					return normalizeIPs(resolved, targetFamily, dest.Address.IP()), nil
				}
			} else if ob.Target.Address != nil && ob.Target.Address.Family().IsDomain() {
				if resolved, err := internet.LookupForIPWithContext(ctx, ob.Target.Address.Domain(), strategy, nil); err == nil && len(resolved) > 0 {
					return normalizeIPs(resolved, targetFamily, dest.Address.IP()), nil
				}
			}
			return []net.IP{dest.Address.IP()}, nil
		}
		if dest.Address.Family().IsDomain() {
			resolved, err := internet.LookupForIPWithContext(ctx, dest.Address.Domain(), strategy, nil)
			if err != nil || len(resolved) == 0 {
				return nil, err
			}
			return normalizeIPs(resolved, net.AddressFamilyDomain, nil), nil
		}
		return nil, os.ErrInvalid
	}

	ips, err := resolveIPs()
	if err != nil {
		return nil, err
	}
	if len(ips) == 1 {
		return internet.Dial(ctx, net.Destination{Network: dest.Network, Address: net.IPAddress(ips[0]), Port: dest.Port}, h.streamSettings)
	}

	needsGateway := h.senderSettings != nil && (h.senderSettings.Via != nil || h.senderSettings.Via6 != nil || ob.Gateway != nil)
	var gw4 net.Address
	var gw6 net.Address
	if needsGateway {
		gw4 = h.gatewayForFamily(ctx, net.AddressFamilyIPv4)
		gw6 = h.gatewayForFamily(ctx, net.AddressFamilyIPv6)
		if ob.Gateway != nil && ob.Gateway.Family().IsIP() {
			if gw4 == nil && ob.Gateway.Family().IsIPv4() {
				gw4 = ob.Gateway
			}
			if gw6 == nil && ob.Gateway.Family().IsIPv6() {
				gw6 = ob.Gateway
			}
		}
	}

	var primary, fallback []net.IP
	preferV6First := strategy.PreferIP6()
	hasFallback := strategy.HasFallback()

	for _, ip := range ips {
		if ip.To4() == nil {
			if preferV6First {
				primary = append(primary, ip)
			} else {
				fallback = append(fallback, ip)
			}
		} else {
			if !preferV6First {
				primary = append(primary, ip)
			} else {
				fallback = append(fallback, ip)
			}
		}
	}
	if len(primary) == 0 {
		primary, fallback = fallback, nil
	}
	timeout := time.Duration(h.senderSettings.RaceTimeoutMs)
	if timeout <= 0 {
		timeout = 250
	}
	timeout = timeout * time.Millisecond

	tryDial := func(list []net.IP) (stat.Connection, error) {
		ctxDial, cancel := context.WithCancel(ctx)
		defer cancel()
		type res struct {
			conn stat.Connection
			err  error
		}
		ch := make(chan res, len(list))
		for _, ip := range list {
			ipCopy := ip
			go func() {
				dialCtx := ctxDial
				if needsGateway {
					if ipCopy.To4() == nil {
						dialCtx = contextWithOutboundGateway(ctxDial, ob, gw6)
					} else {
						dialCtx = contextWithOutboundGateway(ctxDial, ob, gw4)
					}
				}
				c, err := internet.Dial(dialCtx, net.Destination{Network: dest.Network, Address: net.IPAddress(ipCopy), Port: dest.Port}, h.streamSettings)
				if err == nil {
					cancel()
				}
				ch <- res{c, err}
			}()
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		for i := 0; i < len(list); i++ {
			select {
			case r := <-ch:
				if r.err == nil {
					return r.conn, nil
				}
			case <-timer.C:
				return nil, os.ErrDeadlineExceeded
			}
		}
		return nil, os.ErrDeadlineExceeded
	}

	conn, err := tryDial(primary)
	if err == nil {
		return conn, nil
	}
	if hasFallback && len(fallback) > 0 {
		return tryDial(fallback)
	}
	return nil, err
}

// Dial implements internet.Dialer.
func (h *Handler) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	outbounds := session.OutboundsFromContext(ctx)
	var dialerProxy string
	if h.streamSettings != nil && h.streamSettings.SocketSettings != nil {
		dialerProxy = h.streamSettings.SocketSettings.DialerProxy
	}
	errors.LogDebug(ctx, "outbound dial start: tag=", h.tag, " dest=", dest, " strategy=", h.effectiveStrategy(), " tcpConcurrent=", tcpConcurrentEnabled(h.senderSettings), " dialerProxy=", dialerProxy)
	if h.senderSettings != nil {
		if h.senderSettings.Via != nil && len(outbounds) > 0 {
			ob := outbounds[len(outbounds)-1]
			h.SetOutboundGateway(ctx, ob)
		}
	}

	h.setTransparentGateway(ctx, outbounds)

	h.setOutboundStrategy(outbounds)

	if dest.Network == net.Network_TCP && tcpConcurrentEnabled(h.senderSettings) {
		conn, err := h.dialConcurrent(ctx, dest)
		if err != os.ErrInvalid {
			if err != nil {
				errors.LogDebugInner(ctx, err, "outbound dial concurrent failed: tag=", h.tag, " dest=", dest)
			}
			h.setOutboundLocal(ctx, conn)
			setOutboundConn(outbounds, conn)
			return conn, err
		}
	}

	if conn, err := h.getUoTConnection(ctx, dest); err != os.ErrInvalid {
		if err != nil {
			errors.LogDebugInner(ctx, err, "outbound dial UoT failed: tag=", h.tag, " dest=", dest)
		}
		h.setOutboundLocal(ctx, conn)
		setOutboundConn(outbounds, conn)
		return conn, err
	}

	conn, err := internet.Dial(ctx, dest, h.streamSettings)
	if err != nil {
		errors.LogDebugInner(ctx, err, "outbound dial failed: tag=", h.tag, " dest=", dest)
	}
	conn = h.getStatCouterConnection(conn)
	h.setOutboundLocal(ctx, conn)
	setOutboundConn(outbounds, conn) // for observatory and Vision pre-connect
	return conn, err
}

func setOutboundConn(outbounds []*session.Outbound, conn stat.Connection) {
	if conn == nil || len(outbounds) == 0 {
		return
	}
	ob := outbounds[len(outbounds)-1]
	if ob == nil {
		return
	}
	ob.Conn = conn
}

func (h *Handler) setTransparentGateway(ctx context.Context, outbounds []*session.Outbound) {
	if len(outbounds) == 0 {
		return
	}
	if _, ok := h.proxyConfig.(*freedom.Config); !ok {
		return
	}
	ob := outbounds[len(outbounds)-1]
	if ob == nil {
		return
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !inbound.Transparent {
		return
	}
	if !inbound.Source.IsValid() || inbound.Source.Port == 0 {
		return
	}
	if ob.Gateway != nil && inbound.Source.Address != nil && inbound.Source.Address.Family().IsIP() {
		if gwIP := ob.Gateway.IP(); gwIP != nil && gwIP.Equal(inbound.Source.Address.IP()) {
			return
		}
	}
	if ob.Gateway == nil {
		if inbound.Source.Address != nil && inbound.Source.Address.Family().IsIPv6() {
			ob.Gateway = net.AnyIPv6
		} else {
			ob.Gateway = net.AnyIP
		}
	}
	if ob.GatewayPort == 0 {
		ob.GatewayPort = inbound.Source.Port
	}
}

func (h *Handler) setOutboundLocal(ctx context.Context, conn stat.Connection) {
	if conn == nil {
		return
	}
	ct := conntrack.ConnectionFromContext(ctx)
	if ct == nil {
		return
	}
	local := conn.LocalAddr()
	if local == nil {
		return
	}
	switch local.(type) {
	case *net.TCPAddr, *net.UDPAddr, *net.UnixAddr:
		ct.SetOutboundLocal(net.DestinationFromAddr(local))
	}
}

// shouldSetGateway checks if gateway should be configured for the outbound.
func (h *Handler) shouldSetGateway(ob *session.Outbound) bool {
	if ob.Gateway != nil || h.senderSettings == nil {
		return false
	}
	if h.streamSettings.SocketSettings != nil && len(h.streamSettings.SocketSettings.DialerProxy) > 0 {
		return false
	}
	return true
}

// getInboundAddress returns inbound address for "origin" or "srcip" domain.
func getInboundAddress(ctx context.Context, domain string) net.Address {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return nil
	}
	switch domain {
	case "origin":
		if inbound.Local.IsValid() && inbound.Local.Address.Family().IsIP() {
			errors.LogDebug(ctx, "use inbound local ip as sendthrough: ", inbound.Local.Address.String())
			return inbound.Local.Address
		}
	case "srcip":
		if inbound.Source.IsValid() && inbound.Source.Address.Family().IsIP() {
			errors.LogDebug(ctx, "use inbound source ip as sendthrough: ", inbound.Source.Address.String())
			// Only return if it matches expected family (IPv6 when used for Via6).
			return inbound.Source.Address
		}
	}
	return nil
}

func (h *Handler) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {
	s := h.senderSettings
	if s != nil {
		ob.TcpConcurrent = tcpConcurrentEnabled(s)
		ob.HasSecondaryGateway = s.Via6 != nil
	}
	if !h.shouldSetGateway(ob) {
		return
	}
	strategy := h.effectiveStrategy()
	if ob != nil {
		if hinted := internet.DomainStrategy(ob.TargetStrategy); hinted.HasStrategy() {
			strategy = hinted
		}
	}
	// Fall back to socket DNS strategy when target strategy is not set, so
	// sendThrough stack selection matches the IP preference used for dialing.
	useSecondary := shouldUseSecondaryStack(ob, strategy, s.Via6 != nil)

	var viaCompiled, via6Compiled *internet.CompiledSendThrough
	if h.freedomSettings != nil {
		viaCompiled = h.freedomSettings.ViaCompiled
		via6Compiled = h.freedomSettings.Via6Compiled
	}

	// Select primary/secondary based on stack preference
	primary, secondary := s.Via, s.Via6
	primaryCidr, secondaryCidr := s.ViaCidr, s.Via6Cidr
	primaryCompiled, secondaryCompiled := viaCompiled, via6Compiled
	if useSecondary {
		primary, secondary = s.Via6, s.Via
		primaryCidr, secondaryCidr = s.Via6Cidr, s.ViaCidr
		primaryCompiled, secondaryCompiled = via6Compiled, viaCompiled
	}

	// Handle system default markers
	switch {
	case isIPv6Unspecified(primary):
		return
	case isIPv4Unspecified(primary) && s.Via6 != nil:
		ob.Gateway = net.AnyIP
		return
	case isIPv4Unspecified(primary) || isIPv6Unspecified(s.Via):
		return
	}

	// Select gateway: explicit priority prevents cross-stack fallback
	addr, cidr, compiled := primary, primaryCidr, primaryCompiled
	if addr == nil {
		if strategy.HasFallback() {
			// Explicit priority: no gateway, let system route handle DNS fallback case
			return
		}
		addr, cidr, compiled = secondary, secondaryCidr, secondaryCompiled
	}
	if addr == nil {
		return
	}

	// Set gateway
	switch domain := addr.GetDomain(); {
	case cidr != "":
		if compiled != nil {
			ob.Gateway = internet.ParseRandomIPCompiled(ctx, compiled, ob)
			return
		}
		ob.Gateway = ParseRandomIP(ctx, addr.AsAddress(), cidr, ob)
	case domain == "origin" || domain == "srcip":
		gw := getInboundAddress(ctx, domain)
		if gw == nil {
			return
		}
		// When the strategy has an explicit ordered preference (e.g., ForceIPv6v4/UseIPv6v4),
		// don't let inbound source IP override the stack choice. Only allow when the inbound
		// address matches the preferred stack.
		if strategy.HasFallback() && strategy.PreferIP6() != strategy.PreferIP4() {
			if strategy.PreferIP6() && !gw.Family().IsIPv6() {
				return
			}
			if strategy.PreferIP4() && !gw.Family().IsIPv4() {
				return
			}
		}
		// Prevent IPv4 gateway being used for Via6.
		if domain == "srcip" && useSecondary && gw.Family().IsIPv4() {
			return
		}
		ob.Gateway = gw
	default:
		ob.Gateway = addr.AsAddress()
	}
}

func (h *Handler) gatewayForFamily(ctx context.Context, family net.AddressFamily) net.Address {
	if h.senderSettings == nil {
		return nil
	}
	s := h.senderSettings
	var addr *net.IPOrDomain
	var cidr string
	var compiled *internet.CompiledSendThrough
	switch {
	case family.IsIPv6():
		addr, cidr = s.Via6, s.Via6Cidr
		if h.freedomSettings != nil {
			compiled = h.freedomSettings.Via6Compiled
		}
	case family.IsIPv4():
		addr, cidr = s.Via, s.ViaCidr
		if h.freedomSettings != nil {
			compiled = h.freedomSettings.ViaCompiled
		}
	default:
		return nil
	}
	switch {
	case addr == nil || isIPv6Unspecified(addr):
		return nil
	case family.IsIPv4() && isIPv4Unspecified(addr) && s.Via6 != nil:
		return net.AnyIP
	case family.IsIPv4() && isIPv4Unspecified(addr):
		return nil
	}

	switch domain := addr.GetDomain(); {
	case cidr != "":
		if compiled != nil {
			return internet.ParseRandomIPCompiled(ctx, compiled, outboundFromContext(ctx))
		}
		return ParseRandomIP(ctx, addr.AsAddress(), cidr, outboundFromContext(ctx))
	case domain == "origin" || domain == "srcip":
		gw := getInboundAddress(ctx, domain)
		if gw == nil {
			return nil
		}
		if family.IsIPv6() && gw.Family().IsIPv4() {
			return nil
		}
		if family.IsIPv4() && gw.Family().IsIPv6() {
			return nil
		}
		return gw
	default:
		gw := addr.AsAddress()
		if gw == nil {
			return nil
		}
		if family.IsIPv6() && !gw.Family().IsIPv6() {
			return nil
		}
		if family.IsIPv4() && !gw.Family().IsIPv4() {
			return nil
		}
		return gw
	}
}

func contextWithOutboundGateway(ctx context.Context, ob *session.Outbound, gw net.Address) context.Context {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || ob == nil {
		return ctx
	}
	obCopy := *ob
	obCopy.Gateway = gw
	newOutbounds := make([]*session.Outbound, len(outbounds), len(outbounds)+1)
	copy(newOutbounds, outbounds)
	newOutbounds = append(newOutbounds, &obCopy)
	return session.ContextWithOutbounds(ctx, newOutbounds)
}

func outboundFromContext(ctx context.Context) *session.Outbound {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return nil
	}
	return outbounds[len(outbounds)-1]
}

func shouldUseSecondaryStack(ob *session.Outbound, strategy internet.DomainStrategy, hasSecondary bool) bool {
	if !hasSecondary {
		return false
	}
	// For re-lookup flows we intentionally want to prefer the secondary stack (typically IPv6)
	// when the strategy allows IPv6, even if the original target was IPv4.
	if ob.ReLookup && hasSecondary {
		if strategy.HasFallback() {
			return strategy.PreferIP6()
		}
		if strategy.PreferIP6() {
			return true
		}
	}
	targetAddr := ob.Target.Address
	routeAddr := ob.RouteTarget.Address
	origAddr := ob.OriginalTarget.Address

	// Follow resolved IP version if target/route already became IP.
	for _, addr := range []net.Address{targetAddr, routeAddr} {
		if addr != nil && addr.Family().IsIP() {
			return addr.Family().IsIPv6()
		}
	}

	targetIsDomain := targetAddr != nil && targetAddr.Family().IsDomain()
	routeIsDomain := routeAddr != nil && routeAddr.Family().IsDomain()

	// When target is domain, honor strategy preference before original target IP (e.g. TPROXY).
	if targetIsDomain || routeIsDomain {
		if strategy.HasFallback() {
			return strategy.PreferIP6()
		}
		if strategy.HasStrategy() && strategy.PreferIP6() != strategy.PreferIP4() {
			return strategy.PreferIP6()
		}
	}

	// Fall back to original target IP version.
	if origAddr != nil && origAddr.Family().IsIP() {
		return origAddr.Family().IsIPv6()
	}

	// Explicit priority from strategy
	if strategy.HasFallback() {
		return strategy.PreferIP6()
	}

	// Honor strategy preference for domain targets
	if strategy.HasStrategy() && strategy.PreferIP6() != strategy.PreferIP4() {
		return strategy.PreferIP6()
	}

	return hasSecondary
}

func isIPv6Unspecified(addr *net.IPOrDomain) bool {
	if addr == nil {
		return false
	}
	address := addr.AsAddress()
	if address == nil || !address.Family().IsIPv6() {
		return false
	}
	ip := address.IP()
	return ip != nil && ip.To4() == nil && ip.IsUnspecified()
}

func isIPv4Unspecified(addr *net.IPOrDomain) bool {
	if addr == nil {
		return false
	}
	address := addr.AsAddress()
	if address == nil || !address.Family().IsIPv4() {
		return false
	}
	ip := address.IP()
	return ip != nil && ip.To4() != nil && ip.IsUnspecified()
}

func (h *Handler) getStatCouterConnection(conn stat.Connection) stat.Connection {
	if h.uplinkCounter != nil || h.downlinkCounter != nil {
		return &stat.CounterConnection{
			Connection:   conn,
			ReadCounter:  h.downlinkCounter,
			WriteCounter: h.uplinkCounter,
		}
	}
	return conn
}

// GetOutbound implements proxy.GetOutbound.
func (h *Handler) GetOutbound() proxy.Outbound {
	return h.proxy
}

// Start implements common.Runnable.
func (h *Handler) Start() error {
	return nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	common.Close(h.mux)
	common.Close(h.proxy)
	return nil
}

// SenderSettings implements outbound.Handler.
func (h *Handler) SenderSettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.senderSettings)
}

// FreedomDialerSettings exposes precompiled freedom sender settings for transport layer.
func (h *Handler) FreedomDialerSettings() *internet.FreedomDialerSettings {
	return h.freedomSettings
}

// ProxySettings implements outbound.Handler.
func (h *Handler) ProxySettings() *serial.TypedMessage {
	return serial.ToTypedMessage(h.proxyConfig)
}

func ParseRandomIP(ctx context.Context, addr net.Address, prefix string, ob *session.Outbound) net.Address {
	return internet.ParseRandomIP(ctx, addr, prefix, ob)
}
