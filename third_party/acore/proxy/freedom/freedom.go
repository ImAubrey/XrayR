package freedom

import (
	"context"
	"crypto/rand"
	"io"
	stdnet "net"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/crypto"
	xctx "github.com/ImAubrey/acore/common/ctx"
	"github.com/ImAubrey/acore/common/dice"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/platform"
	"github.com/ImAubrey/acore/common/retry"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/common/signal"
	"github.com/ImAubrey/acore/common/task"
	"github.com/ImAubrey/acore/common/utils"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/policy"
	"github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/proxy"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/stat"
	"github.com/ImAubrey/acore/transport/pipe"
	"github.com/pires/go-proxyproto"
	"golang.org/x/sync/singleflight"
)

var useSplice bool

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
			return h.Init(config.(*Config), pm)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseFreedomSplice).GetValue(func() string { return defaultFlagValue })
	switch value {
	case defaultFlagValue, "auto", "enable":
		useSplice = true
	}
}

// ConnExpire holds a pre-connected connection with expiration time.
type ConnExpire struct {
	Conn   stat.Connection
	Expire time.Time
	Dest   net.Destination
}

// Handler handles Freedom connections.
type Handler struct {
	policyManager policy.Manager
	config        *Config

	initpre  sync.Once
	preDone  chan struct{}
	preWG    sync.WaitGroup
	preConns chan *ConnExpire

	closeOnce sync.Once

	preConKeepEnabled bool
	preConKeep        time.Duration
}

type cachedMultiBufferReader interface {
	ReadCachedMultiBuffer() (buf.MultiBuffer, bool)
	UnderlyingReader() buf.TimeoutReader
}

// Init initializes the Handler with necessary parameters.
func (h *Handler) Init(config *Config, pm policy.Manager) error {
	h.config = config
	h.policyManager = pm
	h.preConKeep, h.preConKeepEnabled = preconnectKeepaliveFromConfig(config.PreConKeep)
	return nil
}

func (h *Handler) policy() policy.Session {
	p := h.policyManager.ForLevel(h.config.UserLevel)
	return p
}

// writeProxyProtocol writes proxy protocol header to the connection.
// Returns error if write fails, nil on success or if proxy protocol is disabled.
func (h *Handler) writeProxyProtocol(conn stat.Connection, inbound *session.Inbound, network net.Network) error {
	if h.config.ProxyProtocol <= 0 || h.config.ProxyProtocol > 2 || network != net.Network_TCP {
		return nil
	}
	version := byte(h.config.ProxyProtocol)
	srcAddr := inbound.Source.RawNetAddr()
	dstAddr := conn.RemoteAddr()
	header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
	_, err := header.WriteTo(conn)
	return err
}

// startPreconnectWorker starts a goroutine that pre-establishes connections.
func (h *Handler) startPreconnectWorker(ctx context.Context, dialer internet.Dialer, destBase net.Destination, picker func() (net.Address, error), dialTimeout time.Duration) {
	h.preWG.Add(1)
	go func() {
		defer h.preWG.Done()
		if ctx == nil {
			ctx = context.Background()
		}
		preCtx := xctx.ContextWithID(ctx, session.NewID())
		for {
			select {
			case <-h.preDone:
				return
			default:
			}

			addr, err := picker()
			if err != nil || addr == nil {
				if err != nil {
					errors.LogWarningInner(preCtx, err, "pre-connect failed: invalid redirect address")
				} else {
					errors.LogWarning(preCtx, "pre-connect skipped: redirect address missing")
				}
				time.Sleep(preconnectRetryDelay)
				continue
			}

			preDest := destBase
			preDest.Address = addr

			dialCtx := preCtx
			var cancel context.CancelFunc
			if dialTimeout > 0 {
				dialCtx, cancel = context.WithTimeout(preCtx, dialTimeout)
			}
			preConn, err := dialer.Dial(dialCtx, preDest)
			if cancel != nil {
				cancel()
			}
			if err != nil {
				errors.LogWarningInner(preCtx, err, "pre-connect failed")
				time.Sleep(preconnectRetryDelay)
				continue
			}

			if h.preConKeepEnabled {
				applyPreconnectKeepalive(preConn, h.preConKeep)
			}
			connTime := &ConnExpire{
				Conn:   preConn,
				Expire: time.Now().Add(time.Minute * 2),
				Dest:   preDest,
			}
			select {
			case h.preConns <- connTime:
			case <-h.preDone:
				preConn.Close()
				return
			}

			select {
			case <-h.preDone:
				return
			default:
			}
			time.Sleep(preconnectRetryDelay)
		}
	}()
}

// getPreconnection retrieves a valid pre-established connection from the pool.
// It discards expired connections and returns the first valid one.
func (h *Handler) getPreconnection(ctx context.Context, timeout time.Duration) (*ConnExpire, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var timer <-chan time.Time
	var t *time.Timer
	if timeout > 0 {
		t = time.NewTimer(timeout)
		timer = t.C
	}
	if t != nil {
		defer t.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer:
			return nil, errors.New("pre-connect timeout")
		case connTime := <-h.preConns:
			if connTime == nil {
				return nil, errors.New("closed handler")
			}
			if time.Now().Before(connTime.Expire) {
				if conn, ok := isPreconnectUsable(connTime.Conn); ok {
					connTime.Conn = conn
					return connTime, nil
				}
				connTime.Conn.Close()
				continue
			}
			connTime.Conn.Close()
		}
	}
}

type preReadConn struct {
	stat.Connection
	buf []byte
}

func (c *preReadConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Connection.Read(p)
}

func (c *preReadConn) NetConn() stdnet.Conn {
	return c.Connection
}

// isPreconnectUsable checks if a preconnected TCP conn is still alive.
// It treats any read error (except timeout) as unusable. If data is pending,
// it keeps the connection usable and preserves the data.
func isPreconnectUsable(conn stat.Connection) (stat.Connection, bool) {
	if conn == nil {
		return nil, false
	}
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		// Best effort: if we can't set deadline, keep the old behavior.
		return conn, true
	}
	defer conn.SetReadDeadline(time.Time{})

	var b [1]byte
	n, err := conn.Read(b[:])
	if n > 0 {
		return &preReadConn{Connection: conn, buf: b[:n]}, true
	}
	if err == nil {
		return conn, true
	}
	if ne, ok := err.(stdnet.Error); ok && ne.Timeout() {
		return conn, true
	}
	return conn, false
}

const defaultPreConKeep = 25 * time.Second
const defaultPreconnectWait = 5 * time.Second
const preconnectRetryDelay = 200 * time.Millisecond

func preconnectKeepaliveFromConfig(v int64) (time.Duration, bool) {
	if v < 0 {
		return 0, false
	}
	if v == 0 {
		return defaultPreConKeep, true
	}
	return time.Duration(v), true
}

func applyPreconnectKeepalive(conn stat.Connection, keepAlive time.Duration) {
	if conn == nil || keepAlive <= 0 {
		return
	}
	raw := stat.TryUnwrapStatsConn(conn)
	raw = unwrapNetConn(raw)
	tcpConn, ok := raw.(*stdnet.TCPConn)
	if !ok {
		return
	}
	_ = tcpConn.SetKeepAliveConfig(stdnet.KeepAliveConfig{
		Enable:   true,
		Idle:     keepAlive,
		Interval: keepAlive,
	})
}

func unwrapNetConn(conn stdnet.Conn) stdnet.Conn {
	for {
		switch c := conn.(type) {
		case interface{ NetConn() stdnet.Conn }:
			next := c.NetConn()
			if next == nil || next == conn {
				return conn
			}
			conn = next
			continue
		}
		return conn
	}
}

func preconnectBaseContext(ob *session.Outbound) context.Context {
	ctx := context.Background()
	if ob == nil {
		return ctx
	}
	obCopy := *ob
	return session.ContextWithOutbounds(ctx, []*session.Outbound{&obCopy})
}

// resolveDestination resolves domain address to IP if domain strategy is configured.
func (h *Handler) resolveDestination(ctx context.Context, dest net.Destination, origTargetAddr, outGateway net.Address) (net.Destination, error) {
	// choose strategy: outbound freedom config > session hint (TargetStrategy) > socket domainStrategy
	outbounds := session.OutboundsFromContext(ctx)
	var ob *session.Outbound
	if len(outbounds) > 0 {
		ob = outbounds[len(outbounds)-1]
	}

	strategy := h.config.DomainStrategy
	if !strategy.HasStrategy() {
		if ob != nil {
			if s := internet.DomainStrategy(ob.TargetStrategy); s.HasStrategy() {
				strategy = s
			}
		}
	}

	isDomain := dest.Address.Family().IsDomain()
	errors.LogDebug(ctx, "freedom resolve: target=", dest, " isDomain=", isDomain, " strategy=", strategy, " gateway=", outGateway)
	if !strategy.HasStrategy() && isDomain {
		// When outbound stack selection is in effect (sendThrough/tcpConcurrent),
		// avoid dialing with unresolved domain and falling back to system stack.
		if ob != nil && (ob.Gateway != nil || ob.HasSecondaryGateway || ob.TcpConcurrent) {
			strategy = internet.DomainStrategy_USE_IP
		}
	}
	if !strategy.HasStrategy() || !isDomain {
		errors.LogDebug(ctx, "freedom resolve: skip resolve, target=", dest, " strategy=", strategy)
		return dest, nil
	}

	if dest.Network == net.Network_UDP && origTargetAddr != nil && outGateway == nil {
		strategy = strategy.GetDynamicStrategy(origTargetAddr.Family())
	}
	localAddr := outGateway
	if ob != nil && ob.TcpConcurrent && ob.HasSecondaryGateway {
		localAddr = nil
	}
	ips, err := internet.LookupForIPWithContext(ctx, dest.Address.Domain(), strategy, localAddr)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", dest.Address.Domain())
		if strategy.ForceIP() {
			return dest, err
		}
		return dest, nil
	}
	if ob != nil {
		ob.TargetIPs = ips
	}
	chosen := ips[dice.Roll(len(ips))]
	if ob != nil && ob.ReLookup && strategy.PreferIP6() {
		if preferred := pickPreferredIP(ips, true); preferred != nil {
			chosen = preferred
		}
	}
	resolved := net.Destination{
		Network: dest.Network,
		Address: net.IPAddress(chosen),
		Port:    dest.Port,
	}
	errors.LogInfo(ctx, "dialing to ", resolved)
	errors.LogDebug(ctx, "freedom resolve: resolved target=", resolved, " original=", dest, " ips=", ips)
	return resolved, nil
}

// createWriter creates appropriate buf.Writer based on network type and config.
func (h *Handler) createWriter(ctx context.Context, conn stat.Connection, dest net.Destination, UDPOverride net.Destination) buf.Writer {
	if dest.Network == net.Network_TCP {
		if h.config.Fragment != nil {
			errors.LogDebug(ctx, "FRAGMENT", h.config.Fragment.PacketsFrom, h.config.Fragment.PacketsTo,
				h.config.Fragment.LengthMin, h.config.Fragment.LengthMax,
				h.config.Fragment.IntervalMin, h.config.Fragment.IntervalMax,
				h.config.Fragment.MaxSplitMin, h.config.Fragment.MaxSplitMax)
			return buf.NewWriter(&FragmentWriter{fragment: h.config.Fragment, writer: conn})
		}
		return buf.NewWriter(conn)
	}
	writer := NewPacketWriter(conn, h, UDPOverride, dest)
	if h.config.Noises != nil {
		errors.LogDebug(ctx, "NOISE", h.config.Noises)
		return &NoisePacketWriter{
			Writer:      writer,
			noises:      h.config.Noises,
			firstWrite:  true,
			UDPOverride: UDPOverride,
			remoteAddr:  net.DestinationFromAddr(conn.RemoteAddr()).Address,
		}
	}
	return writer
}

// createReader creates appropriate buf.Reader based on network type.
func (h *Handler) createReader(conn stat.Connection, dest net.Destination, UDPOverride net.Destination) buf.Reader {
	if dest.Network == net.Network_TCP {
		return buf.NewReader(conn)
	}
	return NewPacketReader(conn, UDPOverride, dest)
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	h.closeOnce.Do(func() {
		if h.preDone != nil {
			close(h.preDone)
		}
		// Wait for preconnect workers to stop sending before closing the channel.
		h.preWG.Wait()
		if h.preConns != nil {
			close(h.preConns)
			for connTime := range h.preConns {
				if connTime != nil && connTime.Conn != nil {
					connTime.Conn.Close()
				}
			}
		}
	})
	return nil
}

func isValidAddress(addr *net.IPOrDomain) bool {
	if addr == nil {
		return false
	}

	a := addr.AsAddress()
	return a != net.AnyIP && a != net.AnyIPv6
}

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

// unwrapStatConn returns the underlying net.Conn along with read/write counters (if any).
func unwrapStatConn(conn net.Conn) (net.Conn, stats.Counter, stats.Counter) {
	if c, ok := conn.(*stat.CounterConnection); ok {
		return c.Connection, c.ReadCounter, c.WriteCounter
	}
	return conn, nil, nil
}

type cidrPicker struct {
	base net.IP
	mask net.IPMask
	size int
}

func (p *cidrPicker) Next() (net.Address, error) {
	randBytes := make([]byte, p.size)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, err
	}
	out := make(net.IP, p.size)
	for i := 0; i < p.size; i++ {
		out[i] = (p.base[i] & p.mask[i]) | (randBytes[i] & ^p.mask[i])
	}
	return net.IPAddress(out), nil
}

func newCIDRPicker(cidr string) (*cidrPicker, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip4 := ip.To4(); ip4 != nil {
		if len(ipnet.Mask) != net.IPv4len {
			return nil, errors.New("invalid CIDR mask: ", cidr)
		}
		base := make(net.IP, net.IPv4len)
		copy(base, ip4)
		return &cidrPicker{base: base, mask: ipnet.Mask, size: net.IPv4len}, nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, errors.New("invalid CIDR address: ", cidr)
	}
	if len(ipnet.Mask) != net.IPv6len {
		return nil, errors.New("invalid CIDR mask: ", cidr)
	}
	base := make(net.IP, net.IPv6len)
	copy(base, ip16)
	return &cidrPicker{base: base, mask: ipnet.Mask, size: net.IPv6len}, nil
}

func redirectAddressPicker(addr *net.IPOrDomain) (func() (net.Address, error), error) {
	if addr == nil {
		return nil, nil
	}
	if ip := addr.GetIp(); len(ip) > 0 {
		fixed := net.IPAddress(ip)
		return func() (net.Address, error) { return fixed, nil }, nil
	}
	domain := strings.TrimSpace(addr.GetDomain())
	if domain == "" {
		return nil, nil
	}
	if strings.Contains(domain, "/") {
		picker, err := newCIDRPicker(domain)
		if err != nil {
			return nil, err
		}
		return picker.Next, nil
	}
	fixed := net.ParseAddress(domain)
	return func() (net.Address, error) { return fixed, nil }, nil
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "freedom"
	ob.CanSpliceCopy = 1
	if h.config.DomainStrategy.HasStrategy() {
		ob.TargetStrategy = uint8(h.config.DomainStrategy)
	}
	inbound := session.InboundFromContext(ctx)

	destination := ob.Target
	origTargetAddr := ob.OriginalTarget.Address
	if origTargetAddr == nil {
		origTargetAddr = ob.Target.Address
	}
	errors.LogDebug(ctx, "freedom start: tag=", ob.Tag, " target=", ob.Target, " original=", ob.OriginalTarget, " route=", ob.RouteTarget, " strategy=", h.config.DomainStrategy, " tcpConcurrent=", ob.TcpConcurrent, " gateway=", ob.Gateway, " gatewayPort=", ob.GatewayPort)
	dialer.SetOutboundGateway(ctx, ob)
	UDPOverride := net.UDPDestination(nil, 0)
	var redirectAddrPicker func() (net.Address, error)
	redirectPortSet := false
	if h.config.DestinationOverride != nil {
		server := h.config.DestinationOverride.Server
		if server != nil {
			if isValidAddress(server.Address) {
				picker, err := redirectAddressPicker(server.Address)
				if err != nil {
					return errors.New("invalid redirect address").Base(err)
				}
				redirectAddrPicker = picker
			}
			if server.Port != 0 {
				destination.Port = net.Port(server.Port)
				UDPOverride.Port = destination.Port
				redirectPortSet = true
			}
		}
	}

	input := link.Reader
	output := link.Writer

	var conn stat.Connection

	// Pre-connection logic: use pre-established connections if testpre is enabled
	preconnectRequested := h.config.Testpre > 0 && h.config.DestinationOverride != nil
	usePreconnect := preconnectRequested && redirectAddrPicker != nil && redirectPortSet
	if preconnectRequested && !usePreconnect {
		errors.LogWarning(ctx, "pre-connect skipped: redirect address/port missing")
	}
	if usePreconnect {
		errors.LogDebug(ctx, "freedom pre-connect enabled: target=", destination, " redirectPortSet=", redirectPortSet)
	}

	applyRedirect := func() error {
		if redirectAddrPicker == nil {
			return nil
		}
		addr, err := redirectAddrPicker()
		if err != nil {
			return errors.New("invalid redirect address").Base(err)
		}
		if addr != nil {
			destination.Address = addr
			UDPOverride.Address = destination.Address
		}
		return nil
	}

	if !usePreconnect {
		if err := applyRedirect(); err != nil {
			return err
		}
	}

	if usePreconnect {
		preconnectTimeout := h.policy().Timeouts.Handshake
		if preconnectTimeout <= 0 {
			preconnectTimeout = defaultPreconnectWait
		}
		h.initpre.Do(func() {
			h.preDone = make(chan struct{})
			// Unbuffered channel: each worker holds at most one connection, avoiding 2x pool growth.
			h.preConns = make(chan *ConnExpire)
			destBase := net.Destination{Network: destination.Network, Port: destination.Port}
			for range h.config.Testpre {
				h.startPreconnectWorker(preconnectBaseContext(ob), dialer, destBase, redirectAddrPicker, preconnectTimeout)
			}
		})
		connTime, err := h.getPreconnection(ctx, preconnectTimeout)
		if err != nil {
			errors.LogWarningInner(ctx, err, "pre-connect unavailable, fallback to direct dial")
			usePreconnect = false
			if err := applyRedirect(); err != nil {
				return err
			}
		} else {
			conn = connTime.Conn
			destination.Address = connTime.Dest.Address
			destination.Port = connTime.Dest.Port
			UDPOverride.Address = destination.Address
			UDPOverride.Port = destination.Port
		}
	}

	if conn != nil {
		if err := h.writeProxyProtocol(conn, inbound, destination.Network); err != nil {
			errors.LogWarningInner(ctx, err, "failed to write proxy protocol header on pre-connected conn")
			conn.Close()
			conn = nil
		}
	}

	if conn == nil {
		err := retry.ExponentialBackoff(5, 100).On(func() error {
			dialDest, err := h.resolveDestination(ctx, destination, origTargetAddr, ob.Gateway)
			if err != nil {
				errors.LogDebugInner(ctx, err, "freedom dial resolve failed: target=", destination)
				return err
			}

			errors.LogDebug(ctx, "freedom dial attempt: target=", dialDest, " original=", destination, " gateway=", ob.Gateway, " gatewayPort=", ob.GatewayPort, " tcpConcurrent=", ob.TcpConcurrent)
			rawConn, err := dialer.Dial(ctx, dialDest)
			if err != nil {
				errors.LogDebugInner(ctx, err, "freedom dial failed: target=", dialDest)
				return err
			}

			if err = h.writeProxyProtocol(rawConn, inbound, destination.Network); err != nil {
				errors.LogDebugInner(ctx, err, "freedom proxy protocol write failed: target=", dialDest)
				rawConn.Close()
				return err
			}

			conn = rawConn
			return nil
		})
		if err != nil {
			errors.LogDebugInner(ctx, err, "freedom dial exhausted: target=", destination)
			return errors.New("failed to open connection to ", destination).Base(err)
		}
	}
	defer conn.Close()
	if ob != nil {
		ob.Conn = conn
	}
	errors.LogInfo(ctx, "connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, plcy.Timeouts.ConnectionIdle)
	downlinkOnlyTimeout := proxy.AdaptHalfCloseTimeout(conn, plcy.Timeouts.DownlinkOnly)
	uplinkOnlyTimeout := proxy.AdaptHalfCloseTimeout(conn, plcy.Timeouts.UplinkOnly)
	spliceCapable := destination.Network == net.Network_TCP && useSplice && proxy.IsRAWTransportWithoutSecurity(conn)

	requestDone := func() error {
		defer func() {
			if spliceCapable {
				proxy.MarkConntrackSpliceHalfClosed(ctx, downlinkOnlyTimeout)
			}
			timer.SetTimeout(downlinkOnlyTimeout)
		}()
		writer := h.createWriter(ctx, conn, destination, UDPOverride)
		if spliceCapable && h.config.Fragment == nil {
			used, err := func() (bool, error) {
				inbound := session.InboundFromContext(ctx)
				switch {
				case inbound == nil || inbound.Conn == nil:
					errors.LogDebug(ctx, "splice uplink skipped: inbound conn missing")
					return false, nil
				case inbound.CanSpliceCopy == 3 || ob.CanSpliceCopy == 3:
					errors.LogDebug(ctx, "splice uplink skipped: splice disabled")
					return false, nil
				}

				var rawReader buf.Reader
				var cached cachedMultiBufferReader
				var buffered *buf.BufferedReader
				switch r := link.Reader.(type) {
				case *conntrack.CountingReader:
					rawReader = r.Reader
				case *buf.TimeoutWrapperReader:
					rawReader = r.Reader
				case cachedMultiBufferReader:
					cached = r
					rawReader = r.UnderlyingReader()
				case *buf.BufferedReader:
					buffered = r
					rawReader = r.Reader
				default:
					errors.LogDebug(ctx, "splice uplink skipped: unsupported reader (sniffing?)")
					return false, nil
				}

				for {
					switch rr := rawReader.(type) {
					case *conntrack.CountingReader:
						rawReader = rr.Reader
						continue
					case *buf.TimeoutWrapperReader:
						if _, isPipe := rr.Reader.(*pipe.Reader); isPipe {
							errors.LogDebug(ctx, "splice uplink skipped: pipe reader (sniffing)")
							return false, nil
						}
						if br, ok := rr.Reader.(*buf.BufferedReader); ok {
							buffered = br
						}
					case *pipe.Reader:
						errors.LogDebug(ctx, "splice uplink skipped: pipe reader (sniffing)")
						return false, nil
					case *buf.BufferedReader:
						buffered = rr
					}
					break
				}

				flushCachedAndBuffered := func() (string, error) {
					logMsg := "splice uplink enabled"
					if cached != nil {
						for {
							mb, ok := cached.ReadCachedMultiBuffer()
							if !ok {
								break
							}
							if mb != nil && !mb.IsEmpty() {
								if err := writer.WriteMultiBuffer(mb); err != nil {
									return "", errors.New("failed to flush sniffed data").Base(err)
								}
							}
						}
						logMsg = "splice uplink enabled after sniffing"
					}
					if buffered != nil && buffered.BufferedBytes() > 0 {
						mb, err := buffered.ReadMultiBuffer()
						if err != nil {
							return "", errors.New("failed to flush buffered data").Base(err)
						}
						if mb != nil && !mb.IsEmpty() {
							if err := writer.WriteMultiBuffer(mb); err != nil {
								return "", errors.New("failed to flush buffered data").Base(err)
							}
						}
						logMsg = "splice uplink enabled after buffered flush"
					}
					return logMsg, nil
				}

				spliceReady := func() bool {
					inbound := session.InboundFromContext(ctx)
					return inbound != nil && inbound.CanSpliceCopy == 1 && ob.CanSpliceCopy == 1
				}

				if spliceReady() {
					logMsg, err := flushCachedAndBuffered()
					if err != nil {
						return true, err
					}
					errors.LogDebug(ctx, logMsg)
					return true, proxy.CopyRawConnIfExist(ctx, inbound.Conn, conn, writer, timer, inbound.Timer)
				}

				// Vision (and some other protocols) may become splice-ready after initial processing. Copy through
				// the decoded reader first, then switch to splice once all splice flags are ready.
				for {
					mb, rerr := input.ReadMultiBuffer()
					if !mb.IsEmpty() {
						timer.Update()
						if werr := writer.WriteMultiBuffer(mb); werr != nil {
							return true, werr
						}
					}
					if rerr != nil {
						if errors.Cause(rerr) == io.EOF {
							return true, nil
						}
						return true, rerr
					}
					if spliceReady() {
						logMsg, err := flushCachedAndBuffered()
						if err != nil {
							return true, err
						}
						errors.LogDebug(ctx, logMsg+" (late)")
						return true, proxy.CopyRawConnIfExist(ctx, inbound.Conn, conn, writer, timer, inbound.Timer)
					}
				}
			}()
			if used {
				return err
			}
		}
		if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		defer func() {
			if spliceCapable {
				proxy.MarkConntrackSpliceHalfClosed(ctx, uplinkOnlyTimeout)
			}
			timer.SetTimeout(uplinkOnlyTimeout)
		}()
		if spliceCapable {
			var writeConn net.Conn
			var inTimer *signal.ActivityTimer
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
				writeConn = inbound.Conn
				inTimer = inbound.Timer
			}
			return proxy.CopyRawConnIfExist(ctx, conn, writeConn, link.Writer, timer, inTimer)
		}
		reader := h.createReader(conn, destination, UDPOverride)
		if err := buf.Copy(reader, output, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process response").Base(err)
		}
		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(output))); err != nil {
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func NewPacketReader(conn net.Conn, UDPOverride net.Destination, DialDest net.Destination) buf.Reader {
	iConn, counter, _ := unwrapStatConn(conn)
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		isOverridden := false
		if UDPOverride.Address != nil || UDPOverride.Port != 0 {
			isOverridden = true
		}

		return &PacketReader{
			PacketConnWrapper: c,
			Counter:           counter,
			IsOverridden:      isOverridden,
			InitUnchangedAddr: DialDest.Address,
			InitChangedAddr:   net.DestinationFromAddr(conn.RemoteAddr()).Address,
		}
	}
	return &buf.PacketReader{Reader: conn}
}

type PacketReader struct {
	*internet.PacketConnWrapper
	stats.Counter
	IsOverridden      bool
	InitUnchangedAddr net.Address
	InitChangedAddr   net.Address
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, d, err := r.PacketConnWrapper.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	// if udp dest addr is changed, we are unable to get the correct src addr
	// so we don't attach src info to udp packet, break cone behavior, assuming the dial dest is the expected scr addr
	if !r.IsOverridden {
		address := net.IPAddress(d.(*net.UDPAddr).IP)
		if r.InitChangedAddr == address {
			address = r.InitUnchangedAddr
		}
		b.UDP = &net.Destination{
			Address: address,
			Port:    net.Port(d.(*net.UDPAddr).Port),
			Network: net.Network_UDP,
		}
	}
	if r.Counter != nil {
		r.Counter.Add(int64(n))
	}
	return buf.MultiBuffer{b}, nil
}

// DialDest means the dial target used in the dialer when creating conn
func NewPacketWriter(conn net.Conn, h *Handler, UDPOverride net.Destination, DialDest net.Destination) buf.Writer {
	iConn, _, counter := unwrapStatConn(conn)
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		// If DialDest is a domain, it will be resolved in dialer
		// check this behavior and add it to map
		resolvedUDPAddr := utils.NewTypedSyncMap[string, net.Address]()
		if DialDest.Address.Family().IsDomain() {
			resolvedUDPAddr.Store(DialDest.Address.Domain(), net.DestinationFromAddr(conn.RemoteAddr()).Address)
		}
		return &PacketWriter{
			PacketConnWrapper: c,
			Counter:           counter,
			Handler:           h,
			UDPOverride:       UDPOverride,
			ResolvedUDPAddr:   resolvedUDPAddr,
			LocalAddr:         net.DestinationFromAddr(conn.LocalAddr()).Address,
		}

	}
	return &buf.SequentialWriter{Writer: conn}
}

const packetWriterResolveCacheTTL = 10 * time.Second
const packetWriterWriteBatchSize = 32

type cachedPacketWriterAddress struct {
	addr   net.Address
	expire time.Time
}

var (
	packetWriterResolvedAddrCache      = make(map[string]cachedPacketWriterAddress)
	packetWriterResolvedAddrCacheMu    sync.RWMutex
	packetWriterResolvedAddrCacheGroup singleflight.Group
)

func packetWriterResolveCacheKey(remoteAddress string, localAddr net.Address) string {
	key := "packetWriterAddr|"
	switch {
	case localAddr == nil:
		key += "a"
	case localAddr.Family().IsIPv4():
		key += "4"
	case localAddr.Family().IsIPv6():
		key += "6"
	default:
		key += "u"
	}

	host := remoteAddress
	if h, _, err := stdnet.SplitHostPort(remoteAddress); err == nil {
		host = h
	}
	key += "|" + strings.ToLower(strings.TrimSuffix(host, "."))
	return key
}

func getCachedPacketWriterResolveAddr(key string) (net.Address, bool) {
	packetWriterResolvedAddrCacheMu.RLock()
	entry, ok := packetWriterResolvedAddrCache[key]
	packetWriterResolvedAddrCacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expire) {
		packetWriterResolvedAddrCacheMu.Lock()
		delete(packetWriterResolvedAddrCache, key)
		packetWriterResolvedAddrCacheMu.Unlock()
		return nil, false
	}
	return entry.addr, true
}

func setCachedPacketWriterResolveAddr(key string, addr net.Address) {
	packetWriterResolvedAddrCacheMu.Lock()
	packetWriterResolvedAddrCache[key] = cachedPacketWriterAddress{
		addr:   addr,
		expire: time.Now().Add(packetWriterResolveCacheTTL),
	}
	packetWriterResolvedAddrCacheMu.Unlock()
}

func resolvePacketWriterAddress(remoteAddress string, localAddr net.Address) (net.Address, error) {
	key := packetWriterResolveCacheKey(remoteAddress, localAddr)
	if addr, ok := getCachedPacketWriterResolveAddr(key); ok {
		return addr, nil
	}

	v, err, _ := packetWriterResolvedAddrCacheGroup.Do(key, func() (any, error) {
		if addr, ok := getCachedPacketWriterResolveAddr(key); ok {
			return addr, nil
		}
		udpAddr, err := stdnet.ResolveUDPAddr("udp", remoteAddress)
		if err != nil {
			return nil, err
		}
		if udpAddr == nil || udpAddr.IP == nil {
			return nil, errors.New("empty udp address")
		}
		addr := net.IPAddress(udpAddr.IP)
		if addr == nil {
			return nil, errors.New("invalid udp address")
		}
		setCachedPacketWriterResolveAddr(key, addr)
		return addr, nil
	})
	if err != nil {
		return nil, err
	}
	addr, ok := v.(net.Address)
	if !ok || addr == nil {
		return nil, errors.New("packet writer resolve cache type mismatch")
	}
	return addr, nil
}

type PacketWriter struct {
	*internet.PacketConnWrapper
	stats.Counter
	*Handler
	UDPOverride net.Destination

	// Dest of udp packets might be a domain, we will resolve them to IP
	// But resolver will return a random one if the domain has many IPs
	// Resulting in these packets being sent to many different IPs randomly
	// So, cache and keep the resolve result
	ResolvedUDPAddr *utils.TypedSyncMap[string, net.Address]
	LocalAddr       net.Address
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	batchBuffers := make([]*buf.Buffer, 0, packetWriterWriteBatchSize)
	batchPayloads := make([][]byte, 0, packetWriterWriteBatchSize)
	batchAddrs := make([]net.Addr, 0, packetWriterWriteBatchSize)

	flushBatch := func() error {
		if len(batchBuffers) == 0 {
			return nil
		}

		sent, err := w.PacketConnWrapper.WriteBatch(batchPayloads, batchAddrs)
		if sent < 0 {
			sent = 0
		} else if sent > len(batchBuffers) {
			sent = len(batchBuffers)
		}

		for i := 0; i < sent; i++ {
			if w.Counter != nil {
				w.Counter.Add(int64(len(batchPayloads[i])))
			}
			batchBuffers[i].Release()
		}

		if err != nil {
			for i := sent; i < len(batchBuffers); i++ {
				batchBuffers[i].Release()
			}
			batchBuffers = batchBuffers[:0]
			batchPayloads = batchPayloads[:0]
			batchAddrs = batchAddrs[:0]
			return err
		}

		if sent < len(batchBuffers) {
			for i := sent; i < len(batchBuffers); i++ {
				n, writeErr := w.PacketConnWrapper.WriteTo(batchPayloads[i], batchAddrs[i])
				if writeErr != nil {
					batchBuffers[i].Release()
					for j := i + 1; j < len(batchBuffers); j++ {
						batchBuffers[j].Release()
					}
					batchBuffers = batchBuffers[:0]
					batchPayloads = batchPayloads[:0]
					batchAddrs = batchAddrs[:0]
					return writeErr
				}
				if w.Counter != nil {
					w.Counter.Add(int64(n))
				}
				batchBuffers[i].Release()
			}
		}

		batchBuffers = batchBuffers[:0]
		batchPayloads = batchPayloads[:0]
		batchAddrs = batchAddrs[:0]
		return nil
	}

	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		var destAddr net.Addr
		if b.UDP != nil {
			if w.UDPOverride.Address != nil {
				b.UDP.Address = w.UDPOverride.Address
			}
			if w.UDPOverride.Port != 0 {
				b.UDP.Port = w.UDPOverride.Port
			}
			if b.UDP.Address.Family().IsDomain() {
				if ip, ok := w.ResolvedUDPAddr.Load(b.UDP.Address.Domain()); ok {
					b.UDP.Address = ip
				} else {
					ShouldUseSystemResolver := true
					if w.Handler.config.DomainStrategy.HasStrategy() {
						addr, err := internet.LookupForAddressPick(b.UDP.Address.Domain(), w.Handler.config.DomainStrategy, w.LocalAddr)
						if err != nil {
							// drop packet if resolve failed when forceIP
							if w.Handler.config.DomainStrategy.ForceIP() {
								b.Release()
								continue
							}
						} else {
							ip = addr
							ShouldUseSystemResolver = false
						}
					}
					if ShouldUseSystemResolver {
						addr, err := resolvePacketWriterAddress(b.UDP.NetAddr(), w.LocalAddr)
						if err != nil {
							b.Release()
							continue
						}
						ip = addr
					}
					if ip != nil {
						b.UDP.Address, _ = w.ResolvedUDPAddr.LoadOrStore(b.UDP.Address.Domain(), ip)
					}
				}
			}
			destAddr := b.UDP.RawNetAddr()
			if destAddr == nil {
				b.Release()
				continue
			}
			batchBuffers = append(batchBuffers, b)
			batchPayloads = append(batchPayloads, b.Bytes())
			batchAddrs = append(batchAddrs, destAddr)
		} else {
			destAddr = w.PacketConnWrapper.RemoteAddr()
			if destAddr == nil {
				b.Release()
				continue
			}
			batchBuffers = append(batchBuffers, b)
			batchPayloads = append(batchPayloads, b.Bytes())
			batchAddrs = append(batchAddrs, destAddr)
		}

		if len(batchBuffers) >= packetWriterWriteBatchSize {
			if err := flushBatch(); err != nil {
				buf.ReleaseMulti(mb)
				return err
			}
		}
	}
	return flushBatch()
}

type NoisePacketWriter struct {
	buf.Writer
	noises      []*Noise
	firstWrite  bool
	UDPOverride net.Destination
	remoteAddr  net.Address
}

// MultiBuffer writer with Noise before first packet
func (w *NoisePacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.firstWrite {
		w.firstWrite = false
		//Do not send Noise for dns requests(just to be safe)
		if w.UDPOverride.Port == 53 {
			return w.Writer.WriteMultiBuffer(mb)
		}
		var noise []byte
		var err error
		if w.remoteAddr.Family().IsDomain() {
			panic("impossible, remoteAddr is always IP")
		}
		for _, n := range w.noises {
			switch n.ApplyTo {
			case "ipv4":
				if w.remoteAddr.Family().IsIPv6() {
					continue
				}
			case "ipv6":
				if w.remoteAddr.Family().IsIPv4() {
					continue
				}
			case "ip":
			default:
				panic("unreachable, applyTo is ip/ipv4/ipv6")
			}
			//User input string or base64 encoded string or hex string
			if n.Packet != nil {
				noise = n.Packet
			} else {
				//Random noise
				noise, err = GenerateRandomBytes(crypto.RandBetween(int64(n.LengthMin),
					int64(n.LengthMax)))
			}
			if err != nil {
				return err
			}
			err = w.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(noise)})
			if err != nil {
				return err
			}

			if n.DelayMin != 0 || n.DelayMax != 0 {
				time.Sleep(time.Duration(crypto.RandBetween(int64(n.DelayMin), int64(n.DelayMax))) * time.Millisecond)
			}
		}

	}
	return w.Writer.WriteMultiBuffer(mb)
}

type FragmentWriter struct {
	fragment *Fragment
	writer   io.Writer
	count    uint64
}

func (f *FragmentWriter) Write(b []byte) (int, error) {
	f.count++

	if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.writer.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.writer.Write(b)
		}
		data := b[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
		var splitNum int64
		for from := 0; ; {
			to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
			splitNum++
			if to > len(data) || (maxSplit > 0 && splitNum >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], b)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if f.fragment.IntervalMax == 0 { // combine fragmented tlshello if interval is 0
				hello = append(hello, buff[:5+l]...)
			} else {
				_, err := f.writer.Write(buff[:5+l])
				time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
				if err != nil {
					return 0, err
				}
			}
			if from == len(data) {
				if len(hello) > 0 {
					_, err := f.writer.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(b) > recordLen {
					n, err := f.writer.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}
	}

	if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
		return f.writer.Write(b)
	}
	maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
	var splitNum int64
	for from := 0; ; {
		to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
		splitNum++
		if to > len(b) || (maxSplit > 0 && splitNum >= maxSplit) {
			to = len(b)
		}
		n, err := f.writer.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}
		time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
		if from >= len(b) {
			return from, nil
		}
	}
}

func GenerateRandomBytes(n int64) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
