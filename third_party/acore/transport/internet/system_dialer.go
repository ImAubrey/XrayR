package internet

import (
	"context"
	"math/rand"
	stdnet "net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sync/singleflight"
)

var effectiveSystemDialer SystemDialer = &DefaultSystemDialer{}

type SystemDialer interface {
	Dial(ctx context.Context, source net.Address, sourcePort net.Port, destination net.Destination, sockopt *SocketConfig) (net.Conn, error)
	DestIpAddress() net.IP
}

type DefaultSystemDialer struct {
	controllers []control.Func
	dns         dns.Client
	obm         outbound.Manager
}

func resolveSrcAddr(network net.Network, src net.Address, srcPort net.Port) net.Addr {
	if src == nil {
		return nil
	}
	// When src is AnyIP (0.0.0.0), we should bind to 0.0.0.0:0 to force IPv4
	// This prevents system from choosing IPv6 when both are available
	if network == net.Network_TCP {
		return &net.TCPAddr{
			IP:   src.IP(),
			Port: int(srcPort),
		}
	}

	return &net.UDPAddr{
		IP:   src.IP(),
		Port: int(srcPort),
	}
}

func udpListenNetwork(srcAddr net.Addr, destAddr *net.UDPAddr) string {
	if srcAddr != nil {
		if udpAddr, ok := srcAddr.(*net.UDPAddr); ok && udpAddr != nil && udpAddr.IP != nil && !udpAddr.IP.IsUnspecified() {
			if udpAddr.IP.To4() != nil {
				return "udp4"
			}
			return "udp6"
		}
	}
	if destAddr != nil && destAddr.IP != nil {
		if destAddr.IP.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	return "udp"
}

func resolveSourceAddrForUDP(ctx context.Context, destAddr *net.UDPAddr, srcPort net.Port, network string) net.Addr {
	if destAddr == nil || len(destAddr.IP) == 0 {
		return nil
	}

	conn, err := (&stdnet.Dialer{}).DialContext(ctx, network, destAddr.String())
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*stdnet.UDPAddr)
	if !ok || localAddr == nil || localAddr.IP == nil || localAddr.IP.IsUnspecified() {
		return nil
	}

	return &stdnet.UDPAddr{
		IP:   localAddr.IP,
		Port: int(srcPort),
	}
}

const (
	udpSourceAddrProbeCacheTTL      = 10 * time.Second
	udpSourceAddrProbeCacheNegTTL   = 1 * time.Second
	udpSourceAddrProbeCacheMaxItems = 128
)

type udpSourceAddrProbeCacheKey struct {
	network string
	dest    netip.Addr
	iface   string
	mark    int32
}

type udpSourceAddrProbeCacheEntry struct {
	ip     net.IP
	expire time.Time
	bad    bool
}

var (
	udpSourceAddrProbeCacheMu    sync.RWMutex
	udpSourceAddrProbeCache      = make(map[udpSourceAddrProbeCacheKey]udpSourceAddrProbeCacheEntry)
	udpSourceAddrProbeCacheGroup singleflight.Group
)

func netipAddrFromIP(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	if ip4 := ip.To4(); ip4 != nil {
		var a [4]byte
		copy(a[:], ip4)
		return netip.AddrFrom4(a), true
	}
	if ip16 := ip.To16(); ip16 != nil {
		var a [16]byte
		copy(a[:], ip16)
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

func udpSourceAddrProbeKey(destAddr *net.UDPAddr, network string, sockopt *SocketConfig) (udpSourceAddrProbeCacheKey, bool) {
	if destAddr == nil || destAddr.IP == nil || len(destAddr.IP) == 0 {
		return udpSourceAddrProbeCacheKey{}, false
	}
	dest, ok := netipAddrFromIP(destAddr.IP)
	if !ok {
		return udpSourceAddrProbeCacheKey{}, false
	}
	var iface string
	var mark int32
	if sockopt != nil {
		iface = sockopt.Interface
		mark = sockopt.Mark
	}
	return udpSourceAddrProbeCacheKey{
		network: network,
		dest:    dest,
		iface:   iface,
		mark:    mark,
	}, true
}

func getCachedUDPSourceAddrProbe(key udpSourceAddrProbeCacheKey) (ip net.IP, ok bool, bad bool) {
	now := time.Now()
	udpSourceAddrProbeCacheMu.RLock()
	entry, found := udpSourceAddrProbeCache[key]
	udpSourceAddrProbeCacheMu.RUnlock()
	if !found {
		return nil, false, false
	}
	if now.After(entry.expire) {
		udpSourceAddrProbeCacheMu.Lock()
		// Re-check under write lock to avoid deleting a refreshed entry.
		if current, ok := udpSourceAddrProbeCache[key]; ok && now.After(current.expire) {
			delete(udpSourceAddrProbeCache, key)
		}
		udpSourceAddrProbeCacheMu.Unlock()
		return nil, false, false
	}
	if entry.bad || entry.ip == nil {
		return nil, true, true
	}
	return append(net.IP(nil), entry.ip...), true, false
}

func evictUDPSourceAddrProbeCacheLocked(now time.Time) {
	if len(udpSourceAddrProbeCache) <= udpSourceAddrProbeCacheMaxItems {
		return
	}
	for k, v := range udpSourceAddrProbeCache {
		if now.After(v.expire) {
			delete(udpSourceAddrProbeCache, k)
		}
	}
	for len(udpSourceAddrProbeCache) > udpSourceAddrProbeCacheMaxItems {
		for k := range udpSourceAddrProbeCache {
			delete(udpSourceAddrProbeCache, k)
			break
		}
	}
}

func setCachedUDPSourceAddrProbe(key udpSourceAddrProbeCacheKey, ip net.IP, ttl time.Duration, bad bool) {
	if ttl <= 0 {
		ttl = udpSourceAddrProbeCacheTTL
	}
	entry := udpSourceAddrProbeCacheEntry{
		expire: time.Now().Add(ttl),
		bad:    bad,
	}
	if !bad && ip != nil {
		entry.ip = append(net.IP(nil), ip...)
	}
	udpSourceAddrProbeCacheMu.Lock()
	udpSourceAddrProbeCache[key] = entry
	evictUDPSourceAddrProbeCacheLocked(time.Now())
	udpSourceAddrProbeCacheMu.Unlock()
}

func udpSourceAddrProbeSingleflightKey(key udpSourceAddrProbeCacheKey) string {
	// Only used on cache miss; keep it simple.
	var b strings.Builder
	b.Grow(64)
	b.WriteString(key.network)
	b.WriteByte('|')
	b.WriteString(key.dest.String())
	b.WriteByte('|')
	b.WriteString(key.iface)
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(int64(key.mark), 10))
	return b.String()
}

func probeUDPSourceAddr(ctx context.Context, destAddr *net.UDPAddr, network string, control func(network, address string, c syscall.RawConn) error) net.IP {
	if destAddr == nil || len(destAddr.IP) == 0 {
		return nil
	}
	dialer := &net.Dialer{
		Control: control,
	}
	conn, err := dialer.DialContext(ctx, network, destAddr.String())
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*stdnet.UDPAddr)
	if !ok || localAddr == nil || localAddr.IP == nil || localAddr.IP.IsUnspecified() {
		return nil
	}
	return append(net.IP(nil), localAddr.IP...)
}

func (d *DefaultSystemDialer) resolveSourceAddrForUDP(ctx context.Context, destAddr *net.UDPAddr, srcPort net.Port, network string, sockopt *SocketConfig) net.Addr {
	key, keyOk := udpSourceAddrProbeKey(destAddr, network, sockopt)
	if keyOk {
		if cached, ok, bad := getCachedUDPSourceAddrProbe(key); ok {
			if bad || cached == nil {
				return nil
			}
			return &stdnet.UDPAddr{IP: cached, Port: int(srcPort)}
		}
		sfKey := udpSourceAddrProbeSingleflightKey(key)
		v, _, _ := udpSourceAddrProbeCacheGroup.Do(sfKey, func() (any, error) {
			if cached, ok, bad := getCachedUDPSourceAddrProbe(key); ok {
				if bad {
					return nil, nil
				}
				return cached, nil
			}
			ip := probeUDPSourceAddr(ctx, destAddr, network, d.applyControllers(ctx, sockopt, destAddr.String(), nil))
			if ip == nil {
				setCachedUDPSourceAddrProbe(key, nil, udpSourceAddrProbeCacheNegTTL, true)
				return nil, nil
			}
			setCachedUDPSourceAddrProbe(key, ip, udpSourceAddrProbeCacheTTL, false)
			return ip, nil
		})
		if ip, ok := v.(net.IP); ok && ip != nil {
			return &stdnet.UDPAddr{IP: append(net.IP(nil), ip...), Port: int(srcPort)}
		}
		return nil
	}

	// Fallback (no cache key): keep the original best-effort behavior.
	return resolveSourceAddrForUDP(ctx, destAddr, srcPort, network)
}

func hasBindAddr(sockopt *SocketConfig) bool {
	return sockopt != nil && len(sockopt.BindAddress) > 0 && sockopt.BindPort > 0
}

// applyControllers applies external controllers and socket options.
func (d *DefaultSystemDialer) applyControllers(ctx context.Context, sockopt *SocketConfig, destAddr string, extraFn func(fd uintptr)) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		for _, ctl := range d.controllers {
			if err := ctl(network, address, c); err != nil {
				errors.LogInfoInner(ctx, err, "failed to apply external controller")
			}
		}
		return c.Control(func(fd uintptr) {
			_ = setReuseAddr(fd)
			_ = setReusePort(fd)
			if sockopt != nil {
				if err := applyOutboundSocketOptions(network, destAddr, fd, sockopt); err != nil {
					errors.LogInfoInner(ctx, err, "failed to apply socket options")
				}
			}
			if extraFn != nil {
				extraFn(fd)
			}
		})
	}
}

// configureKeepAlive returns keepalive configuration based on socket options.
func configureKeepAlive(sockopt *SocketConfig) (net.KeepAliveConfig, time.Duration, error) {
	config := net.KeepAliveConfig{
		Enable:   true,
		Idle:     45 * time.Second,
		Interval: 45 * time.Second,
		Count:    -1,
	}
	keepAlive := time.Duration(0)
	if sockopt == nil {
		return config, keepAlive, nil
	}
	// Invalid: one positive and one negative (mixed enable/disable)
	if sockopt.TcpKeepAliveIdle*sockopt.TcpKeepAliveInterval < 0 {
		return config, keepAlive, errors.New("invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: ", sockopt.TcpKeepAliveIdle, " ", sockopt.TcpKeepAliveInterval)
	}
	// Negative value disables keepalive
	if sockopt.TcpKeepAliveIdle < 0 || sockopt.TcpKeepAliveInterval < 0 {
		config.Enable = false
		return config, -1, nil
	}
	if sockopt.TcpKeepAliveIdle > 0 {
		config.Idle = time.Duration(sockopt.TcpKeepAliveIdle) * time.Second
	}
	if sockopt.TcpKeepAliveInterval > 0 {
		config.Interval = time.Duration(sockopt.TcpKeepAliveInterval) * time.Second
	}
	return config, keepAlive, nil
}

// dialUDP creates a UDP connection using ListenPacket.
func (d *DefaultSystemDialer) dialUDP(ctx context.Context, src net.Address, srcPort net.Port, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	destAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
	if err != nil {
		return nil, err
	}
	srcAddr := resolveSrcAddr(net.Network_UDP, src, srcPort)
	listenNetwork := udpListenNetwork(srcAddr, destAddr)

	// If source is unspecified (nil/0.0.0.0/::), proactively detect the actual outbound
	// source IP chosen by the system route, then bind to it to avoid wildcard endpoints.
	pinnedSourceIP := false
	if udpSrc, ok := srcAddr.(*net.UDPAddr); srcAddr == nil || (ok && (udpSrc.IP == nil || udpSrc.IP.IsUnspecified())) {
		if resolved := d.resolveSourceAddrForUDP(ctx, destAddr, srcPort, listenNetwork, sockopt); resolved != nil {
			srcAddr = resolved
			if udp, ok := resolved.(*stdnet.UDPAddr); ok && udp != nil && udp.IP != nil && !udp.IP.IsUnspecified() {
				pinnedSourceIP = true
			}
		} else {
			srcAddr = nil
		}
	}
	if srcAddr == nil {
		srcAddr = &stdnet.UDPAddr{IP: nil, Port: int(srcPort)}
	}
	lc := net.ListenConfig{
		Control: d.applyControllers(ctx, sockopt, destAddr.String(), nil),
	}
	packetConn, err := lc.ListenPacket(ctx, listenNetwork, srcAddr.String())
	// If the pinned (probed or cached) source IP becomes invalid (e.g. route/interface change),
	// fall back to wildcard bind to preserve the original best-effort behavior.
	if err != nil && pinnedSourceIP {
		srcAddr = &stdnet.UDPAddr{IP: nil, Port: int(srcPort)}
		packetConn, err = lc.ListenPacket(ctx, listenNetwork, srcAddr.String())
	}
	if err != nil && srcPort != 0 {
		srcAddr = resolveSrcAddr(net.Network_UDP, src, 0)
		if srcAddr == nil {
			srcAddr = &stdnet.UDPAddr{IP: nil}
		}
		packetConn, err = lc.ListenPacket(ctx, udpListenNetwork(srcAddr, destAddr), srcAddr.String())
	}
	if err != nil {
		return nil, err
	}
	return &PacketConnWrapper{
		Conn:      packetConn,
		Dest:      destAddr,
		localAddr: localAddrForSource(srcAddr, packetConn.LocalAddr()),
	}, nil
}

func (d *DefaultSystemDialer) Dial(ctx context.Context, src net.Address, srcPort net.Port, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	errors.LogDebug(ctx, "dialing to ", dest)

	if dest.Network == net.Network_UDP && !hasBindAddr(sockopt) {
		return d.dialUDP(ctx, src, srcPort, dest, sockopt)
	}

	keepAliveConfig, keepAlive, err := configureKeepAlive(sockopt)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:         time.Second * 16,
		LocalAddr:       resolveSrcAddr(dest.Network, src, srcPort),
		KeepAlive:       keepAlive,
		KeepAliveConfig: keepAliveConfig,
	}

	if sockopt != nil && sockopt.TcpMptcp {
		dialer.SetMultipathTCP(true)
	}
	var extraFn func(fd uintptr)
	if dest.Network == net.Network_UDP && hasBindAddr(sockopt) {
		extraFn = func(fd uintptr) {
			if err := bindAddr(fd, sockopt.BindAddress, sockopt.BindPort); err != nil {
				errors.LogInfoInner(ctx, err, "failed to bind source address to ", sockopt.BindAddress)
			}
		}
	}
	dialer.Control = d.applyControllers(ctx, sockopt, dest.NetAddr(), extraFn)

	conn, err := dialer.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
	if err != nil && srcPort != 0 {
		dialer.LocalAddr = resolveSrcAddr(dest.Network, src, 0)
		return dialer.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
	}
	return conn, err
}

func (d *DefaultSystemDialer) DestIpAddress() net.IP {
	return nil
}

type PacketConnWrapper struct {
	Conn      net.PacketConn
	Dest      net.Addr
	localAddr net.Addr
}

func (c *PacketConnWrapper) Close() error {
	return c.Conn.Close()
}

func (c *PacketConnWrapper) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return c.Conn.LocalAddr()
}

func (c *PacketConnWrapper) RemoteAddr() net.Addr {
	return c.Dest
}

func (c *PacketConnWrapper) Write(p []byte) (int, error) {
	return c.Conn.WriteTo(p, c.Dest)
}

func (c *PacketConnWrapper) Read(p []byte) (int, error) {
	n, _, err := c.Conn.ReadFrom(p)
	return n, err
}

func (c *PacketConnWrapper) WriteTo(p []byte, d net.Addr) (int, error) {
	return c.Conn.WriteTo(p, d)
}

func (c *PacketConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.Conn.ReadFrom(p)
}

func (c *PacketConnWrapper) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *PacketConnWrapper) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *PacketConnWrapper) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func localAddrForSource(srcAddr net.Addr, actualAddr net.Addr) net.Addr {
	if srcAddr == nil || actualAddr == nil {
		return actualAddr
	}
	udpSrc, ok := srcAddr.(*net.UDPAddr)
	if !ok || udpSrc == nil || udpSrc.IP == nil || udpSrc.IP.IsUnspecified() {
		return actualAddr
	}

	actualUDP, ok := actualAddr.(*net.UDPAddr)
	if !ok || actualUDP == nil {
		return actualAddr
	}

	return &net.UDPAddr{
		IP:   append(net.IP(nil), udpSrc.IP...),
		Port: actualUDP.Port,
		Zone: actualUDP.Zone,
	}
}

type SystemDialerAdapter interface {
	Dial(network string, address string) (net.Conn, error)
}

type SimpleSystemDialer struct {
	adapter SystemDialerAdapter
}

func WithAdapter(dialer SystemDialerAdapter) SystemDialer {
	return &SimpleSystemDialer{
		adapter: dialer,
	}
}

func (v *SimpleSystemDialer) Dial(ctx context.Context, src net.Address, srcPort net.Port, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	return v.adapter.Dial(dest.Network.SystemString(), dest.NetAddr())
}

func (d *SimpleSystemDialer) DestIpAddress() net.IP {
	return nil
}

// UseAlternativeSystemDialer replaces the current system dialer with a given one.
// Caller must ensure there is no race condition.
//
// acore:api:stable
func UseAlternativeSystemDialer(dialer SystemDialer) {
	if dialer == nil {
		dialer = &DefaultSystemDialer{}
	}
	effectiveSystemDialer = dialer
}

// RegisterDialerController adds a controller to the effective system dialer.
// The controller can be used to operate on file descriptors before they are put into use.
// It only works when effective dialer is the default dialer.
//
// acore:api:beta
func RegisterDialerController(ctl control.Func) error {
	if ctl == nil {
		return errors.New("nil listener controller")
	}

	dialer, ok := effectiveSystemDialer.(*DefaultSystemDialer)
	if !ok {
		return errors.New("RegisterListenerController not supported in custom dialer")
	}

	dialer.controllers = append(dialer.controllers, ctl)
	return nil
}

type FakePacketConn struct {
	net.Conn
}

func (c *FakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c *FakePacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *FakePacketConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IP{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
		Port: rand.Intn(65536),
	}
}

func (c *FakePacketConn) SetReadBuffer(bytes int) error {
	// do nothing, this function is only there to suppress quic-go printing
	// random warnings about UDP buffers to stdout
	return nil
}
