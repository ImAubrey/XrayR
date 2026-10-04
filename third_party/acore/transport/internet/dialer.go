package internet

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/dice"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/net/cnc"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/internet/stat"
	"github.com/ImAubrey/acore/transport/pipe"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Dialer is the interface for dialing outbound connections.
type Dialer interface {
	// Dial dials a system connection to the given destination.
	Dial(ctx context.Context, destination net.Destination) (stat.Connection, error)

	// DestIpAddress returns the ip of proxy server. It is useful in case of Android client, which prepare an IP before proxy connection is established
	DestIpAddress() net.IP

	// SetOutboundGateway set outbound gateway
	SetOutboundGateway(ctx context.Context, ob *session.Outbound)
}

// dialFunc is an interface to dial network connection to a specific destination.
type dialFunc func(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (stat.Connection, error)

var transportDialerCache = make(map[string]dialFunc)

// RegisterTransportDialer registers a Dialer with given name.
func RegisterTransportDialer(protocol string, dialer dialFunc) error {
	if _, found := transportDialerCache[protocol]; found {
		return errors.New(protocol, " dialer already registered").AtError()
	}
	transportDialerCache[protocol] = dialer
	return nil
}

// Dial dials a internet connection towards the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig) (stat.Connection, error) {
	if dest.Network == net.Network_TCP {
		if streamSettings == nil {
			s, err := ToMemoryStreamConfig(nil)
			if err != nil {
				return nil, errors.New("failed to create default stream settings").Base(err)
			}
			streamSettings = s
		}

		protocol := streamSettings.ProtocolName
		dialer := transportDialerCache[protocol]
		if dialer == nil {
			return nil, errors.New(protocol, " dialer not registered").AtError()
		}
		return dialer(ctx, dest, streamSettings)
	}

	if dest.Network == net.Network_UDP {
		udpDialer := transportDialerCache["udp"]
		if udpDialer == nil {
			return nil, errors.New("UDP dialer not registered").AtError()
		}
		return udpDialer(ctx, dest, streamSettings)
	}

	return nil, errors.New("unknown network ", dest.Network)
}

// DestIpAddress returns the ip of proxy server. It is useful in case of Android client, which prepare an IP before proxy connection is established
func DestIpAddress() net.IP {
	return effectiveSystemDialer.DestIpAddress()
}

var (
	dnsClient           dns.Client
	obm                 outbound.Manager
	destinationResolver routing.DestinationResolver
)

const lookupForIPCacheTTL = 10 * time.Second

type lookupForIPCacheEntry struct {
	ips    []net.IP
	expire time.Time
}

type lookupForIPKey struct {
	domain      string
	outboundTag string
	strategy    DomainStrategy
	ipv4Enable  bool
	ipv6Enable  bool
}

var (
	lookupForIPCache      = make(map[lookupForIPKey]lookupForIPCacheEntry)
	lookupForIPCacheMu    sync.RWMutex
	lookupForIPCacheGroup singleflight.Group
)

const freedomProxyConfigType = "acore.proxy.freedom.Config"

func outboundTagFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return ""
	}
	ob := outbounds[len(outbounds)-1]
	if ob == nil {
		return ""
	}
	return ob.Tag
}

func LookupForIPWithContext(ctx context.Context, domain string, strategy DomainStrategy, localAddr net.Address) ([]net.IP, error) {
	return lookupForIP(domain, strategy, localAddr, outboundTagFromContext(ctx))
}

func LookupForIP(domain string, strategy DomainStrategy, localAddr net.Address) ([]net.IP, error) {
	return lookupForIP(domain, strategy, localAddr, "")
}

func normalizeLookupDomain(domain string) string {
	if domain == "" {
		return ""
	}
	// Trim a single trailing dot to normalize FQDN forms.
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	// Fast path: ASCII and already lower-case.
	isASCII := true
	needsLower := false
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c >= utf8.RuneSelf {
			isASCII = false
			break
		}
		if c >= 'A' && c <= 'Z' {
			needsLower = true
		}
	}
	if isASCII {
		if !needsLower {
			return domain
		}
		b := make([]byte, len(domain))
		for i := 0; i < len(domain); i++ {
			c := domain[i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b[i] = c
		}
		return string(b)
	}

	// Non-ASCII: fall back to Unicode-aware lowercasing.
	return strings.ToLower(domain)
}

func lookupForIPCacheKey(domain string, strategy DomainStrategy, ipv4Enable bool, ipv6Enable bool, outboundTag string) lookupForIPKey {
	return lookupForIPKey{
		domain:      normalizeLookupDomain(domain),
		outboundTag: outboundTag,
		strategy:    strategy,
		ipv4Enable:  ipv4Enable,
		ipv6Enable:  ipv6Enable,
	}
}

func (k lookupForIPKey) singleflightKey() string {
	// Only used on cache miss; keep it allocation-light but not overly complex.
	var b strings.Builder
	b.Grow(2 + len(k.domain) + 1 + len(k.outboundTag) + 1 + 16 + 1 + 1 + 1)
	b.WriteString("i|")
	b.WriteString(k.domain)
	b.WriteByte('|')
	b.WriteString(k.outboundTag)
	b.WriteByte('|')
	var tmp [16]byte
	intStr := strconv.AppendInt(tmp[:0], int64(int32(k.strategy)), 10)
	_, _ = b.Write(intStr)
	b.WriteByte('|')
	if k.ipv4Enable {
		b.WriteByte('4')
	}
	b.WriteByte('|')
	if k.ipv6Enable {
		b.WriteByte('6')
	}
	return b.String()
}

func getCachedLookupForIP(key lookupForIPKey) ([]net.IP, bool) {
	lookupForIPCacheMu.RLock()
	entry, ok := lookupForIPCache[key]
	lookupForIPCacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expire) {
		lookupForIPCacheMu.Lock()
		delete(lookupForIPCache, key)
		lookupForIPCacheMu.Unlock()
		return nil, false
	}
	return cloneNetIPs(entry.ips), true
}

func getCachedLookupForIPRaw(key lookupForIPKey) ([]net.IP, bool) {
	lookupForIPCacheMu.RLock()
	entry, ok := lookupForIPCache[key]
	lookupForIPCacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expire) {
		lookupForIPCacheMu.Lock()
		delete(lookupForIPCache, key)
		lookupForIPCacheMu.Unlock()
		return nil, false
	}
	// Treat cached IPs as immutable.
	return entry.ips, true
}

func cacheLookupForIPResult(key lookupForIPKey, ips []net.IP, ttl uint32) {
	expireDuration := lookupForIPCacheTTL
	if ttl > 0 {
		expireDuration = time.Duration(ttl) * time.Second
	}
	lookupForIPCacheMu.Lock()
	lookupForIPCache[key] = lookupForIPCacheEntry{
		ips:    ips,
		expire: time.Now().Add(expireDuration),
	}
	lookupForIPCacheMu.Unlock()
}

func cloneNetIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	// Deep-clone with a single backing buffer to reduce per-IP allocations.
	total := 0
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		total += len(ip)
	}
	out := make([]net.IP, len(ips))
	if total == 0 {
		return out
	}
	buf := make([]byte, total)
	off := 0
	for i, ip := range ips {
		if ip == nil {
			continue
		}
		n := copy(buf[off:], ip)
		out[i] = buf[off : off+n : off+n]
		off += n
	}
	return out
}

func cloneNetIPs2(ips []net.IP) ([]net.IP, []net.IP) {
	if len(ips) == 0 {
		return nil, nil
	}
	// Deep-clone twice using one net.IP slice buffer and one backing byte buffer.
	// This is used on cache miss to keep cache storage and caller returns fully isolated
	// without doubling allocations.
	total := 0
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		total += len(ip)
	}
	headers := make([]net.IP, len(ips)*2)
	out0 := headers[:len(ips):len(ips)]
	out1 := headers[len(ips):][:len(ips):len(ips)]
	if total == 0 {
		return out0, out1
	}
	buf := make([]byte, total*2)
	off0 := 0
	off1 := total
	for i, ip := range ips {
		if ip == nil {
			continue
		}
		l := len(ip)
		copy(buf[off0:off0+l], ip)
		out0[i] = buf[off0 : off0+l : off0+l]
		copy(buf[off1:off1+l], ip)
		out1[i] = buf[off1 : off1+l : off1+l]
		off0 += l
		off1 += l
	}
	return out0, out1
}

func lookupForIPWithDNS(domain string, strategy DomainStrategy, ipv4Enable bool, ipv6Enable bool, outboundTag string) ([]net.IP, uint32, error) {
	ips, ttl, err := dnsClient.LookupIP(domain, dns.IPOption{
		IPv4Enable:  ipv4Enable,
		IPv6Enable:  ipv6Enable,
		OutboundTag: outboundTag,
	})

	// 回退逻辑：首选失败时尝试回退类型
	if (len(ips) == 0 || err != nil) && strategy.HasFallback() {
		ips, ttl, err = dnsClient.LookupIP(domain, dns.IPOption{
			IPv4Enable:  strategy.FallbackIP4(),
			IPv6Enable:  strategy.FallbackIP6(),
			OutboundTag: outboundTag,
		})
	}

	if err == nil && len(ips) == 0 {
		return nil, 0, dns.ErrEmptyResponse
	}
	return ips, ttl, err
}

func lookupForIPEnabled(strategy DomainStrategy, localAddr net.Address) (ipv4Enable bool, ipv6Enable bool) {
	if strategy.HasFallback() {
		// 有回退（prefer4 或 prefer6）：首次仅查询首选类型
		ipv4Enable = strategy.PreferIP4() && !strategy.PreferIP6()
		ipv6Enable = strategy.PreferIP6() && !strategy.PreferIP4()
		return ipv4Enable, ipv6Enable
	}
	if localAddr == nil {
		// 无 localAddr：启用策略允许的类型（双栈时两者都启用）
		ipv4Enable = !strategy.OnlyIPv6()
		ipv6Enable = !strategy.OnlyIPv4()
		return ipv4Enable, ipv6Enable
	}
	// 有 localAddr：根据地址族限制
	ipv4Enable = localAddr.Family().IsIPv4() && !strategy.OnlyIPv6()
	ipv6Enable = localAddr.Family().IsIPv6() && !strategy.OnlyIPv4()
	return ipv4Enable, ipv6Enable
}

func lookupForIP(domain string, strategy DomainStrategy, localAddr net.Address, outboundTag string) ([]net.IP, error) {
	if dnsClient == nil {
		return nil, errors.New("DNS client not initialized").AtError()
	}

	ipv4Enable, ipv6Enable := lookupForIPEnabled(strategy, localAddr)

	cacheKey := lookupForIPCacheKey(domain, strategy, ipv4Enable, ipv6Enable, outboundTag)
	if cached, ok := getCachedLookupForIP(cacheKey); ok {
		return cached, nil
	}

	sfKey := cacheKey.singleflightKey()
	result, err, _ := lookupForIPCacheGroup.Do(sfKey, func() (any, error) {
		if cached, ok := getCachedLookupForIP(cacheKey); ok {
			return cached, nil
		}
		ips, ttl, err := lookupForIPWithDNS(domain, strategy, ipv4Enable, ipv6Enable, outboundTag)
		if err != nil {
			return nil, err
		}
		toCache, toCaller := cloneNetIPs2(ips)
		cacheLookupForIPResult(cacheKey, toCache, ttl)
		return toCaller, nil
	})
	if err != nil {
		return nil, err
	}

	cached, ok := result.([]net.IP)
	if !ok {
		return nil, errors.New("lookupForIP cache data type invalid")
	}
	return cached, nil
}

func pickRandomAddr(ips []net.IP) net.Address {
	if len(ips) == 0 {
		return nil
	}
	return net.IPAddress(ips[dice.Roll(len(ips))])
}

func pickPreferredAddr(ips []net.IP, preferV6 bool) net.Address {
	if len(ips) == 0 {
		return nil
	}

	// Same selection semantics as proxyman/outbound pickPreferredIP without allocating a preferred slice.
	matches := 0
	for _, ip := range ips {
		if preferV6 {
			if ip.To4() == nil {
				matches++
			}
		} else {
			if ip.To4() != nil {
				matches++
			}
		}
	}

	if matches > 0 {
		nth := dice.Roll(matches)
		for _, ip := range ips {
			if preferV6 {
				if ip.To4() == nil {
					if nth == 0 {
						return net.IPAddress(ip)
					}
					nth--
				}
			} else {
				if ip.To4() != nil {
					if nth == 0 {
						return net.IPAddress(ip)
					}
					nth--
				}
			}
		}
	}

	return pickRandomAddr(ips)
}

// LookupForAddressPickWithContext resolves the domain according to strategy and returns one selected IP as net.Address.
// It avoids cloning the full IP slice on cache hits.
func LookupForAddressPickWithContext(ctx context.Context, domain string, strategy DomainStrategy, localAddr net.Address) (net.Address, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	outboundTag := outboundTagFromContext(ctx)

	ipv4Enable, ipv6Enable := lookupForIPEnabled(strategy, localAddr)
	cacheKey := lookupForIPCacheKey(domain, strategy, ipv4Enable, ipv6Enable, outboundTag)
	if cached, ok := getCachedLookupForIPRaw(cacheKey); ok {
		return pickRandomAddr(cached), nil
	}

	ips, err := lookupForIP(domain, strategy, localAddr, outboundTag)
	if err != nil {
		return nil, err
	}
	return pickRandomAddr(ips), nil
}

// LookupForAddressPick resolves the domain according to strategy and returns one selected IP as net.Address.
// It avoids cloning the full IP slice on cache hits.
func LookupForAddressPick(domain string, strategy DomainStrategy, localAddr net.Address) (net.Address, error) {
	ipv4Enable, ipv6Enable := lookupForIPEnabled(strategy, localAddr)
	cacheKey := lookupForIPCacheKey(domain, strategy, ipv4Enable, ipv6Enable, "")
	if cached, ok := getCachedLookupForIPRaw(cacheKey); ok {
		return pickRandomAddr(cached), nil
	}

	ips, err := lookupForIP(domain, strategy, localAddr, "")
	if err != nil {
		return nil, err
	}
	return pickRandomAddr(ips), nil
}

// LookupForAddressPickPreferredWithContext resolves the domain according to strategy and returns one IP from the
// preferred family if available (preferV6 == true prefers IPv6; false prefers IPv4), falling back to any.
// It avoids cloning the full IP slice on cache hits.
func LookupForAddressPickPreferredWithContext(ctx context.Context, domain string, strategy DomainStrategy, localAddr net.Address, preferV6 bool) (net.Address, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	outboundTag := outboundTagFromContext(ctx)

	ipv4Enable, ipv6Enable := lookupForIPEnabled(strategy, localAddr)
	cacheKey := lookupForIPCacheKey(domain, strategy, ipv4Enable, ipv6Enable, outboundTag)
	if cached, ok := getCachedLookupForIPRaw(cacheKey); ok {
		return pickPreferredAddr(cached, preferV6), nil
	}

	ips, err := lookupForIP(domain, strategy, localAddr, outboundTag)
	if err != nil {
		return nil, err
	}
	return pickPreferredAddr(ips, preferV6), nil
}

// LookupForAddressPickPreferred resolves the domain according to strategy and returns one IP from the
// preferred family if available (preferV6 == true prefers IPv6; false prefers IPv4), falling back to any.
// It avoids cloning the full IP slice on cache hits.
func LookupForAddressPickPreferred(domain string, strategy DomainStrategy, localAddr net.Address, preferV6 bool) (net.Address, error) {
	ipv4Enable, ipv6Enable := lookupForIPEnabled(strategy, localAddr)
	cacheKey := lookupForIPCacheKey(domain, strategy, ipv4Enable, ipv6Enable, "")
	if cached, ok := getCachedLookupForIPRaw(cacheKey); ok {
		return pickPreferredAddr(cached, preferV6), nil
	}

	ips, err := lookupForIP(domain, strategy, localAddr, "")
	if err != nil {
		return nil, err
	}
	return pickPreferredAddr(ips, preferV6), nil
}

func redirect(ctx context.Context, dst net.Destination, obt string, h outbound.Handler) net.Conn {
	errors.LogInfo(ctx, "redirecting request ", dst.String(), " to ", obt)
	outbounds := session.OutboundsFromContext(ctx)
	ctx = session.ContextWithOutbounds(ctx, append(outbounds, &session.Outbound{
		Target:  dst,
		Gateway: nil,
		Tag:     obt,
	})) // add another outbound in session ctx

	ur, uw := pipe.New(pipe.OptionsFromContext(ctx)...)
	dr, dw := pipe.New(pipe.OptionsFromContext(ctx)...)

	go h.Dispatch(context.WithoutCancel(ctx), &transport.Link{Reader: ur, Writer: dw})
	var readerOpt cnc.ConnectionOption
	if dst.Network == net.Network_TCP {
		readerOpt = cnc.ConnectionOutputMulti(dr)
	} else {
		readerOpt = cnc.ConnectionOutputMultiUDP(dr)
	}
	nc := cnc.NewConnection(
		cnc.ConnectionInputMulti(uw),
		readerOpt,
		cnc.ConnectionOnClose(common.ChainedClosable{uw, dw}),
	)
	return nc

}

func checkAddressPortStrategy(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (*net.Destination, error) {
	if sockopt.AddressPortStrategy == AddressPortStrategy_None {
		return nil, nil
	}
	newDest := dest
	var OverridePort, OverrideAddress bool
	var OverrideBy string
	switch sockopt.AddressPortStrategy {
	case AddressPortStrategy_SrvPortOnly:
		OverridePort = true
		OverrideAddress = false
		OverrideBy = "srv"
	case AddressPortStrategy_SrvAddressOnly:
		OverridePort = false
		OverrideAddress = true
		OverrideBy = "srv"
	case AddressPortStrategy_SrvPortAndAddress:
		OverridePort = true
		OverrideAddress = true
		OverrideBy = "srv"
	case AddressPortStrategy_TxtPortOnly:
		OverridePort = true
		OverrideAddress = false
		OverrideBy = "txt"
	case AddressPortStrategy_TxtAddressOnly:
		OverridePort = false
		OverrideAddress = true
		OverrideBy = "txt"
	case AddressPortStrategy_TxtPortAndAddress:
		OverridePort = true
		OverrideAddress = true
		OverrideBy = "txt"
	default:
		return nil, errors.New("unknown AddressPortStrategy")
	}

	if !dest.Address.Family().IsDomain() {
		return nil, nil
	}

	if OverrideBy == "srv" {
		errors.LogDebug(ctx, "query SRV record for ", dest.Address)
		parts := strings.SplitN(dest.Address.String(), ".", 3)
		if len(parts) != 3 {
			return nil, errors.New("invalid address format", dest.Address.String())
		}
		_, srvRecords, err := net.DefaultResolver.LookupSRV(context.Background(), parts[0][1:], parts[1][1:], parts[2])
		if err != nil {
			return nil, errors.New("failed to lookup SRV record").Base(err)
		}
		errors.LogDebug(
			ctx,
			"SRV record: addr=", srvRecords[0].Target,
			", port=", srvRecords[0].Port,
			", priority=", srvRecords[0].Priority,
			", weight=", srvRecords[0].Weight,
		)
		if OverridePort {
			newDest.Port = net.Port(srvRecords[0].Port)
		}
		if OverrideAddress {
			newDest.Address = net.ParseAddress(srvRecords[0].Target)
		}
		return &newDest, nil
	}
	if OverrideBy == "txt" {
		errors.LogDebug(ctx, "query TXT record for ", dest.Address)
		txtRecords, err := net.DefaultResolver.LookupTXT(ctx, dest.Address.String())
		if err != nil {
			errors.LogErrorInner(ctx, err, "failed to lookup TXT record")
			return nil, errors.New("failed to lookup TXT record").Base(err)
		}
		for _, txtRecord := range txtRecords {
			errors.LogDebug(ctx, "TXT record: ", txtRecord)
			addr_s, port_s, _ := net.SplitHostPort(string(txtRecord))
			addr := net.ParseAddress(addr_s)
			port, err := net.PortFromString(port_s)
			if err != nil {
				continue
			}

			if OverridePort {
				newDest.Port = port
			}
			if OverrideAddress {
				newDest.Address = addr
			}
			return &newDest, nil
		}
	}
	return nil, nil
}

func messageField(msg protoreflect.Message, name string) (protoreflect.Message, bool) {
	if msg == nil {
		return nil, false
	}
	field := msg.Descriptor().Fields().ByName(protoreflect.Name(name))
	if field == nil || field.Kind() != protoreflect.MessageKind {
		return nil, false
	}
	if !msg.Has(field) {
		return nil, false
	}
	value := msg.Get(field)
	if !value.IsValid() {
		return nil, false
	}
	return value.Message(), true
}

func stringField(msg protoreflect.Message, name string) string {
	if msg == nil {
		return ""
	}
	field := msg.Descriptor().Fields().ByName(protoreflect.Name(name))
	if field == nil || field.Kind() != protoreflect.StringKind {
		return ""
	}
	return msg.Get(field).String()
}

func enumField(msg protoreflect.Message, name string) (int32, bool) {
	if msg == nil {
		return 0, false
	}
	field := msg.Descriptor().Fields().ByName(protoreflect.Name(name))
	if field == nil || field.Kind() != protoreflect.EnumKind {
		return 0, false
	}
	if !msg.Has(field) {
		return 0, false
	}
	value := msg.Get(field)
	if !value.IsValid() {
		return 0, false
	}
	return int32(value.Enum()), true
}

func uint32Field(msg protoreflect.Message, name string) (uint32, bool) {
	if msg == nil {
		return 0, false
	}
	field := msg.Descriptor().Fields().ByName(protoreflect.Name(name))
	if field == nil || field.Kind() != protoreflect.Uint32Kind {
		return 0, false
	}
	if !msg.Has(field) {
		return 0, false
	}
	value := msg.Get(field)
	if !value.IsValid() {
		return 0, false
	}
	return uint32(value.Uint()), true
}

type FreedomDialerSettings struct {
	Via            *net.IPOrDomain
	Via6           *net.IPOrDomain
	ViaCidr        string
	Via6Cidr       string
	ViaCompiled    *CompiledSendThrough
	Via6Compiled   *CompiledSendThrough
	TargetStrategy DomainStrategy
	SocketSettings *SocketConfig
}

type freedomDialerSettingsProvider interface {
	FreedomDialerSettings() *FreedomDialerSettings
}

func BuildFreedomDialerSettings(via, via6 *net.IPOrDomain, viaCidr, via6Cidr string, targetStrategy DomainStrategy, socketSettings *SocketConfig) *FreedomDialerSettings {
	settings := &FreedomDialerSettings{
		Via:            via,
		Via6:           via6,
		ViaCidr:        viaCidr,
		Via6Cidr:       via6Cidr,
		TargetStrategy: targetStrategy,
		SocketSettings: socketSettings,
	}
	if settings.Via != nil && settings.ViaCidr != "" {
		settings.ViaCompiled = CompileSendThrough(settings.Via.AsAddress(), settings.ViaCidr)
	}
	if settings.Via6 != nil && settings.Via6Cidr != "" {
		settings.Via6Compiled = CompileSendThrough(settings.Via6.AsAddress(), settings.Via6Cidr)
	}
	if !settings.TargetStrategy.HasStrategy() && socketSettings != nil && socketSettings.DomainStrategy.HasStrategy() {
		settings.TargetStrategy = socketSettings.DomainStrategy
	}
	return settings
}

func isFreedomHandler(h outbound.Handler) bool {
	if h == nil {
		return false
	}
	proxySettings := h.ProxySettings()
	return proxySettings != nil && proxySettings.Type == freedomProxyConfigType
}

func readFreedomDialerSettings(h outbound.Handler) *FreedomDialerSettings {
	if h == nil {
		return nil
	}
	if provider, ok := h.(freedomDialerSettingsProvider); ok {
		if settings := provider.FreedomDialerSettings(); settings != nil {
			return settings
		}
	}
	senderSettings := h.SenderSettings()
	if senderSettings == nil {
		return nil
	}
	msg, err := senderSettings.GetInstance()
	if err != nil {
		return nil
	}
	ref := msg.ProtoReflect()
	var via, via6 *net.IPOrDomain
	viaCidr := stringField(ref, "via_cidr")
	via6Cidr := stringField(ref, "via6_cidr")
	if viaMsg, ok := messageField(ref, "via"); ok {
		if v, ok := viaMsg.Interface().(*net.IPOrDomain); ok {
			via = v
		}
	}
	if via6Msg, ok := messageField(ref, "via6"); ok {
		if v6, ok := via6Msg.Interface().(*net.IPOrDomain); ok {
			via6 = v6
		}
	}
	targetStrategy := DomainStrategy_AS_IS
	if v, ok := enumField(ref, "target_strategy"); ok {
		targetStrategy = DomainStrategy(v)
	}
	var socketSettings *SocketConfig
	if streamMsg, ok := messageField(ref, "stream_settings"); ok {
		if streamSettings, ok := streamMsg.Interface().(*StreamConfig); ok {
			socketSettings = streamSettings.SocketSettings
		}
	}
	return BuildFreedomDialerSettings(via, via6, viaCidr, via6Cidr, targetStrategy, socketSettings)
}

func readFreedomProxyConfig(h outbound.Handler) (DomainStrategy, net.Address, net.Port) {
	if h == nil {
		return DomainStrategy_AS_IS, nil, 0
	}
	proxySettings := h.ProxySettings()
	if proxySettings == nil || proxySettings.Type != freedomProxyConfigType {
		return DomainStrategy_AS_IS, nil, 0
	}
	msg, err := proxySettings.GetInstance()
	if err != nil {
		return DomainStrategy_AS_IS, nil, 0
	}
	ref := msg.ProtoReflect()
	strategy := DomainStrategy_AS_IS
	if v, ok := enumField(ref, "domain_strategy"); ok {
		strategy = DomainStrategy(v)
	}
	var overrideAddr net.Address
	var overridePort net.Port
	if overrideMsg, ok := messageField(ref, "destination_override"); ok {
		if serverMsg, ok := messageField(overrideMsg, "server"); ok {
			if addrMsg, ok := messageField(serverMsg, "address"); ok {
				if addr, ok := addrMsg.Interface().(*net.IPOrDomain); ok && addr != nil {
					overrideAddr = addr.AsAddress()
				}
			}
			if port, ok := uint32Field(serverMsg, "port"); ok && port != 0 {
				overridePort = net.Port(port)
			}
		}
	}
	return strategy, overrideAddr, overridePort
}

func copySocketConfig(cfg *SocketConfig) *SocketConfig {
	if cfg == nil {
		return nil
	}
	if cloned, ok := proto.Clone(cfg).(*SocketConfig); ok {
		return cloned
	}
	// Should never happen, but keep a safe fallback.
	out := new(SocketConfig)
	proto.Merge(out, cfg)
	return out
}

const mergeSocketConfigCacheMaxItems = 64

type mergeSocketConfigCacheKey struct {
	primary       *SocketConfig
	fallback      *SocketConfig
	proxyStrategy DomainStrategy
}

var (
	mergeSocketConfigCacheMu sync.RWMutex
	mergeSocketConfigCache   = make(map[mergeSocketConfigCacheKey]*SocketConfig)
)

func getCachedMergeSocketConfig(key mergeSocketConfigCacheKey) (*SocketConfig, bool) {
	mergeSocketConfigCacheMu.RLock()
	cached, ok := mergeSocketConfigCache[key]
	mergeSocketConfigCacheMu.RUnlock()
	return cached, ok
}

func setCachedMergeSocketConfig(key mergeSocketConfigCacheKey, merged *SocketConfig) {
	mergeSocketConfigCacheMu.Lock()
	mergeSocketConfigCache[key] = merged
	for len(mergeSocketConfigCache) > mergeSocketConfigCacheMaxItems {
		for k := range mergeSocketConfigCache {
			delete(mergeSocketConfigCache, k)
			break
		}
	}
	mergeSocketConfigCacheMu.Unlock()
}

func mergeSocketConfig(primary, fallback *SocketConfig) *SocketConfig {
	if primary == nil && fallback == nil {
		return nil
	}
	if primary == nil {
		merged := copySocketConfig(fallback)
		if merged != nil {
			merged.DialerProxy = ""
		}
		return merged
	}
	merged := copySocketConfig(primary)
	if fallback == nil {
		merged.DialerProxy = ""
		return merged
	}
	if merged.Mark == 0 {
		merged.Mark = fallback.Mark
	}
	if merged.Tfo == 0 {
		merged.Tfo = fallback.Tfo
	}
	if merged.Tproxy == SocketConfig_Off {
		merged.Tproxy = fallback.Tproxy
	}
	if !merged.ReceiveOriginalDestAddress {
		merged.ReceiveOriginalDestAddress = fallback.ReceiveOriginalDestAddress
	}
	if len(merged.BindAddress) == 0 {
		merged.BindAddress = append([]byte(nil), fallback.BindAddress...)
	}
	if merged.BindPort == 0 {
		merged.BindPort = fallback.BindPort
	}
	if !merged.AcceptProxyProtocol {
		merged.AcceptProxyProtocol = fallback.AcceptProxyProtocol
	}
	if !merged.DomainStrategy.HasStrategy() && fallback.DomainStrategy.HasStrategy() {
		merged.DomainStrategy = fallback.DomainStrategy
	}
	if merged.TcpKeepAliveInterval == 0 {
		merged.TcpKeepAliveInterval = fallback.TcpKeepAliveInterval
	}
	if merged.TcpKeepAliveIdle == 0 {
		merged.TcpKeepAliveIdle = fallback.TcpKeepAliveIdle
	}
	if merged.TcpCongestion == "" {
		merged.TcpCongestion = fallback.TcpCongestion
	}
	if merged.Interface == "" {
		merged.Interface = fallback.Interface
	}
	if !merged.V6Only {
		merged.V6Only = fallback.V6Only
	}
	if merged.TcpWindowClamp == 0 {
		merged.TcpWindowClamp = fallback.TcpWindowClamp
	}
	if merged.TcpUserTimeout == 0 {
		merged.TcpUserTimeout = fallback.TcpUserTimeout
	}
	if merged.TcpMaxSeg == 0 {
		merged.TcpMaxSeg = fallback.TcpMaxSeg
	}
	if !merged.Penetrate {
		merged.Penetrate = fallback.Penetrate
	}
	if !merged.TcpMptcp {
		merged.TcpMptcp = fallback.TcpMptcp
	}
	if len(merged.CustomSockopt) == 0 {
		merged.CustomSockopt = append([]*CustomSockopt(nil), fallback.CustomSockopt...)
	}
	if merged.AddressPortStrategy == AddressPortStrategy_None {
		merged.AddressPortStrategy = fallback.AddressPortStrategy
	}
	if len(merged.TrustedXForwardedFor) == 0 {
		merged.TrustedXForwardedFor = append([]string(nil), fallback.TrustedXForwardedFor...)
	}
	merged.DialerProxy = ""
	return merged
}

func mergeSocketConfigWithProxyStrategy(primary, fallback *SocketConfig, proxyStrategy DomainStrategy) *SocketConfig {
	if primary == nil && fallback == nil {
		return nil
	}
	key := mergeSocketConfigCacheKey{
		primary:       primary,
		fallback:      fallback,
		proxyStrategy: proxyStrategy,
	}
	if cached, ok := getCachedMergeSocketConfig(key); ok {
		return cached
	}

	merged := mergeSocketConfig(primary, fallback)
	if merged != nil && !merged.DomainStrategy.HasStrategy() && proxyStrategy.HasStrategy() {
		merged.DomainStrategy = proxyStrategy
	}
	setCachedMergeSocketConfig(key, merged)
	return merged
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
			return inbound.Source.Address
		}
	}
	return nil
}

func shouldUseSecondaryStack(ob *session.Outbound, strategy DomainStrategy, hasSecondary bool) bool {
	if !hasSecondary || ob == nil {
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

func selectFreedomGateway(ctx context.Context, ob *session.Outbound, strategy DomainStrategy, settings *FreedomDialerSettings) net.Address {
	if settings == nil || (settings.Via == nil && settings.Via6 == nil) {
		return nil
	}
	useSecondary := shouldUseSecondaryStack(ob, strategy, settings.Via6 != nil)

	primary, secondary := settings.Via, settings.Via6
	primaryCidr, secondaryCidr := settings.ViaCidr, settings.Via6Cidr
	primaryCompiled, secondaryCompiled := settings.ViaCompiled, settings.Via6Compiled
	if useSecondary {
		primary, secondary = settings.Via6, settings.Via
		primaryCidr, secondaryCidr = settings.Via6Cidr, settings.ViaCidr
		primaryCompiled, secondaryCompiled = settings.Via6Compiled, settings.ViaCompiled
	}

	// Handle system default markers
	switch {
	case isIPv6Unspecified(primary):
		return nil
	case isIPv4Unspecified(primary) && settings.Via6 != nil:
		return net.AnyIP
	case isIPv4Unspecified(primary) || isIPv6Unspecified(settings.Via):
		return nil
	}

	addr, cidr, compiled := primary, primaryCidr, primaryCompiled
	if addr == nil {
		if strategy.HasFallback() {
			// Explicit priority: no gateway, let system route handle DNS fallback case
			return nil
		}
		addr, cidr, compiled = secondary, secondaryCidr, secondaryCompiled
	}
	if addr == nil {
		return nil
	}

	switch domain := addr.GetDomain(); {
	case cidr != "":
		if compiled != nil {
			return ParseRandomIPCompiled(ctx, compiled, ob)
		}
		return ParseRandomIP(ctx, addr.AsAddress(), cidr, ob)
	case domain == "origin" || domain == "srcip":
		gw := getInboundAddress(ctx, domain)
		if gw == nil {
			return nil
		}
		// When the strategy has an explicit ordered preference (e.g., ForceIPv6v4/UseIPv6v4),
		// don't let inbound source IP override the stack choice. Only allow when the inbound
		// address matches the preferred stack.
		if strategy.HasFallback() && strategy.PreferIP6() != strategy.PreferIP4() {
			if strategy.PreferIP6() && !gw.Family().IsIPv6() {
				return nil
			}
			if strategy.PreferIP4() && !gw.Family().IsIPv4() {
				return nil
			}
		}
		// Prevent IPv4 gateway being used for Via6.
		if domain == "srcip" && useSecondary && gw.Family().IsIPv4() {
			return nil
		}
		return gw
	default:
		return addr.AsAddress()
	}
}

func prepareFreedomDialerProxy(ctx context.Context, dest net.Destination, sockopt *SocketConfig, ob *session.Outbound, h outbound.Handler, src net.Address, srcPort net.Port) (net.Destination, net.Address, net.Port, *SocketConfig) {
	settings := readFreedomDialerSettings(h)
	proxyStrategy, overrideAddr, overridePort := readFreedomProxyConfig(h)
	var fallbackSockopt *SocketConfig
	var strategy DomainStrategy
	if settings != nil {
		fallbackSockopt = settings.SocketSettings
		strategy = settings.TargetStrategy
	}
	effectiveSockopt := mergeSocketConfigWithProxyStrategy(sockopt, fallbackSockopt, proxyStrategy)
	if ob != nil && src == nil && ob.Gateway != nil {
		src = ob.Gateway
		if srcPort == 0 {
			srcPort = ob.GatewayPort
		}
	}
	if ob != nil {
		if hinted := DomainStrategy(ob.TargetStrategy); hinted.HasStrategy() {
			strategy = hinted
		}
	}
	if !strategy.HasStrategy() && effectiveSockopt != nil && effectiveSockopt.DomainStrategy.HasStrategy() {
		strategy = effectiveSockopt.DomainStrategy
	}
	if settings != nil && src == nil {
		src = selectFreedomGateway(ctx, ob, strategy, settings)
	}
	if overrideAddr != nil {
		dest.Address = overrideAddr
	}
	if overridePort != 0 {
		dest.Port = overridePort
	}
	return dest, src, srcPort, effectiveSockopt
}

// DialSystem calls system dialer to create a network connection.
func DialSystem(ctx context.Context, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	var src net.Address
	var srcPort net.Port
	outbounds := session.OutboundsFromContext(ctx)
	var outboundName string
	var origTargetAddr net.Address
	disableDialerProxy := false
	var ob *session.Outbound
	if len(outbounds) > 0 {
		ob = outbounds[len(outbounds)-1]
		disableDialerProxy = ob.DialerProxyDisabled
		if sockopt == nil || len(sockopt.DialerProxy) == 0 || disableDialerProxy {
			src = ob.Gateway
			srcPort = ob.GatewayPort
		}
		outboundName = ob.Name
		origTargetAddr = ob.OriginalTarget.Address
		if origTargetAddr == nil {
			origTargetAddr = ob.Target.Address
		}
	}
	flowObserver := firewall.FlowObserverFromContext(ctx)
	if sockopt == nil {
		conn, err := effectiveSystemDialer.Dial(ctx, src, srcPort, dest, sockopt)
		return wrapConnWithFlowObserver(conn, flowObserver), err
	}

	effectiveSockopt := sockopt
	dialerProxyDestination := ""
	var dialerProxyHandler outbound.Handler
	if len(sockopt.DialerProxy) > 0 && !disableDialerProxy {
		if obm == nil {
			return nil, errors.New("there is no outbound manager for dialerProxy").AtError()
		}
		destination := sockopt.DialerProxy
		if destinationResolver != nil {
			resolved, err := destinationResolver.ResolveDestination(destination)
			if err != nil {
				return nil, errors.New("failed to resolve dialerProxy destination: ", destination).Base(err)
			}
			destination = resolved
		}
		h := obm.GetHandler(destination)
		if h == nil {
			return nil, errors.New("there is no outbound handler for dialerProxy").AtError()
		}
		dialerProxyDestination = destination
		dialerProxyHandler = h
		if isFreedomHandler(h) {
			dest, src, srcPort, effectiveSockopt = prepareFreedomDialerProxy(ctx, dest, sockopt, ob, h, src, srcPort)
			disableDialerProxy = true
			if ob != nil {
				ob.DialerProxyDisabled = true
			}
		}
	}

	if newDest, err := checkAddressPortStrategy(ctx, dest, effectiveSockopt); err == nil && newDest != nil {
		errors.LogInfo(ctx, "replace destination with ", newDest.String())
		dest = *newDest
	}

	if effectiveSockopt.DomainStrategy.HasStrategy() && dest.Address.Family().IsDomain() {
		finalStrategy := effectiveSockopt.DomainStrategy
		if outboundName == "freedom" && dest.Network == net.Network_UDP && origTargetAddr != nil && src == nil {
			finalStrategy = finalStrategy.GetDynamicStrategy(origTargetAddr.Family())
		}
		addr, err := LookupForAddressPickWithContext(ctx, dest.Address.Domain(), finalStrategy, src)
		if err != nil {
			errors.LogErrorInner(ctx, err, "failed to resolve ip")
			if effectiveSockopt.DomainStrategy.ForceIP() {
				return nil, err
			}
		} else {
			dest.Address = addr
			errors.LogInfo(ctx, "replace destination with ", dest.String())
		}
	}

	// Clear gateway when IP family of resolved target mismatches the selected stack.
	if src != nil && dest.Address.Family().IsIP() && src.Family().IsIP() && dest.Address.Family().IsIPv6() != src.Family().IsIPv6() {
		if len(outbounds) > 0 {
			outbounds[len(outbounds)-1].Gateway = nil
		}
		src = nil
		srcPort = 0
	}

	if len(sockopt.DialerProxy) > 0 && !disableDialerProxy {
		if dialerProxyDestination == "" || dialerProxyHandler == nil {
			return nil, errors.New("there is no outbound handler for dialerProxy").AtError()
		}
		return wrapConnWithFlowObserver(redirect(ctx, dest, dialerProxyDestination, dialerProxyHandler), flowObserver), nil
	}

	conn, err := effectiveSystemDialer.Dial(ctx, src, srcPort, dest, effectiveSockopt)
	return wrapConnWithFlowObserver(conn, flowObserver), err
}

func InitSystemDialer(dc dns.Client, om outbound.Manager, router routing.Router) {
	dnsClient = dc
	obm = om
	if resolver, ok := router.(routing.DestinationResolver); ok {
		destinationResolver = resolver
	} else {
		destinationResolver = nil
	}
}

// SystemDialerState captures the global dependencies used by the transport/internet package.
// It is primarily intended for callers that need to validate/build instances without
// permanently mutating the active runtime dialer dependencies.
type SystemDialerState struct {
	DNSClient           dns.Client
	OutboundManager     outbound.Manager
	DestinationResolver routing.DestinationResolver
}

func SnapshotSystemDialerState() SystemDialerState {
	return SystemDialerState{
		DNSClient:           dnsClient,
		OutboundManager:     obm,
		DestinationResolver: destinationResolver,
	}
}

func RestoreSystemDialerState(state SystemDialerState) {
	dnsClient = state.DNSClient
	obm = state.OutboundManager
	destinationResolver = state.DestinationResolver
}
