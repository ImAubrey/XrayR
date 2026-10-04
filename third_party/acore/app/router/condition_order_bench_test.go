package router

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ImAubrey/acore/common/net"
	acore_dns "github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/routing"
)

type benchDNS struct {
	lookups atomic.Uint64
	ips     []net.IP
}

func (d *benchDNS) Type() interface{} { return acore_dns.ClientType() }
func (d *benchDNS) Start() error      { return nil }
func (d *benchDNS) Close() error      { return nil }

func (d *benchDNS) LookupIP(domain string, option acore_dns.IPOption) ([]net.IP, uint32, error) {
	_ = domain
	_ = option
	d.lookups.Add(1)
	return d.ips, acore_dns.DefaultTTL, nil
}

type benchRoutingCtx struct {
	inboundTag   string
	sourceIPs    []net.IP
	sourcePort   net.Port
	targetIPs    []net.IP
	targetPort   net.Port
	localIPs     []net.IP
	localPort    net.Port
	targetDomain string
	network      net.Network
	protocol     string
	user         string
	vlessRoute   net.Port
	attributes   map[string]string
	skipDNS      bool

	dnsClient *benchDNS

	ruleTags map[string]struct{}
}

func (c *benchRoutingCtx) GetInboundTag() string            { return c.inboundTag }
func (c *benchRoutingCtx) GetSourceIPs() []net.IP           { return c.sourceIPs }
func (c *benchRoutingCtx) GetSourcePort() net.Port          { return c.sourcePort }
func (c *benchRoutingCtx) GetTargetPort() net.Port          { return c.targetPort }
func (c *benchRoutingCtx) GetLocalIPs() []net.IP            { return c.localIPs }
func (c *benchRoutingCtx) GetLocalPort() net.Port           { return c.localPort }
func (c *benchRoutingCtx) GetTargetDomain() string          { return c.targetDomain }
func (c *benchRoutingCtx) GetNetwork() net.Network          { return c.network }
func (c *benchRoutingCtx) GetProtocol() string              { return c.protocol }
func (c *benchRoutingCtx) GetUser() string                  { return c.user }
func (c *benchRoutingCtx) GetVlessRoute() net.Port          { return c.vlessRoute }
func (c *benchRoutingCtx) GetAttributes() map[string]string { return c.attributes }
func (c *benchRoutingCtx) GetSkipDNSResolve() bool          { return c.skipDNS }

func (c *benchRoutingCtx) GetTargetIPs() []net.IP {
	if len(c.targetIPs) > 0 {
		return c.targetIPs
	}
	if c.dnsClient == nil || c.targetDomain == "" {
		return nil
	}
	ips, _, _ := c.dnsClient.LookupIP(c.targetDomain, acore_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: false,
	})
	c.targetIPs = ips
	return ips
}

// routing.RuleTagManager
func (c *benchRoutingCtx) AddRuleTag(tag string) {
	if tag == "" {
		return
	}
	if c.ruleTags == nil {
		c.ruleTags = make(map[string]struct{}, 1)
	}
	c.ruleTags[tag] = struct{}{}
}

func (c *benchRoutingCtx) HasRuleTag(tag string) bool {
	if c.ruleTags == nil {
		return false
	}
	_, ok := c.ruleTags[tag]
	return ok
}

func permute(in []string) [][]string {
	if len(in) == 0 {
		return [][]string{{}}
	}
	var out [][]string
	for i := range in {
		rest := make([]string, 0, len(in)-1)
		rest = append(rest, in[:i]...)
		rest = append(rest, in[i+1:]...)
		for _, p := range permute(rest) {
			seq := append([]string{in[i]}, p...)
			out = append(out, seq)
		}
	}
	return out
}

func orderName(order []string) string {
	return strings.Join(order, "-")
}

func mustCondition(b testing.TB, cond Condition, err error) Condition {
	b.Helper()
	if err != nil {
		b.Fatalf("failed to build condition: %v", err)
	}
	return cond
}

func buildOrderedRuleCondition(b testing.TB, order []string) Condition {
	b.Helper()

	// Fixed cheap prefix.
	conds := NewConditionChan()
	rtc, err := NewRuleTagCondition([]string{"tag-ok"})
	conds.Add(mustCondition(b, rtc, err))
	conds.Add(NewInboundTagMatcher([]string{"in"}))
	conds.Add(NewNetworkMatcher([]net.Network{net.Network_TCP}))
	conds.Add(NewPortMatcher(&net.PortList{Range: []*net.PortRange{net.SinglePortRange(net.Port(443))}}, MatcherAsType_Target))
	conds.Add(NewUserMatcher([]string{"user@example.com"}))

	// Matchers we want to permute.
	protoCond := Condition(NewProtocolMatcher([]string{"http"}))
	dm, err := NewMphMatcherGroup([]*Domain{{Type: Domain_Full, Value: "example.com"}})
	domainCond := mustCondition(b, dm, err)
	attrCond := Condition(&AttributeMatcher{configuredKeys: map[string]*regexp.Regexp{
		":path": regexp.MustCompile("^/api"),
	}})
	ipm, err := NewIPMatcher([]*GeoIP{{
		Cidr: []*CIDR{{
			Ip:     []byte{1, 1, 1, 1},
			Prefix: 32,
		}},
	}}, MatcherAsType_Target)
	geoipCond := mustCondition(b, ipm, err)

	m := map[string]Condition{
		"protocol":   protoCond,
		"domain":     domainCond,
		"attributes": attrCond,
		"geoip":      geoipCond,
	}

	for _, k := range order {
		cond, ok := m[k]
		if !ok {
			b.Fatalf("unknown key in order: %q", k)
		}
		conds.Add(cond)
	}

	return conds
}

func Benchmark_RuleConditionOrderMatrix(b *testing.B) {
	// We only permute these because they are the ones that materially trade off
	// between cheap string checks and potentially expensive DNS/GeoIP work.
	keys := []string{"protocol", "domain", "attributes", "geoip"}
	orders := permute(keys)

	type scenario struct {
		name   string
		newCtx func(dns *benchDNS) *benchRoutingCtx
	}

	scenarios := []scenario{
		{
			name: "proto_miss",
			newCtx: func(dns *benchDNS) *benchRoutingCtx {
				// Everything else matches; only protocol fails.
				return &benchRoutingCtx{
					inboundTag:   "in",
					sourceIPs:    []net.IP{net.IP{192, 0, 2, 1}},
					targetPort:   net.Port(443),
					targetDomain: "example.com",
					network:      net.Network_TCP,
					protocol:     "",
					user:         "user@example.com",
					attributes:   map[string]string{":path": "/api/v1"},
					dnsClient:    dns,
					ruleTags:     map[string]struct{}{"tag-ok": {}},
				}
			},
		},
		{
			name: "domain_miss",
			newCtx: func(dns *benchDNS) *benchRoutingCtx {
				// Everything else matches; only domain fails.
				return &benchRoutingCtx{
					inboundTag:   "in",
					sourceIPs:    []net.IP{net.IP{192, 0, 2, 1}},
					targetPort:   net.Port(443),
					targetDomain: "other.example",
					network:      net.Network_TCP,
					protocol:     "http/1.1",
					user:         "user@example.com",
					attributes:   map[string]string{":path": "/api/v1"},
					dnsClient:    dns,
					ruleTags:     map[string]struct{}{"tag-ok": {}},
				}
			},
		},
		{
			name: "attr_miss",
			newCtx: func(dns *benchDNS) *benchRoutingCtx {
				// Everything else matches; only attributes fail.
				return &benchRoutingCtx{
					inboundTag:   "in",
					sourceIPs:    []net.IP{net.IP{192, 0, 2, 1}},
					targetPort:   net.Port(443),
					targetDomain: "example.com",
					network:      net.Network_TCP,
					protocol:     "http/1.1",
					user:         "user@example.com",
					attributes:   map[string]string{":path": "/not-api"},
					dnsClient:    dns,
					ruleTags:     map[string]struct{}{"tag-ok": {}},
				}
			},
		},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			for _, order := range orders {
				order := order
				b.Run(orderName(order), func(b *testing.B) {
					b.ReportAllocs()

					cond := buildOrderedRuleCondition(b, order)

					dns := &benchDNS{ips: []net.IP{net.IP{1, 1, 1, 1}}}
					ctx := sc.newCtx(dns)

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						// Reset per-op cache so orderings that avoid GeoIP also avoid DNS work.
						ctx.targetIPs = nil
						if cond.Apply(routing.Context(ctx)) {
							// Keep compiler from optimizing away the call.
							b.Fatalf("unexpected match in scenario %s order %s", sc.name, fmt.Sprint(order))
						}
					}

					b.StopTimer()
					b.ReportMetric(float64(dns.lookups.Load())/float64(b.N), "dnslookups/op")
				})
			}
		})
	}
}
