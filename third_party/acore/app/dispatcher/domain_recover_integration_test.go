package dispatcher_test

import (
	"context"
	"sync"
	"testing"

	"github.com/ImAubrey/acore/app/dispatcher"
	appdns "github.com/ImAubrey/acore/app/dns"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	feature_dns "github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/policy"
	"github.com/ImAubrey/acore/features/routing"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

type testRoute struct {
	routing.Context
	outboundTag string
}

func (r *testRoute) GetOutboundGroupTags() []string { return nil }
func (r *testRoute) GetOutboundTag() string         { return r.outboundTag }
func (r *testRoute) GetRuleTag() string             { return "" }

type testRouter struct {
	route routing.Route
	mode  string
}

func (r *testRouter) Type() interface{} { return routing.RouterType() }
func (r *testRouter) Start() error      { return nil }
func (r *testRouter) Close() error      { return nil }

func (r *testRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	return r.route, nil
}

func (r *testRouter) AddRule(*serial.TypedMessage, bool) error { return nil }
func (r *testRouter) RemoveRule(string) error                  { return nil }
func (r *testRouter) DomainRecoverMode() string                { return r.mode }

type captureHandler struct {
	tag string

	mu        sync.Mutex
	gotTarget net.Destination
	gotRoute  net.Destination
}

func (h *captureHandler) Tag() string                          { return h.tag }
func (h *captureHandler) Start() error                         { return nil }
func (h *captureHandler) Close() error                         { return nil }
func (h *captureHandler) SenderSettings() *serial.TypedMessage { return nil }
func (h *captureHandler) ProxySettings() *serial.TypedMessage  { return nil }

func (h *captureHandler) Dispatch(ctx context.Context, _ *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	h.mu.Lock()
	h.gotTarget = ob.Target
	h.gotRoute = ob.RouteTarget
	h.mu.Unlock()
}

type managerStub struct {
	handler outbound.Handler
}

func (m *managerStub) Type() interface{} { return outbound.ManagerType() }
func (m *managerStub) Start() error      { return nil }
func (m *managerStub) Close() error      { return nil }
func (m *managerStub) GetHandler(tag string) outbound.Handler {
	if m.handler != nil && m.handler.Tag() == tag {
		return m.handler
	}
	return nil
}
func (m *managerStub) GetDefaultHandler() outbound.Handler                { return m.handler }
func (m *managerStub) AddHandler(context.Context, outbound.Handler) error { return nil }
func (m *managerStub) RemoveHandler(context.Context, string) error        { return nil }
func (m *managerStub) ListHandlers(context.Context) []outbound.Handler    { return nil }

type noopWriter struct{}

func (noopWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func TestDomainRecoverAfterLookupIPWithMultipleIPs(t *testing.T) {
	dnsServer, err := appdns.New(context.Background(), &appdns.Config{
		QueryStrategy: appdns.QueryStrategy_USE_IP,
		StaticHosts: []*appdns.Config_HostMapping{
			{
				Type:   appdns.DomainMatchingType_Full,
				Domain: "multi.example",
				Ip: [][]byte{
					{203, 0, 113, 31},
					{203, 0, 113, 32},
					{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	ips, _, err := dnsServer.LookupIP("multi.example", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	if err != nil {
		t.Fatalf("LookupIP() failed: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("expected 3 ips from LookupIP, got %d", len(ips))
	}

	handler := &captureHandler{tag: "direct"}
	router := &testRouter{mode: "iprediscover"}
	d := new(dispatcher.DefaultDispatcher)
	if err := d.Init(
		&dispatcher.Config{},
		&managerStub{handler: handler},
		router,
		firewall.DefaultManager{},
		policy.DefaultManager{},
		stats.NoopManager{},
		dnsServer,
		conntrack.NewManager(),
	); err != nil {
		t.Fatalf("dispatcher init failed: %v", err)
	}

	for _, ip := range ips {
		ob := &session.Outbound{
			Target: net.TCPDestination(net.ParseAddress(ip.String()), 443),
		}
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: session.SniffingRequest{Enabled: false},
		})
		router.route = &testRoute{
			Context:     routing_session.AsRoutingContext(ctx),
			outboundTag: "direct",
		}

		reader, _ := pipe.New()
		if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
			Reader: reader,
			Writer: noopWriter{},
		}); err != nil {
			t.Fatalf("DispatchLink() failed for ip %s: %v", ip.String(), err)
		}

		handler.mu.Lock()
		gotRoute := handler.gotRoute
		handler.mu.Unlock()
		if !gotRoute.IsValid() || !gotRoute.Address.Family().IsDomain() {
			t.Fatalf("expected domain RouteTarget for ip %s, got %v", ip.String(), gotRoute)
		}
		if got := gotRoute.Address.Domain(); got != "multi.example" {
			t.Fatalf("expected mapped domain multi.example for ip %s, got %q", ip.String(), got)
		}
	}
}

func TestDomainRecoverAfterLookupIPWithMultipleIPsUDP(t *testing.T) {
	dnsServer, err := appdns.New(context.Background(), &appdns.Config{
		QueryStrategy: appdns.QueryStrategy_USE_IP,
		StaticHosts: []*appdns.Config_HostMapping{
			{
				Type:   appdns.DomainMatchingType_Full,
				Domain: "multi-udp.example",
				Ip: [][]byte{
					{203, 0, 113, 41},
					{203, 0, 113, 42},
					{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	ips, _, err := dnsServer.LookupIP("multi-udp.example", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	if err != nil {
		t.Fatalf("LookupIP() failed: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("expected 3 ips from LookupIP, got %d", len(ips))
	}

	handler := &captureHandler{tag: "direct"}
	router := &testRouter{mode: "iprediscover"}
	d := new(dispatcher.DefaultDispatcher)
	if err := d.Init(
		&dispatcher.Config{},
		&managerStub{handler: handler},
		router,
		firewall.DefaultManager{},
		policy.DefaultManager{},
		stats.NoopManager{},
		dnsServer,
		conntrack.NewManager(),
	); err != nil {
		t.Fatalf("dispatcher init failed: %v", err)
	}

	for _, ip := range ips {
		ob := &session.Outbound{
			Target: net.UDPDestination(net.ParseAddress(ip.String()), 51820),
		}
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: session.SniffingRequest{Enabled: false},
		})
		router.route = &testRoute{
			Context:     routing_session.AsRoutingContext(ctx),
			outboundTag: "direct",
		}

		reader, _ := pipe.New()
		if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
			Reader: reader,
			Writer: noopWriter{},
		}); err != nil {
			t.Fatalf("DispatchLink() failed for ip %s: %v", ip.String(), err)
		}

		handler.mu.Lock()
		gotRoute := handler.gotRoute
		handler.mu.Unlock()
		if !gotRoute.IsValid() || !gotRoute.Address.Family().IsDomain() {
			t.Fatalf("expected domain RouteTarget for udp ip %s, got %v", ip.String(), gotRoute)
		}
		if got := gotRoute.Address.Domain(); got != "multi-udp.example" {
			t.Fatalf("expected mapped domain multi-udp.example for udp ip %s, got %q", ip.String(), got)
		}
		if gotRoute.Network != net.Network_UDP {
			t.Fatalf("expected udp network to be preserved, got %v", gotRoute.Network)
		}
	}
}
