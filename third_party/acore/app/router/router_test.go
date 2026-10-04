package router_test

import (
	"context"
	"testing"

	. "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/outbound"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/testing/mocks"
	"github.com/golang/mock/gomock"
)

type mockOutboundManager struct {
	outbound.Manager
	outbound.HandlerSelector
}

func TestSimpleRouter(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Networks: []net.Network{net.Network_TCP},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestDomainRecoverModeFromInternalRule(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Networks: []net.Network{net.Network_TCP},
			},
			{
				InboundTag: []string{InternalDomainRecoverInboundTag},
				Attributes: map[string]string{
					InternalDomainRecoverAttr: "IPReDisCover",
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if mode := r.DomainRecoverMode(); mode != "iprediscover" {
		t.Fatalf("expected domain recover mode iprediscover, got %q", mode)
	}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Fatalf("expect tag 'test', got %q", tag)
	}
}

func TestReLookupFlagPreservedOnRoute(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Networks: []net.Network{net.Network_TCP},
				ReLookup: true,
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ob := &session.Outbound{
		Target:      net.TCPDestination(net.ParseAddress("104.18.32.47"), 80),
		RouteTarget: net.TCPDestination(net.DomainAddress("chatgpt.com"), 80),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)

	rl, ok := route.(interface{ ReLookup() bool })
	if !ok || !rl.ReLookup() {
		t.Fatalf("expected route ReLookup to be true")
	}
	if ob.Target.Address.Family().IsDomain() {
		t.Fatalf("expected outbound target to remain IP before dispatcher, got %v", ob.Target)
	}
	if ob.ReLookup {
		t.Fatalf("expected outbound ReLookup to remain false before dispatcher")
	}
}

func TestDestVlessRoutePreservedOnRoute(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Networks: []net.Network{net.Network_TCP},
				Attributes: map[string]string{
					InternalDestVlessRouteAttr: "4660",
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)

	dr, ok := route.(interface {
		DestVlessRoute() (net.Port, bool)
	})
	if !ok {
		t.Fatalf("expected route to expose DestVlessRoute")
	}
	value, ok := dr.DestVlessRoute()
	if !ok {
		t.Fatalf("expected DestVlessRoute to be present")
	}
	if value != net.Port(4660) {
		t.Fatalf("expected DestVlessRoute=4660, got %d", value)
	}
}

func TestVlessRouteQuickTargetRouteSelection(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "mark-vless",
				Attributes: map[string]string{
					InternalVlessRouteTargetAttr: `[{"ranges":[{"from":53,"to":53},{"from":443,"to":443}],"destination":"quick-out"}]`,
				},
			},
			{
				RuleTag: "fallback-rule",
				TargetTag: &RoutingRule_Tag{
					Tag: "fallback-out",
				},
				RequireRuleTag: []string{"mark-vless"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	buildCtx := func(vlessRoute net.Port) context.Context {
		ctx := context.Background()
		ctx = session.ContextWithInbound(ctx, &session.Inbound{VlessRoute: vlessRoute})
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
			Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
		}})
		return ctx
	}

	matchedRoute, err := r.PickRoute(routing_session.AsRoutingContext(buildCtx(53)))
	common.Must(err)
	if tag := matchedRoute.GetOutboundTag(); tag != "quick-out" {
		t.Fatalf("expected quick-out for matched vlessRoute, got %q", tag)
	}
	if ruleTag := matchedRoute.GetRuleTag(); ruleTag != "mark-vless" {
		t.Fatalf("expected first ruleTag on quick match, got %q", ruleTag)
	}

	fallbackRoute, err := r.PickRoute(routing_session.AsRoutingContext(buildCtx(54)))
	common.Must(err)
	if tag := fallbackRoute.GetOutboundTag(); tag != "fallback-out" {
		t.Fatalf("expected fallback-out for unmatched vlessRoute, got %q", tag)
	}
	if ruleTag := fallbackRoute.GetRuleTag(); ruleTag != "fallback-rule" {
		t.Fatalf("expected fallback-rule after quick target miss, got %q", ruleTag)
	}
}

func TestSimpleBalancer(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{
					BalancingTag: "balance",
				},
				Networks: []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:              "balance",
				OutboundSelector: []string{"test-"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	mockHs.EXPECT().Select(gomock.Eq([]string{"test-"})).Return([]string{"test"})

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestNestedBalancer(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{
					BalancingTag: "outer",
				},
				Networks: []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:              "inner",
				OutboundSelector: []string{"test-"},
			},
			{
				Tag:              "outer",
				OutboundSelector: []string{"inner"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()
	mockHs.EXPECT().Select(gomock.Eq([]string{"test-"})).Return([]string{"test"}).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestBalancerLoopDetection(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{
					BalancingTag: "a",
				},
				Networks: []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:              "a",
				OutboundSelector: []string{"b"},
			},
			{
				Tag:              "b",
				OutboundSelector: []string{"a"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	if err := r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil); err == nil {
		t.Fatal("expected balancer loop detection error")
	}
}

/*

Do not work right now: need a full client setup

func TestLeastLoadBalancer(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{
					BalancingTag: "balance",
				},
				Networks: []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:              "balance",
				OutboundSelector: []string{"test-"},
				Strategy:         "leastLoad",
				StrategySettings: serial.ToTypedMessage(&StrategyLeastLoadConfig{
					Baselines:   nil,
					Expected:    1,
				}),
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)

	mockHs.EXPECT().Select(gomock.Eq([]string{"test-"})).Return([]string{"test1"})

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))
	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("v2ray.com"), 80)})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test1" {
		t.Error("expect tag 'test1', bug actually ", tag)
	}
}*/

func TestIPOnDemand(t *testing.T) {
	config := &Config{
		DomainStrategy: Config_IpOnDemand,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Geoip: []*GeoIP{
					{
						Cidr: []*CIDR{
							{
								Ip:     []byte{192, 168, 0, 0},
								Prefix: 16,
							},
						},
					},
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockDNS.EXPECT().LookupIP(gomock.Eq("example.com"), dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: false,
	}).Return([]net.IP{{192, 168, 0, 1}}, uint32(600), nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, nil, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestIPIfNonMatchDomain(t *testing.T) {
	config := &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Geoip: []*GeoIP{
					{
						Cidr: []*CIDR{
							{
								Ip:     []byte{192, 168, 0, 0},
								Prefix: 16,
							},
						},
					},
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockDNS.EXPECT().LookupIP(gomock.Eq("example.com"), dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: false,
	}).Return([]net.IP{{192, 168, 0, 1}}, uint32(600), nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, nil, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestIPIfNonMatchIP(t *testing.T) {
	config := &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Geoip: []*GeoIP{
					{
						Cidr: []*CIDR{
							{
								Ip:     []byte{127, 0, 0, 0},
								Prefix: 8,
							},
						},
					},
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, nil, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.LocalHostIP, 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestShouldSniffProtocolWireGuard(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"wireguard"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("wireguard") {
		t.Fatal("expected wireguard sniffing to be enabled by routing rule")
	}
	if r.ShouldSniffProtocol("dns") {
		t.Fatal("expected dns sniffing to be disabled without dns protocol rule")
	}
}

func TestShouldSniffProtocolWireGuardNegation(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"!wireguard"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("wireguard") {
		t.Fatal("expected wireguard sniffing to be enabled by protocol negation rule")
	}
}

func TestShouldSniffProtocolZeroTier(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"zerotier"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("zerotier") {
		t.Fatal("expected zerotier sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolMTProto(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"mtproto"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("mtproto") {
		t.Fatal("expected mtproto sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolECH(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"ech"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("ech") {
		t.Fatal("expected ech sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolRDP(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"rdp"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("rdp") {
		t.Fatal("expected rdp sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolMQTT(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"mqtt"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("mqtt") {
		t.Fatal("expected mqtt sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolNTP(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"ntp"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("ntp") {
		t.Fatal("expected ntp sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolPostgres(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"postgres"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("postgres") {
		t.Fatal("expected postgres sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolIKEv2(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"ikev2"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("ikev2") {
		t.Fatal("expected ikev2 sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolDTLS(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"dtls"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("dtls") {
		t.Fatal("expected dtls sniffing to be enabled by routing rule")
	}
}

func TestShouldSniffProtocolJA4ByAttrs(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("ja4") {
		t.Fatal("expected ja4 sniffing to be enabled by attrs.ja4")
	}
}

func TestShouldSniffProtocolJA4DisabledWithoutAttrs(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"tls"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if r.ShouldSniffProtocol("ja4") {
		t.Fatal("expected ja4 sniffing to stay disabled without attrs.ja4")
	}
}

func TestShouldSniffProtocolJA4WithContextMatch(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				InboundTag: []string{"ja4-in"},
				Networks:   []net.Network{net.Network_TCP},
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	matching := context.Background()
	matching = session.ContextWithInbound(matching, &session.Inbound{Tag: "ja4-in"})
	matching = session.ContextWithOutbounds(matching, []*session.Outbound{{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	}})
	if !r.ShouldSniffProtocolForContext("ja4", routing_session.AsRoutingContext(matching)) {
		t.Fatal("expected ja4 sniffing for matching context")
	}

	nonMatching := context.Background()
	nonMatching = session.ContextWithInbound(nonMatching, &session.Inbound{Tag: "other"})
	nonMatching = session.ContextWithOutbounds(nonMatching, []*session.Outbound{{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	}})
	if r.ShouldSniffProtocolForContext("ja4", routing_session.AsRoutingContext(nonMatching)) {
		t.Fatal("expected ja4 sniffing to be disabled for non-matching context")
	}
}

func TestRemoveRuleUpdatesJA4SniffFlag(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				RuleTag: "ja4-rule",
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	if !r.ShouldSniffProtocol("ja4") {
		t.Fatal("expected ja4 sniffing to be enabled before removing rule")
	}
	if err := r.RemoveRule("ja4-rule"); err != nil {
		t.Fatalf("remove rule failed: %v", err)
	}
	if r.ShouldSniffProtocol("ja4") {
		t.Fatal("expected ja4 sniffing to be disabled after removing ja4 rule")
	}
}

func TestShouldSniffProtocolWireGuardWithContextMatch(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				InboundTag: []string{"wg-in"},
				Networks:   []net.Network{net.Network_UDP},
				Protocol:   []string{"wireguard"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	matching := context.Background()
	matching = session.ContextWithInbound(matching, &session.Inbound{Tag: "wg-in"})
	matching = session.ContextWithOutbounds(matching, []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("198.51.100.2"), 51820),
	}})
	if !r.ShouldSniffProtocolForContext("wireguard", routing_session.AsRoutingContext(matching)) {
		t.Fatal("expected wireguard sniffing for matching context")
	}

	nonMatching := context.Background()
	nonMatching = session.ContextWithInbound(nonMatching, &session.Inbound{Tag: "other"})
	nonMatching = session.ContextWithOutbounds(nonMatching, []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("198.51.100.2"), 51820),
	}})
	if r.ShouldSniffProtocolForContext("wireguard", routing_session.AsRoutingContext(nonMatching)) {
		t.Fatal("expected wireguard sniffing to be disabled for non-matching context")
	}
}

func TestShouldSniffProtocolWireGuardWithContextNegation(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				InboundTag: []string{"wg-in"},
				Networks:   []net.Network{net.Network_UDP},
				Protocol:   []string{"!wireguard"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	matching := context.Background()
	matching = session.ContextWithInbound(matching, &session.Inbound{Tag: "wg-in"})
	matching = session.ContextWithOutbounds(matching, []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("198.51.100.2"), 51820),
	}})
	if !r.ShouldSniffProtocolForContext("wireguard", routing_session.AsRoutingContext(matching)) {
		t.Fatal("expected wireguard sniffing for negation rule in matching context")
	}

	nonMatching := context.Background()
	nonMatching = session.ContextWithInbound(nonMatching, &session.Inbound{Tag: "other"})
	nonMatching = session.ContextWithOutbounds(nonMatching, []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("198.51.100.2"), 51820),
	}})
	if r.ShouldSniffProtocolForContext("wireguard", routing_session.AsRoutingContext(nonMatching)) {
		t.Fatal("expected wireguard sniffing to be disabled for non-matching context")
	}
}

func TestShouldSniffProtocolWireGuardWithContextPositiveAndNegation(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				InboundTag: []string{"wg-in"},
				Networks:   []net.Network{net.Network_UDP},
				Protocol:   []string{"http", "!wireguard"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	matching := context.Background()
	matching = session.ContextWithInbound(matching, &session.Inbound{Tag: "wg-in"})
	matching = session.ContextWithOutbounds(matching, []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("198.51.100.2"), 51820),
	}})
	if r.ShouldSniffProtocolForContext("wireguard", routing_session.AsRoutingContext(matching)) {
		t.Fatal("expected wireguard sniffing to stay disabled when positive protocol does not include wireguard")
	}
}
