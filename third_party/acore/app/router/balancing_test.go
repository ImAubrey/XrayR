package router_test

import (
	"context"
	"testing"

	. "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/core"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/testing/mocks"
	"github.com/golang/mock/gomock"
)

func TestPrincipleTargetKeepsNestedBalancerTag(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{BalancingTag: "outer"},
				Networks:  []net.Network{net.Network_TCP},
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
	initCtx := context.WithValue(context.Background(), core.AcoreKey(1), &core.Instance{})
	common.Must(r.Init(initCtx, config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	targets, err := r.GetPrincipleTarget("outer")
	common.Must(err)
	if len(targets) != 1 || targets[0] != "inner" {
		t.Fatalf("unexpected principle targets: got=%v want=[inner]", targets)
	}

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Fatalf("unexpected outbound tag: got=%q want=%q", tag, "test")
	}
}

func TestFallbackTagPrefixRandomPick(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{BalancingTag: "balance"},
				Networks:  []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:              "balance",
				Strategy:         "fallback",
				OutboundSelector: []string{"main-"},
				FallbackTag:      "fb-",
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()
	mockHs.EXPECT().Select(gomock.Eq([]string{"main-"})).Return([]string{}).AnyTimes()
	mockHs.EXPECT().Select(gomock.Eq([]string{"fb-"})).Return([]string{"fb-a", "fb-b"}).AnyTimes()

	r := new(Router)
	initCtx := context.WithValue(context.Background(), core.AcoreKey(1), &core.Instance{})
	common.Must(r.Init(initCtx, config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	seen := map[string]struct{}{}
	for i := 0; i < 24; i++ {
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
		}})
		route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
		common.Must(err)
		tag := route.GetOutboundTag()
		if tag != "fb-a" && tag != "fb-b" {
			t.Fatalf("unexpected fallback target: %q", tag)
		}
		seen[tag] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("fallback target is not random enough, only seen: %#v", seen)
	}
}
