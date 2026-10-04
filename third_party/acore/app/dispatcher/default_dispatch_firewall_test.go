package dispatcher

import (
	"context"
	"testing"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	feature_firewall "github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/transport"
)

type firewallOrderTestHandler struct {
	tag         string
	dispatchHit bool
}

func (h *firewallOrderTestHandler) Type() interface{} { return nil }
func (h *firewallOrderTestHandler) Start() error      { return nil }
func (h *firewallOrderTestHandler) Close() error      { return nil }
func (h *firewallOrderTestHandler) Tag() string       { return h.tag }
func (h *firewallOrderTestHandler) Dispatch(context.Context, *transport.Link) {
	h.dispatchHit = true
}
func (h *firewallOrderTestHandler) SenderSettings() *serial.TypedMessage { return nil }
func (h *firewallOrderTestHandler) ProxySettings() *serial.TypedMessage  { return nil }

type firewallOrderOutboundManager struct {
	handler outbound.Handler
}

func (m *firewallOrderOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (m *firewallOrderOutboundManager) Start() error      { return nil }
func (m *firewallOrderOutboundManager) Close() error      { return nil }
func (m *firewallOrderOutboundManager) GetHandler(tag string) outbound.Handler {
	if m.handler != nil && m.handler.Tag() == tag {
		return m.handler
	}
	return nil
}
func (m *firewallOrderOutboundManager) GetDefaultHandler() outbound.Handler { return m.handler }
func (m *firewallOrderOutboundManager) AddHandler(context.Context, outbound.Handler) error {
	return nil
}
func (m *firewallOrderOutboundManager) RemoveHandler(context.Context, string) error { return nil }
func (m *firewallOrderOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	if m.handler == nil {
		return nil
	}
	return []outbound.Handler{m.handler}
}

type firewallOrderRoute struct {
	routing.Context
	outboundTag string
	ruleTag     string
}

func (r *firewallOrderRoute) GetOutboundGroupTags() []string { return nil }
func (r *firewallOrderRoute) GetOutboundTag() string         { return r.outboundTag }
func (r *firewallOrderRoute) GetRuleTag() string             { return r.ruleTag }

type firewallOrderRouter struct {
	route  routing.Route
	picked bool
}

func (r *firewallOrderRouter) Type() interface{} { return routing.RouterType() }
func (r *firewallOrderRouter) Start() error      { return nil }
func (r *firewallOrderRouter) Close() error      { return nil }
func (r *firewallOrderRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.picked = true
	return r.route, nil
}
func (r *firewallOrderRouter) AddRule(*serial.TypedMessage, bool) error { return nil }
func (r *firewallOrderRouter) RemoveRule(string) error                  { return nil }

func TestRoutedDispatchEvaluatesFirewallAfterRouting(t *testing.T) {
	ctx := context.Background()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.40"), 10000),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         net.TCPDestination(net.ParseAddress("198.51.100.40"), 443),
		OriginalTarget: net.TCPDestination(net.ParseAddress("198.51.100.40"), 443),
	}})

	baseRoutingCtx := routing_session.AsRoutingContext(ctx)
	route := &firewallOrderRoute{
		Context:     baseRoutingCtx,
		outboundTag: "test-out",
		ruleTag:     "route-hit",
	}
	router := &firewallOrderRouter{route: route}
	handler := &firewallOrderTestHandler{tag: "test-out"}
	fw := &firewallOrderRecorder{
		routePicked: &router.picked,
		expectedCtx: route,
	}

	d := &DefaultDispatcher{
		ohm:    &firewallOrderOutboundManager{handler: handler},
		router: router,
		fw:     fw,
	}

	d.routedDispatch(ctx, &transport.Link{}, net.TCPDestination(net.ParseAddress("198.51.100.40"), 443))

	if !fw.evaluateCalled {
		t.Fatal("expected firewall Evaluate to be called")
	}
	if !router.picked {
		t.Fatal("expected route to be picked before firewall evaluation")
	}
	if handler.dispatchHit {
		t.Fatal("expected blocked connection not to reach outbound handler")
	}
}

type firewallOrderRecorder struct {
	routePicked    *bool
	expectedCtx    routing.Context
	evaluateCalled bool
}

func (m *firewallOrderRecorder) Type() interface{} { return feature_firewall.ManagerType() }
func (m *firewallOrderRecorder) Start() error      { return nil }
func (m *firewallOrderRecorder) Close() error      { return nil }
func (m *firewallOrderRecorder) Evaluate(_ context.Context, routingCtx routing.Context) feature_firewall.Decision {
	m.evaluateCalled = true
	if m.routePicked == nil || !*m.routePicked {
		panic("firewall evaluated before route pick")
	}
	if routingCtx != m.expectedCtx {
		panic("firewall did not receive picked route context")
	}
	return feature_firewall.Decision{
		Action:  feature_firewall.ActionBlock,
		RuleTag: "fw-after-route",
	}
}
func (m *firewallOrderRecorder) ShouldSniffProtocol(string) bool { return false }
func (m *firewallOrderRecorder) ShouldSniffProtocolForContext(string, routing.Context) bool {
	return false
}
func (m *firewallOrderRecorder) NewFlowObserver(context.Context, routing.Context, func(feature_firewall.Decision)) feature_firewall.FlowObserver {
	return nil
}
