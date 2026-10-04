package dispatcher

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	core "github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

const acoreKey core.AcoreKey = 1

type stubRoute struct {
	routing.Context
	outboundTag string
	ruleTag     string
	reLookup    bool
}

func (r *stubRoute) GetOutboundGroupTags() []string { return nil }
func (r *stubRoute) GetOutboundTag() string         { return r.outboundTag }
func (r *stubRoute) GetRuleTag() string             { return r.ruleTag }
func (r *stubRoute) ReLookup() bool                 { return r.reLookup }

type stubRouter struct {
	route          routing.Route
	sniffProtocols map[string]bool
	sniffDecider   func(protocol string, ctx routing.Context) bool
	ja4Lookup      func(string) string
}

func (r *stubRouter) Type() interface{} { return routing.RouterType() }
func (r *stubRouter) Start() error      { return nil }
func (r *stubRouter) Close() error      { return nil }
func (r *stubRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	return r.route, nil
}
func (r *stubRouter) AddRule(*serial.TypedMessage, bool) error { return nil }
func (r *stubRouter) RemoveRule(string) error                  { return nil }
func (r *stubRouter) ShouldSniffProtocol(protocol string) bool {
	if r == nil || r.sniffProtocols == nil {
		return false
	}
	return r.sniffProtocols[strings.ToLower(protocol)]
}
func (r *stubRouter) ShouldSniffProtocolForContext(protocol string, ctx routing.Context) bool {
	if r != nil && r.sniffDecider != nil {
		return r.sniffDecider(strings.ToLower(protocol), ctx)
	}
	return r.ShouldSniffProtocol(protocol)
}
func (r *stubRouter) LookupJA4Tag(fingerprint string) string {
	if r != nil && r.ja4Lookup != nil {
		return r.ja4Lookup(fingerprint)
	}
	return ""
}

type stubHandler struct {
	tag string
	mu  sync.Mutex

	gotTarget   net.Destination
	gotRoute    net.Destination
	gotReLookup bool
	gotProtocol string
	gotJA4      string
	gotJA4Tag   string
}

func (h *stubHandler) Tag() string                          { return h.tag }
func (h *stubHandler) Start() error                         { return nil }
func (h *stubHandler) Close() error                         { return nil }
func (h *stubHandler) SenderSettings() *serial.TypedMessage { return nil }
func (h *stubHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *stubHandler) Dispatch(ctx context.Context, link *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	content := session.ContentFromContext(ctx)
	h.mu.Lock()
	h.gotTarget = ob.Target
	h.gotRoute = ob.RouteTarget
	h.gotReLookup = ob.ReLookup
	if content != nil {
		h.gotProtocol = content.Protocol
		h.gotJA4 = content.Attribute("ja4")
		h.gotJA4Tag = content.Attribute("ja4_tag")
	}
	h.mu.Unlock()
}

type stubManager struct {
	handler outbound.Handler
}

func (m *stubManager) Type() interface{} { return outbound.ManagerType() }
func (m *stubManager) Start() error      { return nil }
func (m *stubManager) Close() error      { return nil }
func (m *stubManager) GetHandler(tag string) outbound.Handler {
	if m.handler != nil && m.handler.Tag() == tag {
		return m.handler
	}
	return nil
}
func (m *stubManager) GetDefaultHandler() outbound.Handler                { return m.handler }
func (m *stubManager) AddHandler(context.Context, outbound.Handler) error { return nil }
func (m *stubManager) RemoveHandler(context.Context, string) error        { return nil }
func (m *stubManager) ListHandlers(context.Context) []outbound.Handler    { return nil }

type noopWriter struct{}

func (noopWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func TestRoutedDispatchAppliesReLookup(t *testing.T) {
	ob := &session.Outbound{
		Target:      net.TCPDestination(net.ParseAddress("104.18.32.47"), 80),
		RouteTarget: net.TCPDestination(net.DomainAddress("chatgpt.com"), 80),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "nat-v6",
		ruleTag:     "local-out",
		reLookup:    true,
	}

	handler := &stubHandler{tag: "nat-v6"}
	d := &DefaultDispatcher{
		ohm:    &stubManager{handler: handler},
		router: &stubRouter{route: route},
	}

	reader, writer := pipe.New()
	link := &transport.Link{Reader: reader, Writer: writer}
	d.routedDispatch(ctx, link, ob.Target)

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if !handler.gotReLookup {
		t.Fatalf("expected ReLookup to be set on outbound")
	}
	if !handler.gotTarget.Address.Family().IsDomain() || handler.gotTarget.Address.Domain() != "chatgpt.com" {
		t.Fatalf("expected Target to be reLookup domain, got %v (routeTarget %v)", handler.gotTarget, handler.gotRoute)
	}
}

func TestDispatchLinkSniffWireGuardWithoutInboundSniffing(t *testing.T) {
	ob := &session.Outbound{
		Target: net.UDPDestination(net.ParseAddress("198.51.100.2"), 51820),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	v, _ := core.New(&core.Config{})
	ctx = context.WithValue(ctx, acoreKey, v)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled: false,
		},
	})

	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "wg-out",
		ruleTag:     "wg-rule",
	}
	handler := &stubHandler{tag: "wg-out"}
	d := &DefaultDispatcher{
		ohm: &stubManager{handler: handler},
		router: &stubRouter{
			route: route,
			sniffProtocols: map[string]bool{
				"wireguard": true,
			},
		},
	}

	reader, writer := pipe.New()
	packet := make([]byte, 64)
	packet[0] = 4 // WireGuard transport data message type in little-endian u32 format.
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, packet)); err != nil {
		t.Fatalf("failed to write test packet: %v", err)
	}

	if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
		Reader: reader,
		Writer: noopWriter{},
	}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.gotProtocol != "wireguard" {
		t.Fatalf("expected protocol wireguard, got %q", handler.gotProtocol)
	}
}

func TestDispatchLinkWireGuardSniffRequiresContextMatch(t *testing.T) {
	ob := &session.Outbound{
		Target: net.UDPDestination(net.ParseAddress("198.51.100.2"), 51820),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	v, _ := core.New(&core.Config{})
	ctx = context.WithValue(ctx, acoreKey, v)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled: false,
		},
	})

	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "wg-out",
		ruleTag:     "wg-rule",
	}
	handler := &stubHandler{tag: "wg-out"}
	d := &DefaultDispatcher{
		ohm: &stubManager{handler: handler},
		router: &stubRouter{
			route: route,
			sniffProtocols: map[string]bool{
				"wireguard": true,
			},
			sniffDecider: func(protocol string, ctx routing.Context) bool {
				return false
			},
		},
	}

	reader, writer := pipe.New()
	packet := make([]byte, 64)
	packet[0] = 4
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, packet)); err != nil {
		t.Fatalf("failed to write test packet: %v", err)
	}

	if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
		Reader: reader,
		Writer: noopWriter{},
	}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.gotProtocol != "" {
		t.Fatalf("expected empty protocol when context does not match, got %q", handler.gotProtocol)
	}
}
