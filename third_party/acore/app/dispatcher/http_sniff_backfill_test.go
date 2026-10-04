package dispatcher

import (
	"context"
	"testing"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	core "github.com/ImAubrey/acore/core"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

func TestDispatchLinkHTTPHostBackfillsTargetDomain(t *testing.T) {
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 80),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	v, _ := core.New(&core.Config{})
	ctx = context.WithValue(ctx, acoreKey, v)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:                        true,
			OverrideDestinationForProtocol: []string{"http"},
		},
	})

	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "direct",
	}
	handler := &stubHandler{tag: "direct"}
	d := &DefaultDispatcher{
		ohm:    &stubManager{handler: handler},
		router: &stubRouter{route: route},
	}

	reader, writer := pipe.New()
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, req)); err != nil {
		t.Fatalf("failed to write test request: %v", err)
	}

	if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
		Reader: reader,
		Writer: noopWriter{},
	}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if !handler.gotTarget.IsValid() || !handler.gotTarget.Address.Family().IsDomain() {
		t.Fatalf("expected Target to be domain after HTTP host sniff, got %v", handler.gotTarget)
	}
	if got := handler.gotTarget.Address.Domain(); got != "example.com" {
		t.Fatalf("expected Target domain example.com, got %q", got)
	}
}

func TestDispatchLinkHTTPHostBackfillsRouteTargetWhenRouteOnly(t *testing.T) {
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 80),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	v, _ := core.New(&core.Config{})
	ctx = context.WithValue(ctx, acoreKey, v)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:                        true,
			RouteOnly:                      true,
			OverrideDestinationForProtocol: []string{"http"},
		},
	})

	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "direct",
	}
	handler := &stubHandler{tag: "direct"}
	d := &DefaultDispatcher{
		ohm:    &stubManager{handler: handler},
		router: &stubRouter{route: route},
	}

	reader, writer := pipe.New()
	req := []byte("GET / HTTP/1.1\r\nHost: route-only.example\r\n\r\n")
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, req)); err != nil {
		t.Fatalf("failed to write test request: %v", err)
	}

	if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
		Reader: reader,
		Writer: noopWriter{},
	}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if !handler.gotRoute.IsValid() || !handler.gotRoute.Address.Family().IsDomain() {
		t.Fatalf("expected RouteTarget to be domain when routeOnly=true, got %v", handler.gotRoute)
	}
	if got := handler.gotRoute.Address.Domain(); got != "route-only.example" {
		t.Fatalf("expected RouteTarget domain route-only.example, got %q", got)
	}
	if !handler.gotTarget.IsValid() || !handler.gotTarget.Address.Family().IsIP() {
		t.Fatalf("expected Target to remain IP when routeOnly=true, got %v", handler.gotTarget)
	}
}
