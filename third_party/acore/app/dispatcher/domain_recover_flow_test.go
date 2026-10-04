package dispatcher

import (
	"context"
	stderrs "errors"
	"testing"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	core "github.com/ImAubrey/acore/core"
	feature_dns "github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/routing"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

type recoverDNSStub struct {
	domain  string
	hit     bool
	lookups int
}

func (s *recoverDNSStub) Type() interface{} { return feature_dns.ClientType() }
func (s *recoverDNSStub) Start() error      { return nil }
func (s *recoverDNSStub) Close() error      { return nil }

func (s *recoverDNSStub) LookupIP(string, feature_dns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, stderrs.New("not used in this test")
}

func (s *recoverDNSStub) LookupDomainByIP(ip net.IP) (string, bool) {
	if len(ip) > 0 {
		s.lookups++
	}
	return s.domain, s.hit
}

func (s *recoverDNSStub) LookupCount() int { return s.lookups }

type recoverRouterStub struct {
	route routing.Route
	mode  string
}

func (r *recoverRouterStub) Type() interface{} { return routing.RouterType() }
func (r *recoverRouterStub) Start() error      { return nil }
func (r *recoverRouterStub) Close() error      { return nil }

func (r *recoverRouterStub) PickRoute(ctx routing.Context) (routing.Route, error) {
	if r.route != nil {
		return r.route, nil
	}
	return nil, stderrs.New("no route")
}

func (r *recoverRouterStub) AddRule(*serial.TypedMessage, bool) error { return nil }
func (r *recoverRouterStub) RemoveRule(string) error                  { return nil }

func (r *recoverRouterStub) DomainRecoverMode() string { return r.mode }

func TestApplyDomainRecoverSnifferFirstFallbackToDNSCache(t *testing.T) {
	dnsStub := &recoverDNSStub{
		domain: "cached.example",
		hit:    true,
	}
	d := &DefaultDispatcher{
		router: &recoverRouterStub{mode: "snifferfirst"},
		dns:    dnsStub,
	}

	ob := &session.Outbound{}
	origin := net.TCPDestination(net.ParseAddress("203.0.113.7"), 443)
	d.applyDomainRecover(ob, origin, nil, stderrs.New("sniff failed"), nil)

	if got := dnsStub.LookupCount(); got != 1 {
		t.Fatalf("expected 1 DNS reverse lookup, got %d", got)
	}
	if !ob.RouteTarget.IsValid() {
		t.Fatalf("expected RouteTarget to be set")
	}
	if !ob.RouteTarget.Address.Family().IsDomain() {
		t.Fatalf("expected RouteTarget to be domain, got %v", ob.RouteTarget)
	}
	if ob.RouteTarget.Address.Domain() != "cached.example" {
		t.Fatalf("expected RouteTarget domain cached.example, got %s", ob.RouteTarget.Address.Domain())
	}
}

func TestApplyDomainRecoverSnifferFirstSkipsWhenDomainAlreadyPresent(t *testing.T) {
	dnsStub := &recoverDNSStub{
		domain: "cached.example",
		hit:    true,
	}
	d := &DefaultDispatcher{
		router: &recoverRouterStub{mode: "snifferfirst"},
		dns:    dnsStub,
	}

	ob := &session.Outbound{
		RouteTarget: net.TCPDestination(net.DomainAddress("sni.example"), 443),
	}
	origin := net.TCPDestination(net.ParseAddress("203.0.113.99"), 443)
	d.applyDomainRecover(ob, origin, nil, nil, nil)

	if got := dnsStub.LookupCount(); got != 0 {
		t.Fatalf("expected no DNS reverse lookup when route already has domain, got %d", got)
	}
	if got := ob.RouteTarget.Address.Domain(); got != "sni.example" {
		t.Fatalf("expected RouteTarget domain unchanged, got %s", got)
	}
}

func TestDispatchLinkRunsDomainRecoverWhenSniffingDisabled(t *testing.T) {
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("203.0.113.8"), 443),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled: false,
		},
	})

	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "direct",
	}
	handler := &stubHandler{tag: "direct"}
	dnsStub := &recoverDNSStub{domain: "cached.example", hit: true}
	d := &DefaultDispatcher{
		ohm:    &stubManager{handler: handler},
		router: &recoverRouterStub{route: route, mode: "snifferfirst"},
		dns:    dnsStub,
	}

	reader, writer := pipe.New()
	if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
		Reader: reader,
		Writer: writer,
	}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	if got := dnsStub.LookupCount(); got != 1 {
		t.Fatalf("expected DNS reverse lookup to run when sniffing is disabled, got %d", got)
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if !handler.gotRoute.IsValid() || !handler.gotRoute.Address.Family().IsDomain() {
		t.Fatalf("expected RouteTarget domain from DNS cache, got %v", handler.gotRoute)
	}
	if got := handler.gotRoute.Address.Domain(); got != "cached.example" {
		t.Fatalf("expected RouteTarget domain cached.example, got %s", got)
	}
}

func TestDispatchLinkRunsDomainRecoverWhenSniffingEnabled(t *testing.T) {
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("203.0.113.9"), 443),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	v, _ := core.New(&core.Config{})
	ctx = context.WithValue(ctx, acoreKey, v)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: true,
		},
	})

	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "direct",
	}
	handler := &stubHandler{tag: "direct"}
	dnsStub := &recoverDNSStub{domain: "cached.example", hit: true}
	d := &DefaultDispatcher{
		ohm:    &stubManager{handler: handler},
		router: &recoverRouterStub{route: route, mode: "snifferfirst"},
		dns:    dnsStub,
	}

	reader, _ := pipe.New()
	if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
		Reader: reader,
		Writer: noopWriter{},
	}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	if got := dnsStub.LookupCount(); got == 0 {
		t.Fatalf("expected DNS reverse lookup to run when sniffing is enabled")
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if !handler.gotRoute.IsValid() || !handler.gotRoute.Address.Family().IsDomain() {
		t.Fatalf("expected RouteTarget domain from DNS cache, got %v", handler.gotRoute)
	}
	if handler.gotRoute.Address.Domain() != "cached.example" {
		t.Fatalf("expected RouteTarget domain cached.example, got %s", handler.gotRoute.Address.Domain())
	}
}
