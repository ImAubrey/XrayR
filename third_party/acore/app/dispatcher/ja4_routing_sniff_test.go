package dispatcher

import (
	"context"
	"testing"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	core "github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/routing"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

func buildTLSClientHelloForDispatcherJA4Test() []byte {
	handshake := []byte{
		0x01, 0x00, 0x00, 0x2b, // Handshake: ClientHello, length=43
		0x03, 0x03, // legacy_version
	}
	handshake = append(handshake, make([]byte, 32)...) // random
	handshake = append(handshake,
		0x00,       // session_id_len
		0x00, 0x02, // cipher_suites_len
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01,       // compression_methods_len
		0x00,       // compression_method: null
		0x00, 0x00, // extensions_len
	)
	record := []byte{
		0x16, 0x03, 0x01, 0x00, byte(len(handshake)),
	}
	return append(record, handshake...)
}

func TestShouldEnableJA4Sniffer(t *testing.T) {
	if shouldEnableJA4Sniffer(context.Background()) {
		t.Fatal("expected ja4 sniffer disabled by default")
	}
	ctx := context.WithValue(context.Background(), ja4SniffingEnabledKey{}, true)
	if !shouldEnableJA4Sniffer(ctx) {
		t.Fatal("expected ja4 sniffer enabled when context key is set")
	}
}

func TestShouldEnableProtocolSniffingJA4IgnoresContextDecider(t *testing.T) {
	d := &DefaultDispatcher{
		router: &stubRouter{
			sniffProtocols: map[string]bool{
				"ja4": true,
			},
			sniffDecider: func(protocol string, _ routing.Context) bool {
				return false
			},
		},
	}
	if !d.shouldEnableProtocolSniffingWithRoutingContext(context.Background(), nil, "ja4") {
		t.Fatal("expected ja4 sniffing to be enabled by rule presence even when context decider returns false")
	}
}

func TestForceSniffingConfigPublishesTLSWhenJA4Forced(t *testing.T) {
	c := forceSniffingConfig{ja4: true}
	if !c.shouldPublishProtocol(false, "tls") {
		t.Fatal("expected forced ja4 sniffing to publish tls protocol")
	}
}

func TestForceSniffingConfigPublishesQUICWhenJA4Forced(t *testing.T) {
	c := forceSniffingConfig{ja4: true}
	if !c.shouldPublishProtocol(false, "quic") {
		t.Fatal("expected forced ja4 sniffing to publish quic protocol")
	}
}

func TestSniffTLSRespectsJA4SniffingContext(t *testing.T) {
	packet := buildTLSClientHelloForDispatcherJA4Test()

	resultDisabled, err := sniffTLS(context.Background(), packet)
	if err != nil {
		t.Fatalf("sniffTLS() with ja4 disabled error: %v", err)
	}
	fpDisabled, ok := resultDisabled.(interface{ JA4() string })
	if !ok {
		t.Fatal("expected sniff result to expose JA4()")
	}
	if got := fpDisabled.JA4(); got != "" {
		t.Fatalf("expected empty JA4 when disabled, got %q", got)
	}

	ctx := context.WithValue(context.Background(), ja4SniffingEnabledKey{}, true)
	resultEnabled, err := sniffTLS(ctx, packet)
	if err != nil {
		t.Fatalf("sniffTLS() with ja4 enabled error: %v", err)
	}
	fpEnabled, ok := resultEnabled.(interface{ JA4() string })
	if !ok {
		t.Fatal("expected sniff result to expose JA4()")
	}
	if got := fpEnabled.JA4(); got == "" {
		t.Fatal("expected non-empty JA4 when enabled")
	}
}

func TestDispatchLinkSetsJA4AttributeWhenRoutingRequestsJA4(t *testing.T) {
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
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
		outboundTag: "tls-out",
		ruleTag:     "ja4-rule",
	}
	handler := &stubHandler{tag: "tls-out"}
	d := &DefaultDispatcher{
		ohm: &stubManager{handler: handler},
		router: &stubRouter{
			route: route,
			sniffProtocols: map[string]bool{
				"ja4": true,
			},
		},
	}

	reader, writer := pipe.New()
	packet := buildTLSClientHelloForDispatcherJA4Test()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(packet)}); err != nil {
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
	if handler.gotJA4 == "" {
		t.Fatal("expected ja4 attribute to be populated when routing requests ja4")
	}
}

func TestDispatchLinkSkipsJA4AttributeWithoutRoutingHint(t *testing.T) {
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	v, _ := core.New(&core.Config{})
	ctx = context.WithValue(ctx, acoreKey, v)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled: true,
		},
	})

	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "tls-out",
		ruleTag:     "tls-rule",
	}
	handler := &stubHandler{tag: "tls-out"}
	d := &DefaultDispatcher{
		ohm: &stubManager{handler: handler},
		router: &stubRouter{
			route: route,
		},
	}

	reader, writer := pipe.New()
	packet := buildTLSClientHelloForDispatcherJA4Test()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(packet)}); err != nil {
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
	if handler.gotJA4 != "" {
		t.Fatalf("expected empty ja4 attribute without routing hint, got %q", handler.gotJA4)
	}
}

func TestDispatchLinkAutoSetsJA4TagWithTriggerOnlyRule(t *testing.T) {
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
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
		outboundTag: "tls-out",
		ruleTag:     "catch-all",
	}
	handler := &stubHandler{tag: "tls-out"}
	d := &DefaultDispatcher{
		ohm: &stubManager{handler: handler},
		router: &stubRouter{
			route: route,
			sniffProtocols: map[string]bool{
				"ja4": true,
			},
			ja4Lookup: func(string) string { return "source:ja4db" },
		},
	}

	reader, writer := pipe.New()
	packet := buildTLSClientHelloForDispatcherJA4Test()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(packet)}); err != nil {
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
	if handler.gotJA4 == "" {
		t.Fatal("expected ja4 attribute to be populated")
	}
	if handler.gotJA4Tag != "source:ja4db" {
		t.Fatalf("expected ja4_tag to be auto-resolved, got %q", handler.gotJA4Tag)
	}
}
