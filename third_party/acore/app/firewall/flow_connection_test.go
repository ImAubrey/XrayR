package firewall

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"

	routerapp "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	xnet "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	feature_firewall "github.com/ImAubrey/acore/features/firewall"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	shadowocksproxy "github.com/ImAubrey/acore/proxy/shadowsocks"
)

func mustShadowsocksUser(t *testing.T) *protocol.MemoryUser {
	t.Helper()
	account, err := (&shadowocksproxy.Account{
		Password:   "firewall-ss-test",
		CipherType: shadowocksproxy.CipherType_AES_128_GCM,
	}).AsAccount()
	if err != nil {
		t.Fatalf("AsAccount() error = %v", err)
	}
	return &protocol.MemoryUser{
		Email:   "firewall-ss@example.com",
		Account: account,
	}
}

func buildDetectableShadowsocksPayload(t *testing.T) []byte {
	t.Helper()

	request := &protocol.RequestHeader{
		Version: shadowocksproxy.Version,
		Command: protocol.RequestCommandTCP,
		Address: xnet.ParseAddress("198.51.100.31"),
		Port:    8388,
		User:    mustShadowsocksUser(t),
	}
	for attempt := 0; attempt < 128; attempt++ {
		var wire bytes.Buffer
		writer, err := shadowocksproxy.WriteTCPRequest(request, &wire)
		if err != nil {
			t.Fatalf("WriteTCPRequest() error = %v", err)
		}
		payload := buf.New()
		common.Must2(payload.WriteString("live shadowsocks payload"))
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			t.Fatalf("WriteMultiBuffer() error = %v", err)
		}
		encoded := append([]byte(nil), wire.Bytes()...)
		if len(encoded) >= 32 && !looksLikeCommonTLSOrHTTP(encoded) && looksLikeShadowsocksFirstPayload(encoded) {
			return encoded
		}
	}
	t.Fatal("failed to generate a detectable shadowsocks payload")
	return nil
}

func newConnectionFlowObserverForTest(t *testing.T, protocol string, sourceIP string, destinationIP string, destinationPort xnet.Port) (feature_firewall.FlowObserver, conntrack.Connection, *[]feature_firewall.Decision) {
	t.Helper()

	mgr := conntrack.NewManager()
	current := mgr.NewConnection(conntrack.Meta{
		Source:      xnet.TCPDestination(xnet.ParseAddress(sourceIP), 12001),
		Destination: xnet.TCPDestination(xnet.ParseAddress(destinationIP), destinationPort),
		Target:      xnet.TCPDestination(xnet.ParseAddress(destinationIP), destinationPort),
	})

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:    "flow-test",
					InboundTag: []string{"socks"},
					Protocol:   []string{protocol},
				},
				Action: Rule_Block,
			},
		},
	}, mgr); err != nil {
		current.Close()
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress(sourceIP), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         xnet.TCPDestination(xnet.ParseAddress(destinationIP), destinationPort),
		OriginalTarget: xnet.TCPDestination(xnet.ParseAddress(destinationIP), destinationPort),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	decisions := make([]feature_firewall.Decision, 0, 1)
	observer := fw.NewFlowObserver(ctx, routing_session.AsRoutingContext(ctx), func(decision feature_firewall.Decision) {
		decisions = append(decisions, decision)
	})
	if observer == nil {
		current.Close()
		t.Fatal("expected flow observer")
	}

	return observer, current, &decisions
}

func writeObserved(conn stdnet.Conn, observer feature_firewall.FlowObserver, payload []byte) error {
	n, err := conn.Write(payload)
	if n > 0 && observer != nil {
		observer.OnUpload(payload[:n])
	}
	if err != nil && observer != nil {
		observer.OnClose(err)
	}
	return err
}

func readObserved(conn stdnet.Conn, observer feature_firewall.FlowObserver, size int) error {
	buf := make([]byte, size)
	n, err := io.ReadFull(conn, buf)
	if n > 0 && observer != nil {
		observer.OnDownload(buf[:n])
	}
	if err != nil && observer != nil {
		observer.OnClose(err)
	}
	return err
}

func TestFlowObserverDetectsShadowsocksTCPConnection(t *testing.T) {
	observer, current, decisions := newConnectionFlowObserverForTest(t, flowProtocolShadowsocks, "203.0.113.31", "198.51.100.31", 8388)
	defer current.Close()

	client, server := stdnet.Pipe()
	defer client.Close()
	defer server.Close()

	encoded := buildDetectableShadowsocksPayload(t)

	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, make([]byte, len(encoded)))
		readDone <- err
	}()

	if err := writeObserved(client, observer, encoded); err != nil {
		t.Fatalf("writeObserved() error = %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("server ReadFull() error = %v", err)
	}

	if len(*decisions) != 1 {
		t.Fatalf("decision count = %d, want 1", len(*decisions))
	}
	if (*decisions)[0].Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", (*decisions)[0].Action)
	}
	if current.Snapshot().Protocol != flowProtocolShadowsocks {
		t.Fatalf("protocol = %q, want %q", current.Snapshot().Protocol, flowProtocolShadowsocks)
	}
}

func TestFlowObserverDetectsTrojanTLSInTLSConnection(t *testing.T) {
	observer, current, decisions := newConnectionFlowObserverForTest(t, flowProtocolTrojanTLSInTLS, "203.0.113.30", "198.51.100.30", 443)
	defer current.Close()

	client, server := stdnet.Pipe()
	defer client.Close()
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		if _, err := io.ReadFull(server, make([]byte, len(trojanTLSCCSRecord))); err != nil {
			serverDone <- err
			return
		}
		if _, err := io.ReadFull(server, make([]byte, 694)); err != nil {
			serverDone <- err
			return
		}
		if _, err := server.Write(make([]byte, 175)); err != nil {
			serverDone <- err
			return
		}
		if _, err := io.ReadFull(server, make([]byte, 1)); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	if err := writeObserved(client, observer, append([]byte(nil), trojanTLSCCSRecord...)); err != nil {
		t.Fatalf("first writeObserved() error = %v", err)
	}
	if err := writeObserved(client, observer, make([]byte, 694)); err != nil {
		t.Fatalf("second writeObserved() error = %v", err)
	}
	if err := readObserved(client, observer, 175); err != nil {
		t.Fatalf("readObserved() error = %v", err)
	}
	if err := writeObserved(client, observer, []byte{0x01}); err != nil {
		t.Fatalf("final writeObserved() error = %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server sequence error = %v", err)
	}

	if len(*decisions) != 1 {
		t.Fatalf("decision count = %d, want 1", len(*decisions))
	}
	if (*decisions)[0].Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", (*decisions)[0].Action)
	}
	if current.Snapshot().Protocol != flowProtocolTrojanTLSInTLS {
		t.Fatalf("protocol = %q, want %q", current.Snapshot().Protocol, flowProtocolTrojanTLSInTLS)
	}
}

func TestFlowObserverDetectsTrojanTLSInTLSConnectionOnClose(t *testing.T) {
	observer, current, decisions := newConnectionFlowObserverForTest(t, flowProtocolTrojanTLSInTLS, "203.0.113.36", "198.51.100.36", 443)
	defer current.Close()

	observer.OnUpload(append([]byte(nil), trojanTLSCCSRecord...))
	observer.OnUpload(make([]byte, 694))
	observer.OnDownload(make([]byte, 175))
	observer.OnClose(io.EOF)

	if len(*decisions) != 1 {
		t.Fatalf("decision count = %d, want 1", len(*decisions))
	}
	if (*decisions)[0].Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", (*decisions)[0].Action)
	}
	if current.Snapshot().Protocol != flowProtocolTrojanTLSInTLS {
		t.Fatalf("protocol = %q, want %q", current.Snapshot().Protocol, flowProtocolTrojanTLSInTLS)
	}
}

func TestFlowObserverDetectsTrojanTLSInTLSConnectionAfterOuterTLSHandshake(t *testing.T) {
	mgr := conntrack.NewManager()
	current := mgr.NewConnection(conntrack.Meta{
		Source:      xnet.TCPDestination(xnet.ParseAddress("203.0.113.32"), 12001),
		Destination: xnet.TCPDestination(xnet.ParseAddress("141.11.240.200"), 45654),
		Target:      xnet.TCPDestination(xnet.ParseAddress("141.11.240.200"), 45654),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:  "trojan-flow-only",
					Protocol: []string{flowProtocolTrojanTLSInTLS},
				},
				Action: Rule_Block,
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.32"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         xnet.TCPDestination(xnet.ParseAddress("141.11.240.200"), 45654),
		OriginalTarget: xnet.TCPDestination(xnet.ParseAddress("141.11.240.200"), 45654),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	decisions := make([]feature_firewall.Decision, 0, 1)
	observer := fw.NewFlowObserver(ctx, routing_session.AsRoutingContext(ctx), func(decision feature_firewall.Decision) {
		decisions = append(decisions, decision)
	})
	if observer == nil {
		t.Fatal("expected flow observer for protocol-only flow rule")
	}

	outerClientHello := make([]byte, 1755)
	copy(outerClientHello, []byte{0x16, 0x03, 0x01, 0x06, 0xd6})

	outerServerFlight := make([]byte, 3114)
	copy(outerServerFlight, []byte{0x16, 0x03, 0x03, 0x00, 0x7a})

	postHandshakeFlightPart1 := make([]byte, 64)
	copy(postHandshakeFlightPart1, []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03})

	postHandshakeFlightPart2 := make([]byte, 556)
	copy(postHandshakeFlightPart2, []byte{0x17, 0x03, 0x03, 0x02, 0x27})

	serverResponseFlight := make([]byte, 3453)
	copy(serverResponseFlight, []byte{0x17, 0x03, 0x03, 0x04, 0xb3})

	observer.OnUpload(outerClientHello)
	observer.OnDownload(outerServerFlight)
	observer.OnUpload(postHandshakeFlightPart1)
	observer.OnUpload(postHandshakeFlightPart2)
	observer.OnDownload(serverResponseFlight)
	observer.OnUpload(make([]byte, 102))

	if len(decisions) != 1 {
		t.Fatalf("decision count = %d, want 1", len(decisions))
	}
	if decisions[0].Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", decisions[0].Action)
	}
	if current.Snapshot().Protocol != flowProtocolTrojanTLSInTLS {
		t.Fatalf("protocol = %q, want %q", current.Snapshot().Protocol, flowProtocolTrojanTLSInTLS)
	}
}

func TestFlowObserverCloneKeepsDialAttemptsIsolated(t *testing.T) {
	mgr := conntrack.NewManager()
	current := mgr.NewConnection(conntrack.Meta{
		Source:      xnet.TCPDestination(xnet.ParseAddress("203.0.113.33"), 12001),
		Destination: xnet.TCPDestination(xnet.ParseAddress("141.11.240.200"), 45654),
		Target:      xnet.TCPDestination(xnet.ParseAddress("141.11.240.200"), 45654),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:  "trojan-flow-only",
					Protocol: []string{flowProtocolTrojanTLSInTLS},
				},
				Action: Rule_Block,
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.33"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         xnet.TCPDestination(xnet.ParseAddress("141.11.240.200"), 45654),
		OriginalTarget: xnet.TCPDestination(xnet.ParseAddress("141.11.240.200"), 45654),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	decisions := make([]feature_firewall.Decision, 0, 1)
	prototype := fw.NewFlowObserver(ctx, routing_session.AsRoutingContext(ctx), func(decision feature_firewall.Decision) {
		decisions = append(decisions, decision)
	})
	if prototype == nil {
		t.Fatal("expected flow observer")
	}
	cloner, ok := prototype.(feature_firewall.FlowObserverCloner)
	if !ok {
		t.Fatal("expected cloneable flow observer")
	}

	outerClientHello := make([]byte, 1755)
	copy(outerClientHello, []byte{0x16, 0x03, 0x01, 0x06, 0xd6})

	outerServerFlight := make([]byte, 3114)
	copy(outerServerFlight, []byte{0x16, 0x03, 0x03, 0x00, 0x7a})

	postHandshakeFlightPart1 := make([]byte, 64)
	copy(postHandshakeFlightPart1, []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03})

	postHandshakeFlightPart2 := make([]byte, 556)
	copy(postHandshakeFlightPart2, []byte{0x17, 0x03, 0x03, 0x02, 0x27})

	serverResponseFlight := make([]byte, 3453)
	copy(serverResponseFlight, []byte{0x17, 0x03, 0x03, 0x04, 0xb3})

	firstDial := cloner.CloneFlowObserver()
	secondDial := cloner.CloneFlowObserver()
	if firstDial == nil || secondDial == nil {
		t.Fatal("expected cloned flow observers")
	}

	firstDial.OnUpload(outerClientHello)
	firstDial.OnDownload(outerServerFlight)
	firstDial.OnUpload(postHandshakeFlightPart1)
	secondDial.OnUpload(postHandshakeFlightPart2)
	secondDial.OnDownload(serverResponseFlight)
	secondDial.OnUpload(make([]byte, 102))

	if len(decisions) != 0 {
		t.Fatalf("decision count = %d, want 0", len(decisions))
	}

	firstDial.OnUpload(postHandshakeFlightPart1)
	firstDial.OnUpload(postHandshakeFlightPart2)
	firstDial.OnDownload(serverResponseFlight)
	firstDial.OnUpload(make([]byte, 102))

	if len(decisions) != 1 {
		t.Fatalf("decision count = %d, want 1", len(decisions))
	}
	if decisions[0].Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", decisions[0].Action)
	}
}

func TestShadowsocksFlowDetectorMatchesEncryptedUpload(t *testing.T) {
	detector := newShadowsocksDetector()
	if !detector.OnUpload(buildDetectableShadowsocksPayload(t)) {
		t.Fatal("expected encrypted shadowsocks upload to trigger shadowsocks detector")
	}
}

func TestFlowObserverSkipsShadowsocksWhenRoutingAlreadySniffed(t *testing.T) {
	mgr := conntrack.NewManager()
	current := mgr.NewConnection(conntrack.Meta{
		Source:      xnet.TCPDestination(xnet.ParseAddress("203.0.113.34"), 12001),
		Destination: xnet.TCPDestination(xnet.ParseAddress("198.51.100.34"), 443),
		Target:      xnet.TCPDestination(xnet.ParseAddress("198.51.100.34"), 443),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:  "ss-flow-only",
					Protocol: []string{flowProtocolShadowsocks},
				},
				Action: Rule_Block,
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("203.0.113.34"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         xnet.TCPDestination(xnet.ParseAddress("198.51.100.34"), 443),
		OriginalTarget: xnet.TCPDestination(xnet.ParseAddress("198.51.100.34"), 443),
	}})
	ctx = session.ContextWithContent(ctx, &session.Content{
		Protocol: "tls",
		Attributes: map[string]string{
			"alpn":    "h2",
			"tls_sni": "1",
		},
	})
	ctx = conntrack.ContextWithConnection(ctx, current)

	observer := fw.NewFlowObserver(ctx, routing_session.AsRoutingContext(ctx), func(feature_firewall.Decision) {})
	if observer != nil {
		t.Fatal("expected no shadowsocks flow observer when routing already identified TLS metadata")
	}
}

func TestFlowObserverSkipsShadowsocksForNonTCP(t *testing.T) {
	mgr := conntrack.NewManager()
	current := mgr.NewConnection(conntrack.Meta{
		Source:      xnet.UDPDestination(xnet.ParseAddress("203.0.113.35"), 12001),
		Destination: xnet.UDPDestination(xnet.ParseAddress("198.51.100.35"), 8388),
		Target:      xnet.UDPDestination(xnet.ParseAddress("198.51.100.35"), 8388),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:  "ss-flow-only",
					Protocol: []string{flowProtocolShadowsocks},
				},
				Action: Rule_Block,
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: xnet.UDPDestination(xnet.ParseAddress("203.0.113.35"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         xnet.UDPDestination(xnet.ParseAddress("198.51.100.35"), 8388),
		OriginalTarget: xnet.UDPDestination(xnet.ParseAddress("198.51.100.35"), 8388),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	observer := fw.NewFlowObserver(ctx, routing_session.AsRoutingContext(ctx), func(feature_firewall.Decision) {})
	if observer != nil {
		t.Fatal("expected no shadowsocks flow observer for non-TCP routing context")
	}
}
