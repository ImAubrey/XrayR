package firewall

import (
	"context"
	"testing"
	"time"

	routerapp "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	feature_firewall "github.com/ImAubrey/acore/features/firewall"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
)

func testGeoIPCIDRs(ip []byte, prefix uint32) []*routerapp.GeoIP {
	return []*routerapp.GeoIP{{
		Cidr: []*routerapp.CIDR{{
			Ip:     append([]byte(nil), ip...),
			Prefix: prefix,
		}},
	}}
}

func TestFirewallBlocksWhenSourceIPLimitExceeded(t *testing.T) {
	mgr := conntrack.NewManager()
	mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12000),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	})
	current := mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.3"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.3"), 443),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:    "src-limit",
					InboundTag: []string{"socks"},
				},
				Action: Rule_Limit,
				Limit: &ConnectionLimit{
					Key:            ConnectionLimit_SrcIp,
					MaxConnections: 1,
				},
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.10"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         net.TCPDestination(net.ParseAddress("198.51.100.3"), 443),
		OriginalTarget: net.TCPDestination(net.ParseAddress("198.51.100.3"), 443),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	decision := fw.Evaluate(ctx, routing_session.AsRoutingContext(ctx))
	if decision.Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", decision.Action)
	}
	if decision.RuleTag != "src-limit" {
		t.Fatalf("rule tag = %q, want src-limit", decision.RuleTag)
	}
	if decision.Count != 2 {
		t.Fatalf("counter count = %d, want 2", decision.Count)
	}
	if decision.SourceIP != "203.0.113.10" {
		t.Fatalf("source ip = %q, want 203.0.113.10", decision.SourceIP)
	}
}

func TestFirewallBlocksWhenDestinationIPLimitExceeded(t *testing.T) {
	mgr := conntrack.NewManager()
	mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12000),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.8"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.8"), 443),
	})
	current := mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.11"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.8"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.8"), 443),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:    "dst-limit",
					InboundTag: []string{"socks"},
				},
				Action: Rule_Limit,
				Limit: &ConnectionLimit{
					Key:            ConnectionLimit_DstIp,
					MaxConnections: 1,
				},
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.11"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         net.TCPDestination(net.ParseAddress("198.51.100.8"), 443),
		OriginalTarget: net.TCPDestination(net.ParseAddress("198.51.100.8"), 443),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	decision := fw.Evaluate(ctx, routing_session.AsRoutingContext(ctx))
	if decision.Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", decision.Action)
	}
	if decision.RuleTag != "dst-limit" {
		t.Fatalf("rule tag = %q, want dst-limit", decision.RuleTag)
	}
	if decision.Count != 2 {
		t.Fatalf("counter count = %d, want 2", decision.Count)
	}
	if decision.DestinationIP != "198.51.100.8" {
		t.Fatalf("destination ip = %q, want 198.51.100.8", decision.DestinationIP)
	}
}

func TestFirewallBlocksWhenNewSourceIPLimitExceeded(t *testing.T) {
	mgr := conntrack.NewManager()
	mgr.NewConnection(conntrack.Meta{
		Start:       time.Now().Add(-10 * time.Second),
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.15"), 12000),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.5"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.5"), 443),
	})
	current := mgr.NewConnection(conntrack.Meta{
		Start:       time.Now().Add(-5 * time.Second),
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.15"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.6"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.6"), 443),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:    "src-burst",
					InboundTag: []string{"socks"},
				},
				Action: Rule_Limit,
				Limit: &ConnectionLimit{
					Key:            ConnectionLimit_SrcIp,
					Mode:           ConnectionLimit_NewConnections,
					WindowSeconds:  30,
					MaxConnections: 1,
				},
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.15"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         net.TCPDestination(net.ParseAddress("198.51.100.6"), 443),
		OriginalTarget: net.TCPDestination(net.ParseAddress("198.51.100.6"), 443),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	decision := fw.Evaluate(ctx, routing_session.AsRoutingContext(ctx))
	if decision.Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", decision.Action)
	}
	if decision.CounterMode != conntrack.CounterModeNewConnections {
		t.Fatalf("counter mode = %v, want newConnections", decision.CounterMode)
	}
	if decision.Window != 30*time.Second {
		t.Fatalf("window = %v, want 30s", decision.Window)
	}
	if decision.Count != 2 {
		t.Fatalf("counter count = %d, want 2", decision.Count)
	}
}

func TestFirewallBlocksWhenSourcePrefixLimitExceeded(t *testing.T) {
	mgr := conntrack.NewManager()
	mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12000),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.5"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.5"), 443),
	})
	current := mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.55"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.6"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.6"), 443),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:     "src-prefix-limit",
					InboundTag:  []string{"socks"},
					SourceGeoip: testGeoIPCIDRs([]byte{203, 0, 113, 0}, 24),
				},
				Action: Rule_Limit,
				Limit: &ConnectionLimit{
					Key:            ConnectionLimit_SrcPrefix,
					MaxConnections: 1,
				},
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.55"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         net.TCPDestination(net.ParseAddress("198.51.100.6"), 443),
		OriginalTarget: net.TCPDestination(net.ParseAddress("198.51.100.6"), 443),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	decision := fw.Evaluate(ctx, routing_session.AsRoutingContext(ctx))
	if decision.Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", decision.Action)
	}
	if decision.SourcePrefix != "203.0.113.0/24" {
		t.Fatalf("source prefix = %q, want 203.0.113.0/24", decision.SourcePrefix)
	}
	if decision.Count != 2 {
		t.Fatalf("counter count = %d, want 2", decision.Count)
	}
}

func TestFirewallBlocksWhenDestinationPrefixLimitExceeded(t *testing.T) {
	mgr := conntrack.NewManager()
	mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12000),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.8"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.8"), 443),
	})
	current := mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.11"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.9"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.9"), 443),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:    "dst-prefix-limit",
					InboundTag: []string{"socks"},
					Geoip:      testGeoIPCIDRs([]byte{198, 51, 100, 0}, 24),
				},
				Action: Rule_Limit,
				Limit: &ConnectionLimit{
					Key:            ConnectionLimit_DstPrefix,
					MaxConnections: 1,
				},
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.11"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         net.TCPDestination(net.ParseAddress("198.51.100.9"), 443),
		OriginalTarget: net.TCPDestination(net.ParseAddress("198.51.100.9"), 443),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	decision := fw.Evaluate(ctx, routing_session.AsRoutingContext(ctx))
	if decision.Action != feature_firewall.ActionBlock {
		t.Fatalf("decision action = %v, want block", decision.Action)
	}
	if decision.DestinationPrefix != "198.51.100.0/24" {
		t.Fatalf("destination prefix = %q, want 198.51.100.0/24", decision.DestinationPrefix)
	}
	if decision.Count != 2 {
		t.Fatalf("counter count = %d, want 2", decision.Count)
	}
}

func TestFirewallFlowObserverBlocksTrojanTLSInTLS(t *testing.T) {
	mgr := conntrack.NewManager()
	current := mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.30"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.30"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.30"), 443),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:    "trojan-flow",
					InboundTag: []string{"socks"},
					Protocol:   []string{flowProtocolTrojanTLSInTLS},
				},
				Action: Rule_Block,
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.30"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         net.TCPDestination(net.ParseAddress("198.51.100.30"), 443),
		OriginalTarget: net.TCPDestination(net.ParseAddress("198.51.100.30"), 443),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	var decisions []feature_firewall.Decision
	observer := fw.NewFlowObserver(ctx, routing_session.AsRoutingContext(ctx), func(decision feature_firewall.Decision) {
		decisions = append(decisions, decision)
	})
	if observer == nil {
		t.Fatal("expected flow observer")
	}

	observer.OnUpload(append([]byte(nil), trojanTLSCCSRecord...))
	observer.OnUpload(make([]byte, 694))
	observer.OnDownload(make([]byte, 175))
	observer.OnUpload([]byte{0x01})

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

func TestFirewallFlowObserverBlocksShadowsocks(t *testing.T) {
	mgr := conntrack.NewManager()
	current := mgr.NewConnection(conntrack.Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.31"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.31"), 8388),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.31"), 8388),
	})
	defer current.Close()

	fw := &Firewall{}
	if err := fw.Init(&Config{
		Rule: []*Rule{
			{
				Match: &routerapp.RoutingRule{
					RuleTag:    "ss-flow",
					InboundTag: []string{"socks"},
					Protocol:   []string{flowProtocolShadowsocks},
				},
				Action: Rule_Block,
			},
		},
	}, mgr); err != nil {
		t.Fatalf("firewall init failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.31"), 12001),
		Tag:    "socks",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target:         net.TCPDestination(net.ParseAddress("198.51.100.31"), 8388),
		OriginalTarget: net.TCPDestination(net.ParseAddress("198.51.100.31"), 8388),
	}})
	ctx = conntrack.ContextWithConnection(ctx, current)

	payload := buildDetectableShadowsocksPayload(t)

	var decisions []feature_firewall.Decision
	observer := fw.NewFlowObserver(ctx, routing_session.AsRoutingContext(ctx), func(decision feature_firewall.Decision) {
		decisions = append(decisions, decision)
	})
	if observer == nil {
		t.Fatal("expected flow observer")
	}

	observer.OnUpload(payload)

	if len(decisions) != 1 {
		t.Fatalf("decision count = %d, want 1", len(decisions))
	}
	if decisions[0].RuleTag != "ss-flow" {
		t.Fatalf("rule tag = %q, want ss-flow", decisions[0].RuleTag)
	}
	if current.Snapshot().Protocol != flowProtocolShadowsocks {
		t.Fatalf("protocol = %q, want %q", current.Snapshot().Protocol, flowProtocolShadowsocks)
	}
}

func TestShadowsocksFlowDetectorIgnoresHTTP(t *testing.T) {
	detector := newShadowsocksDetector()
	if detector.OnUpload([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) {
		t.Fatal("expected HTTP payload not to trigger shadowsocks detector")
	}
}

func TestShadowsocksFlowDetectorIgnoresTLSApplicationData(t *testing.T) {
	detector := newShadowsocksDetector()
	payload := make([]byte, 64)
	copy(payload, []byte{0x17, 0x03, 0x03, 0x00, 0x3b})
	if detector.OnUpload(payload) {
		t.Fatal("expected TLS application data not to trigger shadowsocks detector")
	}
}
