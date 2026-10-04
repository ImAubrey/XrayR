package outbound

import (
	"context"
	"testing"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/proxy/freedom"
)

func TestTransparentFreedomUDPReusesInboundSourcePort(t *testing.T) {
	h := &Handler{proxyConfig: &freedom.Config{}}
	ob := &session.Outbound{
		Target: net.UDPDestination(net.ParseAddress("203.0.113.10"), 443),
	}
	inbound := &session.Inbound{
		Transparent: true,
		Source:      net.UDPDestination(net.ParseAddress("192.0.2.10"), 34567),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	h.setTransparentGateway(ctx, []*session.Outbound{ob})

	if ob.Gateway == nil {
		t.Fatal("expected transparent UDP to keep an IPv4 gateway hint")
	}
	if !ob.Gateway.Family().IsIPv4() || !ob.Gateway.IP().IsUnspecified() {
		t.Fatalf("unexpected UDP gateway: %v", ob.Gateway)
	}
	if ob.GatewayPort != inbound.Source.Port {
		t.Fatalf("UDP should reuse inbound source port, got %d want %d", ob.GatewayPort, inbound.Source.Port)
	}
}

func TestTransparentFreedomTCPReusesInboundSourcePort(t *testing.T) {
	h := &Handler{proxyConfig: &freedom.Config{}}
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("203.0.113.10"), 443),
	}
	inbound := &session.Inbound{
		Transparent: true,
		Source:      net.TCPDestination(net.ParseAddress("192.0.2.10"), 34567),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	h.setTransparentGateway(ctx, []*session.Outbound{ob})

	if ob.Gateway == nil {
		t.Fatal("expected transparent TCP to keep an IPv4 gateway hint")
	}
	if !ob.Gateway.Family().IsIPv4() || !ob.Gateway.IP().IsUnspecified() {
		t.Fatalf("unexpected TCP gateway: %v", ob.Gateway)
	}
	if ob.GatewayPort != inbound.Source.Port {
		t.Fatalf("TCP should reuse inbound source port, got %d want %d", ob.GatewayPort, inbound.Source.Port)
	}
}
