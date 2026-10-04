package net

import (
	gonet "net"
	"testing"
)

func TestDestinationFromAddr_Nil_NoPanic(t *testing.T) {
	var a gonet.Addr
	d := DestinationFromAddr(a)
	if d.IsValid() {
		t.Fatalf("expected invalid destination for nil addr, got %v", d)
	}
}

func TestDestinationFromAddr_InvalidPort_DoesNotWrap(t *testing.T) {
	tcp := &gonet.TCPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: -1}
	d := DestinationFromAddr(tcp)
	if d.Port != 0 {
		t.Fatalf("expected port 0 for invalid TCP port, got %d", d.Port)
	}

	udp := &gonet.UDPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: 70000}
	d = DestinationFromAddr(udp)
	if d.Port != 0 {
		t.Fatalf("expected port 0 for invalid UDP port, got %d", d.Port)
	}
}

func TestEndpointAsDestination_InvalidPort_DoesNotWrap(t *testing.T) {
	ep := &Endpoint{
		Network: Network_TCP,
		Address: &IPOrDomain{
			Address: &IPOrDomain_Ip{
				Ip: []byte{127, 0, 0, 1},
			},
		},
		Port: 70000,
	}

	d := ep.AsDestination()
	if d.Port != 0 {
		t.Fatalf("expected port 0 for invalid endpoint port, got %d", d.Port)
	}
}
