package udp

import (
	"context"
	"fmt"
	"testing"
	"time"

	xnet "github.com/ImAubrey/acore/common/net"
)

func TestHubLoopbackEcho(t *testing.T) {
	ctx := context.Background()
	hub, err := ListenUDP(ctx, xnet.LocalHostIP, xnet.Port(0), nil, HubCapacity(1024))
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer hub.Close()

	laddr, ok := hub.Addr().(*xnet.UDPAddr)
	if !ok || laddr == nil {
		t.Fatalf("unexpected hub addr: %T", hub.Addr())
	}

	client, err := xnet.DialUDP("udp", nil, laddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer client.Close()

	const N = 200
	sent := make(map[string]struct{}, N)
	for i := 0; i < N; i++ {
		p := []byte(fmt.Sprintf("acore-udp-%d", i))
		sent[string(p)] = struct{}{}
		if _, err := client.Write(p); err != nil {
			t.Fatalf("client write %d: %v", i, err)
		}
	}

	received := make(map[string]struct{}, N)
	deadline := time.After(3 * time.Second)
	for len(received) < N {
		select {
		case <-deadline:
			t.Fatalf("timeout receiving on hub: got %d/%d", len(received), N)
		case pkt, ok := <-hub.Receive():
			if !ok {
				t.Fatalf("hub closed early")
			}
			s := string(pkt.Payload.Bytes())
			received[s] = struct{}{}
			if _, err := hub.WriteTo(pkt.Payload.Bytes(), pkt.Source); err != nil {
				pkt.Payload.Release()
				t.Fatalf("hub echo write: %v", err)
			}
			pkt.Payload.Release()
		}
	}

	echoes := make(map[string]struct{}, N)
	buf := make([]byte, 2048)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	for len(echoes) < N {
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("client read echo after %d/%d: %v", len(echoes), N, err)
		}
		echoes[string(buf[:n])] = struct{}{}
	}

	for s := range sent {
		if _, ok := received[s]; !ok {
			t.Fatalf("missing on hub receive: %q", s)
		}
		if _, ok := echoes[s]; !ok {
			t.Fatalf("missing echo: %q", s)
		}
	}
}
