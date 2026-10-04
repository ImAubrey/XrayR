package dispatcher

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
)

func makeZeroTierHelloPacket() []byte {
	packet := make([]byte, 64)
	packet[8] = 0x01
	packet[9] = 0x02
	packet[10] = 0x03
	packet[11] = 0x04
	packet[12] = 0x05
	packet[13] = 0x06
	packet[14] = 0x07
	packet[15] = 0x08
	packet[16] = 0x09
	packet[17] = 0x0a
	packet[18] = 0x00 // cipher=0, extended armor off
	packet[27] = 0x01 // HELLO
	packet[28] = 13   // protocol version
	packet[29] = 1
	packet[30] = 0
	binary.BigEndian.PutUint64(packet[33:41], uint64(1700000000000))
	return packet
}

func TestSniffZeroTierHello(t *testing.T) {
	result, err := sniffZeroTier(context.Background(), makeZeroTierHelloPacket())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Protocol() != "zerotier" {
		t.Fatalf("expected protocol zerotier, got %q", result.Protocol())
	}
}

func TestSniffZeroTierFragment(t *testing.T) {
	packet := make([]byte, 16)
	packet[8] = 0x11
	packet[9] = 0x22
	packet[10] = 0x33
	packet[11] = 0x44
	packet[12] = 0x55
	packet[13] = 0xff
	packet[14] = 0x21 // total=2, no=1
	packet[15] = 0x03 // hops<=7

	result, err := sniffZeroTier(context.Background(), packet)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "zerotier" {
		t.Fatalf("expected zerotier result, got %#v", result)
	}
}

func TestSniffZeroTierNeedMoreData(t *testing.T) {
	result, err := sniffZeroTier(context.Background(), make([]byte, 15))
	if err != common.ErrNoClue {
		t.Fatalf("expected common.ErrNoClue, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result, got %#v", result)
	}
}

func TestShouldEnableZeroTierSniffer(t *testing.T) {
	if shouldEnableZeroTierSniffer(context.Background()) {
		t.Fatal("expected zerotier sniffer disabled by default")
	}
	ctx := context.WithValue(context.Background(), zeroTierSniffingEnabledKey{}, true)
	if !shouldEnableZeroTierSniffer(ctx) {
		t.Fatal("expected zerotier sniffer enabled when context key is set")
	}
}

func TestSniffZeroTierByPortHardMatch(t *testing.T) {
	packet := make([]byte, 32)
	packet[8] = 0x01
	packet[9] = 0x02
	packet[10] = 0x03
	packet[11] = 0x04
	packet[12] = 0x05
	packet[13] = 0x06
	packet[14] = 0x07
	packet[15] = 0x08
	packet[16] = 0x09
	packet[17] = 0x0a
	packet[18] = 0x08 // cipher=1, non-hello encrypted/control traffic
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{Target: net.UDPDestination(net.ParseAddress("103.195.103.66"), ztDefaultPort)},
	})
	result, err := sniffZeroTier(ctx, packet)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "zerotier" {
		t.Fatalf("expected zerotier result, got %#v", result)
	}
}

func TestSniffZeroTierByPortNotAlwaysMatch(t *testing.T) {
	packet := make([]byte, 32)
	// Reserved destination address: should be rejected even with 9993 hint.
	packet[8] = 0x00
	packet[9] = 0x00
	packet[10] = 0x00
	packet[11] = 0x00
	packet[12] = 0x00
	packet[13] = 0x01
	packet[14] = 0x02
	packet[15] = 0x03
	packet[16] = 0x04
	packet[17] = 0x05
	packet[18] = 0x08
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{Target: net.UDPDestination(net.ParseAddress("103.195.103.66"), ztDefaultPort)},
	})
	result, err := sniffZeroTier(ctx, packet)
	if err == nil || result != nil {
		t.Fatalf("expected non-zerotier for reserved address, got result=%#v err=%v", result, err)
	}
}

func TestSniffZeroTierByPortShortPacketNoPanic(t *testing.T) {
	packet := make([]byte, 16)
	packet[8] = 0x01
	packet[9] = 0x02
	packet[10] = 0x03
	packet[11] = 0x04
	packet[12] = 0x05
	packet[13] = 0x06
	packet[14] = 0x07
	packet[15] = 0x08

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{
		{Target: net.UDPDestination(net.ParseAddress("103.195.103.66"), ztDefaultPort)},
	})

	result, err := sniffZeroTier(ctx, packet)
	if err != common.ErrNoClue {
		t.Fatalf("expected common.ErrNoClue, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result, got %#v", result)
	}
}
