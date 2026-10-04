package dispatcher

import (
	"context"
	"errors"
	"testing"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/protocol"
)

func TestSniffMTProtoAbridged(t *testing.T) {
	packet := append([]byte{0xef, 0x04}, make([]byte, 16)...)
	result, err := sniffMTProto(context.Background(), packet)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "mtproto" {
		t.Fatalf("expected mtproto result, got %#v", result)
	}
}

func TestSniffMTProtoAbridgedExtendedLen(t *testing.T) {
	// 0x7f + 3-byte LE words length = 4 words => 16 bytes payload.
	packet := append([]byte{0xef, 0x7f, 0x04, 0x00, 0x00}, make([]byte, 16)...)
	result, err := sniffMTProto(context.Background(), packet)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "mtproto" {
		t.Fatalf("expected mtproto result, got %#v", result)
	}
}

func TestSniffMTProtoIntermediate(t *testing.T) {
	packet := append([]byte{
		0xee, 0xee, 0xee, 0xee,
		0x10, 0x00, 0x00, 0x00, // 16 bytes payload
	}, make([]byte, 16)...)
	result, err := sniffMTProto(context.Background(), packet)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "mtproto" {
		t.Fatalf("expected mtproto result, got %#v", result)
	}
}

func TestSniffMTProtoPaddedIntermediate(t *testing.T) {
	packet := append([]byte{
		0xdd, 0xdd, 0xdd, 0xdd,
		0x14, 0x00, 0x00, 0x00, // 20 bytes payload (includes random padding)
	}, make([]byte, 20)...)
	result, err := sniffMTProto(context.Background(), packet)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "mtproto" {
		t.Fatalf("expected mtproto result, got %#v", result)
	}
}

func TestSniffMTProtoNeedMoreData(t *testing.T) {
	packet := []byte{0xef, 0x04} // expects 16 bytes payload, absent.
	result, err := sniffMTProto(context.Background(), packet)
	if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
		t.Fatalf("expected ErrProtoNeedMoreData, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result, got %#v", result)
	}
}

func TestSniffMTProtoNoClue(t *testing.T) {
	result, err := sniffMTProto(context.Background(), nil)
	if err != common.ErrNoClue {
		t.Fatalf("expected common.ErrNoClue, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result, got %#v", result)
	}
}

func TestShouldEnableMTProtoSniffer(t *testing.T) {
	if shouldEnableMTProtoSniffer(context.Background()) {
		t.Fatal("expected mtproto sniffer disabled by default")
	}
	ctx := context.WithValue(context.Background(), mtProtoSniffingEnabledKey{}, true)
	if !shouldEnableMTProtoSniffer(ctx) {
		t.Fatal("expected mtproto sniffer enabled when context key is set")
	}
}
