package ike_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/protocol/ike"
)

func TestSniffIKEv2_MinHeader(t *testing.T) {
	// Minimal IKEv2 header (28 bytes).
	// Initiator SPI (8) + Responder SPI (8) = zeros
	// Next Payload = 0
	// Version = 0x20 (IKEv2)
	// Exchange Type = 34 (IKE_SA_INIT)
	// Flags = 0
	// Message ID = 0
	// Length = 28
	input := make([]byte, 28)
	input[17] = 0x20
	input[18] = 34
	input[27] = 0x1c // 28

	h, err := ike.SniffIKEv2(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if got := h.Protocol(); got != "ikev2" {
		t.Fatalf("expected protocol 'ikev2', got: %q", got)
	}
	if got := h.Domain(); got != "" {
		t.Fatalf("expected empty domain, got: %q", got)
	}
}
