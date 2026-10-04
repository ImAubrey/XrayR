package rdp_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/protocol/rdp"
)

func TestSniffRDP_ConnectionRequest(t *testing.T) {
	// A minimal RDP negotiation request (TPKT + X.224 Connection Request + RDP Negotiation Request).
	input := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: v3, reserved, length=0x13 (19)
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224: len, CR TPDU, refs, class
		0x01, 0x00, 0x08, 0x00, // RDP Negotiation Request: type, flags, length (little-endian)
		0x03, 0x00, 0x00, 0x00, // requestedProtocols
	}

	h, err := rdp.SniffRDP(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if got := h.Protocol(); got != "rdp" {
		t.Fatalf("expected protocol 'rdp', got: %q", got)
	}
	if got := h.Domain(); got != "" {
		t.Fatalf("expected empty domain, got: %q", got)
	}
}
