package dtls_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/protocol/dtls"
)

func TestSniffDTLS_RecordHeader(t *testing.T) {
	// Minimal DTLS record header with a 1-byte payload.
	// ContentType: handshake (22)
	// Version: DTLS 1.2 (0xfefd)
	// Epoch: 0
	// Sequence: 0
	// Length: 1
	input := []byte{
		0x16, 0xfe, 0xfd,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01,
		0x00,
	}

	h, err := dtls.SniffDTLS(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if got := h.Protocol(); got != "dtls" {
		t.Fatalf("expected protocol 'dtls', got: %q", got)
	}
	if got := h.Domain(); got != "" {
		t.Fatalf("expected empty domain, got: %q", got)
	}
}
