package ntp_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/protocol/ntp"
)

func TestSniffNTP_RequestV4(t *testing.T) {
	// NTP client request is typically 48 bytes.
	// 0x23 = LI=0, VN=4, Mode=3 (client)
	input := make([]byte, 48)
	input[0] = 0x23
	input[1] = 0x00 // stratum 0 for client request
	input[2] = 0x04
	input[3] = 0xec

	h, err := ntp.SniffNTP(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if got := h.Protocol(); got != "ntp" {
		t.Fatalf("expected protocol 'ntp', got: %q", got)
	}
	if got := h.Domain(); got != "" {
		t.Fatalf("expected empty domain, got: %q", got)
	}
}
