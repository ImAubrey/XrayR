package mqtt_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/protocol/mqtt"
)

func TestSniffMQTT_Connect311(t *testing.T) {
	// Minimal MQTT 3.1.1 CONNECT with empty ClientID and Clean Session set.
	input := []byte{
		0x10, 0x0c,
		0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
		0x04,
		0x02,
		0x00, 0x00,
		0x00, 0x00,
	}

	h, err := mqtt.SniffMQTT(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if got := h.Protocol(); got != "mqtt" {
		t.Fatalf("expected protocol 'mqtt', got: %q", got)
	}
	if got := h.Domain(); got != "" {
		t.Fatalf("expected empty domain, got: %q", got)
	}
}
