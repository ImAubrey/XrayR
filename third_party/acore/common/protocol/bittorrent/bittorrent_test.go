package bittorrent_test

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/protocol/bittorrent"
)

func TestSniffUTP_TimestampNearNow(t *testing.T) {
	// Minimal uTP packet header layout used by SniffUTP:
	// [0] type/version, [1] extension, [2:4] conn id, [4:8] timestamp, ...
	p := make([]byte, 20)
	p[0] = 0x11 // type=1, version=1
	p[1] = 0x00 // no extensions
	now := uint32(time.Now().UnixMicro())
	binary.BigEndian.PutUint32(p[4:8], now)

	h, err := bittorrent.SniffUTP(p)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if got := h.Protocol(); got != "bittorrent" {
		t.Fatalf("expected protocol 'bittorrent', got: %q", got)
	}
}
