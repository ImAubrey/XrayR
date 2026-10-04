package dispatcher

import (
	"context"
	stderrs "errors"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/core"
)

const testAcoreKey core.AcoreKey = 1

type oneShotTimeoutReader struct {
	packet []byte
	sent   bool
}

func (r *oneShotTimeoutReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.ReadMultiBufferTimeout(0)
}

func (r *oneShotTimeoutReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	if !r.sent {
		r.sent = true
		return buf.MultiBuffer{buf.FromBytes(append([]byte(nil), r.packet...))}, nil
	}
	return nil, buf.ErrReadTimeout
}

func TestSnifferLikelyQUICNoClueWaitsForMoreData(t *testing.T) {
	// Valid QUIC initial header with packet length > actual bytes.
	// QUIC sniffer will report common.ErrNoClue, so dispatcher should keep waiting.
	packet := []byte{
		0xc0,                   // long header + fixed bit + initial packet type
		0x00, 0x00, 0x00, 0x01, // version 1
		0x08,                                           // DCID length
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // DCID
		0x00, // SCID length
		0x00, // token length
		0x20, // packet length (32 bytes), but payload below is intentionally shorter
		0x00, 0x00, 0x00, 0x00,
	}

	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatalf("failed to initialize core: %v", err)
	}
	defer v.Close()

	baseCtx := context.WithValue(context.Background(), testAcoreKey, v)
	ctx, cancel := context.WithTimeout(baseCtx, 40*time.Millisecond)
	defer cancel()

	cReader := &cachedReader{
		reader: &oneShotTimeoutReader{packet: packet},
	}
	_, err = sniffer(ctx, cReader, false, net.Network_UDP)
	if !stderrs.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}
}

func TestIsLikelyQUICInitial(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    bool
	}{
		{
			name:    "version1",
			payload: []byte{0xc0, 0x00, 0x00, 0x00, 0x01},
			want:    true,
		},
		{
			name:    "draft29",
			payload: []byte{0xc0, 0xff, 0x00, 0x00, 0x1d},
			want:    true,
		},
		{
			name:    "shortHeader",
			payload: []byte{0x40, 0x00, 0x00, 0x00, 0x01},
			want:    false,
		},
		{
			name:    "fixedBitUnset",
			payload: []byte{0x80, 0x00, 0x00, 0x00, 0x01},
			want:    false,
		},
		{
			name:    "notInitialType",
			payload: []byte{0xd0, 0x00, 0x00, 0x00, 0x01},
			want:    false,
		},
		{
			name:    "unsupportedVersion",
			payload: []byte{0xc0, 0x00, 0x00, 0x00, 0x02},
			want:    false,
		},
		{
			name:    "initialTypeShortVersion",
			payload: []byte{0xc0, 0x00, 0x00},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyQUICInitial(tt.payload)
			if got != tt.want {
				t.Fatalf("isLikelyQUICInitial() = %v, want %v", got, tt.want)
			}
		})
	}
}
