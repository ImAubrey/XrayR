package axpath

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestAXPathReorderCapDoesNotCloseSessionOnInOrderArrival(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use newSession to get a fully-initialized session, but force a tiny cap
	// afterwards to exercise the edge case.
	s := newSession(ctx, &Config{
		Subflows:         1,
		ChunkSize:        1024,
		AckMaskBits:      256,
		MaxInflightBytes: 16 * 1024 * 1024,
	})
	defer s.closeWithError(io.EOF)

	// Make reorder cap = 2 KiB, then buffer exactly 2 KiB out-of-order.
	s.maxInflight = 1024

	p2 := bytes.Repeat([]byte{2}, 1024)
	p3 := bytes.Repeat([]byte{3}, 1024)
	s.onData(1024, p2)
	s.onData(2048, p3)

	if err := s.ctx.Err(); err != nil {
		t.Fatalf("session closed unexpectedly: %v", err)
	}

	// This is the missing in-order frame. The old implementation applied the
	// reorder cap check before the seq==recvNext branch and would close here.
	p1 := bytes.Repeat([]byte{1}, 1024)
	s.onData(0, p1)

	if err := s.ctx.Err(); err != nil {
		t.Fatalf("session closed after receiving missing in-order chunk: %v", err)
	}

	buf := make([]byte, 3*1024)
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	for i := 0; i < 1024; i++ {
		if buf[i] != 1 {
			t.Fatalf("bad data at %d: got=%d want=1", i, buf[i])
		}
	}
	for i := 1024; i < 2*1024; i++ {
		if buf[i] != 2 {
			t.Fatalf("bad data at %d: got=%d want=2", i, buf[i])
		}
	}
	for i := 2 * 1024; i < 3*1024; i++ {
		if buf[i] != 3 {
			t.Fatalf("bad data at %d: got=%d want=3", i, buf[i])
		}
	}
}

func TestAXPathReorderCapDropsOutOfOrderInsteadOfClosing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newSession(ctx, &Config{
		Subflows:         1,
		ChunkSize:        1024,
		AckMaskBits:      256,
		MaxInflightBytes: 16 * 1024 * 1024,
	})
	defer s.closeWithError(io.EOF)

	s.maxInflight = 1024 // cap = 2048

	s.onData(1024, bytes.Repeat([]byte{2}, 1024))
	s.onData(2048, bytes.Repeat([]byte{3}, 1024))

	// Would exceed cap (hold already 2048), so should be dropped.
	s.onData(3072, bytes.Repeat([]byte{4}, 1024))

	if err := s.ctx.Err(); err != nil {
		t.Fatalf("session closed unexpectedly: %v", err)
	}

	s.recvMu.Lock()
	_, ok := s.recvHold[3072]
	s.recvMu.Unlock()
	if ok {
		t.Fatalf("seq 4 unexpectedly buffered despite cap")
	}
}
