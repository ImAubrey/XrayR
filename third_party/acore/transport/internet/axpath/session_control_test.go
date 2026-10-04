package axpath

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestAXPathSendControlBlocksUntilEnqueuedWhenQueueFull(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	s := newSession(ctx, &Config{
		Subflows:         1,
		ChunkSize:        1024,
		AckMaskBits:      256,
		MaxInflightBytes: 1024 * 1024,
		MaxQueuePerFlow:  1,
	})
	defer s.closeWithError(io.EOF)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	f := newSubflow(0, c1, 1)

	s.flowsMu.Lock()
	s.flows[0] = f
	s.flowsMu.Unlock()

	// Fill the control queue so sendControl has to block until there is room.
	for i := 0; i < cap(f.ctlCh); i++ {
		f.ctlCh <- []byte("dummy")
	}

	// Drain one item later, then sendControl should enqueue the control frame.
	go func() {
		time.Sleep(50 * time.Millisecond)
		<-f.ctlCh
	}()

	control := []byte{frameTypeAck, 0, 1, 2}

	done := make(chan struct{})
	go func() {
		s.sendControl(control)
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("sendControl did not return: %v", ctx.Err())
	}

	found := false
	for i := 0; i < cap(f.ctlCh); i++ {
		select {
		case got := <-f.ctlCh:
			if bytes.Equal(got, control) {
				found = true
			}
		case <-ctx.Done():
			t.Fatalf("control frame not queued: %v", ctx.Err())
		}
	}
	if !found {
		t.Fatalf("control frame not queued")
	}
}
