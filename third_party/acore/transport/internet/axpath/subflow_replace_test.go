package axpath

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestAXPathReplaceSubflowDoesNotKillNewFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s := newSession(ctx, &Config{
		Subflows:         1,
		ChunkSize:        1024,
		AckMaskBits:      256,
		MaxInflightBytes: 4 * 1024 * 1024,
		MaxQueuePerFlow:  4,
	})
	defer s.closeWithError(io.EOF)

	// First subflow.
	c1a, c1b := net.Pipe()
	defer c1b.Close()
	if err := s.attachSubflow(0, c1a); err != nil {
		t.Fatalf("attach first subflow: %v", err)
	}

	// Let goroutines start so the close below reliably triggers onSubflowError.
	time.Sleep(20 * time.Millisecond)

	// Replace with a new connection on the same subflow id. The old readLoop will
	// error after being closed; that error must not remove/close the new flow.
	c2a, c2b := net.Pipe()
	defer c2b.Close()
	if err := s.attachSubflow(0, c2a); err != nil {
		t.Fatalf("attach replacement subflow: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.flowsMu.RLock()
		f := s.flows[0]
		s.flowsMu.RUnlock()

		if f != nil && f.conn == c2a && !f.isClosed() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.flowsMu.RLock()
	f := s.flows[0]
	s.flowsMu.RUnlock()

	if f == nil {
		t.Fatalf("flow 0 missing after replacement")
	}
	t.Fatalf("flow 0 unexpected state after replacement: closed=%v conn_is_new=%v", f.isClosed(), f.conn == c2a)
}
