package proxy

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
)

func newTrackedConn(t *testing.T, protocol string) conntrack.Connection {
	t.Helper()

	m := conntrack.NewManager()
	conn := m.NewConnection(conntrack.Meta{Protocol: protocol})
	if conn == nil {
		t.Fatal("failed to create tracked connection")
	}
	return conn
}

func cleanupConntrackSpliceState(t *testing.T, id uint32) {
	t.Helper()
	t.Cleanup(func() {
		value, ok := conntrackSpliceStates.LoadAndDelete(id)
		if !ok {
			return
		}
		state := value.(*conntrackSpliceState)
		state.mu.Lock()
		if state.cleanup != nil {
			state.cleanup.Stop()
			state.cleanup = nil
		}
		state.mu.Unlock()
	})
}

func TestConntrackSpliceTimerNotExtendedAfterHalfClose(t *testing.T) {
	conn := newTrackedConn(t, "")
	cleanupConntrackSpliceState(t, conn.ID())
	ctx := conntrack.ContextWithConnection(context.Background(), conn)

	first, extendTimer := beginConntrackSplice(ctx)
	if !extendTimer {
		t.Fatal("first splice should extend timer")
	}
	first.Done()

	second, extendTimer := beginConntrackSplice(ctx)
	defer second.Done()
	if extendTimer {
		t.Fatal("splice after half-close should not extend timer")
	}
}

func TestMarkConntrackSpliceHalfClosedPreventsLaterTimerExtension(t *testing.T) {
	conn := newTrackedConn(t, "")
	cleanupConntrackSpliceState(t, conn.ID())
	ctx := conntrack.ContextWithConnection(context.Background(), conn)

	MarkConntrackSpliceHalfClosed(ctx, time.Second)

	session, extendTimer := beginConntrackSplice(ctx)
	defer session.Done()
	if extendTimer {
		t.Fatal("splice after marked half-close should not extend timer")
	}
}

func TestConntrackSpliceTimerExtendedWhileBothDirectionsActive(t *testing.T) {
	conn := newTrackedConn(t, "")
	cleanupConntrackSpliceState(t, conn.ID())
	ctx := conntrack.ContextWithConnection(context.Background(), conn)

	first, extendTimer := beginConntrackSplice(ctx)
	defer first.Done()
	if !extendTimer {
		t.Fatal("first active splice should extend timer")
	}

	second, extendTimer := beginConntrackSplice(ctx)
	defer second.Done()
	if !extendTimer {
		t.Fatal("concurrent splice before half-close should extend timer")
	}

	first.Done()
	third, extendTimer := beginConntrackSplice(ctx)
	defer third.Done()
	if extendTimer {
		t.Fatal("splice after any direction completes should not extend timer")
	}
}

func TestInterruptRawConnsOnDoneSetsDeadline(t *testing.T) {
	left, right := stdnet.Pipe()
	defer left.Close()
	defer right.Close()

	ctx, cancel := context.WithCancel(context.Background())
	stop := interruptRawConnsOnDone(ctx, left)
	defer stop()

	done := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := left.Read(b[:])
		done <- err
	}()

	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read should be interrupted")
		}
	case <-time.After(time.Second):
		t.Fatal("read was not interrupted")
	}
}

func TestMarkSpliceProtocolFromConntrack(t *testing.T) {
	conn := newTrackedConn(t, "tls")
	ctx := conntrack.ContextWithConnection(context.Background(), conn)
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "http/1.1"})

	markSpliceProtocol(ctx)

	got := conn.Snapshot().Protocol
	if got != "tls+splice" {
		t.Fatalf("unexpected protocol: got %q want %q", got, "tls+splice")
	}
	if content := session.ContentFromContext(ctx); content == nil || content.Protocol != "http/1.1" {
		t.Fatalf("content protocol should stay untouched, got %#v", content)
	}
}

func TestMarkSpliceProtocolEmpty(t *testing.T) {
	conn := newTrackedConn(t, "")
	ctx := conntrack.ContextWithConnection(context.Background(), conn)

	markSpliceProtocol(ctx)

	got := conn.Snapshot().Protocol
	if got != "splice" {
		t.Fatalf("unexpected protocol: got %q want %q", got, "splice")
	}
}

func TestMarkSpliceProtocolAlreadyMarked(t *testing.T) {
	conn := newTrackedConn(t, "http+splice")
	ctx := conntrack.ContextWithConnection(context.Background(), conn)

	markSpliceProtocol(ctx)

	got := conn.Snapshot().Protocol
	if got != "http+splice" {
		t.Fatalf("unexpected protocol: got %q want %q", got, "http+splice")
	}
}
