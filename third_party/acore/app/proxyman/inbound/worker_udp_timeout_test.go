package inbound

import (
	"context"
	"testing"
	"time"

	xnet "github.com/ImAubrey/acore/common/net"
)

func newTestUDPWorker(unreplied, assured time.Duration) *udpWorker {
	w := &udpWorker{
		activeConn:   make(map[connID]*udpConn, 16),
		address:      xnet.LocalHostIP,
		port:         xnet.Port(41000),
		unrepliedTTL: unreplied,
		assuredTTL:   assured,
	}
	w.startTimeoutManager()
	return w
}

func containsConn(w *udpWorker, id connID) bool {
	w.RLock()
	defer w.RUnlock()
	_, found := w.activeConn[id]
	return found
}

func TestUDPWorkerSharedTimerUnrepliedTimeout(t *testing.T) {
	w := newTestUDPWorker(80*time.Millisecond, 300*time.Millisecond)
	t.Cleanup(func() { _ = w.Close() })

	id := connID{
		src: xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(41001)),
	}

	conn, existing := w.getConnection(id)
	if existing {
		t.Fatal("expected a new UDP connection")
	}
	if conn.cancel == nil {
		t.Fatal("new udp connection should initialize cancel func")
	}
	if conn.ctx == nil {
		t.Fatal("new udp connection should initialize context")
	}

	select {
	case <-conn.done.Wait():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("udp conn should close after unreplied timeout")
	}

	if containsConn(w, id) {
		t.Fatal("expired conn should be removed from active map")
	}
}

func TestUDPWorkerSharedTimerPromotesToAssuredTimeout(t *testing.T) {
	w := newTestUDPWorker(80*time.Millisecond, 400*time.Millisecond)
	t.Cleanup(func() { _ = w.Close() })

	id := connID{
		src: xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(41002)),
	}

	conn, existing := w.getConnection(id)
	if existing {
		t.Fatal("expected a new UDP connection")
	}

	time.Sleep(40 * time.Millisecond)
	conn.markReplied()

	// After promotion, unreplied timeout should no longer close this session.
	time.Sleep(160 * time.Millisecond)
	select {
	case <-conn.done.Wait():
		t.Fatal("udp conn closed too early before assured timeout")
	default:
	}

	select {
	case <-conn.done.Wait():
	case <-time.After(800 * time.Millisecond):
		t.Fatal("udp conn should close after assured timeout")
	}

	if containsConn(w, id) {
		t.Fatal("expired conn should be removed from active map")
	}
}

func TestConeFromContextDefaultAndOverride(t *testing.T) {
	if got := coneFromContext(nil); !got {
		t.Fatalf("coneFromContext(nil) = %v, want true", got)
	}

	if got := coneFromContext(context.Background()); !got {
		t.Fatalf("coneFromContext(background) = %v, want true", got)
	}

	ctx := context.WithValue(context.Background(), "cone", false)
	if got := coneFromContext(ctx); got {
		t.Fatalf("coneFromContext(false) = %v, want false", got)
	}

	ctx = context.WithValue(context.Background(), "cone", true)
	if got := coneFromContext(ctx); !got {
		t.Fatalf("coneFromContext(true) = %v, want true", got)
	}
}
