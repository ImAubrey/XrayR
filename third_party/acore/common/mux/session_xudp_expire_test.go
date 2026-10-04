package mux

import (
	"testing"
	"time"

	"github.com/ImAubrey/acore/transport/pipe"
)

func withIsolatedXUDPMap(t *testing.T) {
	t.Helper()

	XUDPManager.Lock()
	original := XUDPManager.Map
	XUDPManager.Map = make(map[[8]byte]*XUDP)
	XUDPManager.Unlock()

	t.Cleanup(func() {
		XUDPManager.Lock()
		XUDPManager.Map = original
		XUDPManager.Unlock()
	})
}

func TestCleanupExpiredXUDP_ExpireAtNow(t *testing.T) {
	withIsolatedXUDPMap(t)

	now := time.Unix(100, 0)
	id := [8]byte{1}
	pr, pw := pipe.New(pipe.WithoutSizeLimit())
	x := &XUDP{
		GlobalID: id,
		Status:   Expiring,
		Expire:   now,
		Mux: &Session{
			input:  pr,
			output: pw,
		},
	}

	XUDPManager.Lock()
	XUDPManager.Map[id] = x
	XUDPManager.Unlock()
	cleanupExpiredXUDP(now)

	XUDPManager.Lock()
	_, found := XUDPManager.Map[id]
	XUDPManager.Unlock()

	if found {
		t.Fatal("expected expiring xudp to be removed when now == expire")
	}
}

func TestCleanupExpiredXUDP_BeforeExpireKeepsEntry(t *testing.T) {
	withIsolatedXUDPMap(t)

	now := time.Unix(200, 0)
	id := [8]byte{2}
	pr, pw := pipe.New(pipe.WithoutSizeLimit())
	x := &XUDP{
		GlobalID: id,
		Status:   Expiring,
		Expire:   now.Add(time.Second),
		Mux: &Session{
			input:  pr,
			output: pw,
		},
	}

	XUDPManager.Lock()
	XUDPManager.Map[id] = x
	XUDPManager.Unlock()
	cleanupExpiredXUDP(now)

	XUDPManager.Lock()
	_, found := XUDPManager.Map[id]
	XUDPManager.Unlock()

	if !found {
		t.Fatal("expected xudp entry to remain before expiration")
	}
}
