package mux

import (
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/transport/pipe"
)

func TestSessionClose_XUDPWrappedPipeReader_NoPanic(t *testing.T) {
	pr, pw := pipe.New(pipe.WithoutSizeLimit())
	// Match the production wrapper that triggered the panic:
	// *conntrack.CountingReader{Reader: *pipe.Reader}.
	wrapped := conntrack.NewCountingReader(pr, func(int64) {}) // returns buf.Reader

	sm := NewSessionManager()
	s := &Session{
		input:        wrapped,
		output:       pw,
		parent:       sm,
		ID:           1,
		transferType: protocol.TransferTypePacket,
		XUDP:         &XUDP{Status: Active},
	}
	sm.Add(s)

	if err := s.Close(false); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// The XUDP close path should not tear down the underlying pipe; it should
	// remain usable for future sessions.
	b := buf.New()
	_, _ = b.Write([]byte("ok"))
	if err := pw.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("pipe write failed: %v", err)
	}

	tr := interface{}(pr).(buf.TimeoutReader)
	mb, err := tr.ReadMultiBufferTimeout(500 * time.Millisecond)
	if err != nil {
		t.Fatalf("pipe read failed: %v", err)
	}
	buf.ReleaseMulti(mb)
}
