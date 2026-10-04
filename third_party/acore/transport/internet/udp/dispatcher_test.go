package udp_test

import (
	"context"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol/udp"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/transport"
	. "github.com/ImAubrey/acore/transport/internet/udp"
	"github.com/ImAubrey/acore/transport/pipe"
)

type TestDispatcher struct {
	OnDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *TestDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.OnDispatch(ctx, dest)
}

func (d *TestDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	return nil
}

func (d *TestDispatcher) Start() error {
	return nil
}

func (d *TestDispatcher) Close() error {
	return nil
}

func (*TestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestSameDestinationDispatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(1024))

	go func() {
		for {
			data, err := uplinkReader.ReadMultiBuffer()
			if err != nil {
				break
			}
			err = downlinkWriter.WriteMultiBuffer(data)
			common.Must(err)
		}
	}()

	var count uint32
	td := &TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			atomic.AddUint32(&count, 1)
			return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
		},
	}
	dest := net.UDPDestination(net.LocalHostIP, 53)

	b := buf.New()
	b.WriteString("abcd")

	var msgCount uint32
	dispatcher := NewDispatcher(td, func(ctx context.Context, packet *udp.Packet) {
		atomic.AddUint32(&msgCount, 1)
	})

	dispatcher.Dispatch(ctx, dest, b)
	for i := 0; i < 5; i++ {
		dispatcher.Dispatch(ctx, dest, b)
	}

	time.Sleep(time.Second)
	cancel()

	if count != 1 {
		t.Error("count: ", count)
	}
	if v := atomic.LoadUint32(&msgCount); v != 6 {
		t.Error("msgCount: ", v)
	}
}

func TestDialDispatcherCloseStopsWrite(t *testing.T) {
	ctx := context.Background()
	var dispatchCount uint32

	td := &TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			atomic.AddUint32(&dispatchCount, 1)
			return &transport.Link{}, nil
		},
	}

	pc, err := DialDispatcher(ctx, td)
	if err != nil {
		t.Fatalf("DialDispatcher() error: %v", err)
	}

	if err := pc.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	n, err := pc.WriteTo([]byte("x"), &stdnet.UDPAddr{
		IP:   stdnet.IPv4(1, 1, 1, 1),
		Port: 53,
	})
	if err == nil {
		t.Fatal("WriteTo() after Close() should fail")
	}
	if err != io.ErrClosedPipe {
		t.Fatalf("unexpected WriteTo() error after Close(): %v", err)
	}
	if n != 0 {
		t.Fatalf("WriteTo() after Close() wrote %d bytes, expected 0", n)
	}
	if got := atomic.LoadUint32(&dispatchCount); got != 0 {
		t.Fatalf("dispatch should not happen after Close(), got %d", got)
	}
}
