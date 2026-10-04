package dokodemo

import (
	goerrors "errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
)

type stubPacketConn struct {
	writeErr error
	closed   bool
}

func (c *stubPacketConn) ReadFrom(_ []byte) (int, stdnet.Addr, error) {
	return 0, nil, stdnet.ErrClosed
}

func (c *stubPacketConn) WriteTo(p []byte, _ stdnet.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *stubPacketConn) Close() error {
	c.closed = true
	return nil
}

func (c *stubPacketConn) LocalAddr() stdnet.Addr {
	return &stdnet.UDPAddr{IP: stdnet.IPv4zero, Port: 0}
}

func (c *stubPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *stubPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *stubPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func makeUDPDestination(ip stdnet.IP, port int) net.Destination {
	return net.Destination{
		Network: net.Network_UDP,
		Address: net.IPAddress(ip),
		Port:    net.Port(port),
	}
}

func TestPacketWriterFakeUDPConnBounded(t *testing.T) {
	originalFactory := fakeUDPFactory
	defer func() { fakeUDPFactory = originalFactory }()

	created := make([]*stubPacketConn, 0, maxPacketWriterFakeUDPConns+64)
	fakeUDPFactory = func(_ *stdnet.UDPAddr, _ int) (stdnet.PacketConn, error) {
		conn := &stubPacketConn{}
		created = append(created, conn)
		return conn, nil
	}

	baseConn := &stubPacketConn{}
	baseDest := makeUDPDestination(stdnet.IPv4(1, 1, 1, 1), 10000)
	writer := NewPacketWriter(
		baseConn,
		&baseDest,
		0,
		&stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 9999},
	).(*PacketWriter)
	defer writer.Close()

	total := maxPacketWriterFakeUDPConns + 64
	for i := 0; i < total; i++ {
		ip := stdnet.IPv4(10, 0, byte(i/256), byte(i%256))
		dest := makeUDPDestination(ip, 20000+i)
		b := buf.FromBytes([]byte{1, 2, 3, 4})
		b.UDP = &dest
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("WriteMultiBuffer failed: %v", err)
		}
	}

	if got := len(writer.conns); got > maxPacketWriterFakeUDPConns {
		t.Fatalf("fake UDP conn cache exceeded limit: got=%d limit=%d", got, maxPacketWriterFakeUDPConns)
	}

	evicted := 0
	for _, conn := range created {
		if conn.closed {
			evicted++
		}
	}
	if evicted == 0 {
		t.Fatalf("expected cache eviction to close some fake UDP conns")
	}
}

func TestPacketWriterWriteErrorRemovesFailedConn(t *testing.T) {
	originalFactory := fakeUDPFactory
	defer func() { fakeUDPFactory = originalFactory }()

	var failedConn *stubPacketConn
	fakeUDPFactory = func(_ *stdnet.UDPAddr, _ int) (stdnet.PacketConn, error) {
		failedConn = &stubPacketConn{writeErr: goerrors.New("write failed")}
		return failedConn, nil
	}

	baseConn := &stubPacketConn{}
	baseDest := makeUDPDestination(stdnet.IPv4(2, 2, 2, 2), 10001)
	writer := NewPacketWriter(
		baseConn,
		&baseDest,
		0,
		&stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 9999},
	).(*PacketWriter)
	defer writer.Close()

	target := makeUDPDestination(stdnet.IPv4(3, 3, 3, 3), 30003)
	b := buf.FromBytes([]byte{9, 9, 9})
	b.UDP = &target
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("WriteMultiBuffer returned unexpected error: %v", err)
	}

	if failedConn == nil {
		t.Fatalf("fake UDP conn was not created")
	}
	if !failedConn.closed {
		t.Fatalf("failed fake UDP conn was not closed")
	}
	if _, ok := writer.conns[target]; ok {
		t.Fatalf("failed destination conn still present in cache")
	}
}
