package internet

import (
	"errors"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/net"
)

var errWriteBatchTest = errors.New("write failure")

type testPacketConn struct {
	writeCount int
	failAt     int
}

func (c *testPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, nil
}

func (c *testPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.failAt >= 0 && c.writeCount == c.failAt {
		return 0, errWriteBatchTest
	}
	c.writeCount++
	return len(p), nil
}

func (c *testPacketConn) Close() error {
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 10000}
}

func (c *testPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *testPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *testPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestPacketConnWrapperWriteBatchFallback(t *testing.T) {
	c := &PacketConnWrapper{
		Conn: &testPacketConn{failAt: -1},
	}

	payloads := [][]byte{
		[]byte("a"),
		[]byte("bb"),
		[]byte("ccc"),
	}
	addrs := []net.Addr{
		&net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 1111},
		&net.UDPAddr{IP: net.IP{1, 1, 1, 2}, Port: 2222},
		&net.UDPAddr{IP: net.IP{1, 1, 1, 3}, Port: 3333},
	}

	n, err := c.WriteBatch(payloads, addrs)
	if err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}
	if n != len(payloads) {
		t.Fatalf("unexpected sent count: got=%d want=%d", n, len(payloads))
	}

	pc := c.Conn.(*testPacketConn)
	if pc.writeCount != len(payloads) {
		t.Fatalf("unexpected write count: got=%d want=%d", pc.writeCount, len(payloads))
	}
}

func TestPacketConnWrapperWriteBatchFallbackError(t *testing.T) {
	c := &PacketConnWrapper{
		Conn: &testPacketConn{failAt: 1},
	}

	payloads := [][]byte{
		[]byte("a"),
		[]byte("bb"),
		[]byte("ccc"),
	}
	addrs := []net.Addr{
		&net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 1111},
		&net.UDPAddr{IP: net.IP{1, 1, 1, 2}, Port: 2222},
		&net.UDPAddr{IP: net.IP{1, 1, 1, 3}, Port: 3333},
	}

	n, err := c.WriteBatch(payloads, addrs)
	if !errors.Is(err, errWriteBatchTest) {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("unexpected sent count: got=%d want=1", n)
	}

	pc := c.Conn.(*testPacketConn)
	if pc.writeCount != 1 {
		t.Fatalf("unexpected write count: got=%d want=1", pc.writeCount)
	}
}

func TestPacketConnWrapperWriteBatchLenMismatch(t *testing.T) {
	c := &PacketConnWrapper{
		Conn: &testPacketConn{failAt: -1},
	}

	payloads := [][]byte{
		[]byte("a"),
		[]byte("bb"),
	}
	addrs := []net.Addr{
		&net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 1111},
	}

	n, err := c.WriteBatch(payloads, addrs)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if n != 0 {
		t.Fatalf("unexpected sent count: got=%d want=0", n)
	}

	pc := c.Conn.(*testPacketConn)
	if pc.writeCount != 0 {
		t.Fatalf("unexpected write count: got=%d want=0", pc.writeCount)
	}
}
