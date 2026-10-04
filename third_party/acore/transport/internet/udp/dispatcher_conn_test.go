package udp

import (
	"context"
	"io"
	"testing"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	protoUDP "github.com/ImAubrey/acore/common/protocol/udp"
	"github.com/ImAubrey/acore/common/signal/done"
)

func buildTestPacket(payload string) (*protoUDP.Packet, *buf.Buffer) {
	b := buf.New()
	b.WriteString(payload)
	return &protoUDP.Packet{
		Payload: b,
		Source:  net.UDPDestination(net.ParseAddress("127.0.0.1"), 5353),
	}, b
}

func TestDispatcherConnReadFromReleasesPayload(t *testing.T) {
	conn := &dispatcherConn{
		cache: make(chan *protoUDP.Packet, 1),
		done:  done.New(),
		ctx:   context.Background(),
	}

	packet, payload := buildTestPacket("hello")
	conn.cache <- packet

	bufRead := make([]byte, 16)
	n, addr, err := conn.ReadFrom(bufRead)
	if err != nil {
		t.Fatalf("ReadFrom() error: %v", err)
	}
	if n != 5 || string(bufRead[:n]) != "hello" {
		t.Fatalf("ReadFrom() mismatch: n=%d data=%q", n, string(bufRead[:n]))
	}
	if addr == nil {
		t.Fatal("ReadFrom() should return source address")
	}
	if cap(payload.Bytes()) != 0 {
		t.Fatalf("payload was not released, cap=%d", cap(payload.Bytes()))
	}
}

func TestDispatcherConnCloseReleasesQueuedPayloads(t *testing.T) {
	conn := &dispatcherConn{
		dispatcher: &Dispatcher{},
		cache:      make(chan *protoUDP.Packet, 4),
		done:       done.New(),
		ctx:        context.Background(),
	}

	packet1, payload1 := buildTestPacket("a")
	packet2, payload2 := buildTestPacket("b")
	conn.cache <- packet1
	conn.cache <- packet2

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if cap(payload1.Bytes()) != 0 || cap(payload2.Bytes()) != 0 {
		t.Fatalf("queued payloads should be released, caps=(%d,%d)", cap(payload1.Bytes()), cap(payload2.Bytes()))
	}
}

func TestDispatcherConnCallbackReleasesAfterClose(t *testing.T) {
	conn := &dispatcherConn{
		cache: make(chan *protoUDP.Packet, 1),
		done:  done.New(),
		ctx:   context.Background(),
	}
	_ = conn.done.Close()

	packet, payload := buildTestPacket("x")
	conn.callback(context.Background(), packet)
	if cap(payload.Bytes()) != 0 {
		t.Fatalf("payload should be released after close, cap=%d", cap(payload.Bytes()))
	}
	if got := len(conn.cache); got != 0 {
		t.Fatalf("cache should remain empty after close callback, got=%d", got)
	}
}

func TestDispatcherConnReadFromClosedEmpty(t *testing.T) {
	conn := &dispatcherConn{
		cache: make(chan *protoUDP.Packet, 1),
		done:  done.New(),
		ctx:   context.Background(),
	}
	_ = conn.done.Close()

	_, _, err := conn.ReadFrom(make([]byte, 4))
	if err != io.EOF {
		t.Fatalf("ReadFrom() after close expected EOF, got %v", err)
	}
}
