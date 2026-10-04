package hysteria

import (
	"bytes"
	"testing"

	hytransport "github.com/ImAubrey/acore/transport/internet/hysteria"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestReadTCPRequestAfterFrameType(t *testing.T) {
	const addr = "www.google.com:443"

	reader := bytes.NewReader(framedTCPRequest(t, addr))
	frameType, err := quicvarint.Read(quicvarint.NewReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	if frameType != hytransport.FrameTypeTCPRequest {
		t.Fatalf("unexpected frame type: %x", frameType)
	}

	got, err := ReadTCPRequest(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got != addr {
		t.Fatalf("unexpected address: %q", got)
	}
}

func TestReadTCPRequestFailsAfterAddressLengthConsumed(t *testing.T) {
	const addr = "www.google.com:443"

	reader := bytes.NewReader(framedTCPRequest(t, addr))
	if _, err := quicvarint.Read(quicvarint.NewReader(reader)); err != nil {
		t.Fatal(err)
	}
	if _, err := quicvarint.Read(quicvarint.NewReader(reader)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTCPRequest(reader); err == nil {
		t.Fatal("expected invalid TCP request after consuming address length")
	}
}

func framedTCPRequest(t *testing.T, addr string) []byte {
	t.Helper()

	var wire bytes.Buffer
	wire.Write(quicvarint.Append(nil, hytransport.FrameTypeTCPRequest))
	if err := WriteTCPRequest(&wire, addr); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}
