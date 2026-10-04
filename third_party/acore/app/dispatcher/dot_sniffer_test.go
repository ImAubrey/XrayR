package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	core "github.com/ImAubrey/acore/core"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

type dotBranchResult struct {
	protocol string
}

func (r dotBranchResult) Protocol() string { return r.protocol }
func (dotBranchResult) Domain() string     { return "" }

func appendTLSExt(exts []byte, extType uint16, data []byte) []byte {
	exts = append(exts, byte(extType>>8), byte(extType))
	exts = append(exts, byte(len(data)>>8), byte(len(data)))
	exts = append(exts, data...)
	return exts
}

func buildTLSClientHelloForDOTTest(alpn string) []byte {
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)          // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_len
	body = append(body,
		0x00, 0x02, // cipher_suites_len
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x01, 0x00, // compression_methods_len + null compression
	)

	exts := make([]byte, 0, 32)
	if alpn != "" {
		alpnBytes := []byte(alpn)
		alpnData := make([]byte, 0, len(alpnBytes)+3)
		alpnData = append(alpnData, byte((len(alpnBytes)+1)>>8), byte(len(alpnBytes)+1))
		alpnData = append(alpnData, byte(len(alpnBytes)))
		alpnData = append(alpnData, alpnBytes...)
		exts = appendTLSExt(exts, 0x0010, alpnData)
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01) // client hello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x01, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

func TestSniffDOTByALPN(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	}})

	result, err := sniffDOT(ctx, buildTLSClientHelloForDOTTest("dot"))
	if err != nil {
		t.Fatalf("expected dot sniff success, got error: %v", err)
	}
	if result == nil || result.Protocol() != "dot" {
		t.Fatalf("expected protocol dot, got %#v", result)
	}
	if got := result.Domain(); got != "" {
		t.Fatalf("expected empty domain for dot routing sniff, got %q", got)
	}
	alpn, ok := result.(interface{ ALPN() string })
	if !ok {
		t.Fatal("expected dot result to expose ALPN")
	}
	if got := alpn.ALPN(); got != "dot" {
		t.Fatalf("expected ALPN dot, got %q", got)
	}
}

func TestSnifferPrefersDOTOverTLS(t *testing.T) {
	s := &Sniffer{
		sniffer: []protocolSnifferWithMetadata{
			tcpTLSSniffer(func(context.Context, []byte) (SniffResult, error) {
				return dotBranchResult{protocol: "tls"}, nil
			}),
			tcpTLSSniffer(func(context.Context, []byte) (SniffResult, error) {
				time.Sleep(20 * time.Millisecond)
				return dotBranchResult{protocol: "dot"}, nil
			}),
		},
	}

	result, err := s.Sniff(context.Background(), []byte{0x16, 0x03, 0x01, 0x00, 0x00}, net.Network_TCP)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "dot" {
		t.Fatalf("expected dot result, got %#v", result)
	}
}

func TestDispatchLinkSniffDOTWithoutInboundSniffing(t *testing.T) {
	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 853),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
	v, _ := core.New(&core.Config{})
	ctx = context.WithValue(ctx, acoreKey, v)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{Enabled: false},
	})

	route := &stubRoute{
		Context:     routing_session.AsRoutingContext(ctx),
		outboundTag: "dot-out",
		ruleTag:     "dot-rule",
	}
	handler := &stubHandler{tag: "dot-out"}
	d := &DefaultDispatcher{
		ohm: &stubManager{handler: handler},
		router: &stubRouter{
			route: route,
			sniffProtocols: map[string]bool{
				"dot": true,
			},
		},
	}

	reader, writer := pipe.New()
	packet := buildTLSClientHelloForDOTTest("")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(packet)}); err != nil {
		t.Fatalf("failed to write test packet: %v", err)
	}

	if err := d.DispatchLink(ctx, ob.Target, &transport.Link{
		Reader: reader,
		Writer: noopWriter{},
	}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.gotProtocol != "dot" {
		t.Fatalf("expected protocol dot, got %q", handler.gotProtocol)
	}
	if handler.gotTarget.Address.Family().IsDomain() {
		t.Fatalf("expected target to stay IP for dot sniff, got %v", handler.gotTarget)
	}
}
