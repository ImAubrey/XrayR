package dispatcher

import (
	"context"
	"testing"

	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
)

type testSniffResult struct {
	protocol   string
	domain     string
	alpn       string
	tlsVersion string
	ja4        string
}

func (r testSniffResult) Protocol() string   { return r.protocol }
func (r testSniffResult) Domain() string     { return r.domain }
func (r testSniffResult) ALPN() string       { return r.alpn }
func (r testSniffResult) TLSVersion() string { return r.tlsVersion }
func (r testSniffResult) JA4() string        { return r.ja4 }

func TestSetTLSSNIAttribute(t *testing.T) {
	content := &session.Content{}
	ctx := session.ContextWithContent(context.Background(), content)

	setTLSSNIAttribute(ctx, testSniffResult{protocol: "tls", domain: "example.com"})
	if got := content.Attribute("tls_sni"); got != "1" {
		t.Fatalf("expected tls_sni=1, got %q", got)
	}
}

func TestSetTLSSNIAttributeNoSNI(t *testing.T) {
	content := &session.Content{}
	ctx := session.ContextWithContent(context.Background(), content)

	setTLSSNIAttribute(ctx, testSniffResult{protocol: "tls"})
	if got := content.Attribute("tls_sni"); got != "0" {
		t.Fatalf("expected tls_sni=0, got %q", got)
	}
}

func TestSetTLSVersionAttribute(t *testing.T) {
	content := &session.Content{}
	ctx := session.ContextWithContent(context.Background(), content)

	setTLSVersionAttribute(ctx, testSniffResult{protocol: "tls", tlsVersion: "1.3"})
	if got := content.Attribute("tls_version"); got != "1.3" {
		t.Fatalf("expected tls_version=1.3, got %q", got)
	}
}

func TestSetJA4Attribute(t *testing.T) {
	content := &session.Content{}
	ctx := session.ContextWithContent(context.Background(), content)

	setJA4Attribute(ctx, testSniffResult{protocol: "tls", ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1"})
	if got := content.Attribute("ja4"); got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("expected ja4 to be set, got %q", got)
	}
}

func TestSetJA4AttributeAlsoPersistsToConntrack(t *testing.T) {
	content := &session.Content{}
	ctx := session.ContextWithContent(context.Background(), content)
	mgr := conntrack.NewManager()
	conn := mgr.NewConnection(conntrack.Meta{})
	if conn == nil {
		t.Fatal("expected tracked connection")
	}
	ctx = conntrack.ContextWithConnection(ctx, conn)

	setJA4Attribute(ctx, testSniffResult{protocol: "tls", ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1"})

	if got := conn.Snapshot().JA4; got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("expected conntrack JA4 to be set, got %q", got)
	}
}

func TestSetJA4AttributeSupportsQUIC(t *testing.T) {
	content := &session.Content{}
	ctx := session.ContextWithContent(context.Background(), content)

	setJA4Attribute(ctx, testSniffResult{protocol: "quic", ja4: "q13d0312h3_deadbeef0000_deadbeef0000"})
	if got := content.Attribute("ja4"); got != "q13d0312h3_deadbeef0000_deadbeef0000" {
		t.Fatalf("expected ja4 to be set for quic, got %q", got)
	}
}

func TestSetJA4AttributeSkipsUnknownProtocol(t *testing.T) {
	content := &session.Content{}
	ctx := session.ContextWithContent(context.Background(), content)

	setJA4Attribute(ctx, testSniffResult{protocol: "http", ja4: "h13d0312h3_deadbeef0000_deadbeef0000"})
	if got := content.Attribute("ja4"); got != "" {
		t.Fatalf("expected empty ja4 for non-tls/non-quic protocol, got %q", got)
	}
}

func TestSetTLSAttributesOnCompositeTLSProtocol(t *testing.T) {
	content := &session.Content{}
	ctx := session.ContextWithContent(context.Background(), content)

	result := CompositeResult(
		testSniffResult{protocol: "fakedns", domain: "example.com"},
		testSniffResult{
			protocol:   "tls",
			domain:     "example.com",
			tlsVersion: "1.3",
			ja4:        "t13d1516h2_8daaf6152771_e5627efa2ab1",
		},
	)

	setTLSSNIAttribute(ctx, result)
	setTLSVersionAttribute(ctx, result)
	setJA4Attribute(ctx, result)

	if got := content.Attribute("tls_sni"); got != "1" {
		t.Fatalf("expected tls_sni=1 for fakedns+tls composite, got %q", got)
	}
	if got := content.Attribute("tls_version"); got != "1.3" {
		t.Fatalf("expected tls_version=1.3 for fakedns+tls composite, got %q", got)
	}
	if got := content.Attribute("ja4"); got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("expected ja4 to be set for fakedns+tls composite, got %q", got)
	}
}
