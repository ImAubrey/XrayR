package internet

import (
	"bytes"
	"context"
	"testing"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
)

func TestParseRandomIPHashDeterministicForDomain(t *testing.T) {
	base := net.ParseAddress("10.0.0.0")
	ob1 := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("cp.cloudflare.com"), 443)}
	ob2 := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("CP.CloudFlare.Com"), 443)}

	ip1 := ParseRandomIP(context.Background(), base, "hash:24", ob1)
	ip2 := ParseRandomIP(context.Background(), base, "hash:24", ob1)
	ip3 := ParseRandomIP(context.Background(), base, "hash:24", ob2)

	if ip1 == nil || ip2 == nil || ip3 == nil {
		t.Fatal("expected non-nil IP")
	}
	if ip1.String() != ip2.String() {
		t.Fatalf("same domain should map to same IP, got %s and %s", ip1, ip2)
	}
	if ip1.String() != ip3.String() {
		t.Fatalf("domain match should be case-insensitive, got %s and %s", ip1, ip3)
	}
}

func TestParseRandomIPHashDeterministicForIP(t *testing.T) {
	base := net.ParseAddress("10.0.0.0")
	ob := &session.Outbound{Target: net.TCPDestination(net.ParseAddress("1.1.1.1"), 443)}

	ip1 := ParseRandomIP(context.Background(), base, "hash:24", ob)
	ip2 := ParseRandomIP(context.Background(), base, "hash:24", ob)

	if ip1 == nil || ip2 == nil {
		t.Fatal("expected non-nil IP")
	}
	if ip1.String() != ip2.String() {
		t.Fatalf("same target IP should map to same sendThrough IP, got %s and %s", ip1, ip2)
	}

	out := ip1.IP().To4()
	if out == nil {
		t.Fatalf("expected IPv4 result, got %s", ip1)
	}
	if out[0] != 10 || out[1] != 0 || out[2] != 0 {
		t.Fatalf("result %s should be inside 10.0.0.0/24", ip1)
	}
}

func TestGatewayHashKeySourceToggle(t *testing.T) {
	ob := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("cp.cloudflare.com"), 443)}
	src1 := net.ParseAddress("198.51.100.10")
	src2 := net.ParseAddress("198.51.100.11")

	plain1 := gatewayHashKey(ob, false, src1)
	plain2 := gatewayHashKey(ob, false, src2)
	if !bytes.Equal(plain1, plain2) {
		t.Fatal("source must not affect plain hash mode")
	}

	withSrc1 := gatewayHashKey(ob, true, src1)
	withSrc2 := gatewayHashKey(ob, true, src2)
	if bytes.Equal(withSrc1, withSrc2) {
		t.Fatal("different source IP should produce different src-hash key")
	}
}

func TestParseRandomIPSrcHashDeterministicForSource(t *testing.T) {
	base := net.ParseAddress("2001:db8::")
	ob := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("cp.cloudflare.com"), 443)}

	ctx1 := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("198.51.100.10"), 12345),
	})
	ctx2 := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("198.51.100.11"), 23456),
	})

	ip1 := ParseRandomIP(ctx1, base, "src-hash:64", ob)
	ip2 := ParseRandomIP(ctx1, base, "src-hash:64", ob)
	ip3 := ParseRandomIP(ctx2, base, "src-hash:64", ob)
	if ip1 == nil || ip2 == nil || ip3 == nil {
		t.Fatal("expected non-nil IP")
	}
	if ip1.String() != ip2.String() {
		t.Fatalf("same source/target should map to same IP, got %s and %s", ip1, ip2)
	}
	if ip1.String() == ip3.String() {
		t.Fatalf("different source should map to different IP, got %s and %s", ip1, ip3)
	}
}

func TestParseRandomIPCompiledMatchesHash(t *testing.T) {
	base := net.ParseAddress("2001:db8::")
	ob := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("cp.cloudflare.com"), 443)}
	compiled := CompileSendThrough(base, "hash:64")
	if compiled == nil {
		t.Fatal("expected compiled plan")
	}

	ip1 := ParseRandomIP(context.Background(), base, "hash:64", ob)
	ip2 := ParseRandomIPCompiled(context.Background(), compiled, ob)
	if ip1 == nil || ip2 == nil {
		t.Fatal("expected non-nil IP")
	}
	if ip1.String() != ip2.String() {
		t.Fatalf("compiled hash must match runtime hash, got %s and %s", ip1, ip2)
	}
}

func TestParseRandomIPCompiledIPv4AndIPv6RandomRange(t *testing.T) {
	plan4 := CompileSendThrough(net.ParseAddress("10.20.30.40"), "24")
	if plan4 == nil {
		t.Fatal("expected ipv4 compiled plan")
	}
	for i := 0; i < 128; i++ {
		ip := ParseRandomIPCompiled(context.Background(), plan4, nil)
		if ip == nil {
			t.Fatal("expected ipv4 random ip")
		}
		v4 := ip.IP().To4()
		if v4 == nil || v4[0] != 10 || v4[1] != 20 || v4[2] != 30 {
			t.Fatalf("ipv4 random ip out of subnet: %s", ip)
		}
	}

	plan6 := CompileSendThrough(net.ParseAddress("2001:db8::1"), "64")
	if plan6 == nil {
		t.Fatal("expected ipv6 compiled plan")
	}
	for i := 0; i < 128; i++ {
		ip := ParseRandomIPCompiled(context.Background(), plan6, nil)
		if ip == nil {
			t.Fatal("expected ipv6 random ip")
		}
		v6 := ip.IP().To16()
		if v6 == nil || v6.To4() != nil {
			t.Fatalf("expected ipv6 random ip, got %s", ip)
		}
		if v6[0] != 0x20 || v6[1] != 0x01 || v6[2] != 0x0d || v6[3] != 0xb8 {
			t.Fatalf("ipv6 random ip out of subnet: %s", ip)
		}
	}
}

func BenchmarkParseRandomIPHash(b *testing.B) {
	base := net.ParseAddress("2001:db8::")
	ob := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("cp.cloudflare.com"), 443)}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ip := ParseRandomIP(ctx, base, "hash:64", ob); ip == nil {
			b.Fatal("expected non-nil IP")
		}
	}
}

func BenchmarkParseRandomIPRandom(b *testing.B) {
	base := net.ParseAddress("2001:db8::")
	ob := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("cp.cloudflare.com"), 443)}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ip := ParseRandomIP(ctx, base, "64", ob); ip == nil {
			b.Fatal("expected non-nil IP")
		}
	}
}

func BenchmarkParseRandomIPCompiledRandom(b *testing.B) {
	base := net.ParseAddress("2001:db8::")
	compiled := CompileSendThrough(base, "64")
	if compiled == nil {
		b.Fatal("expected compiled plan")
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ip := ParseRandomIPCompiled(ctx, compiled, nil); ip == nil {
			b.Fatal("expected non-nil IP")
		}
	}
}

func BenchmarkParseRandomIPSrcHash(b *testing.B) {
	base := net.ParseAddress("2001:db8::")
	ob := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("cp.cloudflare.com"), 443)}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("198.51.100.10"), 12345),
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ip := ParseRandomIP(ctx, base, "src-hash:64", ob); ip == nil {
			b.Fatal("expected non-nil IP")
		}
	}
}
