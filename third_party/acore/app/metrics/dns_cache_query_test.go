package metrics

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestResolveDNSQueryType(t *testing.T) {
	t.Run("default to A", func(t *testing.T) {
		queryType, reqType, option, ok := resolveDNSQueryType("")
		if !ok {
			t.Fatal("expected empty type to be supported")
		}
		if queryType != "A" {
			t.Fatalf("queryType = %q, want %q", queryType, "A")
		}
		if reqType != dnsmessage.TypeA {
			t.Fatalf("reqType = %v, want %v", reqType, dnsmessage.TypeA)
		}
		if !option.IPv4Enable || option.IPv6Enable {
			t.Fatalf("option = %+v, want IPv4 only", option)
		}
	})

	t.Run("normalize AAAA", func(t *testing.T) {
		queryType, reqType, option, ok := resolveDNSQueryType("  aAaA ")
		if !ok {
			t.Fatal("expected AAAA type to be supported")
		}
		if queryType != "AAAA" {
			t.Fatalf("queryType = %q, want %q", queryType, "AAAA")
		}
		if reqType != dnsmessage.TypeAAAA {
			t.Fatalf("reqType = %v, want %v", reqType, dnsmessage.TypeAAAA)
		}
		if option.IPv4Enable || !option.IPv6Enable {
			t.Fatalf("option = %+v, want IPv6 only", option)
		}
	})

	t.Run("support TXT", func(t *testing.T) {
		queryType, reqType, option, ok := resolveDNSQueryType("txt")
		if !ok {
			t.Fatal("expected TXT to be supported")
		}
		if queryType != "TXT" || reqType != dnsmessage.TypeTXT {
			t.Fatalf("resolved TXT mismatch: queryType=%q reqType=%v", queryType, reqType)
		}
		if !option.IPv4Enable || !option.IPv6Enable {
			t.Fatalf("option = %+v, want dual-stack enabled", option)
		}
	})

	t.Run("reject unknown", func(t *testing.T) {
		queryType, reqType, option, ok := resolveDNSQueryType("RANDOMTYPE")
		if ok {
			t.Fatalf("expected unknown type to be unsupported, got queryType=%q reqType=%v option=%+v", queryType, reqType, option)
		}
	})
}
