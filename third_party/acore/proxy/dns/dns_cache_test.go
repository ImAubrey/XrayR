package dns

import (
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/dnscache"
	dns_proto "github.com/ImAubrey/acore/common/protocol/dns"
	mdns "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

type captureWriter struct {
	raw []byte
}

func (w *captureWriter) WriteMessage(b *buf.Buffer) error {
	w.raw = append([]byte(nil), b.Bytes()...)
	b.Release()
	return nil
}

var _ dns_proto.MessageWriter = (*captureWriter)(nil)

func packTXTResponse(id uint16, domain string, txt string, ttl uint32) []byte {
	m := new(mdns.Msg)
	m.SetReply(&mdns.Msg{
		MsgHdr: mdns.MsgHdr{Id: id, RecursionDesired: true},
		Question: []mdns.Question{{
			Name:   mdns.Fqdn(domain),
			Qtype:  mdns.TypeTXT,
			Qclass: mdns.ClassINET,
		}},
	})
	m.Answer = []mdns.RR{
		&mdns.TXT{
			Hdr: mdns.RR_Header{
				Name:   mdns.Fqdn(domain),
				Rrtype: mdns.TypeTXT,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Txt: []string{txt},
		},
	}
	raw, _ := m.Pack()
	return raw
}

func TestDNSCacheStoresTXTAndServeWithUpdatedTTL(t *testing.T) {
	cache := dnscache.NewRRCache(16)
	const ns = "test-ns"
	h := &Handler{
		rrCache:        cache,
		cacheNamespace: ns,
	}
	raw := packTXTResponse(100, "example.com", "hello", 10)
	h.maybeCacheDNSResponse(raw)

	w := &captureWriter{}
	if ok := h.tryServeDNSCache(200, dnsmessage.TypeTXT, dnsmessage.ClassINET, "example.com.", w); !ok {
		t.Fatal("expected TXT cache hit")
	}

	var out mdns.Msg
	if err := out.Unpack(w.raw); err != nil {
		t.Fatalf("unpack cached response: %v", err)
	}
	if out.Id != 200 {
		t.Fatalf("id = %d, want 200", out.Id)
	}
	if len(out.Answer) == 0 || out.Answer[0].Header().Rrtype != mdns.TypeTXT {
		t.Fatalf("expected TXT answer, got %#v", out.Answer)
	}
	if gotTTL := out.Answer[0].Header().Ttl; gotTTL == 0 || gotTTL > 10 {
		t.Fatalf("unexpected ttl %d", gotTTL)
	}
}

func TestDNSCacheServeStaleAsTTL1(t *testing.T) {
	cache := dnscache.NewRRCache(16)
	const ns = "test-ns"
	h := &Handler{
		rrCache:        cache,
		cacheNamespace: ns,
	}
	raw := packTXTResponse(100, "expired.example", "stale", 1)
	h.maybeCacheDNSResponse(raw)
	time.Sleep(1100 * time.Millisecond)

	w := &captureWriter{}
	if ok := h.tryServeDNSCache(300, dnsmessage.TypeTXT, dnsmessage.ClassINET, "expired.example.", w); !ok {
		t.Fatal("expected stale TXT cache hit")
	}

	var out mdns.Msg
	if err := out.Unpack(w.raw); err != nil {
		t.Fatalf("unpack stale cached response: %v", err)
	}
	if out.Id != 300 {
		t.Fatalf("id = %d, want 300", out.Id)
	}
	if len(out.Answer) == 0 {
		t.Fatalf("expected answer")
	}
	if got := out.Answer[0].Header().Ttl; got != 1 {
		t.Fatalf("stale ttl = %d, want 1", got)
	}
}

func TestDNSCacheStoresARecord(t *testing.T) {
	cache := dnscache.NewRRCache(16)
	const ns = "test-ns"
	h := &Handler{
		rrCache:        cache,
		cacheNamespace: ns,
	}
	m := new(mdns.Msg)
	m.SetReply(&mdns.Msg{
		MsgHdr: mdns.MsgHdr{Id: 101, RecursionDesired: true},
		Question: []mdns.Question{{
			Name:   mdns.Fqdn("a.example"),
			Qtype:  mdns.TypeA,
			Qclass: mdns.ClassINET,
		}},
	})
	m.Answer = []mdns.RR{
		&mdns.A{
			Hdr: mdns.RR_Header{Name: mdns.Fqdn("a.example"), Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 8},
			A:   []byte{1, 2, 3, 4},
		},
	}
	raw, _ := m.Pack()
	h.maybeCacheDNSResponse(raw)

	w := &captureWriter{}
	if ok := h.tryServeDNSCache(202, dnsmessage.TypeA, dnsmessage.ClassINET, "a.example.", w); !ok {
		t.Fatal("expected A cache hit")
	}
	var out mdns.Msg
	if err := out.Unpack(w.raw); err != nil {
		t.Fatalf("unpack cached A response: %v", err)
	}
	if len(out.Answer) == 0 || out.Answer[0].Header().Rrtype != mdns.TypeA {
		t.Fatalf("expected A answer, got %#v", out.Answer)
	}
}

func TestDNSCacheGlobalShareAcrossHandlers(t *testing.T) {
	cache := dnscache.NewRRCache(16)
	const ns = "shared-ns"
	h1 := &Handler{rrCache: cache, cacheNamespace: ns}
	h2 := &Handler{rrCache: cache, cacheNamespace: ns}

	raw := packTXTResponse(123, "shared.example", "global", 10)
	h1.maybeCacheDNSResponse(raw)

	w := &captureWriter{}
	if ok := h2.tryServeDNSCache(321, dnsmessage.TypeTXT, dnsmessage.ClassINET, "shared.example.", w); !ok {
		t.Fatal("expected cache hit from shared global cache")
	}
}

func TestDNSCacheNamespaceIsolation(t *testing.T) {
	cache := dnscache.NewRRCache(16)
	h1 := &Handler{rrCache: cache, cacheNamespace: "ns1"}
	h2 := &Handler{rrCache: cache, cacheNamespace: "ns2"}

	raw := packTXTResponse(123, "isolated.example", "ns", 10)
	h1.maybeCacheDNSResponse(raw)

	w := &captureWriter{}
	if ok := h2.tryServeDNSCache(321, dnsmessage.TypeTXT, dnsmessage.ClassINET, "isolated.example.", w); ok {
		t.Fatal("expected cache miss across different namespaces")
	}
}
