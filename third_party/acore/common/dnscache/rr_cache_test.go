package dnscache

import (
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
)

func packMsg(t *testing.T, id uint16, domain string, qType uint16, rr mdns.RR) []byte {
	t.Helper()
	m := new(mdns.Msg)
	m.SetReply(&mdns.Msg{
		MsgHdr: mdns.MsgHdr{Id: id, RecursionDesired: true},
		Question: []mdns.Question{{
			Name:   mdns.Fqdn(domain),
			Qtype:  qType,
			Qclass: mdns.ClassINET,
		}},
	})
	if rr != nil {
		m.Answer = []mdns.RR{rr}
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack msg: %v", err)
	}
	return raw
}

func TestRRCacheStoreAndServe(t *testing.T) {
	c := NewRRCache(8)
	const ns = "test-ns"
	raw := packMsg(t, 1, "x.example", mdns.TypeTXT, &mdns.TXT{
		Hdr: mdns.RR_Header{Name: mdns.Fqdn("x.example"), Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 5},
		Txt: []string{"ok"},
	})
	if !c.StorePacked(ns, raw, time.Now()) {
		t.Fatal("store failed")
	}
	out, ok := c.TryServe(ns, 2, dnsmessage.TypeTXT, dnsmessage.ClassINET, "x.example.", time.Now())
	if !ok || len(out) == 0 {
		t.Fatal("serve failed")
	}
	var m mdns.Msg
	if err := m.Unpack(out); err != nil {
		t.Fatalf("unpack out: %v", err)
	}
	if m.Id != 2 {
		t.Fatalf("id = %d, want 2", m.Id)
	}
}

func TestRRCacheServeStaleTTL1(t *testing.T) {
	c := NewRRCache(8)
	const ns = "test-ns"
	raw := packMsg(t, 1, "stale.example", mdns.TypeTXT, &mdns.TXT{
		Hdr: mdns.RR_Header{Name: mdns.Fqdn("stale.example"), Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 1},
		Txt: []string{"s"},
	})
	if !c.StorePacked(ns, raw, time.Now().Add(-2*time.Second)) {
		t.Fatal("store failed")
	}
	out, ok := c.TryServe(ns, 3, dnsmessage.TypeTXT, dnsmessage.ClassINET, "stale.example.", time.Now())
	if !ok {
		t.Fatal("serve stale failed")
	}
	var m mdns.Msg
	if err := m.Unpack(out); err != nil {
		t.Fatalf("unpack stale out: %v", err)
	}
	if len(m.Answer) == 0 || m.Answer[0].Header().Ttl != 1 {
		t.Fatalf("ttl = %v, want 1", m.Answer)
	}
}
