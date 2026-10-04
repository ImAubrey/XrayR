package dns

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestRRCacheRespectsSizeLimit(t *testing.T) {
	c := NewCacheController("rr-limit", false, true, 0)
	c.SetCacheSizeLimit(2048)

	for i := 0; i < 32; i++ {
		domain := Fqdn(fmt.Sprintf("rr-%d.example.com", i))
		req := &dnsRequest{
			reqType: dnsmessage.TypeTXT,
			domain:  domain,
			start:   time.Now(),
		}
		rec := &RRRecord{
			ReqID:  uint16(i + 1),
			Values: []string{strings.Repeat("x", 96)},
			Expire: time.Now().Add(30 * time.Minute),
			RCode:  dnsmessage.RCodeSuccess,
		}
		c.updateRRRecord(req, rec)
	}

	c.RLock()
	defer c.RUnlock()

	if c.cacheSizeBytes > c.cacheSizeLimit {
		t.Fatalf("rr cache over limit: usage=%d limit=%d", c.cacheSizeBytes, c.cacheSizeLimit)
	}
	if len(c.rr) == 0 {
		t.Fatal("rr cache unexpectedly empty after updates")
	}
	if len(c.rr) >= 32 {
		t.Fatalf("rr cache did not evict under pressure, entries=%d", len(c.rr))
	}
}

func TestCacheCleanupRemovesExpiredRRRecords(t *testing.T) {
	c := NewCacheController("rr-clean", false, true, 0)
	c.SetCacheSizeLimit(1 << 20)

	domain := Fqdn("expired.example.com")
	req := &dnsRequest{
		reqType: dnsmessage.TypeTXT,
		domain:  domain,
		start:   time.Now(),
	}
	rec := &RRRecord{
		ReqID:  1,
		Values: []string{"stale"},
		Expire: time.Now().Add(-time.Minute),
		RCode:  dnsmessage.RCodeSuccess,
	}

	c.updateRRRecord(req, rec)

	if err := c.CacheCleanup(); err != nil {
		t.Fatalf("cache cleanup failed: %v", err)
	}

	if got := c.findRRRecord(domain, dnsmessage.TypeTXT); got != nil {
		t.Fatalf("expected expired rr cache record to be removed, got %+v", got)
	}
	if c.cacheSizeBytes != 0 {
		t.Fatalf("expected cache usage to be zero after cleanup, got %d", c.cacheSizeBytes)
	}
}
