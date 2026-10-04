package dns

import (
	"context"
	"math"
	"testing"
	"time"

	xnet "github.com/ImAubrey/acore/common/net"
	feature_dns "github.com/ImAubrey/acore/features/dns"
)

type cacheStatsServerStub struct {
	controller *CacheController
}

func (s *cacheStatsServerStub) Name() string {
	return "stub"
}

func (s *cacheStatsServerStub) IsDisableCache() bool {
	return false
}

func (s *cacheStatsServerStub) QueryIP(context.Context, string, feature_dns.IPOption) ([]xnet.IP, uint32, error) {
	return nil, 0, feature_dns.ErrEmptyResponse
}

func (s *cacheStatsServerStub) getCacheController() *CacheController {
	return s.controller
}

func TestGetCacheStatsAggregatesForwardAndReverse(t *testing.T) {
	now := time.Now()
	controller := NewCacheController("UDP://1.1.1.1", false, true, 0)
	controller.Lock()
	controller.ips["example.com"] = &record{
		A: &IPRecord{
			IP:     []xnet.IP{xnet.ParseIP("1.1.1.1")},
			Expire: now.Add(2 * time.Minute),
		},
		AAAA: &IPRecord{
			IP:     []xnet.IP{xnet.ParseIP("2001:4860:4860::8888")},
			Expire: now.Add(-2 * time.Minute),
		},
	}
	controller.cacheSizeLimit = 4 * 1024
	controller.recomputeCacheSizeLocked()
	controller.Unlock()

	server := &DNS{
		clients: []*Client{
			{
				server: &cacheStatsServerStub{controller: controller},
			},
		},
		cachePerStoreBytes: 2 * 1024,
		ipDomainCache: map[string]ipDomainCacheEntry{
			"1.1.1.1": {
				domain: "example.com",
				expire: now.Add(2 * time.Minute),
			},
			"2001:4860:4860::8888": {
				domain: "example.com",
				expire: now.Add(-2 * time.Minute),
			},
		},
	}

	stats := server.GetCacheStats()
	if stats.EntryCount != 4 {
		t.Fatalf("entry_count = %d, want 4", stats.EntryCount)
	}
	if stats.ValidCount != 2 {
		t.Fatalf("valid_count = %d, want 2", stats.ValidCount)
	}
	if stats.ExpiredCount != 2 {
		t.Fatalf("expired_count = %d, want 2", stats.ExpiredCount)
	}
	if math.Abs(stats.ValidRatio-0.5) > 0.0001 {
		t.Fatalf("valid_ratio = %f, want 0.5", stats.ValidRatio)
	}
	if math.Abs(stats.ExpiredRatio-0.5) > 0.0001 {
		t.Fatalf("expired_ratio = %f, want 0.5", stats.ExpiredRatio)
	}
	if stats.UsageBytes <= 0 {
		t.Fatalf("usage_bytes = %d, want > 0", stats.UsageBytes)
	}
	if len(stats.Stores) != 2 {
		t.Fatalf("stores = %d, want 2", len(stats.Stores))
	}
}
