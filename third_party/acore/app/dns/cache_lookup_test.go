package dns

import (
	"testing"
	"time"

	xnet "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/strmatcher"
	feature_dns "github.com/ImAubrey/acore/features/dns"
)

func TestLookupDomainCache_Hit(t *testing.T) {
	now := time.Now()
	controller := NewCacheController("UDP://1.1.1.1", false, true, 0)
	controller.Lock()
	controller.ips["example.com."] = &record{
		A: &IPRecord{
			IP:     []xnet.IP{xnet.ParseIP("1.1.1.1")},
			Expire: now.Add(2 * time.Minute),
		},
	}
	controller.Unlock()

	server := &DNS{
		clients: []*Client{
			{server: &cacheStatsServerStub{controller: controller}},
		},
		domainMatcher: &strmatcher.MatcherGroup{},
		matcherInfos:  []*DomainMatcherInfo{},
		hosts:         mustNewStaticHosts(t),
		ipOption: &feature_dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
		},
	}

	status := server.LookupDomainCache("example.com", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
	})
	if status.State != feature_dns.DomainCacheStateHit {
		t.Fatalf("state = %q, want %q", status.State, feature_dns.DomainCacheStateHit)
	}
	if status.TTLSeconds <= 0 {
		t.Fatalf("ttl = %d, want > 0", status.TTLSeconds)
	}
}

func TestLookupDomainCache_Expired(t *testing.T) {
	now := time.Now()
	controller := NewCacheController("UDP://1.1.1.1", false, true, 0)
	controller.Lock()
	controller.ips["stale.example."] = &record{
		A: &IPRecord{
			IP:     []xnet.IP{xnet.ParseIP("1.1.1.1")},
			Expire: now.Add(-2 * time.Minute),
		},
	}
	controller.Unlock()

	server := &DNS{
		clients: []*Client{
			{server: &cacheStatsServerStub{controller: controller}},
		},
		domainMatcher: &strmatcher.MatcherGroup{},
		matcherInfos:  []*DomainMatcherInfo{},
		hosts:         mustNewStaticHosts(t),
		ipOption: &feature_dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
		},
	}

	status := server.LookupDomainCache("stale.example", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
	})
	if status.State != feature_dns.DomainCacheStateExpired {
		t.Fatalf("state = %q, want %q", status.State, feature_dns.DomainCacheStateExpired)
	}
	if status.TTLSeconds > 0 {
		t.Fatalf("ttl = %d, want <= 0", status.TTLSeconds)
	}
}

func TestLookupDomainCache_Miss(t *testing.T) {
	controller := NewCacheController("UDP://1.1.1.1", false, true, 0)
	server := &DNS{
		clients: []*Client{
			{server: &cacheStatsServerStub{controller: controller}},
		},
		domainMatcher: &strmatcher.MatcherGroup{},
		matcherInfos:  []*DomainMatcherInfo{},
		hosts:         mustNewStaticHosts(t),
		ipOption: &feature_dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
		},
	}

	status := server.LookupDomainCache("missing.example", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
	})
	if status.State != feature_dns.DomainCacheStateMiss {
		t.Fatalf("state = %q, want %q", status.State, feature_dns.DomainCacheStateMiss)
	}
}

func mustNewStaticHosts(t *testing.T) *StaticHosts {
	t.Helper()
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatalf("NewStaticHosts failed: %v", err)
	}
	return hosts
}
