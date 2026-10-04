package dns

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/net"
	feature_dns "github.com/ImAubrey/acore/features/dns"
)

func TestLookupDomainByIPFromStaticHost(t *testing.T) {
	server, err := New(context.Background(), &Config{
		QueryStrategy: QueryStrategy_USE_IP,
		StaticHosts: []*Config_HostMapping{
			{
				Type:   DomainMatchingType_Full,
				Domain: "cached.example",
				Ip:     [][]byte{{203, 0, 113, 8}},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	ips, _, err := server.LookupIP("cached.example", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	if err != nil {
		t.Fatalf("LookupIP() failed: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 ip, got %d", len(ips))
	}

	domain, ok := server.LookupDomainByIP(ips[0])
	if !ok {
		t.Fatal("expected reverse lookup hit from DNS cache")
	}
	if domain != "cached.example" {
		t.Fatalf("expected cached.example, got %q", domain)
	}
}

func TestLookupDomainByIPMiss(t *testing.T) {
	server, err := New(context.Background(), &Config{
		QueryStrategy: QueryStrategy_USE_IP,
	})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	if _, ok := server.LookupDomainByIP(net.ParseIP("203.0.113.10")); ok {
		t.Fatal("expected reverse lookup miss")
	}
}

func TestLookupDomainByIPFromStaticHostMultipleIPs(t *testing.T) {
	server, err := New(context.Background(), &Config{
		QueryStrategy: QueryStrategy_USE_IP,
		StaticHosts: []*Config_HostMapping{
			{
				Type:   DomainMatchingType_Full,
				Domain: "multi.example",
				Ip: [][]byte{
					{203, 0, 113, 11},
					{203, 0, 113, 12},
					{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	ips, _, err := server.LookupIP("multi.example", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	if err != nil {
		t.Fatalf("LookupIP() failed: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("expected 3 ips, got %d", len(ips))
	}

	for _, ip := range ips {
		domain, ok := server.LookupDomainByIP(ip)
		if !ok {
			t.Fatalf("expected reverse lookup hit for ip %s", ip.String())
		}
		if domain != "multi.example" {
			t.Fatalf("expected multi.example for ip %s, got %q", ip.String(), domain)
		}
	}
}

func TestLookupDomainByIPServeStale(t *testing.T) {
	server, err := New(context.Background(), &Config{
		QueryStrategy:   QueryStrategy_USE_IP,
		ServeStale:      true,
		ServeExpiredTTL: 60,
		StaticHosts: []*Config_HostMapping{
			{
				Type:   DomainMatchingType_Full,
				Domain: "stale.example",
				Ip:     [][]byte{{203, 0, 113, 66}},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	ips, _, err := server.LookupIP("stale.example", feature_dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	if err != nil {
		t.Fatalf("LookupIP() failed: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 ip, got %d", len(ips))
	}

	key := ipDomainCacheKey(ips[0])
	server.ipDomainCacheMu.Lock()
	entry := server.ipDomainCache[key]
	entry.expire = time.Now().Add(-5 * time.Second) // stale window hit (within ServeExpiredTTL)
	server.ipDomainCache[key] = entry
	server.ipDomainCacheMu.Unlock()

	if domain, ok := server.LookupDomainByIP(ips[0]); !ok || domain != "stale.example" {
		t.Fatalf("expected stale reverse hit, got domain=%q ok=%v", domain, ok)
	}

	server.ipDomainCacheMu.Lock()
	entry = server.ipDomainCache[key]
	entry.expire = time.Now().Add(-65 * time.Second) // stale window miss
	server.ipDomainCache[key] = entry
	server.ipDomainCacheMu.Unlock()

	if _, ok := server.LookupDomainByIP(ips[0]); ok {
		t.Fatal("expected stale reverse miss after ServeExpiredTTL")
	}
}

func TestLookupDomainByIPCacheSizeLimit(t *testing.T) {
	server, err := New(context.Background(), &Config{
		QueryStrategy: QueryStrategy_USE_IP,
	})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}

	server.ipDomainCacheMu.Lock()
	server.cachePerStoreBytes = 1024
	server.ipDomainCacheMu.Unlock()

	for i := 0; i < 512; i++ {
		ip := net.IP([]byte{198, 18, byte(i / 256), byte(i % 256)})
		domain := fmt.Sprintf("cache-limit-%d.example", i)
		server.storeIPDomainCache(domain, []net.IP{ip}, 300)
	}

	server.ipDomainCacheMu.RLock()
	defer server.ipDomainCacheMu.RUnlock()
	if server.ipDomainCacheSizeBytes > server.cachePerStoreBytes {
		t.Fatalf("expected reverse cache size <= limit, got %d > %d", server.ipDomainCacheSizeBytes, server.cachePerStoreBytes)
	}
	if len(server.ipDomainCache) == 0 {
		t.Fatal("expected reverse cache to retain some entries under size limit")
	}
}
