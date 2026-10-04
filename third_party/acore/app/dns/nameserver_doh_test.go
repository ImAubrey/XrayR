package dns_test

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	. "github.com/ImAubrey/acore/app/dns"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	dns_feature "github.com/ImAubrey/acore/features/dns"
	"github.com/google/go-cmp/cmp"
)

func skipExternalDNSTests(t *testing.T) {
	if os.Getenv("ACORE_DNS_TESTS") == "" {
		t.Skip("Skipping external DNS integration tests. Set ACORE_DNS_TESTS=1 to run.")
	}
}

func TestDOHNameServer(t *testing.T) {
	skipExternalDNSTests(t)
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, false, 0, net.IP(nil))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
}

func TestDOHNameServerWithCache(t *testing.T) {
	skipExternalDNSTests(t)
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, false, 0, net.IP(nil))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips2, _, err := s.QueryIP(ctx2, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if r := cmp.Diff(ips2, ips); r != "" {
		t.Fatal(r)
	}
}

func TestDOHNameServerWithIPv4Override(t *testing.T) {
	skipExternalDNSTests(t)
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, false, 0, net.IP(nil))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	for _, ip := range ips {
		if len(ip) != net.IPv4len {
			t.Error("expect only IPv4 response from DNS query")
		}
	}
}

func TestDOHNameServerWithIPv6Override(t *testing.T) {
	skipExternalDNSTests(t)
	url, err := url.Parse("https+local://1.1.1.1/dns-query")
	common.Must(err)

	s := NewDoHNameServer(url, nil, false, false, false, 0, net.IP(nil))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: false,
		IPv6Enable: true,
	})
	cancel()
	common.Must(err)
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	for _, ip := range ips {
		if len(ip) != net.IPv6len {
			t.Error("expect only IPv6 response from DNS query")
		}
	}
}
