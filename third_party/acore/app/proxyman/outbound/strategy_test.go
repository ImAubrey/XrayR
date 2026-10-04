package outbound

import (
	"testing"

	"github.com/ImAubrey/acore/common/net"
)

func TestPickPreferredIP(t *testing.T) {
	ipv4 := net.ParseAddress("104.18.32.47").IP()
	ipv6 := net.ParseAddress("2a06:98c1:3100::6812:202f").IP()
	ips := []net.IP{ipv4, ipv6}

	pickedV6 := pickPreferredIP(ips, true)
	if pickedV6.To4() != nil {
		t.Fatalf("expected IPv6, got %v", pickedV6)
	}

	pickedV4 := pickPreferredIP(ips, false)
	if pickedV4.To4() == nil {
		t.Fatalf("expected IPv4, got %v", pickedV4)
	}
}
