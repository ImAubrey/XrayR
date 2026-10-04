package internet_test

import (
	"context"
	stdnet "net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/testing/servers/tcp"
	. "github.com/ImAubrey/acore/transport/internet"
	"github.com/google/go-cmp/cmp"
)

func TestDialWithLocalAddr(t *testing.T) {
	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	conn, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), nil)
	common.Must(err)
	if r := cmp.Diff(conn.RemoteAddr().String(), "127.0.0.1:"+dest.Port.String()); r != "" {
		t.Error(r)
	}
	conn.Close()
}

func TestDialUDPAutoDetectSourceIPWhenUnspecified(t *testing.T) {
	udpConn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{
		IP:   stdnet.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	common.Must(err)
	defer udpConn.Close()

	_, portStr, err := stdnet.SplitHostPort(udpConn.LocalAddr().String())
	common.Must(err)
	port, err := net.PortFromString(portStr)
	common.Must(err)

	// No outbound gateway specified: dialer should probe route and bind to the actual source IP.
	conn, err := DialSystem(context.Background(), net.UDPDestination(net.LocalHostIP, port), nil)
	common.Must(err)
	defer conn.Close()

	if got := conn.LocalAddr().String(); !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("unexpected UDP local addr: %s", got)
	}
}

func TestDialUDPWithConfiguredSourceIP(t *testing.T) {
	udpConn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{
		IP:   stdnet.IPv4(127, 0, 0, 1),
		Port: 0,
	})
	common.Must(err)
	defer udpConn.Close()

	_, portStr, err := stdnet.SplitHostPort(udpConn.LocalAddr().String())
	common.Must(err)
	port, err := net.PortFromString(portStr)
	common.Must(err)

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Gateway: net.ParseAddress("127.0.0.1"),
	}})
	conn, err := DialSystem(ctx, net.UDPDestination(net.LocalHostIP, port), nil)
	common.Must(err)
	defer conn.Close()

	if got := conn.LocalAddr().String(); !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("unexpected UDP local addr: %s", got)
	}
}

type testLookupDNSClient struct {
	mu    sync.Mutex
	count int
	ips   []net.IP
	ttl   uint32
	err   error
}

func (c *testLookupDNSClient) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
	if c.err != nil {
		return nil, c.ttl, c.err
	}
	return c.ips, c.ttl, nil
}

func (c *testLookupDNSClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func (c *testLookupDNSClient) Close() error      { return nil }
func (c *testLookupDNSClient) Start() error      { return nil }
func (c *testLookupDNSClient) Type() interface{} { return nil }

func TestLookupForIPCacheReuseShortTerm(t *testing.T) {
	lookupDNS := &testLookupDNSClient{
		ips: []net.IP{
			{127, 0, 0, 1},
		},
		ttl: 60,
	}
	InitSystemDialer(lookupDNS, nil, nil)
	domain := "repeat-lookup-test-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".test"

	ips, err := LookupForIPWithContext(context.Background(), domain, DomainStrategy_USE_IP, nil)
	common.Must(err)
	if len(ips) == 0 {
		t.Fatalf("unexpected empty result")
	}

	if _, err := LookupForIPWithContext(context.Background(), domain, DomainStrategy_USE_IP, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := lookupDNS.callCount(); got != 1 {
		t.Fatalf("unexpected dns query count, want=1 got=%d", got)
	}
}

var benchResolvedAddr net.Address

func BenchmarkResolvePick_LookupForIPWithContext(b *testing.B) {
	lookupDNS := &testLookupDNSClient{
		ips: []net.IP{
			{127, 0, 0, 1},
		},
		ttl: 60,
	}
	InitSystemDialer(lookupDNS, nil, nil)

	domain := "bench-resolve-pick.test"
	_, err := LookupForIPWithContext(context.Background(), domain, DomainStrategy_USE_IP, nil)
	common.Must(err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ips, err := LookupForIPWithContext(context.Background(), domain, DomainStrategy_USE_IP, nil)
		if err != nil {
			b.Fatal(err)
		}
		benchResolvedAddr = net.IPAddress(ips[0])
	}
}

func BenchmarkResolvePick_LookupForAddressPickWithContext(b *testing.B) {
	lookupDNS := &testLookupDNSClient{
		ips: []net.IP{
			{127, 0, 0, 1},
		},
		ttl: 60,
	}
	InitSystemDialer(lookupDNS, nil, nil)

	domain := "bench-resolve-pick.test"
	_, err := LookupForAddressPickWithContext(context.Background(), domain, DomainStrategy_USE_IP, nil)
	common.Must(err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr, err := LookupForAddressPickWithContext(context.Background(), domain, DomainStrategy_USE_IP, nil)
		if err != nil {
			b.Fatal(err)
		}
		benchResolvedAddr = addr
	}
}
