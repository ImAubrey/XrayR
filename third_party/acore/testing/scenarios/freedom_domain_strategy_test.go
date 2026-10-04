package scenarios

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/ImAubrey/acore/app/dns"
	"github.com/ImAubrey/acore/app/proxyman"
	"github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/units"
	core "github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/proxy/blackhole"
	"github.com/ImAubrey/acore/proxy/freedom"
	"github.com/ImAubrey/acore/proxy/socks"
	"github.com/ImAubrey/acore/testing/servers/tcp"
	"github.com/ImAubrey/acore/transport/internet"
	xproxy "golang.org/x/net/proxy"
)

// DomainStrategyTestCase represents a test case for DomainStrategy
type DomainStrategyTestCase struct {
	Name           string
	Strategy       internet.DomainStrategy
	ExpectResolve  bool   // Whether domain should be resolved to IP
	ExpectIPv4     bool   // Whether IPv4 resolution is expected
	ExpectIPv6     bool   // Whether IPv6 resolution is expected
	ExpectFallback bool   // Whether fallback is expected
	ForceIP        bool   // Whether ForceIP mode
	Description    string // Human readable description
}

// DomainStrategyMetrics holds metrics for domain strategy tests
type DomainStrategyMetrics struct {
	TestName       string
	Strategy       internet.DomainStrategy
	StartTime      time.Time
	Duration       time.Duration
	MemAlloc       uint64
	Success        bool
	ResolvedTo     string
	ExpectedResult string
	Error          error
}

func (m *DomainStrategyMetrics) Report(t *testing.T) {
	status := "PASS"
	if !m.Success {
		status = "FAIL"
	}
	t.Logf("[%s] %s (Strategy: %v) - Duration: %v, Mem: %s",
		status, m.TestName, m.Strategy, m.Duration,
		units.ByteSize(m.MemAlloc).String())
	if m.ResolvedTo != "" {
		t.Logf("  Resolved to: %s, Expected: %s", m.ResolvedTo, m.ExpectedResult)
	}
	if m.Error != nil {
		t.Logf("  Error: %v", m.Error)
	}
}

// TestDomainStrategyMethods tests the DomainStrategy helper methods
func TestDomainStrategyMethods(t *testing.T) {
	testCases := []DomainStrategyTestCase{
		{
			Name:           "AS_IS",
			Strategy:       internet.DomainStrategy_AS_IS,
			ExpectResolve:  false,
			ExpectIPv4:     false,
			ExpectIPv6:     false,
			ExpectFallback: false,
			ForceIP:        false,
			Description:    "No resolution, pass domain as-is",
		},
		{
			Name:           "USE_IP",
			Strategy:       internet.DomainStrategy_USE_IP,
			ExpectResolve:  true,
			ExpectIPv4:     true,
			ExpectIPv6:     true,
			ExpectFallback: false,
			ForceIP:        false,
			Description:    "Resolve to IP (both IPv4 and IPv6), no fallback",
		},
		{
			Name:           "USE_IP4",
			Strategy:       internet.DomainStrategy_USE_IP4,
			ExpectResolve:  true,
			ExpectIPv4:     true,
			ExpectIPv6:     false,
			ExpectFallback: false,
			ForceIP:        false,
			Description:    "Prefer IPv4 resolution",
		},
		{
			Name:           "USE_IP6",
			Strategy:       internet.DomainStrategy_USE_IP6,
			ExpectResolve:  true,
			ExpectIPv4:     false,
			ExpectIPv6:     true,
			ExpectFallback: false,
			ForceIP:        false,
			Description:    "Prefer IPv6 resolution",
		},
		{
			Name:           "USE_IP46",
			Strategy:       internet.DomainStrategy_USE_IP46,
			ExpectResolve:  true,
			ExpectIPv4:     true,
			ExpectIPv6:     true,
			ExpectFallback: true,
			ForceIP:        false,
			Description:    "Prefer IPv4, fallback to IPv6",
		},
		{
			Name:           "USE_IP64",
			Strategy:       internet.DomainStrategy_USE_IP64,
			ExpectResolve:  true,
			ExpectIPv4:     true,
			ExpectIPv6:     true,
			ExpectFallback: true,
			ForceIP:        false,
			Description:    "Prefer IPv6, fallback to IPv4",
		},
		{
			Name:           "FORCE_IP",
			Strategy:       internet.DomainStrategy_FORCE_IP,
			ExpectResolve:  true,
			ExpectIPv4:     true,
			ExpectIPv6:     true,
			ExpectFallback: false,
			ForceIP:        true,
			Description:    "Force resolve to IP, fail if cannot resolve",
		},
		{
			Name:           "FORCE_IP4",
			Strategy:       internet.DomainStrategy_FORCE_IP4,
			ExpectResolve:  true,
			ExpectIPv4:     true,
			ExpectIPv6:     false,
			ExpectFallback: false,
			ForceIP:        true,
			Description:    "Force resolve to IPv4 only",
		},
		{
			Name:           "FORCE_IP6",
			Strategy:       internet.DomainStrategy_FORCE_IP6,
			ExpectResolve:  true,
			ExpectIPv4:     false,
			ExpectIPv6:     true,
			ExpectFallback: false,
			ForceIP:        true,
			Description:    "Force resolve to IPv6 only",
		},
		{
			Name:           "FORCE_IP46",
			Strategy:       internet.DomainStrategy_FORCE_IP46,
			ExpectResolve:  true,
			ExpectIPv4:     true,
			ExpectIPv6:     true,
			ExpectFallback: true,
			ForceIP:        true,
			Description:    "Force resolve, prefer IPv4 with IPv6 fallback",
		},
		{
			Name:           "FORCE_IP64",
			Strategy:       internet.DomainStrategy_FORCE_IP64,
			ExpectResolve:  true,
			ExpectIPv4:     true,
			ExpectIPv6:     true,
			ExpectFallback: true,
			ForceIP:        true,
			Description:    "Force resolve, prefer IPv6 with IPv4 fallback",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Test HasStrategy()
			hasStrategy := tc.Strategy.HasStrategy()
			if hasStrategy != tc.ExpectResolve {
				t.Errorf("HasStrategy() = %v, expected %v for %s", hasStrategy, tc.ExpectResolve, tc.Name)
			}

			// Test ForceIP()
			forceIP := tc.Strategy.ForceIP()
			if forceIP != tc.ForceIP {
				t.Errorf("ForceIP() = %v, expected %v for %s", forceIP, tc.ForceIP, tc.Name)
			}

			// Test PreferIP4()
			preferIP4 := tc.Strategy.PreferIP4()
			// PreferIP4 returns true when strategy[s][1] is 4 or 0 (both)

			// Test PreferIP6()
			preferIP6 := tc.Strategy.PreferIP6()
			// PreferIP6 returns true when strategy[s][1] is 6 or 0 (both)

			// Test HasFallback()
			hasFallback := tc.Strategy.HasFallback()
			if hasFallback != tc.ExpectFallback {
				t.Errorf("HasFallback() = %v, expected %v for %s", hasFallback, tc.ExpectFallback, tc.Name)
			}

			t.Logf("Strategy %s (%s): HasStrategy=%v, ForceIP=%v, PreferIP4=%v, PreferIP6=%v, HasFallback=%v",
				tc.Name, tc.Description, hasStrategy, forceIP, preferIP4, preferIP6, hasFallback)
		})
	}
}

// TestGetDynamicStrategy tests the GetDynamicStrategy method
func TestGetDynamicStrategy(t *testing.T) {
	testCases := []struct {
		Name           string
		Strategy       internet.DomainStrategy
		AddressFamily  net.AddressFamily
		ExpectedResult internet.DomainStrategy
	}{
		// USE_IP dynamic strategies
		{"USE_IP_with_IPv4", internet.DomainStrategy_USE_IP, net.AddressFamilyIPv4, internet.DomainStrategy_USE_IP46},
		{"USE_IP_with_IPv6", internet.DomainStrategy_USE_IP, net.AddressFamilyIPv6, internet.DomainStrategy_USE_IP64},
		{"USE_IP_with_Domain", internet.DomainStrategy_USE_IP, net.AddressFamilyDomain, internet.DomainStrategy_USE_IP},

		// FORCE_IP dynamic strategies
		{"FORCE_IP_with_IPv4", internet.DomainStrategy_FORCE_IP, net.AddressFamilyIPv4, internet.DomainStrategy_FORCE_IP46},
		{"FORCE_IP_with_IPv6", internet.DomainStrategy_FORCE_IP, net.AddressFamilyIPv6, internet.DomainStrategy_FORCE_IP64},
		{"FORCE_IP_with_Domain", internet.DomainStrategy_FORCE_IP, net.AddressFamilyDomain, internet.DomainStrategy_FORCE_IP},

		// Other strategies should remain unchanged
		{"AS_IS_with_IPv4", internet.DomainStrategy_AS_IS, net.AddressFamilyIPv4, internet.DomainStrategy_AS_IS},
		{"USE_IP4_with_IPv6", internet.DomainStrategy_USE_IP4, net.AddressFamilyIPv6, internet.DomainStrategy_USE_IP4},
		{"USE_IP6_with_IPv4", internet.DomainStrategy_USE_IP6, net.AddressFamilyIPv4, internet.DomainStrategy_USE_IP6},
		{"USE_IP46_with_IPv4", internet.DomainStrategy_USE_IP46, net.AddressFamilyIPv4, internet.DomainStrategy_USE_IP46},
		{"USE_IP64_with_IPv6", internet.DomainStrategy_USE_IP64, net.AddressFamilyIPv6, internet.DomainStrategy_USE_IP64},
		{"FORCE_IP4_with_IPv6", internet.DomainStrategy_FORCE_IP4, net.AddressFamilyIPv6, internet.DomainStrategy_FORCE_IP4},
		{"FORCE_IP6_with_IPv4", internet.DomainStrategy_FORCE_IP6, net.AddressFamilyIPv4, internet.DomainStrategy_FORCE_IP6},
		{"FORCE_IP46_with_IPv4", internet.DomainStrategy_FORCE_IP46, net.AddressFamilyIPv4, internet.DomainStrategy_FORCE_IP46},
		{"FORCE_IP64_with_IPv6", internet.DomainStrategy_FORCE_IP64, net.AddressFamilyIPv6, internet.DomainStrategy_FORCE_IP64},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := tc.Strategy.GetDynamicStrategy(tc.AddressFamily)
			if result != tc.ExpectedResult {
				t.Errorf("GetDynamicStrategy(%v, %v) = %v, expected %v",
					tc.Strategy, tc.AddressFamily, result, tc.ExpectedResult)
			}
		})
	}
}

// TestFreedomDomainStrategyASIS tests AS_IS strategy (no resolution)
func TestFreedomDomainStrategyASIS(t *testing.T) {
	metrics := &DomainStrategyMetrics{
		TestName:  "Freedom_AS_IS",
		Strategy:  internet.DomainStrategy_AS_IS,
		StartTime: time.Now(),
	}
	defer func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		metrics.MemAlloc = m.Alloc
		metrics.Duration = time.Since(metrics.StartTime)
		metrics.Report(t)
	}()

	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_AS_IS,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}

	// Connect directly using IP (AS_IS should pass through)
	conn, err := dialer.Dial("tcp", dest.NetAddr())
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}
	defer conn.Close()

	testErr := testTCPConn2(conn, 1024, time.Second*5)()
	metrics.Success = testErr == nil
	metrics.Error = testErr
	if testErr != nil {
		t.Error(testErr)
	}
}

// TestFreedomDomainStrategyUSEIP tests USE_IP strategy with DNS resolution
func TestFreedomDomainStrategyUSEIP(t *testing.T) {
	metrics := &DomainStrategyMetrics{
		TestName:  "Freedom_USE_IP",
		Strategy:  internet.DomainStrategy_USE_IP,
		StartTime: time.Now(),
	}
	defer func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		metrics.MemAlloc = m.Alloc
		metrics.Duration = time.Since(metrics.StartTime)
		metrics.Report(t)
	}()

	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dns.Config{
				StaticHosts: []*dns.Config_HostMapping{
					{
						Type:   dns.DomainMatchingType_Full,
						Domain: "test.local",
						Ip:     [][]byte{dest.Address.IP()},
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				DomainStrategy: router.Config_IpIfNonMatch,
				Rule: []*router.RoutingRule{
					{
						Geoip: []*router.GeoIP{
							{
								Cidr: []*router.CIDR{
									{
										Ip:     []byte{127, 0, 0, 0},
										Prefix: 8,
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
			{
				Tag: "direct",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_USE_IP,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}

	// Connect using domain name (USE_IP should resolve it)
	conn, err := dialer.Dial("tcp", fmt.Sprintf("test.local:%d", dest.Port))
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}
	defer conn.Close()

	testErr := testTCPConn2(conn, 1024, time.Second*5)()
	metrics.Success = testErr == nil
	metrics.Error = testErr
	metrics.ResolvedTo = "test.local -> " + dest.Address.String()
	metrics.ExpectedResult = "Resolved to IP"
	if testErr != nil {
		t.Error(testErr)
	}
}

// TestFreedomDomainStrategyFORCEIP tests FORCE_IP strategy
func TestFreedomDomainStrategyFORCEIP(t *testing.T) {
	metrics := &DomainStrategyMetrics{
		TestName:  "Freedom_FORCE_IP",
		Strategy:  internet.DomainStrategy_FORCE_IP,
		StartTime: time.Now(),
	}
	defer func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		metrics.MemAlloc = m.Alloc
		metrics.Duration = time.Since(metrics.StartTime)
		metrics.Report(t)
	}()

	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dns.Config{
				StaticHosts: []*dns.Config_HostMapping{
					{
						Type:   dns.DomainMatchingType_Full,
						Domain: "forceip.local",
						Ip:     [][]byte{dest.Address.IP()},
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				DomainStrategy: router.Config_IpIfNonMatch,
				Rule: []*router.RoutingRule{
					{
						Geoip: []*router.GeoIP{
							{
								Cidr: []*router.CIDR{
									{
										Ip:     []byte{127, 0, 0, 0},
										Prefix: 8,
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
			{
				Tag: "direct",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_FORCE_IP,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}

	// Connect using domain name (FORCE_IP should resolve it)
	conn, err := dialer.Dial("tcp", fmt.Sprintf("forceip.local:%d", dest.Port))
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}
	defer conn.Close()

	testErr := testTCPConn2(conn, 1024, time.Second*5)()
	metrics.Success = testErr == nil
	metrics.Error = testErr
	metrics.ResolvedTo = "forceip.local -> " + dest.Address.String()
	metrics.ExpectedResult = "Force resolved to IP"
	if testErr != nil {
		t.Error(testErr)
	}
}

// TestFreedomDomainStrategyUSEIP4 tests USE_IP4 strategy (IPv4 preferred)
func TestFreedomDomainStrategyUSEIP4(t *testing.T) {
	metrics := &DomainStrategyMetrics{
		TestName:  "Freedom_USE_IP4",
		Strategy:  internet.DomainStrategy_USE_IP4,
		StartTime: time.Now(),
	}
	defer func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		metrics.MemAlloc = m.Alloc
		metrics.Duration = time.Since(metrics.StartTime)
		metrics.Report(t)
	}()

	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dns.Config{
				StaticHosts: []*dns.Config_HostMapping{
					{
						Type:   dns.DomainMatchingType_Full,
						Domain: "ipv4.local",
						Ip:     [][]byte{dest.Address.IP()}, // IPv4 address
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				DomainStrategy: router.Config_IpIfNonMatch,
				Rule: []*router.RoutingRule{
					{
						Geoip: []*router.GeoIP{
							{
								Cidr: []*router.CIDR{
									{
										Ip:     []byte{127, 0, 0, 0},
										Prefix: 8,
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
			{
				Tag: "direct",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_USE_IP4,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("ipv4.local:%d", dest.Port))
	if err != nil {
		metrics.Success = false
		metrics.Error = err
		t.Fatal(err)
	}
	defer conn.Close()

	testErr := testTCPConn2(conn, 1024, time.Second*5)()
	metrics.Success = testErr == nil
	metrics.Error = testErr
	metrics.ResolvedTo = "ipv4.local -> " + dest.Address.String()
	metrics.ExpectedResult = "Resolved to IPv4"
	if testErr != nil {
		t.Error(testErr)
	}
}

// TestAllDomainStrategiesWithConnection runs connection tests for all strategies
func TestAllDomainStrategiesWithConnection(t *testing.T) {
	strategies := []internet.DomainStrategy{
		internet.DomainStrategy_AS_IS,
		internet.DomainStrategy_USE_IP,
		internet.DomainStrategy_USE_IP4,
		internet.DomainStrategy_USE_IP6,
		internet.DomainStrategy_USE_IP46,
		internet.DomainStrategy_USE_IP64,
		internet.DomainStrategy_FORCE_IP,
		internet.DomainStrategy_FORCE_IP4,
		internet.DomainStrategy_FORCE_IP6,
		internet.DomainStrategy_FORCE_IP46,
		internet.DomainStrategy_FORCE_IP64,
	}

	for _, strategy := range strategies {
		t.Run(strategy.String(), func(t *testing.T) {
			tcpServer := tcp.Server{
				MsgProcessor: xor,
			}
			dest, err := tcpServer.Start()
			if err != nil {
				t.Fatal(err)
			}
			defer tcpServer.Close()

			serverPort := tcp.PickPort()

			// For strategies that require DNS resolution, set up DNS config
			var appConfig []*serial.TypedMessage
			if strategy.HasStrategy() {
				appConfig = []*serial.TypedMessage{
					serial.ToTypedMessage(&dns.Config{
						StaticHosts: []*dns.Config_HostMapping{
							{
								Type:   dns.DomainMatchingType_Full,
								Domain: "strategy-test.local",
								Ip:     [][]byte{dest.Address.IP()},
							},
						},
					}),
					serial.ToTypedMessage(&router.Config{
						DomainStrategy: router.Config_IpIfNonMatch,
						Rule: []*router.RoutingRule{
							{
								Geoip: []*router.GeoIP{
									{
										Cidr: []*router.CIDR{
											{
												Ip:     []byte{127, 0, 0, 0},
												Prefix: 8,
											},
										},
									},
								},
								TargetTag: &router.RoutingRule_Tag{
									Tag: "direct",
								},
							},
						},
					}),
				}
			}

			serverConfig := &core.Config{
				App: appConfig,
				Inbound: []*core.InboundHandlerConfig{
					{
						ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
							PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
							Listen:   net.NewIPOrDomain(net.LocalHostIP),
						}),
						ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
							AuthType: socks.AuthType_NO_AUTH,
						}),
					},
				},
				Outbound: []*core.OutboundHandlerConfig{
					{
						ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
					},
					{
						Tag: "direct",
						ProxySettings: serial.ToTypedMessage(&freedom.Config{
							DomainStrategy: strategy,
						}),
					},
				},
			}

			servers, err := InitializeServerConfigs(serverConfig)
			if err != nil {
				t.Fatalf("Failed to initialize server for strategy %v: %v", strategy, err)
			}
			defer CloseAllServers(servers)

			dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), nil, xproxy.Direct)
			if err != nil {
				t.Fatal(err)
			}

			// For AS_IS, use IP directly; for others, use domain
			var target string
			if strategy == internet.DomainStrategy_AS_IS {
				target = dest.NetAddr()
			} else {
				target = fmt.Sprintf("strategy-test.local:%d", dest.Port)
			}

			conn, err := dialer.Dial("tcp", target)
			if err != nil {
				// IPv6-only strategies might fail in IPv4-only environments
				if strategy == internet.DomainStrategy_USE_IP6 ||
					strategy == internet.DomainStrategy_FORCE_IP6 {
					t.Skipf("Skipping IPv6 strategy test (might not have IPv6 support): %v", err)
				}
				t.Fatalf("Failed to connect with strategy %v: %v", strategy, err)
			}
			defer conn.Close()

			if err := testTCPConn2(conn, 1024, time.Second*5)(); err != nil {
				t.Errorf("Connection test failed for strategy %v: %v", strategy, err)
			}

			t.Logf("Strategy %v: Connection successful", strategy)
		})
	}
}

// BenchmarkDomainStrategies benchmarks different domain strategies
func BenchmarkDomainStrategies(b *testing.B) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	if err != nil {
		b.Fatal(err)
	}
	defer tcpServer.Close()

	strategies := []internet.DomainStrategy{
		internet.DomainStrategy_AS_IS,
		internet.DomainStrategy_USE_IP,
		internet.DomainStrategy_USE_IP4,
	}

	for _, strategy := range strategies {
		b.Run(strategy.String(), func(b *testing.B) {
			serverPort := tcp.PickPort()

			serverConfig := &core.Config{
				App: []*serial.TypedMessage{
					serial.ToTypedMessage(&dns.Config{
						StaticHosts: []*dns.Config_HostMapping{
							{
								Type:   dns.DomainMatchingType_Full,
								Domain: "bench.local",
								Ip:     [][]byte{dest.Address.IP()},
							},
						},
					}),
				},
				Inbound: []*core.InboundHandlerConfig{
					{
						ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
							PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
							Listen:   net.NewIPOrDomain(net.LocalHostIP),
						}),
						ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
							AuthType: socks.AuthType_NO_AUTH,
						}),
					},
				},
				Outbound: []*core.OutboundHandlerConfig{
					{
						ProxySettings: serial.ToTypedMessage(&freedom.Config{
							DomainStrategy: strategy,
						}),
					},
				},
			}

			servers, err := InitializeServerConfigs(serverConfig)
			if err != nil {
				b.Fatal(err)
			}
			defer CloseAllServers(servers)

			dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), nil, xproxy.Direct)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var target string
				if strategy == internet.DomainStrategy_AS_IS {
					target = dest.NetAddr()
				} else {
					target = fmt.Sprintf("bench.local:%d", dest.Port)
				}

				conn, err := dialer.Dial("tcp", target)
				if err != nil {
					b.Error(err)
					continue
				}
				if err := testTCPConn2(conn, 1024, time.Second*5)(); err != nil {
					b.Error(err)
				}
				conn.Close()
			}
		})
	}
}

// TestFreedomConfigBuilder tests freedom config building with various DomainStrategy values
func TestFreedomConfigBuilder(t *testing.T) {
	testCases := []struct {
		Name     string
		Strategy internet.DomainStrategy
	}{
		{"AS_IS", internet.DomainStrategy_AS_IS},
		{"USE_IP", internet.DomainStrategy_USE_IP},
		{"USE_IP4", internet.DomainStrategy_USE_IP4},
		{"USE_IP6", internet.DomainStrategy_USE_IP6},
		{"USE_IP46", internet.DomainStrategy_USE_IP46},
		{"USE_IP64", internet.DomainStrategy_USE_IP64},
		{"FORCE_IP", internet.DomainStrategy_FORCE_IP},
		{"FORCE_IP4", internet.DomainStrategy_FORCE_IP4},
		{"FORCE_IP6", internet.DomainStrategy_FORCE_IP6},
		{"FORCE_IP46", internet.DomainStrategy_FORCE_IP46},
		{"FORCE_IP64", internet.DomainStrategy_FORCE_IP64},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			config := &freedom.Config{
				DomainStrategy: tc.Strategy,
			}

			serverConfig := withDefaultApps(&core.Config{
				Outbound: []*core.OutboundHandlerConfig{
					{
						ProxySettings: serial.ToTypedMessage(config),
					},
				},
			})

			// Verify the config can be registered and created
			instance, err := core.New(serverConfig)
			if err != nil {
				t.Fatalf("Failed to create freedom handler with strategy %v: %v", tc.Strategy, err)
			}
			if instance != nil {
				_ = instance.Close()
			}

			if instance == nil {
				t.Fatalf("Instance is nil for strategy %v", tc.Strategy)
			}

			t.Logf("Successfully created instance with strategy %v", tc.Strategy)
		})
	}
}
