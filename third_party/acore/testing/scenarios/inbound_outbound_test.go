package scenarios

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ImAubrey/acore/app/dispatcher"
	"github.com/ImAubrey/acore/app/policy"
	"github.com/ImAubrey/acore/app/proxyman"
	"github.com/ImAubrey/acore/app/stats"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/units"
	"github.com/ImAubrey/acore/common/uuid"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/proxy/dokodemo"
	"github.com/ImAubrey/acore/proxy/freedom"
	"github.com/ImAubrey/acore/proxy/http"
	"github.com/ImAubrey/acore/proxy/socks"
	"github.com/ImAubrey/acore/proxy/vless"
	vless_inbound "github.com/ImAubrey/acore/proxy/vless/inbound"
	vless_outbound "github.com/ImAubrey/acore/proxy/vless/outbound"
	"github.com/ImAubrey/acore/proxy/vmess"
	vmess_inbound "github.com/ImAubrey/acore/proxy/vmess/inbound"
	vmess_outbound "github.com/ImAubrey/acore/proxy/vmess/outbound"
	"github.com/ImAubrey/acore/testing/servers/tcp"
	"github.com/ImAubrey/acore/transport/internet"
	xproxy "golang.org/x/net/proxy"
)

// PerformanceMetrics holds performance monitoring data
type PerformanceMetrics struct {
	TestName      string
	StartTime     time.Time
	EndTime       time.Time
	Duration      time.Duration
	MemAllocStart uint64
	MemAllocEnd   uint64
	MemAllocDelta uint64
	NumGCStart    uint32
	NumGCEnd      uint32
	Success       bool
	Error         error
	mu            sync.Mutex
}

func NewPerformanceMetrics(name string) *PerformanceMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &PerformanceMetrics{
		TestName:      name,
		StartTime:     time.Now(),
		MemAllocStart: m.Alloc,
		NumGCStart:    m.NumGC,
	}
}

func (p *PerformanceMetrics) End(success bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	p.EndTime = time.Now()
	p.Duration = p.EndTime.Sub(p.StartTime)
	p.MemAllocEnd = m.Alloc
	p.MemAllocDelta = m.Alloc - p.MemAllocStart
	p.NumGCEnd = m.NumGC
	p.Success = success
	p.Error = err
}

func (p *PerformanceMetrics) Report(t *testing.T) {
	p.mu.Lock()
	defer p.mu.Unlock()
	status := "PASS"
	if !p.Success {
		status = "FAIL"
	}
	t.Logf("[%s] %s - Duration: %v, MemDelta: %s, GC: %d",
		status, p.TestName, p.Duration,
		units.ByteSize(p.MemAllocDelta).String(),
		p.NumGCEnd-p.NumGCStart)
	if p.Error != nil {
		t.Logf("  Error: %v", p.Error)
	}
}

// InboundType defines types of inbound proxies
type InboundType string

const (
	InboundSocks    InboundType = "socks"
	InboundHTTP     InboundType = "http"
	InboundDokodemo InboundType = "dokodemo"
)

// OutboundType defines types of outbound proxies
type OutboundType string

const (
	OutboundFreedom OutboundType = "freedom"
)

// TestCombination represents an inbound/outbound test combination
type TestCombination struct {
	Inbound  InboundType
	Outbound OutboundType
}

// createInboundConfig creates an inbound configuration based on type
func createInboundConfig(t InboundType, port net.Port, targetPort net.Port) *core.InboundHandlerConfig {
	switch t {
	case InboundSocks:
		return &core.InboundHandlerConfig{
			Tag: string(t),
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
				AuthType:   socks.AuthType_NO_AUTH,
				UdpEnabled: true,
			}),
		}
	case InboundHTTP:
		return &core.InboundHandlerConfig{
			Tag: string(t),
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&http.ServerConfig{}),
		}
	case InboundDokodemo:
		return &core.InboundHandlerConfig{
			Tag: string(t),
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				Address:  net.NewIPOrDomain(net.LocalHostIP),
				Port:     uint32(targetPort),
				Networks: []net.Network{net.Network_TCP, net.Network_UDP},
			}),
		}
	default:
		return nil
	}
}

// createOutboundConfig creates an outbound configuration based on type
func createOutboundConfig(t OutboundType, domainStrategy internet.DomainStrategy) *core.OutboundHandlerConfig {
	switch t {
	case OutboundFreedom:
		return &core.OutboundHandlerConfig{
			Tag: string(t),
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				DomainStrategy: domainStrategy,
			}),
		}
	default:
		return nil
	}
}

// TestInboundOutboundCombinations tests various inbound/outbound combinations
func TestInboundOutboundCombinations(t *testing.T) {
	// Start a TCP echo server
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	// Define test combinations
	combinations := []TestCombination{
		{Inbound: InboundSocks, Outbound: OutboundFreedom},
		{Inbound: InboundHTTP, Outbound: OutboundFreedom},
		{Inbound: InboundDokodemo, Outbound: OutboundFreedom},
	}

	for _, combo := range combinations {
		testName := fmt.Sprintf("%s_to_%s", combo.Inbound, combo.Outbound)
		t.Run(testName, func(t *testing.T) {
			metrics := NewPerformanceMetrics(testName)
			defer metrics.Report(t)

			inboundPort := tcp.PickPort()

			serverConfig := &core.Config{
				App: []*serial.TypedMessage{
					serial.ToTypedMessage(&dispatcher.Config{}),
					serial.ToTypedMessage(&proxyman.InboundConfig{}),
					serial.ToTypedMessage(&proxyman.OutboundConfig{}),
				},
				Inbound: []*core.InboundHandlerConfig{
					createInboundConfig(combo.Inbound, inboundPort, dest.Port),
				},
				Outbound: []*core.OutboundHandlerConfig{
					createOutboundConfig(combo.Outbound, internet.DomainStrategy_AS_IS),
				},
			}

			servers, err := InitializeServerConfigs(serverConfig)
			if err != nil {
				metrics.End(false, err)
				t.Fatal(err)
			}
			defer CloseAllServers(servers)

			// Test the connection based on inbound type
			var testErr error
			switch combo.Inbound {
			case InboundSocks:
				testErr = testSocksConnection(inboundPort, dest, t)
			case InboundHTTP:
				testErr = testHTTPConnection(inboundPort, dest, t)
			case InboundDokodemo:
				testErr = testDokodemoConnection(inboundPort, t)
			}

			metrics.End(testErr == nil, testErr)
			if testErr != nil {
				t.Error(testErr)
			}
		})
	}
}

func testSocksConnection(proxyPort net.Port, dest net.Destination, t *testing.T) error {
	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, proxyPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		return err
	}
	conn, err := dialer.Dial("tcp", dest.NetAddr())
	if err != nil {
		return err
	}
	defer conn.Close()
	return testTCPConn2(conn, 1024, time.Second*5)()
}

func testHTTPConnection(proxyPort net.Port, dest net.Destination, t *testing.T) error {
	// For HTTP proxy, we use CONNECT method through the proxy
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   net.LocalHostIP.IP(),
		Port: int(proxyPort),
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dest.NetAddr(), dest.NetAddr())
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		return err
	}

	// Read response (simplified check)
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	response := string(buf[:n])
	if len(response) < 12 || response[:12] != "HTTP/1.1 200" {
		return fmt.Errorf("unexpected HTTP response: %s", response)
	}

	return testTCPConn2(conn, 1024, time.Second*5)()
}

func testDokodemoConnection(dokodemoPort net.Port, t *testing.T) error {
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   net.LocalHostIP.IP(),
		Port: int(dokodemoPort),
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	return testTCPConn2(conn, 1024, time.Second*5)()
}

// TestVMessInboundOutboundChain tests VMess inbound -> Freedom outbound chain
func TestVMessInboundOutboundChain(t *testing.T) {
	metrics := NewPerformanceMetrics("VMess_Chain")
	defer metrics.Report(t)

	// Start a TCP echo server
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := uuid.New()
	vmessPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	// VMess server config
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "vmess-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(vmessPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&vmess_inbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom-out",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_AS_IS,
				}),
			},
		},
	}

	// Client config that connects through VMess
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "socks-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "vmess-out",
				ProxySettings: serial.ToTypedMessage(&vmess_outbound.Config{
					Receiver: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(vmessPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	// Connect through the client's SOCKS proxy
	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, clientPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", dest.NetAddr())
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer conn.Close()

	testErr := testTCPConn2(conn, 1024, time.Second*5)()
	metrics.End(testErr == nil, testErr)
	if testErr != nil {
		t.Error(testErr)
	}
}

// TestVLessInboundOutboundChain tests VLess inbound -> Freedom outbound chain
func TestVLessInboundOutboundChain(t *testing.T) {
	metrics := NewPerformanceMetrics("VLess_Chain")
	defer metrics.Report(t)

	// Start a TCP echo server
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID := uuid.New()
	vlessPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	// VLess server config
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "vless-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(vlessPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&vless_inbound.Config{
					Clients: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom-out",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_AS_IS,
				}),
			},
		},
	}

	// Client config that connects through VLess
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "socks-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "vless-out",
				ProxySettings: serial.ToTypedMessage(&vless_outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(vlessPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID.String(),
							}),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	// Connect through the client's SOCKS proxy
	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, clientPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", dest.NetAddr())
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer conn.Close()

	testErr := testTCPConn2(conn, 1024, time.Second*5)()
	metrics.End(testErr == nil, testErr)
	if testErr != nil {
		t.Error(testErr)
	}
}

// TestMultiOutboundChain tests multiple outbound chain: SOCKS -> VMess -> VLess -> Freedom
func TestMultiOutboundChain(t *testing.T) {
	metrics := NewPerformanceMetrics("Multi_Outbound_Chain")
	defer metrics.Report(t)

	// Start a TCP echo server
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	userID1 := uuid.New()
	userID2 := uuid.New()

	vmessPort := tcp.PickPort()
	vlessPort := tcp.PickPort()
	clientPort := tcp.PickPort()

	// VMess server (middle hop)
	vmessServerConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "vmess-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(vmessPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&vmess_inbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID1.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "vless-out",
				ProxySettings: serial.ToTypedMessage(&vless_outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(vlessPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID2.String(),
							}),
						},
					},
				}),
			},
		},
	}

	// VLess server (final hop before destination)
	vlessServerConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "vless-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(vlessPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&vless_inbound.Config{
					Clients: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID2.String(),
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom-out",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_AS_IS,
				}),
			},
		},
	}

	// Client config
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "socks-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "vmess-out",
				ProxySettings: serial.ToTypedMessage(&vmess_outbound.Config{
					Receiver: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(vmessPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID1.String(),
							}),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(vlessServerConfig, vmessServerConfig, clientConfig)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	// Connect through the client's SOCKS proxy
	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, clientPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", dest.NetAddr())
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer conn.Close()

	testErr := testTCPConn2(conn, 1024, time.Second*10)()
	metrics.End(testErr == nil, testErr)
	if testErr != nil {
		t.Error(testErr)
	}
}

// BenchmarkInboundOutbound provides benchmark tests for various combinations
func BenchmarkInboundOutbound(b *testing.B) {
	// Start a TCP echo server
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	if err != nil {
		b.Fatal(err)
	}
	defer tcpServer.Close()

	socksPort := tcp.PickPort()

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "socks-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(socksPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom-out",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_AS_IS,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	if err != nil {
		b.Fatal(err)
	}
	defer CloseAllServers(servers)

	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, socksPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := dialer.Dial("tcp", dest.NetAddr())
		if err != nil {
			b.Error(err)
			continue
		}
		if err := testTCPConn2(conn, 1024, time.Second*5)(); err != nil {
			b.Error(err)
		}
		conn.Close()
	}
}

// TestInboundOutboundWithStats tests combinations with statistics tracking
func TestInboundOutboundWithStats(t *testing.T) {
	metrics := NewPerformanceMetrics("Stats_Tracking")
	defer metrics.Report(t)

	// Start a TCP echo server
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	socksPort := tcp.PickPort()

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						InboundUplink:    true,
						InboundDownlink:  true,
						OutboundUplink:   true,
						OutboundDownlink: true,
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "socks-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(socksPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom-out",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_AS_IS,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, socksPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}

	conn, err := dialer.Dial("tcp", dest.NetAddr())
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer conn.Close()

	testErr := testTCPConn2(conn, 1024, time.Second*5)()
	metrics.End(testErr == nil, testErr)
	if testErr != nil {
		t.Error(testErr)
	}
}

// TestConcurrentConnections tests concurrent connections through proxy
func TestConcurrentConnections(t *testing.T) {
	metrics := NewPerformanceMetrics("Concurrent_Connections")
	defer metrics.Report(t)

	// Start a TCP echo server
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	socksPort := tcp.PickPort()

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "socks-in",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(socksPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom-out",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_AS_IS,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}
	defer CloseAllServers(servers)

	dialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, socksPort).NetAddr(), nil, xproxy.Direct)
	if err != nil {
		metrics.End(false, err)
		t.Fatal(err)
	}

	concurrency := 10
	var wg sync.WaitGroup
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := dialer.Dial("tcp", dest.NetAddr())
			if err != nil {
				errors <- fmt.Errorf("connection %d failed: %v", id, err)
				return
			}
			defer conn.Close()

			if err := testTCPConn2(conn, 1024, time.Second*10)(); err != nil {
				errors <- fmt.Errorf("test %d failed: %v", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	var testErr error
	for err := range errors {
		if testErr == nil {
			testErr = err
		}
		t.Error(err)
	}
	metrics.End(testErr == nil, testErr)
}
