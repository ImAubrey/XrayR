package scenarios

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ImAubrey/acore/app/log"
	"github.com/ImAubrey/acore/app/proxyman"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	clog "github.com/ImAubrey/acore/common/log"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/task"
	"github.com/ImAubrey/acore/common/uuid"
	core "github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/proxy/dokodemo"
	"github.com/ImAubrey/acore/proxy/freedom"
	"github.com/ImAubrey/acore/proxy/vless"
	"github.com/ImAubrey/acore/proxy/vless/inbound"
	"github.com/ImAubrey/acore/proxy/vless/outbound"
	"github.com/ImAubrey/acore/testing/servers/tcp"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/pipe"
)

// countingTCPServer tracks concurrent accepted connections.
// It helps ensure pre-connect doesn't create too many idle TCP conns.
type countingTCPServer struct {
	Port         net.Port
	Listen       net.Address
	MsgProcessor func(msg []byte) []byte

	listener  net.Listener
	active    atomic.Int32
	maxActive atomic.Int32
}

func (s *countingTCPServer) Start() (net.Destination, error) {
	listenerAddr := s.Listen
	if listenerAddr == nil {
		listenerAddr = net.LocalHostIP
	}
	listener, err := internet.ListenSystem(context.Background(), &net.TCPAddr{
		IP:   listenerAddr.IP(),
		Port: int(s.Port),
	}, nil)
	if err != nil {
		return net.Destination{}, err
	}

	localAddr := listener.Addr().(*net.TCPAddr)
	s.Port = net.Port(localAddr.Port)
	s.listener = listener
	go s.acceptConnections(listener.(*net.TCPListener))

	return net.TCPDestination(net.IPAddress(localAddr.IP), net.Port(localAddr.Port)), nil
}

func (s *countingTCPServer) acceptConnections(listener *net.TCPListener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		cur := s.active.Add(1)
		for {
			max := s.maxActive.Load()
			if cur <= max || s.maxActive.CompareAndSwap(max, cur) {
				break
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *countingTCPServer) handleConnection(conn net.Conn) {
	defer func() {
		s.active.Add(-1)
		conn.Close()
	}()

	pReader, pWriter := pipe.New(pipe.WithoutSizeLimit())
	err := task.Run(context.Background(), func() error {
		defer pWriter.Close()

		for {
			b := buf.New()
			if _, err := b.ReadFrom(conn); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			copy(b.Bytes(), s.MsgProcessor(b.Bytes()))
			if err := pWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				return err
			}
		}
	}, func() error {
		defer pReader.Interrupt()

		w := buf.NewWriter(conn)
		for {
			mb, err := pReader.ReadMultiBuffer()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if err := w.WriteMultiBuffer(mb); err != nil {
				return err
			}
		}
	})
	_ = err
}

func (s *countingTCPServer) Close() error {
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *countingTCPServer) MaxActive() int {
	return int(s.maxActive.Load())
}

func TestPreconnectTrafficLoop_VlessClient_FreedomServer(t *testing.T) {
	backend := &countingTCPServer{
		MsgProcessor: xor,
	}
	dest, err := backend.Start()
	common.Must(err)
	defer backend.Close()

	// Sanity check: backend itself works.
	if err := testTCPConn(dest.Port, 64*1024, time.Second*5)(); err != nil {
		t.Fatalf("backend self-test failed: %v", err)
	}

	userID := protocol.NewID(uuid.New())

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
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
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DestinationOverride: &freedom.DestinationOverride{
						Server: &protocol.ServerEndpoint{
							Address: net.NewIPOrDomain(dest.Address),
							Port:    uint32(dest.Port),
						},
					},
					Testpre:    3,
					PreConKeep: 0, // default 25s keepalive
				}),
			},
		},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(net.DomainAddress("example.com")),
					Port:     80,
					Networks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:         userID.String(),
								Testpre:    3,
								PreConKeep: 0, // default 25s keepalive
							}),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	// 1) Make sure the loop works end-to-end.
	if err := testTCPConn(clientPort, 256*1024, time.Second*20)(); err != nil {
		t.Fatal(err)
	}

	// 2) Give pre-connect workers time to run another cycle.
	// Older Freedom pre-connect implementation could open up to 2*testpre idle conns.
	deadline := time.Now().Add(time.Second * 5)
	for time.Now().Before(deadline) {
		if backend.MaxActive() >= 3 {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}

	// 3) Verify it still works after pool settles.
	if err := testTCPConn(clientPort, 256*1024, time.Second*20)(); err != nil {
		t.Fatal(err)
	}

	maxActive := backend.MaxActive()
	t.Logf("backend max concurrent TCP connections: %d", maxActive)

	// Freedom testpre should create idle connections to backend.
	if maxActive < 3 {
		t.Fatalf("freedom pre-connect seems inactive: backend maxActive=%d, want >= 3", maxActive)
	}

	// For Freedom testpre=3 with a single in-flight request, we should not exceed 4.
	if maxActive > 4 {
		t.Fatalf("unexpectedly high backend concurrent connections: got %d, want <= 4", maxActive)
	}
}
