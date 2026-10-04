package httpupgrade_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol/tls/cert"
	"github.com/ImAubrey/acore/testing/servers/tcp"
	"github.com/ImAubrey/acore/transport/internet"
	. "github.com/ImAubrey/acore/transport/internet/httpupgrade"
	"github.com/ImAubrey/acore/transport/internet/stat"
	"github.com/ImAubrey/acore/transport/internet/tls"
)

func Test_listenHTTPUpgradeAndDial(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)

	ctx := context.Background()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, err = conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func Test_listenHTTPUpgradeAndDialWithHeaders(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
			Header: map[string]string{
				"User-Agent": "Mozilla",
			},
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)

	ctx := context.Background()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, err = conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func TestDialWithRemoteAddr(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			_, err := c.Read(b[:])
			// common.Must(err)
			if err != nil {
				return
			}

			_, err = c.Write([]byte(c.RemoteAddr().String()))
			common.Must(err)
		}(conn)
	})
	common.Must(err)

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade", Header: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
	})

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "1.1.1.1:0" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(listen.Close())
}

func Test_listenHTTPUpgradePreservesPipelinedEarlyData(t *testing.T) {
	listenPort := tcp.PickPort()
	earlyData := []byte("early-vless-payload")
	got := make(chan []byte, 1)
	errCh := make(chan error, 1)

	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			buf := make([]byte, len(earlyData))
			if _, err := io.ReadFull(c, buf); err != nil {
				errCh <- err
				return
			}
			got <- buf
		}(conn)
	})
	common.Must(err)
	defer listen.Close()

	rawConn, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	common.Must(err)
	defer rawConn.Close()

	request := []byte("GET /httpupgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	common.Must2(rawConn.Write(append(request, earlyData...)))

	resp, err := http.ReadResponse(bufio.NewReader(rawConn), nil)
	common.Must(err)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("unexpected status: %s", resp.Status)
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	case data := <-got:
		if string(data) != string(earlyData) {
			t.Fatalf("early data mismatch: got %q want %q", string(data), string(earlyData))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for early data")
	}
}

func Test_listenHTTPUpgradeAcceptsConnectionTokenList(t *testing.T) {
	listenPort := tcp.PickPort()
	accepted := make(chan struct{}, 1)

	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
	}, func(conn stat.Connection) {
		accepted <- struct{}{}
		_ = conn.Close()
	})
	common.Must(err)
	defer listen.Close()

	rawConn, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	common.Must(err)
	defer rawConn.Close()

	request := []byte("GET /httpupgrade HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n")
	common.Must2(rawConn.Write(request))

	resp, err := http.ReadResponse(bufio.NewReader(rawConn), nil)
	common.Must(err)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("unexpected status: %s", resp.Status)
	}

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accepted connection")
	}
}

func Test_listenHTTPUpgradeIdleConnectionDoesNotBlockAccept(t *testing.T) {
	listenPort := tcp.PickPort()
	accepted := make(chan struct{}, 1)

	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
		},
	}, func(conn stat.Connection) {
		accepted <- struct{}{}
		_ = conn.Close()
	})
	common.Must(err)
	defer listen.Close()

	idleConn, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	common.Must(err)
	defer idleConn.Close()

	rawConn, err := stdnet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	common.Must(err)
	defer rawConn.Close()
	common.Must(rawConn.SetDeadline(time.Now().Add(2 * time.Second)))

	request := []byte("GET /httpupgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	common.Must2(rawConn.Write(request))

	resp, err := http.ReadResponse(bufio.NewReader(rawConn), nil)
	common.Must(err)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("unexpected status: %s", resp.Status)
	}

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accepted connection")
	}
}

func Test_listenHTTPUpgradeAndDial_TLS(t *testing.T) {
	listenPort := tcp.PickPort()
	if runtime.GOARCH == "arm64" {
		return
	}

	start := time.Now()

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrades",
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			AllowInsecure: true,
			Certificate:   []*tls.Certificate{tls.ParseCertificate(cert.MustGenerate(nil, cert.CommonName("localhost")))},
		},
	}
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			_ = conn.Close()
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_ = conn.Close()

	end := time.Now()
	if !end.Before(start.Add(time.Second * 5)) {
		t.Error("end: ", end, " start: ", start)
	}
}
