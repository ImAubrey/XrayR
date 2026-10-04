package scenarios

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	tcpserver "github.com/ImAubrey/acore/testing/servers/tcp"
	xproxy "golang.org/x/net/proxy"
)

type axpathFaultParams struct {
	LogLevel    string `json:"logLevel"`
	PayloadMiB  int    `json:"payloadMiB"`
	CutAfterMiB int    `json:"cutAfterMiB"`
	CutConnIdx  int64  `json:"cutConnIndex"`
}

func envInt(key string, dflt int) int {
	s := os.Getenv(key)
	if s == "" {
		return dflt
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return dflt
	}
	return n
}

func envInt64(key string, dflt int64) int64 {
	s := os.Getenv(key)
	if s == "" {
		return dflt
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return dflt
	}
	return n
}

func forceClose(conn net.Conn) {
	if conn == nil {
		return
	}
	// Best-effort RST: this matches real-world "connection reset by peer" better
	// than a graceful FIN close.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}

func loadAXPathFaultParams(t *testing.T) axpathFaultParams {
	t.Helper()

	p := axpathFaultParams{
		LogLevel:    "debug",
		PayloadMiB:  64,
		CutAfterMiB: 4,
		CutConnIdx:  0,
	}

	repoRoot := findRepoRoot(t)
	paramsPath := filepath.Join(repoRoot, "test-axpath", "fault-params.json")
	if b, err := os.ReadFile(paramsPath); err == nil {
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatalf("parse %s failed: %v", paramsPath, err)
		}
	}

	// Optional env overrides (handy for one-off runs without editing files).
	if v := os.Getenv("ACORE_AXPATH_LOGLEVEL"); v != "" {
		p.LogLevel = v
	}
	p.PayloadMiB = envInt("ACORE_AXPATH_PAYLOAD_MIB", p.PayloadMiB)
	p.CutAfterMiB = envInt("ACORE_AXPATH_CUT_AFTER_MIB", p.CutAfterMiB)
	p.CutConnIdx = envInt64("ACORE_AXPATH_CUT_CONN_INDEX", p.CutConnIdx)

	// Normalize.
	if p.LogLevel == "" {
		p.LogLevel = "debug"
	}
	if p.PayloadMiB < 1 {
		p.PayloadMiB = 1
	}
	if p.CutAfterMiB < 1 {
		p.CutAfterMiB = 1
	}
	if p.CutConnIdx < 0 {
		p.CutConnIdx = 0
	}

	return p
}

func startTCPProxyWithOneDownlinkCut(t *testing.T, upstreamAddr string, cutConnIndex int64, cutAfterBytes int64) (listenAddr string, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var connIdx atomic.Int64

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}

			idx := connIdx.Add(1) - 1
			go func(clientConn net.Conn, index int64) {
				defer forceClose(clientConn)

				serverConn, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
				if err != nil {
					return
				}
				defer forceClose(serverConn)

				c2s := make(chan error, 1)
				s2c := make(chan error, 1)

				go func() {
					_, err := io.Copy(serverConn, clientConn)
					c2s <- err
				}()
				go func() {
					var err error
					if index == cutConnIndex {
						_, err = copyWithOneDownlinkCut(clientConn, serverConn, cutAfterBytes)
					} else {
						_, err = io.Copy(clientConn, serverConn)
					}
					s2c <- err
				}()

				select {
				case <-c2s:
				case <-s2c:
				}
				forceClose(clientConn)
				forceClose(serverConn)
				<-c2s
				<-s2c
			}(c, idx)
		}
	}()

	return ln.Addr().String(), func() {
		cancel()
		_ = ln.Close()
	}
}

func copyWithOneDownlinkCut(dst net.Conn, src net.Conn, cutAfterBytes int64) (n int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			off := 0
			for off < nr {
				nw, werr := dst.Write(buf[off:nr])
				if nw > 0 {
					n += int64(nw)
					off += nw
				}
				if werr != nil {
					return n, werr
				}
			}

			if cutAfterBytes > 0 && n >= cutAfterBytes {
				return n, io.ErrUnexpectedEOF
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return n, nil
			}
			return n, rerr
		}
	}
}

func TestAXPathVLESSOverTLSFileConfig_SubflowDownlinkCutDoesNotDisconnect(t *testing.T) {
	if os.Getenv("ACORE_SCENARIO_TESTS") == "" {
		t.Skip("Skipping scenario tests. Set ACORE_SCENARIO_TESTS=1 to run.")
	}
	if os.Getenv("ACORE_AXPATH_FAULT_TESTS") == "" {
		t.Skip("Skipping fault-injection tests. Set ACORE_AXPATH_FAULT_TESTS=1 to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tmpDir := t.TempDir()

	serverPort := tcpserver.PickPort()
	socksPort := tcpserver.PickPort()

	crtPath, keyPath := writeSelfSignedCert(t, tmpDir)

	psk := "testpsk"
	serverCfgPath := filepath.Join(tmpDir, "server.json")
	clientCfgPath := filepath.Join(tmpDir, "client.json")

	params := loadAXPathFaultParams(t)
	t.Logf("axpath fault params: payload=%dMiB cutAfter=%dMiB cutConnIndex=%d loglevel=%s", params.PayloadMiB, params.CutAfterMiB, params.CutConnIdx, params.LogLevel)

	payloadSize := params.PayloadMiB * 1024 * 1024
	cutAfterBytes := int64(params.CutAfterMiB) * 1024 * 1024

	maxInflightBytes := 16 * 1024 * 1024

	serverCfg := fmt.Sprintf(`{
  "log": { "loglevel": %q },
  "inbounds": [
    {
      "tag": "in_vless_axpath_tls",
      "listen": "127.0.0.1",
      "port": %d,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "b7a3e65f-2dc5-4cda-8b41-bfc4a72e3d6f", "level": 0 }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "axpath",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            { "certificateFile": %q, "keyFile": %q }
          ]
        },
        "axpathSettings": {
          "subflows": 4,
          "maxInflightBytes": %d,
          "maxQueuePerFlow": 256,
          "psk": %q
        }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" }
  ]
}`, params.LogLevel, int(serverPort), filepath.ToSlash(crtPath), filepath.ToSlash(keyPath), maxInflightBytes, psk)

	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	serverCmd, serverOut := startAcoreWithJSON(t, serverCfgPath)
	defer stopProcess(serverCmd)
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(serverPort)), 10*time.Second); err != nil {
		t.Fatalf("server not ready: %v\n%s", err, serverOut.String())
	}

	// Proxy sits between client and server and hard-cuts one subflow downlink
	// mid-transfer to simulate packet loss / NAT reset.
	proxyAddr, closeProxy := startTCPProxyWithOneDownlinkCut(t, fmt.Sprintf("127.0.0.1:%d", int(serverPort)), params.CutConnIdx, cutAfterBytes)
	defer closeProxy()
	_, proxyPortStr, _ := net.SplitHostPort(proxyAddr)
	proxyPort, _ := strconv.Atoi(proxyPortStr)

	// Client: match maxInflight with server and enable reconnect to exercise
	// subflow replacement logic.
	clientCfg := fmt.Sprintf(`{
  "log": { "loglevel": %q },
  "inbounds": [
    {
      "tag": "in_socks",
      "listen": "127.0.0.1",
      "port": %d,
      "protocol": "socks",
      "settings": { "udp": true }
    }
  ],
  "outbounds": [
    {
      "tag": "vless_axpath",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": %d,
            "users": [
              { "id": "b7a3e65f-2dc5-4cda-8b41-bfc4a72e3d6f", "encryption": "none" }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "axpath",
        "security": "tls",
        "tlsSettings": { "serverName": "localhost", "allowInsecure": true },
        "axpathSettings": {
          "subflows": 4,
          "maxInflightBytes": %d,
          "maxQueuePerFlow": 256,
          "reconnect": true,
          "psk": %q
        }
      }
    },
    { "tag": "direct", "protocol": "freedom" }
  ]
}`, params.LogLevel, int(socksPort), proxyPort, maxInflightBytes, psk)
	if err := os.WriteFile(clientCfgPath, []byte(clientCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	clientCmd, clientOut := startAcoreWithJSON(t, clientCfgPath)
	defer stopProcess(clientCmd)
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(socksPort)), 10*time.Second); err != nil {
		t.Fatalf("client not ready: %v\n%s", err, clientOut.String())
	}

	// Large transfer: should still complete even if one subflow is cut mid-transfer.
	httpAddr, closeHTTP := startHTTPServer(t, payloadSize)
	defer closeHTTP()

	dialer, err := xproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", int(socksPort)), nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_ = ctx
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   90 * time.Second,
	}

	url := "http://" + httpAddr + "/payload"
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("http get via socks failed: %v\nclient:\n%s\nserver:\n%s", err, clientOut.String(), serverOut.String())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v\nclient:\n%s\nserver:\n%s", err, clientOut.String(), serverOut.String())
	}
	dur := time.Since(start)
	if n != int64(payloadSize) {
		t.Fatalf("unexpected body length: got=%d want=%d\nclient:\n%s\nserver:\n%s", n, int64(payloadSize), clientOut.String(), serverOut.String())
	}
	t.Logf("axpath subflow-cut transfer: %d bytes in %s (%.1f MiB/s)", n, dur, (float64(n)/(1024.0*1024.0))/dur.Seconds())

	select {
	case <-ctx.Done():
		t.Fatalf("test timeout: %v\nclient:\n%s\nserver:\n%s", ctx.Err(), clientOut.String(), serverOut.String())
	default:
	}
}
