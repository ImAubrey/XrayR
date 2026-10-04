package scenarios

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	tcpserver "github.com/ImAubrey/acore/testing/servers/tcp"
	xproxy "golang.org/x/net/proxy"
)

func TestAXPathPublicNetEmulation_TCPLoadOver16MiB(t *testing.T) {
	if os.Getenv("ACORE_SCENARIO_TESTS") == "" {
		t.Skip("Skipping scenario tests. Set ACORE_SCENARIO_TESTS=1 to run.")
	}
	if os.Getenv("ACORE_AXPATH_PUBLIC_NET_TESTS") == "" {
		t.Skip("Skipping public-net emulation tests. Set ACORE_AXPATH_PUBLIC_NET_TESTS=1 to run.")
	}

	cfg := loadPublicNetFaultConfig()
	logLevel := os.Getenv("ACORE_AXPATH_LOGLEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	subflows := envIntWithDefault("ACORE_AXPATH_PUBLIC_SUBFLOWS", 1)
	if subflows < 1 {
		subflows = 1
	}
	if subflows > 16 {
		subflows = 16
	}

	payloadMiB := envIntWithDefault("ACORE_AXPATH_PUBLIC_TCP_PAYLOAD_MIB", 24) // must exceed 16MiB threshold
	if payloadMiB < 17 {
		payloadMiB = 17
	}
	payloadSize := int64(payloadMiB) * 1024 * 1024
	overallTimeout := 8 * time.Minute
	// Under severe public-net emulation (high delay/jitter/loss/reorder), throughput
	// can become very low but still make forward progress. Scale timeout with payload
	// to avoid classifying slow-progress transfers as hard failures.
	estimated := time.Duration(payloadMiB)*30*time.Second + 2*time.Minute
	if estimated > overallTimeout {
		overallTimeout = estimated
	}
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
	defer cancel()
	clientTimeout := overallTimeout - 30*time.Second
	if clientTimeout < 7*time.Minute {
		clientTimeout = 7 * time.Minute
	}

	t.Logf(
		"public net tcp profile: subflows=%d payload=%dMiB delay=%dms jitter=%dms loss=%d%% reorder=%d%% cut_mod=%d timeout=%s",
		subflows, payloadMiB, cfg.BaseDelayMs, cfg.JitterMs, cfg.LossRatePct, cfg.ReorderRatePct, cfg.CutConnModulo, clientTimeout,
	)

	tmpDir := t.TempDir()
	serverPort := tcpserver.PickPort()
	socksPort := tcpserver.PickPort()
	userID := "b7a3e65f-2dc5-4cda-8b41-bfc4a72e3d6f"
	psk := "testpsk"

	crtPath, keyPath := writeSelfSignedCert(t, tmpDir)
	testFilePath := createTruncatedFile(t, tmpDir, "public-net-test.bin", payloadSize)
	httpAddr, closeHTTP := startHTTPFileServer(t, testFilePath)
	defer closeHTTP()

	serverCfgPath := filepath.Join(tmpDir, "server.json")
	clientCfgPath := filepath.Join(tmpDir, "client.json")

	serverCfg := fmt.Sprintf(`{
  "log": { "loglevel": %q },
  "inbounds": [
    {
      "tag": "in_vless_axpath_tls",
      "listen": "127.0.0.1",
      "port": %d,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": %q, "level": 0 }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "axpath",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{ "certificateFile": %q, "keyFile": %q }]
        },
        "axpathSettings": {
          "subflows": %d,
          "maxInflightBytes": 16777216,
          "maxQueuePerFlow": 256,
          "psk": %q
        }
      }
    }
  ],
  "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
}`, logLevel, int(serverPort), userID, filepath.ToSlash(crtPath), filepath.ToSlash(keyPath), subflows, psk)
	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	serverCmd, serverOut := startAcoreWithJSON(t, serverCfgPath)
	defer stopProcess(serverCmd)
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(serverPort)), 10*time.Second); err != nil {
		t.Fatalf("server not ready: %v\n%s", err, serverOut.String())
	}

	proxyAddr, _, closeProxy := startTCPProxyWithPublicNetFault(t, fmt.Sprintf("127.0.0.1:%d", int(serverPort)), cfg)
	defer closeProxy()
	proxyHost, proxyPortStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("split proxy addr failed: %v", err)
	}
	_ = proxyHost

	clientCfg := fmt.Sprintf(`{
  "log": { "loglevel": %q },
  "inbounds": [
    {
      "tag": "in_socks",
      "listen": "127.0.0.1",
      "port": %d,
      "protocol": "socks",
      "settings": { "udp": false }
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
            "port": %s,
            "users": [{ "id": %q, "encryption": "none" }]
          }
        ]
      },
      "streamSettings": {
        "network": "axpath",
        "security": "tls",
        "tlsSettings": { "serverName": "localhost", "allowInsecure": true },
        "axpathSettings": {
          "subflows": %d,
          "maxInflightBytes": 16777216,
          "maxQueuePerFlow": 256,
          "reconnect": true,
          "psk": %q
        }
      }
    }
  ]
}`, logLevel, int(socksPort), proxyPortStr, userID, subflows, psk)
	if err := os.WriteFile(clientCfgPath, []byte(clientCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	clientCmd, clientOut := startAcoreWithJSON(t, clientCfgPath)
	defer stopProcess(clientCmd)
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(socksPort)), 10*time.Second); err != nil {
		t.Fatalf("client not ready: %v\n%s", err, clientOut.String())
	}

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
		Timeout:   clientTimeout,
	}

	url := "http://" + httpAddr + "/testfile.bin"
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
	if n != payloadSize {
		t.Fatalf("unexpected body length: got=%d want=%d\nclient:\n%s\nserver:\n%s", n, payloadSize, clientOut.String(), serverOut.String())
	}
	t.Logf("public-net tcp transfer: %d bytes in %s (%.2f MiB/s)", n, dur, (float64(n)/(1024.0*1024.0))/dur.Seconds())

	select {
	case <-ctx.Done():
		t.Fatalf("test timeout: %v\nclient:\n%s\nserver:\n%s", ctx.Err(), clientOut.String(), serverOut.String())
	default:
	}
}
