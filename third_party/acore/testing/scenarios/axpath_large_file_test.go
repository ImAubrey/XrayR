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

func createTruncatedFile(t *testing.T, dir string, name string, size int64) string {
	t.Helper()

	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create %s failed: %v", p, err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatalf("truncate %s failed: %v", p, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s failed: %v", p, err)
	}
	return p
}

func startHTTPFileServer(t *testing.T, filePath string) (addr string, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/testfile.bin", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.ServeFile(w, r, filePath)
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)

	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
}

func TestAXPathVLESSOverTLSFileConfig_HTTPFileLarge(t *testing.T) {
	if os.Getenv("ACORE_SCENARIO_TESTS") == "" {
		t.Skip("Skipping scenario tests. Set ACORE_SCENARIO_TESTS=1 to run.")
	}
	if os.Getenv("ACORE_AXPATH_LARGE_FILE_TESTS") == "" {
		t.Skip("Skipping large-file tests. Set ACORE_AXPATH_LARGE_FILE_TESTS=1 to run.")
	}

	payloadMiB := envInt("ACORE_AXPATH_PAYLOAD_MIB", 1024) // default: 1GiB
	if payloadMiB < 1 {
		payloadMiB = 1
	}
	payloadSize := int64(payloadMiB) * 1024 * 1024

	logLevel := os.Getenv("ACORE_AXPATH_LOGLEVEL")
	if logLevel == "" {
		logLevel = "debug"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tmpDir := t.TempDir()

	serverPort := tcpserver.PickPort()
	socksPort := tcpserver.PickPort()

	crtPath, keyPath := writeSelfSignedCert(t, tmpDir)
	testFilePath := createTruncatedFile(t, tmpDir, "testfile.bin", payloadSize)
	httpAddr, closeHTTP := startHTTPFileServer(t, testFilePath)
	defer closeHTTP()

	psk := "testpsk"
	serverCfgPath := filepath.Join(tmpDir, "server.json")
	clientCfgPath := filepath.Join(tmpDir, "client.json")

	maxInflightBytes := 16 * 1024 * 1024

	// Same topology as requested:
	// client: SOCKS inbound -> VLESS+TLS+AXPath outbound
	// server: VLESS+TLS+AXPath inbound -> freedom outbound -> local HTTP server (loopback)
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
}`, logLevel, int(serverPort), filepath.ToSlash(crtPath), filepath.ToSlash(keyPath), maxInflightBytes, psk)

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
    }
  ]
}`, logLevel, int(socksPort), int(serverPort), maxInflightBytes, psk)

	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientCfgPath, []byte(clientCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	serverCmd, serverOut := startAcoreWithJSON(t, serverCfgPath)
	defer stopProcess(serverCmd)
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(serverPort)), 10*time.Second); err != nil {
		t.Fatalf("server not ready: %v\n%s", err, serverOut.String())
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
		Timeout:   9 * time.Minute,
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
	t.Logf("axpath http-file transfer: %d bytes in %s (%.1f MiB/s)", n, dur, (float64(n)/(1024.0*1024.0))/dur.Seconds())

	select {
	case <-ctx.Done():
		t.Fatalf("test timeout: %v\nclient:\n%s\nserver:\n%s", ctx.Err(), clientOut.String(), serverOut.String())
	default:
	}
}
