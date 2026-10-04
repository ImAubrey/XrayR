package scenarios

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	tcpserver "github.com/ImAubrey/acore/testing/servers/tcp"
	xproxy "golang.org/x/net/proxy"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("failed to find repo root (go.mod) from %q", dir)
		}
		dir = parent
	}
}

func waitTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for tcp %s", addr)
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func writeSelfSignedCert(t *testing.T, dir string) (crtPath string, keyPath string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	crtPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")

	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	if err := os.WriteFile(crtPath, crt, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	return crtPath, keyPath
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

func startHTTPServer(t *testing.T, payloadSize int) (addr string, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/payload" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(payloadSize))
			w.WriteHeader(http.StatusOK)
			_, _ = io.CopyN(w, zeroReader{}, int64(payloadSize))
		}),
	}
	go srv.Serve(ln)

	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
}

func startAcoreWithJSON(t *testing.T, cfgPath string) (*exec.Cmd, *lockedBuffer) {
	t.Helper()

	if err := BuildAcore(); err != nil {
		t.Fatal(err)
	}
	genTestBinaryPath()

	out := &lockedBuffer{}
	cmd := exec.Command(testBinaryPath, "run", "-c", cfgPath)
	// Default: capture logs for assertion on failures. For interactive debugging,
	// allow teeing child-process logs to the test runner stdout.
	var w io.Writer = out
	if os.Getenv("ACORE_SCENARIO_TEE_LOGS") != "" {
		w = io.MultiWriter(out, os.Stdout)
	}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start acore with %s: %v\n%s", cfgPath, err, out.String())
	}
	return cmd, out
}

func TestAXPathExampleConfigsValidate(t *testing.T) {
	if err := BuildAcore(); err != nil {
		t.Fatal(err)
	}
	genTestBinaryPath()

	repoRoot := findRepoRoot(t)
	clientCfg := filepath.Join(repoRoot, "test-axpath", "client.json")
	serverCfg := filepath.Join(repoRoot, "test-axpath", "server.json")

	for _, p := range []string{serverCfg, clientCfg} {
		cmd := exec.Command(testBinaryPath, "run", "-test", "-c", p)
		// Example configs reference cert/key paths as relative "certificateFile"/"keyFile".
		// On Windows, acore resolves relative cert paths under ACORE_LOCATION_CERT (default: executable dir).
		// Point it to repo root so "test-axpath/server.{crt,key}" can be found.
		cmd.Env = append(os.Environ(), "ACORE_LOCATION_CERT="+repoRoot)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("acore -test failed for %s: %v\n%s", p, err, string(out))
		}
	}
}

func TestAXPathVLESSOverTLSFileConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	repoRoot := findRepoRoot(t)
	tmpDir := t.TempDir()

	_ = repoRoot // reserved for future: use repoRoot-relative paths when needed

	serverPort := tcpserver.PickPort()
	socksPort := tcpserver.PickPort()

	crtPath, keyPath := writeSelfSignedCert(t, tmpDir)

	// Keep the config minimal and close to real user configs, but with temp ports/paths.
	psk := "testpsk"
	serverCfgPath := filepath.Join(tmpDir, "server.json")
	clientCfgPath := filepath.Join(tmpDir, "client.json")

	serverCfg := fmt.Sprintf(`{
  "log": { "loglevel": "info" },
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
          "psk": %q
        }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" }
  ]
}`, int(serverPort), filepath.ToSlash(crtPath), filepath.ToSlash(keyPath), psk)

	clientCfg := fmt.Sprintf(`{
  "log": { "loglevel": "info" },
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
        "axpathSettings": { "subflows": 4, "reconnect": true, "psk": %q }
      },
      "mux": { "enabled": true, "concurrency": 8 }
    },
    { "tag": "direct", "protocol": "freedom" }
  ]
}`, int(socksPort), int(serverPort), psk)

	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientCfgPath, []byte(clientCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	serverCmd, serverOut := startAcoreWithJSON(t, serverCfgPath)
	defer stopProcess(serverCmd)

	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(serverPort)), 8*time.Second); err != nil {
		t.Fatalf("server not ready: %v\n%s", err, serverOut.String())
	}

	clientCmd, clientOut := startAcoreWithJSON(t, clientCfgPath)
	defer stopProcess(clientCmd)

	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(socksPort)), 8*time.Second); err != nil {
		t.Fatalf("client not ready: %v\n%s", err, clientOut.String())
	}

	httpAddr, closeHTTP := startHTTPServer(t, 8*1024*1024)
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
		Timeout:   20 * time.Second,
	}

	// Single big transfer to validate end-to-end correctness.
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
		t.Fatalf("read body failed: %v", err)
	}
	dur := time.Since(start)
	if n != 8*1024*1024 {
		t.Fatalf("unexpected body length: got=%d want=%d", n, 8*1024*1024)
	}
	t.Logf("axpath file-config transfer: %d bytes in %s (%.1f MiB/s)", n, dur, (float64(n)/(1024.0*1024.0))/dur.Seconds())

	// Ensure the test doesn't run past the top-level timeout due to stuck processes.
	select {
	case <-ctx.Done():
		t.Fatalf("test timeout: %v\nclient:\n%s\nserver:\n%s", ctx.Err(), clientOut.String(), serverOut.String())
	default:
	}
}
