package axpath

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	cnet "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/stat"
	xtls "github.com/ImAubrey/acore/transport/internet/tls"
)

type infiniteZeroReader struct{}

func (infiniteZeroReader) Read(p []byte) (int, error) { return len(p), nil }

func newSelfSignedTLSConfig(t *testing.T) (server *xtls.Config, client *xtls.Config) {
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

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	server = &xtls.Config{
		Certificate: []*xtls.Certificate{
			{
				Certificate:    certPEM,
				Key:            keyPEM,
				Usage:          xtls.Certificate_ENCIPHERMENT,
				OneTimeLoading: true,
			},
		},
	}
	client = &xtls.Config{
		AllowInsecure: true,
		ServerName:    "localhost",
	}
	return server, client
}

func waitSubflows(t *testing.T, s *session, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n := 0
		s.flowsMu.RLock()
		for _, f := range s.flows {
			if f != nil && !f.isClosed() {
				n++
			}
		}
		s.flowsMu.RUnlock()
		if n >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for >=%d subflows (have fewer)", want)
}

func startServer(t *testing.T, ctx context.Context, ss *internet.MemoryStreamConfig) (internet.Listener, cnet.Destination, <-chan net.Conn) {
	t.Helper()

	connCh := make(chan net.Conn, 1)
	ln, err := internet.ListenTCP(ctx, cnet.LocalHostIP, 0, ss, func(c stat.Connection) {
		connCh <- c
	})
	if err != nil {
		t.Fatal(err)
	}

	addr := ln.Addr().(*net.TCPAddr)
	dest := cnet.TCPDestination(cnet.LocalHostIP, cnet.Port(addr.Port))
	return ln, dest, connCh
}

func newStreamSettings(cfg *Config, tlsCfg *xtls.Config) *internet.MemoryStreamConfig {
	secType := "none"
	if tlsCfg != nil {
		secType = "tls"
	}
	return &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: cfg,
		SecurityType:     secType,
		SecuritySettings: tlsCfg,
	}
}

func TestAXPathEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := &Config{
		Subflows:         4,
		ChunkSize:        16 * 1024,
		AckMaskBits:      256,
		MaxInflightBytes: 8 * 1024 * 1024,
		MaxQueuePerFlow:  32,
		JoinTimeoutMs:    3000,
		ResumeTimeoutMs:  5000,
		Psk:              "testpsk",
	}

	serverSS := newStreamSettings(cfg, nil)
	ln, dest, srvConnCh := startServer(t, ctx, serverSS)
	defer ln.Close()

	clientSS := newStreamSettings(cfg, nil)
	cc, err := internet.Dial(ctx, dest, clientSS)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	var sc net.Conn
	select {
	case sc = <-srvConnCh:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer sc.Close()

	waitSubflows(t, cc.(*session), 4, 5*time.Second)
	waitSubflows(t, sc.(*session), 4, 5*time.Second)

	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// Client -> Server -> Client (echo with length prefix).
	go func() {
		var lenBuf [4]byte
		if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(lenBuf[:]))
		b := make([]byte, n)
		if _, err := io.ReadFull(sc, b); err != nil {
			return
		}
		_, _ = sc.Write(lenBuf[:])
		_, _ = sc.Write(b)
	}()

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := cc.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Write(payload); err != nil {
		t.Fatal(err)
	}

	if _, err := io.ReadFull(cc, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint32(lenBuf[:]))
	got := make([]byte, n)
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("echo length mismatch: got=%d want=%d", n, len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo payload mismatch")
	}
}

func TestAXPathEchoTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := &Config{
		Subflows:         4,
		ChunkSize:        16 * 1024,
		AckMaskBits:      256,
		MaxInflightBytes: 8 * 1024 * 1024,
		MaxQueuePerFlow:  32,
		JoinTimeoutMs:    3000,
		ResumeTimeoutMs:  5000,
		Psk:              "testpsk",
	}

	srvTLS, cliTLS := newSelfSignedTLSConfig(t)

	serverSS := newStreamSettings(cfg, srvTLS)
	ln, dest, srvConnCh := startServer(t, ctx, serverSS)
	defer ln.Close()

	clientSS := newStreamSettings(cfg, cliTLS)
	cc, err := internet.Dial(ctx, dest, clientSS)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	var sc net.Conn
	select {
	case sc = <-srvConnCh:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer sc.Close()

	waitSubflows(t, cc.(*session), 4, 5*time.Second)
	waitSubflows(t, sc.(*session), 4, 5*time.Second)

	payload := make([]byte, 256<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	go func() {
		var lenBuf [4]byte
		if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(lenBuf[:]))
		_, _ = io.CopyN(io.Discard, sc, int64(n))
		_, _ = sc.Write([]byte{1})
	}()

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := cc.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Write(payload); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(cc, ack[:]); err != nil {
		t.Fatal(err)
	}
	if ack[0] != 1 {
		t.Fatalf("bad ack: %d", ack[0])
	}
}

func TestAXPathSubflowDrop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	reconnect := true
	cfg := &Config{
		Subflows:         4,
		ChunkSize:        16 * 1024,
		AckMaskBits:      256,
		MaxInflightBytes: 16 * 1024 * 1024,
		MaxQueuePerFlow:  64,
		JoinTimeoutMs:    3000,
		ResumeTimeoutMs:  8000,
		Reconnect:        &reconnect,
		Psk:              "testpsk",
	}

	serverSS := newStreamSettings(cfg, nil)
	ln, dest, srvConnCh := startServer(t, ctx, serverSS)
	defer ln.Close()

	clientSS := newStreamSettings(cfg, nil)
	cc, err := internet.Dial(ctx, dest, clientSS)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	var sc net.Conn
	select {
	case sc = <-srvConnCh:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer sc.Close()

	cs := cc.(*session)
	ss := sc.(*session)

	waitSubflows(t, cs, 4, 5*time.Second)
	waitSubflows(t, ss, 4, 5*time.Second)

	// Drop one client subflow.
	cs.flowsMu.RLock()
	f := cs.flows[0]
	cs.flowsMu.RUnlock()
	if f == nil {
		t.Fatalf("expected subflow 0 to exist")
	}
	f.close()

	// Continue sending data and ensure the logical session survives.
	payload := make([]byte, 4<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	go func() {
		var lenBuf [4]byte
		if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(lenBuf[:]))
		b := make([]byte, n)
		if _, err := io.ReadFull(sc, b); err != nil {
			return
		}
		_, _ = sc.Write(lenBuf[:])
		_, _ = sc.Write(b)
	}()

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := cc.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(cc, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint32(lenBuf[:]))
	got := make([]byte, n)
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch after subflow drop")
	}
}

func TestAXPathTrafficUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := &Config{
		Subflows:         4,
		ChunkSize:        32 * 1024,
		AckMaskBits:      256,
		MaxInflightBytes: 64 * 1024 * 1024,
		MaxQueuePerFlow:  256,
		JoinTimeoutMs:    3000,
		ResumeTimeoutMs:  10000,
		Psk:              "testpsk",
	}

	serverSS := newStreamSettings(cfg, nil)
	ln, dest, srvConnCh := startServer(t, ctx, serverSS)
	defer ln.Close()

	clientSS := newStreamSettings(cfg, nil)
	cc, err := internet.Dial(ctx, dest, clientSS)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	var sc net.Conn
	select {
	case sc = <-srvConnCh:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer sc.Close()

	waitSubflows(t, cc.(*session), 4, 5*time.Second)
	waitSubflows(t, sc.(*session), 4, 5*time.Second)

	const total = 32 * 1024 * 1024

	go func() {
		var lenBuf [8]byte
		if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
			return
		}
		n := int64(binary.BigEndian.Uint64(lenBuf[:]))
		_, _ = io.CopyN(io.Discard, sc, n)
		_, _ = sc.Write([]byte{1})
	}()

	// Send total bytes and wait for ACK.
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(total))
	if _, err := cc.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	buf := make([]byte, 256*1024)
	nWritten, err := io.CopyBuffer(cc, io.LimitReader(infiniteZeroReader{}, total), buf)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	var ack [1]byte
	if _, err := io.ReadFull(cc, ack[:]); err != nil {
		t.Fatal(err)
	}
	if ack[0] != 1 {
		t.Fatalf("bad ack: %d", ack[0])
	}

	mbps := (float64(nWritten) / (1024.0 * 1024.0)) / elapsed.Seconds()
	t.Logf("axpath upload: %d bytes in %s (%.1f MiB/s)", nWritten, elapsed, mbps)
}
