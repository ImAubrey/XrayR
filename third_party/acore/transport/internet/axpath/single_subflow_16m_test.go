package axpath

import (
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	cnet "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/stat"
)

func startAXPathServerForTest(t *testing.T, ctx context.Context, ss *internet.MemoryStreamConfig) (internet.Listener, cnet.Destination, <-chan net.Conn) {
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

func TestAXPathSingleSubflowOver16MiBUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cfg := &Config{
		Subflows:         1,
		ChunkSize:        16 * 1024,
		AckMaskBits:      256,
		MaxInflightBytes: 16 * 1024 * 1024,
		MaxQueuePerFlow:  256,
		JoinTimeoutMs:    3000,
		ResumeTimeoutMs:  15000,
		Psk:              "testpsk",
	}

	serverSS := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: cfg,
	}
	ln, dest, srvConnCh := startAXPathServerForTest(t, ctx, serverSS)
	defer ln.Close()

	clientSS := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: cfg,
	}
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

	waitSubflows(t, cc.(*session), 1, 5*time.Second)
	waitSubflows(t, sc.(*session), 1, 5*time.Second)

	const total = 64 * 1024 * 1024
	go func() {
		var lenBuf [8]byte
		if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
			return
		}
		n := int64(binary.BigEndian.Uint64(lenBuf[:]))
		_, _ = io.CopyN(io.Discard, sc, n)
		_, _ = sc.Write([]byte{1})
	}()

	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(total))
	if _, err := cc.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	written, err := io.CopyBuffer(cc, io.LimitReader(infiniteZeroReader{}, total), make([]byte, 256*1024))
	if err != nil {
		t.Fatalf("upload failed after %d bytes in %s: %v", written, time.Since(start), err)
	}

	var ack [1]byte
	if _, err := io.ReadFull(cc, ack[:]); err != nil {
		t.Fatalf("ack read failed after %d bytes in %s: %v", written, time.Since(start), err)
	}
	if ack[0] != 1 {
		t.Fatalf("bad ack: %d", ack[0])
	}
	if written != total {
		t.Fatalf("written mismatch: got=%d want=%d", written, total)
	}
}

func startTCPFaultProxyForAXPathTest(t *testing.T, upstreamAddr string, seed int64) (listenAddr string, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var idx atomic.Int64

	sleepRange := func(r *rand.Rand, minMs int, maxMs int) {
		if maxMs < minMs {
			maxMs = minMs
		}
		d := minMs
		if maxMs > minMs {
			d += r.Intn(maxMs - minMs + 1)
		}
		if d > 0 {
			time.Sleep(time.Duration(d) * time.Millisecond)
		}
	}

	copyFault := func(dst net.Conn, src net.Conn, r *rand.Rand) error {
		buf := make([]byte, 32*1024)
		for {
			nr, err := src.Read(buf)
			if nr > 0 {
				// base delay + jitter
				sleepRange(r, 20, 60)
				// "20% loss" equivalent: retransmission-like stall
				if r.Intn(100) < 20 {
					sleepRange(r, 80, 400)
				}
				// "20% reorder" equivalent: burst jitter spike
				if r.Intn(100) < 20 {
					sleepRange(r, 40, 200)
				}
				p := buf[:nr]
				for len(p) > 0 {
					nw, werr := dst.Write(p)
					if nw > 0 {
						p = p[nw:]
					}
					if werr != nil {
						return werr
					}
				}
			}
			if err != nil {
				return err
			}
		}
	}

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

			n := idx.Add(1)
			go func(clientConn net.Conn, id int64) {
				defer clientConn.Close()
				serverConn, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
				if err != nil {
					return
				}
				defer serverConn.Close()

				done1 := make(chan error, 1)
				done2 := make(chan error, 1)
				go func() {
					r := rand.New(rand.NewSource(seed + id*10007 + 1))
					done1 <- copyFault(serverConn, clientConn, r)
				}()
				go func() {
					r := rand.New(rand.NewSource(seed + id*10007 + 2))
					done2 <- copyFault(clientConn, serverConn, r)
				}()

				select {
				case <-done1:
				case <-done2:
				}
				_ = clientConn.Close()
				_ = serverConn.Close()
				<-done1
				<-done2
			}(c, n)
		}
	}()

	return ln.Addr().String(), func() {
		cancel()
		_ = ln.Close()
	}
}

func TestAXPathSingleSubflowOver16MiBUpload_GFW20Emulation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short")
	}
	if os.Getenv("CI") == "true" && os.Getenv("ACORE_AXPATH_STRESS_TESTS") != "1" {
		t.Skip("skipping AXPath GFW fault-emulation stress test in CI")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cfg := &Config{
		Subflows:         1,
		ChunkSize:        16 * 1024,
		AckMaskBits:      256,
		MaxInflightBytes: 16 * 1024 * 1024,
		MaxQueuePerFlow:  256,
		JoinTimeoutMs:    3000,
		ResumeTimeoutMs:  15000,
		Psk:              "testpsk",
	}

	serverSS := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: cfg,
	}
	ln, serverDest, srvConnCh := startAXPathServerForTest(t, ctx, serverSS)
	defer ln.Close()

	proxyAddr, closeProxy := startTCPFaultProxyForAXPathTest(t, serverDest.NetAddr(), 20260301)
	defer closeProxy()

	proxyDest, err := cnet.ParseDestination("tcp:" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	clientSS := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: cfg,
	}
	cc, err := internet.Dial(ctx, proxyDest, clientSS)
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

	waitSubflows(t, cc.(*session), 1, 5*time.Second)
	waitSubflows(t, sc.(*session), 1, 5*time.Second)

	const total = 32 * 1024 * 1024 // must exceed 16MiB threshold
	go func() {
		var lenBuf [8]byte
		if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
			return
		}
		n := int64(binary.BigEndian.Uint64(lenBuf[:]))
		_, _ = io.CopyN(io.Discard, sc, n)
		_, _ = sc.Write([]byte{1})
	}()

	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(total))
	if _, err := cc.Write(lenBuf[:]); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	written, err := io.CopyBuffer(cc, io.LimitReader(infiniteZeroReader{}, total), make([]byte, 256*1024))
	if err != nil {
		t.Fatalf("upload failed after %d bytes in %s: %v", written, time.Since(start), err)
	}

	var ack [1]byte
	if _, err := io.ReadFull(cc, ack[:]); err != nil {
		t.Fatalf("ack read failed after %d bytes in %s: %v", written, time.Since(start), err)
	}
	if ack[0] != 1 {
		t.Fatalf("bad ack: %d", ack[0])
	}
	if written != total {
		t.Fatalf("written mismatch: got=%d want=%d", written, total)
	}
}
