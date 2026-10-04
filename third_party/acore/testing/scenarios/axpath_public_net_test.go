package scenarios

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tcpserver "github.com/ImAubrey/acore/testing/servers/tcp"
	udpserver "github.com/ImAubrey/acore/testing/servers/udp"
)

type publicNetFaultConfig struct {
	BaseDelayMs       int
	JitterMs          int
	BurstEveryBytes   int64
	BurstPauseMs      int
	CutConnModulo     int64
	CutAfterMinBytes  int64
	CutAfterMaxBytes  int64
	CutAfterMs        int
	LossRatePct       int
	LossDelayMinMs    int
	LossDelayMaxMs    int
	ReorderRatePct    int
	ReorderDelayMinMs int
	ReorderDelayMaxMs int
	Seed              int64
}

type publicNetProxyStats struct {
	Accepted      int64
	Cuts          int64
	LossEvents    int64
	ReorderEvents int64
}

func envIntWithDefault(key string, dflt int) int {
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

func envInt64WithDefault(key string, dflt int64) int64 {
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

func loadPublicNetFaultConfig() publicNetFaultConfig {
	seed := envInt64WithDefault("ACORE_AXPATH_PUBLIC_SEED", 20260301)
	profile := strings.ToLower(strings.TrimSpace(os.Getenv("ACORE_AXPATH_PUBLIC_PROFILE")))

	baseDelayDflt := 20
	jitterDflt := 40
	burstEveryKBDflt := 128
	burstPauseDflt := 80
	cutConnModuloDflt := int64(5)
	cutMinKBDflt := int64(16)
	cutMaxKBDflt := int64(64)
	cutAfterMsDflt := 1500
	lossRatePctDflt := 0
	lossDelayMinDflt := 120
	lossDelayMaxDflt := 700
	reorderRatePctDflt := 0
	reorderDelayMinDflt := 80
	reorderDelayMaxDflt := 300

	// "gfw-cn" profile emulates severe interference:
	// 20% loss-like retransmit stalls + 20% reorder-like jitter spikes + active subflow cuts.
	if profile == "gfw-cn" || profile == "gfw" {
		baseDelayDflt = 35
		jitterDflt = 90
		burstEveryKBDflt = 64
		burstPauseDflt = 150
		cutConnModuloDflt = 4
		cutMinKBDflt = 8
		cutMaxKBDflt = 48
		cutAfterMsDflt = 1200
		lossRatePctDflt = 20
		lossDelayMinDflt = 120
		lossDelayMaxDflt = 900
		reorderRatePctDflt = 20
		reorderDelayMinDflt = 60
		reorderDelayMaxDflt = 360
	}

	baseDelayMs := envIntWithDefault("ACORE_AXPATH_PUBLIC_BASE_DELAY_MS", baseDelayDflt)
	jitterMs := envIntWithDefault("ACORE_AXPATH_PUBLIC_JITTER_MS", jitterDflt)
	burstEveryKB := envIntWithDefault("ACORE_AXPATH_PUBLIC_BURST_EVERY_KB", burstEveryKBDflt)
	burstPauseMs := envIntWithDefault("ACORE_AXPATH_PUBLIC_BURST_PAUSE_MS", burstPauseDflt)
	cutConnModulo := envInt64WithDefault("ACORE_AXPATH_PUBLIC_CUT_CONN_MOD", cutConnModuloDflt)
	cutMinKB := envInt64WithDefault("ACORE_AXPATH_PUBLIC_CUT_MIN_KB", cutMinKBDflt)
	cutMaxKB := envInt64WithDefault("ACORE_AXPATH_PUBLIC_CUT_MAX_KB", cutMaxKBDflt)
	cutAfterMs := envIntWithDefault("ACORE_AXPATH_PUBLIC_CUT_AFTER_MS", cutAfterMsDflt)
	lossRatePct := envIntWithDefault("ACORE_AXPATH_PUBLIC_LOSS_RATE_PCT", lossRatePctDflt)
	lossDelayMinMs := envIntWithDefault("ACORE_AXPATH_PUBLIC_LOSS_DELAY_MIN_MS", lossDelayMinDflt)
	lossDelayMaxMs := envIntWithDefault("ACORE_AXPATH_PUBLIC_LOSS_DELAY_MAX_MS", lossDelayMaxDflt)
	reorderRatePct := envIntWithDefault("ACORE_AXPATH_PUBLIC_REORDER_RATE_PCT", reorderRatePctDflt)
	reorderDelayMinMs := envIntWithDefault("ACORE_AXPATH_PUBLIC_REORDER_DELAY_MIN_MS", reorderDelayMinDflt)
	reorderDelayMaxMs := envIntWithDefault("ACORE_AXPATH_PUBLIC_REORDER_DELAY_MAX_MS", reorderDelayMaxDflt)

	if baseDelayMs < 0 {
		baseDelayMs = 0
	}
	if jitterMs < 0 {
		jitterMs = 0
	}
	if burstEveryKB < 0 {
		burstEveryKB = 0
	}
	if burstPauseMs < 0 {
		burstPauseMs = 0
	}
	if cutConnModulo < 0 {
		cutConnModulo = 0
	}
	if cutMinKB < 0 {
		cutMinKB = 0
	}
	if cutMaxKB < cutMinKB {
		cutMaxKB = cutMinKB
	}
	if cutAfterMs < 0 {
		cutAfterMs = 0
	}
	if lossRatePct < 0 {
		lossRatePct = 0
	}
	if lossRatePct > 100 {
		lossRatePct = 100
	}
	if lossDelayMinMs < 0 {
		lossDelayMinMs = 0
	}
	if lossDelayMaxMs < lossDelayMinMs {
		lossDelayMaxMs = lossDelayMinMs
	}
	if reorderRatePct < 0 {
		reorderRatePct = 0
	}
	if reorderRatePct > 100 {
		reorderRatePct = 100
	}
	if reorderDelayMinMs < 0 {
		reorderDelayMinMs = 0
	}
	if reorderDelayMaxMs < reorderDelayMinMs {
		reorderDelayMaxMs = reorderDelayMinMs
	}

	return publicNetFaultConfig{
		BaseDelayMs:       baseDelayMs,
		JitterMs:          jitterMs,
		BurstEveryBytes:   cutToBytes(int64(burstEveryKB), 1024),
		BurstPauseMs:      burstPauseMs,
		CutConnModulo:     cutConnModulo,
		CutAfterMinBytes:  cutToBytes(cutMinKB, 1024),
		CutAfterMaxBytes:  cutToBytes(cutMaxKB, 1024),
		CutAfterMs:        cutAfterMs,
		LossRatePct:       lossRatePct,
		LossDelayMinMs:    lossDelayMinMs,
		LossDelayMaxMs:    lossDelayMaxMs,
		ReorderRatePct:    reorderRatePct,
		ReorderDelayMinMs: reorderDelayMinMs,
		ReorderDelayMaxMs: reorderDelayMaxMs,
		Seed:              seed,
	}
}

func cutToBytes(v int64, unit int64) int64 {
	if v <= 0 || unit <= 0 {
		return 0
	}
	return v * unit
}

func sleepNetDelay(cfg publicNetFaultConfig, r *rand.Rand) {
	delayMs := cfg.BaseDelayMs
	if cfg.JitterMs > 0 {
		delayMs += r.Intn(cfg.JitterMs + 1)
	}
	if delayMs <= 0 {
		return
	}
	time.Sleep(time.Duration(delayMs) * time.Millisecond)
}

func sleepRandomRangeMs(r *rand.Rand, minMs int, maxMs int) {
	if minMs < 0 {
		minMs = 0
	}
	if maxMs < minMs {
		maxMs = minMs
	}
	if maxMs <= 0 {
		return
	}
	d := minMs
	if maxMs > minMs {
		d += r.Intn(maxMs - minMs + 1)
	}
	if d > 0 {
		time.Sleep(time.Duration(d) * time.Millisecond)
	}
}

func writeAllBytes(dst net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := dst.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func copyWithPublicNetFault(dst net.Conn, src net.Conn, cfg publicNetFaultConfig, r *rand.Rand, cutAfterBytes int64, lossEvents *atomic.Int64, reorderEvents *atomic.Int64) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	var nextBurstAt int64
	if cfg.BurstEveryBytes > 0 {
		nextBurstAt = cfg.BurstEveryBytes
	}

	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			sleepNetDelay(cfg, r)
			// Loss-like impairment: emulate IP loss + TCP retransmission by injecting
			// an additional stall (bytes are not dropped at stream layer).
			if cfg.LossRatePct > 0 && r.Intn(100) < cfg.LossRatePct {
				if lossEvents != nil {
					lossEvents.Add(1)
				}
				sleepRandomRangeMs(r, cfg.LossDelayMinMs, cfg.LossDelayMaxMs)
			}
			// Reorder-like impairment: emulate out-of-order arrival impact by adding
			// variable delay spikes on a subset of frames.
			if cfg.ReorderRatePct > 0 && r.Intn(100) < cfg.ReorderRatePct {
				if reorderEvents != nil {
					reorderEvents.Add(1)
				}
				sleepRandomRangeMs(r, cfg.ReorderDelayMinMs, cfg.ReorderDelayMaxMs)
			}

			if err := writeAllBytes(dst, buf[:nr]); err != nil {
				return total, err
			}
			total += int64(nr)

			if cfg.BurstEveryBytes > 0 && cfg.BurstPauseMs > 0 {
				for total >= nextBurstAt && nextBurstAt > 0 {
					time.Sleep(time.Duration(cfg.BurstPauseMs) * time.Millisecond)
					nextBurstAt += cfg.BurstEveryBytes
				}
			}

			if cutAfterBytes > 0 && total >= cutAfterBytes {
				return total, io.ErrUnexpectedEOF
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

func pickCutAfterBytes(cfg publicNetFaultConfig, connIndex int64) int64 {
	if cfg.CutConnModulo <= 0 {
		return 0
	}
	// Use 1-based modulo for readability: modulo=5 means #5/#10/... are cut.
	if (connIndex+1)%cfg.CutConnModulo != 0 {
		return 0
	}

	minB := cfg.CutAfterMinBytes
	maxB := cfg.CutAfterMaxBytes
	if minB <= 0 && maxB <= 0 {
		return 0
	}
	if maxB < minB {
		maxB = minB
	}
	if maxB == minB {
		return minB
	}
	rr := rand.New(rand.NewSource(cfg.Seed + connIndex*13331 + 97))
	return minB + rr.Int63n(maxB-minB+1)
}

func startTCPProxyWithPublicNetFault(t *testing.T, upstreamAddr string, cfg publicNetFaultConfig) (listenAddr string, statsFn func() publicNetProxyStats, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var accepted atomic.Int64
	var cuts atomic.Int64
	var lossEvents atomic.Int64
	var reorderEvents atomic.Int64

	go func() {
		for {
			clientConn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}

			connIndex := accepted.Add(1) - 1
			go func(c net.Conn, idx int64) {
				defer forceClose(c)

				serverConn, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
				if err != nil {
					return
				}
				defer forceClose(serverConn)

				shouldCutConn := cfg.CutConnModulo > 0 && (idx+1)%cfg.CutConnModulo == 0
				// Emulate "公网断流": kill selected subflows by byte threshold and/or timer.
				cutAfterDownlink := int64(0)
				if shouldCutConn {
					cutAfterDownlink = pickCutAfterBytes(cfg, idx)
				}
				var cutOnce sync.Once
				markCut := func() {
					cutOnce.Do(func() { cuts.Add(1) })
				}
				if shouldCutConn && cfg.CutAfterMs > 0 {
					go func() {
						time.Sleep(time.Duration(cfg.CutAfterMs) * time.Millisecond)
						markCut()
						forceClose(c)
						forceClose(serverConn)
					}()
				}

				c2sDone := make(chan error, 1)
				s2cDone := make(chan error, 1)

				go func() {
					r1 := rand.New(rand.NewSource(cfg.Seed + idx*20011 + 1))
					_, err := copyWithPublicNetFault(serverConn, c, cfg, r1, 0, &lossEvents, &reorderEvents)
					c2sDone <- err
				}()

				go func() {
					r2 := rand.New(rand.NewSource(cfg.Seed + idx*20011 + 2))
					_, err := copyWithPublicNetFault(c, serverConn, cfg, r2, cutAfterDownlink, &lossEvents, &reorderEvents)
					if err == io.ErrUnexpectedEOF {
						markCut()
					}
					s2cDone <- err
				}()

				select {
				case <-c2sDone:
				case <-s2cDone:
				}
				forceClose(c)
				forceClose(serverConn)
				<-c2sDone
				<-s2cDone
			}(clientConn, connIndex)
		}
	}()

	return ln.Addr().String(), func() publicNetProxyStats {
			return publicNetProxyStats{
				Accepted:      accepted.Load(),
				Cuts:          cuts.Load(),
				LossEvents:    lossEvents.Load(),
				ReorderEvents: reorderEvents.Load(),
			}
		}, func() {
			cancel()
			_ = ln.Close()
		}
}

func makeUDPPayload(flowID int, seq int, n int) []byte {
	if n < 8 {
		n = 8
	}
	p := make([]byte, n)
	p[0] = byte(flowID)
	p[1] = byte(seq)
	p[2] = byte(seq >> 8)
	p[3] = byte(flowID >> 8)
	for i := 4; i < len(p); i++ {
		p[i] = byte((flowID*31 + seq*17 + i) & 0xff)
	}
	return p
}

func runUDPLoad(flowID int, targetPort int, packets int, payloadSize int, key byte, retries int) (okCount int, failCount int) {
	conn, err := net.DialUDP(
		"udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: targetPort},
	)
	if err != nil {
		return 0, packets
	}
	defer conn.Close()

	if retries < 1 {
		retries = 1
	}

	for seq := 0; seq < packets; seq++ {
		payload := makeUDPPayload(flowID, seq, payloadSize)
		want := xorWithKey(key, payload)
		success := false

		for attempt := 0; attempt < retries; attempt++ {
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				continue
			}
			resp := make([]byte, len(payload))
			n, err := conn.Read(resp)
			if err != nil {
				continue
			}
			if n != len(payload) {
				continue
			}
			if bytesEqual(resp, want) {
				success = true
				break
			}
		}

		if success {
			okCount++
		} else {
			failCount++
		}
	}

	return okCount, failCount
}

func TestAXPathPublicNetEmulation_UDPLoad(t *testing.T) {
	if os.Getenv("ACORE_SCENARIO_TESTS") == "" {
		t.Skip("Skipping scenario tests. Set ACORE_SCENARIO_TESTS=1 to run.")
	}
	if os.Getenv("ACORE_AXPATH_PUBLIC_NET_TESTS") == "" {
		t.Skip("Skipping public-net emulation tests. Set ACORE_AXPATH_PUBLIC_NET_TESTS=1 to run.")
	}

	udpFlows := envIntWithDefault("ACORE_AXPATH_PUBLIC_UDP_FLOWS", 8)
	udpPacketsPerFlow := envIntWithDefault("ACORE_AXPATH_PUBLIC_UDP_PACKETS", 120)
	udpPayloadSize := envIntWithDefault("ACORE_AXPATH_PUBLIC_UDP_SIZE", 256)
	udpRetries := envIntWithDefault("ACORE_AXPATH_PUBLIC_UDP_RETRIES", 3)
	minSuccessPct := envIntWithDefault("ACORE_AXPATH_PUBLIC_MIN_SUCCESS_PCT", 95)
	subflows := envIntWithDefault("ACORE_AXPATH_PUBLIC_SUBFLOWS", 4)
	logLevel := os.Getenv("ACORE_AXPATH_LOGLEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	if udpFlows < 1 {
		udpFlows = 1
	}
	if udpPacketsPerFlow < 1 {
		udpPacketsPerFlow = 1
	}
	if udpPayloadSize < 8 {
		udpPayloadSize = 8
	}
	if minSuccessPct < 1 {
		minSuccessPct = 1
	}
	if minSuccessPct > 100 {
		minSuccessPct = 100
	}
	if subflows < 1 {
		subflows = 1
	}
	if subflows > 16 {
		subflows = 16
	}

	cfg := loadPublicNetFaultConfig()
	t.Logf(
		"public net profile: delay=%dms jitter=%dms burst_every=%dB burst_pause=%dms cut_mod=%d cut=[%dB..%dB] cut_after_ms=%d loss=%d%%(%d-%dms) reorder=%d%%(%d-%dms) seed=%d",
		cfg.BaseDelayMs, cfg.JitterMs, cfg.BurstEveryBytes, cfg.BurstPauseMs, cfg.CutConnModulo, cfg.CutAfterMinBytes, cfg.CutAfterMaxBytes, cfg.CutAfterMs,
		cfg.LossRatePct, cfg.LossDelayMinMs, cfg.LossDelayMaxMs,
		cfg.ReorderRatePct, cfg.ReorderDelayMinMs, cfg.ReorderDelayMaxMs,
		cfg.Seed,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tmpDir := t.TempDir()
	serverPort := tcpserver.PickPort()
	clientUDPPort := udpserver.PickPort()
	userID := "b7a3e65f-2dc5-4cda-8b41-bfc4a72e3d6f"
	psk := "testpsk"
	key := byte(0x5C)

	udpEchoPort, closeEcho := startUDPEcho(t, key)
	defer closeEcho()

	crtPath, keyPath := writeSelfSignedCert(t, tmpDir)
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
  "outbounds": [
    {
      "tag": "udp_echo",
      "protocol": "freedom",
      "settings": { "redirect": "127.0.0.1:%d" }
    },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["in_vless_axpath_tls"],
        "network": "udp",
        "outboundTag": "udp_echo"
      }
    ]
  }
}`, logLevel, int(serverPort), userID, filepath.ToSlash(crtPath), filepath.ToSlash(keyPath), subflows, psk, udpEchoPort)

	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	serverCmd, serverOut := startAcoreWithJSON(t, serverCfgPath)
	defer stopProcess(serverCmd)
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", int(serverPort)), 10*time.Second); err != nil {
		t.Fatalf("server not ready: %v\n%s", err, serverOut.String())
	}

	proxyAddr, statsFn, closeProxy := startTCPProxyWithPublicNetFault(t, fmt.Sprintf("127.0.0.1:%d", int(serverPort)), cfg)
	defer closeProxy()
	_, proxyPortStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("split proxy addr failed: %v", err)
	}
	proxyPort, err := strconv.Atoi(proxyPortStr)
	if err != nil {
		t.Fatalf("proxy port parse failed: %v", err)
	}

	clientCfg := fmt.Sprintf(`{
  "log": { "loglevel": %q },
  "inbounds": [
    {
      "tag": "in_udp",
      "listen": "127.0.0.1",
      "port": %d,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "8.8.8.8",
        "port": 53,
        "network": "udp"
      }
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
    },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["in_udp"],
        "outboundTag": "vless_axpath"
      }
    ]
  }
}`, logLevel, int(clientUDPPort), proxyPort, userID, subflows, psk)

	if err := os.WriteFile(clientCfgPath, []byte(clientCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	clientCmd, clientOut := startAcoreWithJSON(t, clientCfgPath)
	defer stopProcess(clientCmd)

	// Warm up the path and allow first subflow group to establish.
	warmOK := false
	for i := 0; i < 10; i++ {
		okN, failN := runUDPLoad(0, int(clientUDPPort), 1, 64, key, 2)
		if okN == 1 && failN == 0 {
			warmOK = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !warmOK {
		t.Fatalf("warmup failed\nclient:\n%s\nserver:\n%s", clientOut.String(), serverOut.String())
	}

	start := time.Now()
	var (
		wg        sync.WaitGroup
		totalOK   atomic.Int64
		totalFail atomic.Int64
	)
	for i := 0; i < udpFlows; i++ {
		wg.Add(1)
		go func(flowID int) {
			defer wg.Done()
			okN, failN := runUDPLoad(flowID+1, int(clientUDPPort), udpPacketsPerFlow, udpPayloadSize, key, udpRetries)
			totalOK.Add(int64(okN))
			totalFail.Add(int64(failN))
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		t.Fatalf("test timeout: %v\nclient:\n%s\nserver:\n%s", ctx.Err(), clientOut.String(), serverOut.String())
	case <-done:
	}

	elapsed := time.Since(start)
	okN := totalOK.Load()
	failN := totalFail.Load()
	totalN := okN + failN
	if totalN <= 0 {
		t.Fatalf("no udp packets processed\nclient:\n%s\nserver:\n%s", clientOut.String(), serverOut.String())
	}

	successPct := int((okN * 100) / totalN)
	stats := statsFn()
	t.Logf(
		"udp load done: subflows=%d flows=%d packets_per_flow=%d payload=%dB retries=%d success=%d/%d (%d%%) fail=%d elapsed=%s accepted_subflows=%d forced_cuts=%d loss_events=%d reorder_events=%d",
		subflows, udpFlows, udpPacketsPerFlow, udpPayloadSize, udpRetries, okN, totalN, successPct, failN, elapsed, stats.Accepted, stats.Cuts, stats.LossEvents, stats.ReorderEvents,
	)

	if successPct < minSuccessPct {
		t.Fatalf(
			"udp success ratio too low: got=%d%% want>=%d%% (ok=%d total=%d fail=%d)\nclient:\n%s\nserver:\n%s",
			successPct, minSuccessPct, okN, totalN, failN, clientOut.String(), serverOut.String(),
		)
	}
}
