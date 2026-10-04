package scenarios

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tcpserver "github.com/ImAubrey/acore/testing/servers/tcp"
	udpserver "github.com/ImAubrey/acore/testing/servers/udp"
	"golang.org/x/net/dns/dnsmessage"
	xproxy "golang.org/x/net/proxy"
)

type trafficCase struct {
	name string

	// Injection kind: "direct-tcp" | "direct-udp" | "socks-tcp".
	inject string

	// Direct injection: connect to this client inbound.
	clientInboundTag  string
	clientInboundPort int

	// For "socks-tcp" injection.
	socksAddr string
	socksDest string // may include "{FAKEIP}" placeholder

	// Dokodemo target for direct injection inbounds.
	targetAddr string
	targetPort int

	// Inbound sniffing config (nil means sniffing disabled).
	sniffing map[string]any

	// Client routing rule extra fields (merged into a base field rule).
	clientRuleExtra map[string]any

	// Optional local source port when dialing the client inbound (direct injection only).
	localPort int

	// Payload and expected echo key.
	payload []byte
	key     byte

	// Client outbound tag (VLESS over AXPath) and the corresponding server inbound/outbound.
	clientOutboundTag string
	serverInboundTag  string
	serverInboundPort int
	serverOutboundTag string

	// Server routing rule extra fields (merged into base inboundTag -> outboundTag rule).
	serverRuleExtra map[string]any

	// Echo endpoint.
	echoNetwork string // "tcp" | "udp"
	echoPort    int
}

func xorWithKey(key byte, b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ key
	}
	return out
}

func startTCPEcho(t *testing.T, key byte) (port int, closeFn func()) {
	t.Helper()
	s := &tcpserver.Server{
		MsgProcessor: func(msg []byte) []byte { return xorWithKey(key, msg) },
	}
	dest, err := s.Start()
	if err != nil {
		t.Fatal(err)
	}
	return int(dest.Port), func() { _ = s.Close() }
}

func startUDPEcho(t *testing.T, key byte) (port int, closeFn func()) {
	t.Helper()
	s := &udpserver.Server{
		MsgProcessor: func(msg []byte) []byte { return xorWithKey(key, msg) },
	}
	dest, err := s.Start()
	if err != nil {
		t.Fatal(err)
	}
	return int(dest.Port), func() { _ = s.Close() }
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal json failed: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s failed: %v", path, err)
	}
}

func dialAndExchangeTCP(t *testing.T, port int, localPort int, payload []byte, key byte) {
	t.Helper()
	d := &net.Dialer{Timeout: 3 * time.Second}
	if localPort != 0 {
		d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort}
	}
	conn, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial tcp :%d failed: %v", port, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("tcp write failed: %v", err)
	}
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("tcp read failed: %v", err)
	}
	want := xorWithKey(key, payload)
	if !bytesEqual(resp, want) {
		t.Fatalf("unexpected tcp response\n got: %x\nwant: %x", resp, want)
	}
}

func dialAndExchangeUDP(t *testing.T, port int, localPort int, payload []byte, key byte) {
	t.Helper()
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	if localPort != 0 {
		laddr.Port = localPort
	}
	raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		t.Fatalf("dial udp :%d failed: %v", port, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("udp write failed: %v", err)
	}
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("udp read failed: %v", err)
	}
	want := xorWithKey(key, payload)
	if !bytesEqual(resp, want) {
		t.Fatalf("unexpected udp response\n got: %x\nwant: %x", resp, want)
	}
}

func dialAndExchangeSocksTCP(t *testing.T, socksAddr string, destAddr string, payload []byte, key byte) {
	t.Helper()
	dialer, err := xproxy.SOCKS5("tcp", socksAddr, nil, xproxy.Direct)
	if err != nil {
		t.Fatalf("create socks dialer failed: %v", err)
	}
	conn, err := dialer.Dial("tcp", destAddr)
	if err != nil {
		t.Fatalf("socks dial %s failed: %v", destAddr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("socks tcp write failed: %v", err)
	}
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("socks tcp read failed: %v", err)
	}
	want := xorWithKey(key, payload)
	if !bytesEqual(resp, want) {
		t.Fatalf("unexpected socks tcp response\n got: %x\nwant: %x", resp, want)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func buildDNSQueryA(t *testing.T, domain string, id uint16) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatalf("dns name: %v", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("dns pack: %v", err)
	}
	return b
}

func parseDNSAnswerA(t *testing.T, resp []byte, id uint16, domain string) net.IP {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatalf("dns parse start: %v", err)
	}
	if h.ID != id {
		t.Fatalf("dns id mismatch: got=%d want=%d", h.ID, id)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatalf("dns parse question: %v", err)
	}
	if got := q.Name.String(); got != domain+"." {
		t.Fatalf("dns question name mismatch: got=%q want=%q", got, domain+".")
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("dns skip questions: %v", err)
	}
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatalf("dns answer header: %v", err)
		}
		if ah.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				t.Fatalf("dns skip answer: %v", err)
			}
			continue
		}
		ar, err := p.AResource()
		if err != nil {
			t.Fatalf("dns A resource: %v", err)
		}
		return net.IPv4(ar.A[0], ar.A[1], ar.A[2], ar.A[3])
	}
	t.Fatalf("no A answer found for %q", domain)
	return nil
}

func decodeHexParts(t *testing.T, parts ...string) []byte {
	t.Helper()
	s := strings.Join(parts, "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return b
}

func buildTLSClientHello(host string, alpn string, cipherSuites int) []byte {
	if cipherSuites <= 0 {
		cipherSuites = 10
	}
	body := make([]byte, 0, 512)
	body = append(body, 0x03, 0x03)          // client_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_len

	suites := make([]byte, 0, cipherSuites*2)
	for i := 0; i < cipherSuites; i++ {
		v := uint16(0x000a + i)
		suites = append(suites, byte(v>>8), byte(v))
	}
	body = append(body, byte(len(suites)>>8), byte(len(suites)))
	body = append(body, suites...)

	body = append(body, 0x01, 0x00) // compression methods: null

	exts := make([]byte, 0, 256)
	if host != "" {
		name := []byte(host)
		listLen := 1 + 2 + len(name)
		sni := make([]byte, 0, 2+listLen)
		sni = append(sni, byte(listLen>>8), byte(listLen))
		sni = append(sni, 0x00, byte(len(name)>>8), byte(len(name)))
		sni = append(sni, name...)
		exts = append(exts, 0x00, 0x00, byte(len(sni)>>8), byte(len(sni)))
		exts = append(exts, sni...)
	}
	if alpn != "" {
		name := []byte(alpn)
		list := make([]byte, 0, 2+1+len(name))
		list = append(list, 0x00, byte(1+len(name)))
		list = append(list, byte(len(name)))
		list = append(list, name...)
		exts = append(exts, 0x00, 0x10, byte(len(list)>>8), byte(len(list)))
		exts = append(exts, list...)
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01)
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x01, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

func buildUTPPacket() []byte {
	p := make([]byte, 20)
	p[0] = 0x11 // type=1, version=1
	p[1] = 0x00 // no extensions
	ts := uint32(time.Now().UnixMicro())
	binary.BigEndian.PutUint32(p[4:8], ts)
	return p
}

func TestAXPathTrafficLoop_AllSniffers_AllRoutingMatchers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tmpDir := t.TempDir()
	crtPath, keyPath := writeSelfSignedCert(t, tmpDir)
	crtPath = filepath.ToSlash(crtPath)
	keyPath = filepath.ToSlash(keyPath)

	userID := "b7a3e65f-2dc5-4cda-8b41-bfc4a72e3d6f"
	// VlessRoute is UUID bytes[6:8] big-endian; for the userID above: 0x4cda == 19674.
	vlessRoutePort := 19674

	psk := "axpath-test-psk"

	// SOCKS inbound used only for FakeDNS metadata-only sniffing (dynamic destination).
	socksMetaTag := "in_socks_fakedns_meta"
	// Ports are assigned after echo servers are started to avoid collisions.
	socksMetaPort := 0
	socksAddr := ""

	// DNS seed inbound to trigger FakeDNS assignment through DNS outbound (no external network).
	dnsSeedTag := "in_dns_seed"
	// Port is assigned after echo servers are started to avoid collisions.
	dnsSeedPort := 0
	dnsOutTag := "out_dns_seed"

	sniffAll := map[string]any{
		"enabled":      true,
		"routeOnly":    true,
		"destOverride": []string{"http", "tls", "quic", "dns", "fakedns"},
	}

	quicPayload := decodeHexParts(t,
		"cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55",
		"c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3",
		"e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fd",
		"dbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559",
		"757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e",
		"7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0",
		"b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4",
		"fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d049",
		"04b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1",
		"bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9c",
		"ec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b54",
		"0f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf",
		"5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec186",
		"70d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393",
		"df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a583616",
		"9bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a",
		"5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb9",
		"49cb1f40feb7c1d9ce5e71b",
	)

	// Define all cases.
	cases := []trafficCase{
		// Sniffer protocol coverage.
		{
			name:            "sniff_http1",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"http1"}},
			payload:         []byte("GET / HTTP/1.1\r\nHost: http1.local\r\n\r\n"),
		},
		{
			name:            "sniff_http2",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"http2"}},
			payload:         []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		},
		{
			name:            "sniff_tls",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      443,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"tls"}},
			// Include ALPN to ensure this is not mis-classified as "trojan".
			payload: buildTLSClientHello("tls.local", "h2", 10),
		},
		{
			name:            "sniff_socks4",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"socks4"}},
			payload:         []byte{0x04, 0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x00},
		},
		{
			name:            "sniff_socks5",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"socks5"}},
			payload:         []byte{0x05, 0x01, 0x00},
		},
		{
			name:            "sniff_ssh",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      22,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"ssh"}},
			payload:         []byte("SSH-2.0-OpenSSH_9.0\r\n"),
		},
		{
			name:            "sniff_rdp",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      3389,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"rdp"}},
			payload: []byte{
				0x03, 0x00, 0x00, 0x13,
				0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x08, 0x00,
				0x03, 0x00, 0x00, 0x00,
			},
		},
		{
			name:            "sniff_mqtt",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      1883,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"mqtt"}},
			payload: []byte{
				0x10, 0x0c,
				0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
				0x04,
				0x02,
				0x00, 0x00,
				0x00, 0x00,
			},
		},
		{
			name:            "sniff_postgres",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      5432,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"postgres"}},
			payload: []byte{
				0x00, 0x00, 0x00, 0x08,
				0x00, 0x03, 0x00, 0x00,
			},
		},
		{
			name:            "sniff_bittorrent_tcp",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      6881,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"bittorrent"}},
			payload:         append([]byte{19}, []byte("BitTorrent protocol")...),
		},
		{
			name:            "sniff_ech",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      443,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"ech"}},
			payload: []byte{
				0x16, 0x03, 0x01, 0x00, 0x33,
				0x01, 0x00, 0x00, 0x2f,
				0x03, 0x03,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00,
				0x00, 0x02,
				0x13, 0x01,
				0x01,
				0x00,
				0x00, 0x04,
				0xfe, 0x0d, 0x00, 0x00,
			},
		},
		{
			name:            "sniff_dns",
			inject:          "direct-udp",
			targetAddr:      "8.8.8.8",
			targetPort:      53,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"dns"}},
			payload:         buildDNSQueryA(t, "dns.local", 0x1234),
		},
		{
			name:            "sniff_wireguard",
			inject:          "direct-udp",
			targetAddr:      "1.2.3.4",
			targetPort:      51820,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"wireguard"}},
			payload: func() []byte {
				p := make([]byte, 148)
				p[0] = 1
				return p
			}(),
		},
		{
			name:            "sniff_ntp",
			inject:          "direct-udp",
			targetAddr:      "1.2.3.4",
			targetPort:      123,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"ntp"}},
			payload: func() []byte {
				p := make([]byte, 48)
				p[0] = 0x23
				p[1] = 0x00
				p[2] = 0x04
				p[3] = 0xec
				return p
			}(),
		},
		{
			name:            "sniff_ikev2",
			inject:          "direct-udp",
			targetAddr:      "1.2.3.4",
			targetPort:      500,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"ikev2"}},
			payload: func() []byte {
				p := make([]byte, 28)
				p[17] = 0x20
				p[18] = 34
				p[27] = 0x1c
				return p
			}(),
		},
		{
			name:            "sniff_dtls",
			inject:          "direct-udp",
			targetAddr:      "1.2.3.4",
			targetPort:      443,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"dtls"}},
			payload: []byte{
				0x16, 0xfe, 0xfd,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x01,
				0x00,
			},
		},
		{
			name:            "sniff_quic",
			inject:          "direct-udp",
			targetAddr:      "1.2.3.4",
			targetPort:      443,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"quic"}},
			payload:         quicPayload,
		},
		{
			name:            "sniff_stun",
			inject:          "direct-udp",
			targetAddr:      "1.2.3.4",
			targetPort:      3478,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"stun"}},
			payload: []byte{
				0x00, 0x01, 0x00, 0x00,
				0x21, 0x12, 0xA4, 0x42,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:            "sniff_turn",
			inject:          "direct-udp",
			targetAddr:      "1.2.3.4",
			targetPort:      3478,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"turn"}},
			payload: []byte{
				0x00, 0x03, 0x00, 0x00,
				0x21, 0x12, 0xA4, 0x42,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:            "sniff_bittorrent_utp",
			inject:          "direct-udp",
			targetAddr:      "1.2.3.4",
			targetPort:      6881,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"protocol": []string{"bittorrent"}},
			payload:         buildUTPPacket(),
		},
		{
			name:   "sniff_fakedns_meta",
			inject: "socks-tcp",
			// Filled after ports are assigned.
			socksAddr:        "",
			socksDest:        "{FAKEIP}:443",
			payload:          []byte("fakedns"),
			clientInboundTag: socksMetaTag,
			clientRuleExtra:  map[string]any{"protocol": []string{"fakedns"}},
		},

		// Routing matcher coverage (client-side).
		{
			name:            "match_ip",
			inject:          "direct-tcp",
			targetAddr:      "10.0.0.1",
			targetPort:      80,
			clientRuleExtra: map[string]any{"ip": []string{"10.0.0.0/8"}},
			payload:         []byte("ip"),
		},
		{
			name:            "match_port",
			inject:          "direct-tcp",
			targetAddr:      "10.1.1.1",
			targetPort:      23456,
			clientRuleExtra: map[string]any{"port": 23456},
			payload:         []byte("port"),
		},
		{
			name:            "match_network_udp",
			inject:          "direct-udp",
			targetAddr:      "10.2.2.2",
			targetPort:      9999,
			clientRuleExtra: map[string]any{"network": "udp"},
			payload:         []byte("net"),
		},
		{
			name:            "match_source_ip",
			inject:          "direct-tcp",
			targetAddr:      "10.3.3.3",
			targetPort:      3333,
			clientRuleExtra: map[string]any{"sourceIP": []string{"127.0.0.0/8"}},
			payload:         []byte("srcip"),
		},
		{
			name:       "match_source_port",
			inject:     "direct-tcp",
			targetAddr: "10.4.4.4",
			targetPort: 4444,
			// Filled after ports are assigned.
			localPort:       0,
			clientRuleExtra: map[string]any{}, // filled after localPort assigned
			payload:         []byte("srcport"),
		},
		{
			name:            "match_local_ip",
			inject:          "direct-tcp",
			targetAddr:      "10.5.5.5",
			targetPort:      5555,
			clientRuleExtra: map[string]any{"localIP": []string{"127.0.0.1"}},
			payload:         []byte("localip"),
		},
		{
			name:            "match_local_port",
			inject:          "direct-tcp",
			targetAddr:      "10.6.6.6",
			targetPort:      6666,
			clientRuleExtra: map[string]any{}, // filled after inbound port assigned
			payload:         []byte("localport"),
		},
		{
			name:            "match_attrs",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"attrs": map[string]string{":path": "^/attrs-match$"}},
			payload:         []byte("GET /attrs-match HTTP/1.1\r\nHost: attrs.local\r\n\r\n"),
		},
		{
			name:            "match_domain_full",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"domain": []string{"full:full.domain.local"}},
			payload:         []byte("GET / HTTP/1.1\r\nHost: full.domain.local\r\n\r\n"),
		},
		{
			name:            "match_domain_domain",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"domain": []string{"domain:domain.local"}},
			payload:         []byte("GET / HTTP/1.1\r\nHost: sub.domain.local\r\n\r\n"),
		},
		{
			name:            "match_domain_regex",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"domain": []string{"regexp:^regex-[0-9]+\\.local$"}},
			payload:         []byte("GET / HTTP/1.1\r\nHost: regex-123.local\r\n\r\n"),
		},
		{
			name:            "match_domain_keyword",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			sniffing:        sniffAll,
			clientRuleExtra: map[string]any{"domain": []string{"keyword:keyword"}},
			payload:         []byte("GET / HTTP/1.1\r\nHost: hello-keyword.local\r\n\r\n"),
		},
		{
			name:       "match_require_ruletag",
			inject:     "direct-tcp",
			targetAddr: "1.2.3.4",
			targetPort: 80,
			sniffing:   sniffAll,
			clientRuleExtra: map[string]any{
				"requireRuleTag": []string{"tag_reqtag"},
				"domain":         []string{"full:reqtag.local"},
			},
			payload: []byte("GET / HTTP/1.1\r\nHost: reqtag.local\r\n\r\n"),
		},
		{
			name:       "match_relookup",
			inject:     "direct-tcp",
			targetAddr: "1.2.3.4",
			targetPort: 80,
			sniffing:   sniffAll,
			clientRuleExtra: map[string]any{
				"attrs":    map[string]string{":path": "^/relookup$"},
				"reLookup": true,
			},
			serverRuleExtra: map[string]any{"domain": []string{"full:relookup.local"}},
			payload:         []byte("GET /relookup HTTP/1.1\r\nHost: relookup.local\r\n\r\n"),
		},

		// Routing matcher coverage (server-side).
		{
			name:            "server_match_user",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			clientRuleExtra: map[string]any{}, // inboundTag-only routing on client
			serverRuleExtra: map[string]any{"user": []string{"user@example.test"}},
			payload:         []byte("user"),
		},
		{
			name:            "server_match_vlessroute",
			inject:          "direct-tcp",
			targetAddr:      "1.2.3.4",
			targetPort:      80,
			clientRuleExtra: map[string]any{}, // inboundTag-only routing on client
			serverRuleExtra: map[string]any{"vlessRoute": vlessRoutePort},
			payload:         []byte("vlessroute"),
		},
	}

	// Assign tags/keys and start echo servers first.
	// Then assign all acore listen ports (TCP/UDP) to avoid collisions with OS-assigned echo ports.
	var (
		key     byte = 0x41 // 'A'
		closers      = make([]func(), 0, len(cases))
	)
	defer func() {
		for _, fn := range closers {
			fn()
		}
	}()

	tcpUsed := make(map[int]bool)
	udpUsed := make(map[int]bool)

	for i := range cases {
		c := &cases[i]
		c.key = key
		key++

		c.clientOutboundTag = "out_" + c.name
		c.serverInboundTag = "srv_in_" + c.name
		c.serverOutboundTag = "srv_out_" + c.name

		switch c.inject {
		case "direct-tcp":
			c.clientInboundTag = "in_" + c.name
			c.echoNetwork = "tcp"
			p, closeFn := startTCPEcho(t, c.key)
			c.echoPort = p
			tcpUsed[p] = true
			closers = append(closers, closeFn)
		case "direct-udp":
			c.clientInboundTag = "in_" + c.name
			c.echoNetwork = "udp"
			p, closeFn := startUDPEcho(t, c.key)
			c.echoPort = p
			udpUsed[p] = true
			closers = append(closers, closeFn)
		case "socks-tcp":
			// Uses the shared SOCKS inbound tag.
			c.clientInboundTag = socksMetaTag
			c.echoNetwork = "tcp"
			p, closeFn := startTCPEcho(t, c.key)
			c.echoPort = p
			tcpUsed[p] = true
			closers = append(closers, closeFn)
		default:
			t.Fatalf("unknown inject kind: %q", c.inject)
		}
	}

	pickUniqueTCP := func() int {
		for attempt := 0; attempt < 100; attempt++ {
			p := int(tcpserver.PickPort())
			if p == 0 || tcpUsed[p] {
				continue
			}
			tcpUsed[p] = true
			return p
		}
		t.Fatal("failed to pick unique tcp port")
		return 0
	}
	pickUniqueUDP := func() int {
		for attempt := 0; attempt < 100; attempt++ {
			p := int(udpserver.PickPort())
			if p == 0 || udpUsed[p] {
				continue
			}
			udpUsed[p] = true
			return p
		}
		t.Fatal("failed to pick unique udp port")
		return 0
	}

	socksMetaPort = pickUniqueTCP()
	socksAddr = fmt.Sprintf("127.0.0.1:%d", socksMetaPort)
	dnsSeedPort = pickUniqueUDP()

	// Assign all acore ports and any remaining per-case fields.
	for i := range cases {
		c := &cases[i]

		c.serverInboundPort = pickUniqueTCP()
		switch c.inject {
		case "direct-tcp":
			c.clientInboundPort = pickUniqueTCP()
		case "direct-udp":
			c.clientInboundPort = pickUniqueUDP()
		case "socks-tcp":
			c.socksAddr = socksAddr
		}

		if c.name == "match_source_port" {
			c.localPort = pickUniqueTCP()
		}
	}

	// Fill rules that depend on runtime-assigned ports.
	for i := range cases {
		c := &cases[i]
		switch c.name {
		case "match_source_port":
			c.clientRuleExtra["sourcePort"] = c.localPort
		case "match_local_port":
			c.clientRuleExtra["localPort"] = c.clientInboundPort
		}
	}

	// Build server config.
	serverInbounds := make([]any, 0, len(cases))
	serverOutbounds := make([]any, 0, 1+len(cases))
	serverRules := make([]any, 0, len(cases))
	serverOutbounds = append(serverOutbounds, map[string]any{"tag": "block", "protocol": "blackhole"})

	for _, c := range cases {
		// Only the "server_match_user" inbound has a non-empty email.
		email := ""
		if c.name == "server_match_user" {
			email = "user@example.test"
		}
		clientObj := map[string]any{"id": userID, "level": 0}
		if email != "" {
			clientObj["email"] = email
		}

		serverInbounds = append(serverInbounds, map[string]any{
			"tag":      c.serverInboundTag,
			"listen":   "127.0.0.1",
			"port":     c.serverInboundPort,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{clientObj},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network":  "axpath",
				"security": "tls",
				"tlsSettings": map[string]any{
					"certificates": []any{
						map[string]any{"certificateFile": crtPath, "keyFile": keyPath},
					},
				},
				"axpathSettings": map[string]any{"subflows": 2, "psk": psk},
			},
		})

		serverOutbounds = append(serverOutbounds, map[string]any{
			"tag":      c.serverOutboundTag,
			"protocol": "freedom",
			"settings": map[string]any{
				"redirect": fmt.Sprintf("127.0.0.1:%d", c.echoPort),
			},
		})

		r := map[string]any{
			"type":        "field",
			"inboundTag":  []string{c.serverInboundTag},
			"outboundTag": c.serverOutboundTag,
			"ruleTag":     c.name,
		}
		for k, v := range c.serverRuleExtra {
			r[k] = v
		}
		serverRules = append(serverRules, r)
	}

	serverCfg := map[string]any{
		// Keep this at "info" so failures can be debugged from captured logs.
		"log":       map[string]any{"loglevel": "info"},
		"inbounds":  serverInbounds,
		"outbounds": serverOutbounds,
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules":          serverRules,
		},
	}

	// Build client config.
	clientInbounds := make([]any, 0, 2+len(cases))
	clientOutbounds := make([]any, 0, 2+len(cases))
	clientRules := make([]any, 0, 2+len(cases))

	clientOutbounds = append(clientOutbounds, map[string]any{"tag": "block", "protocol": "blackhole"})

	clientOutbounds = append(clientOutbounds, map[string]any{
		"tag":      dnsOutTag,
		"protocol": "dns",
		"settings": map[string]any{
			"network":    "udp",
			"address":    "8.8.8.8",
			"port":       53,
			"nonIPQuery": "reject",
		},
	})

	// Shared SOCKS inbound for FakeDNS metadata-only sniffing.
	clientInbounds = append(clientInbounds, map[string]any{
		"tag":      socksMetaTag,
		"listen":   "127.0.0.1",
		"port":     socksMetaPort,
		"protocol": "socks",
		"settings": map[string]any{"udp": false},
		"sniffing": map[string]any{
			"enabled":      true,
			"metadataOnly": true,
			"routeOnly":    true,
			"destOverride": []string{"fakedns"},
		},
	})

	// DNS seed inbound (UDP) routed to DNS outbound.
	clientInbounds = append(clientInbounds, map[string]any{
		"tag":      dnsSeedTag,
		"listen":   "127.0.0.1",
		"port":     dnsSeedPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{
			"address": "8.8.8.8",
			"port":    53,
			"network": "udp",
		},
	})
	clientRules = append(clientRules, map[string]any{
		"type":        "field",
		"inboundTag":  []string{dnsSeedTag},
		"outboundTag": dnsOutTag,
		"ruleTag":     "dns_seed",
	})

	for _, c := range cases {
		// Per-case outbound (VLESS over AXPath) to server per-case inbound.
		clientOutbounds = append(clientOutbounds, map[string]any{
			"tag":      c.clientOutboundTag,
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []any{
					map[string]any{
						"address": "127.0.0.1",
						"port":    c.serverInboundPort,
						"users": []any{
							map[string]any{"id": userID, "encryption": "none"},
						},
					},
				},
			},
			"streamSettings": map[string]any{
				"network":  "axpath",
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":    "localhost",
					"allowInsecure": true,
				},
				"axpathSettings": map[string]any{
					"subflows":  2,
					"reconnect": true,
					"psk":       psk,
				},
			},
		})

		// Per-case direct injection inbounds.
		if c.inject == "direct-tcp" || c.inject == "direct-udp" {
			in := map[string]any{
				"tag":      c.clientInboundTag,
				"listen":   "127.0.0.1",
				"port":     c.clientInboundPort,
				"protocol": "dokodemo-door",
				"settings": map[string]any{
					"address": c.targetAddr,
					"port":    c.targetPort,
					"network": strings.TrimPrefix(c.inject, "direct-"),
				},
			}
			if c.sniffing != nil {
				in["sniffing"] = c.sniffing
			}
			clientInbounds = append(clientInbounds, in)
		}

		// Per-case routing rule.
		r := map[string]any{
			"type":        "field",
			"inboundTag":  []string{c.clientInboundTag},
			"outboundTag": c.clientOutboundTag,
			"ruleTag":     c.name,
		}
		for k, v := range c.clientRuleExtra {
			r[k] = v
		}

		// requireRuleTag needs a marker rule first (no outbound).
		if c.name == "match_require_ruletag" {
			clientRules = append(clientRules, map[string]any{
				"type":       "field",
				"inboundTag": []string{c.clientInboundTag},
				"ruleTag":    "tag_reqtag",
				"domain":     []string{"full:reqtag.local"},
			})
		}

		clientRules = append(clientRules, r)
	}

	clientCfg := map[string]any{
		// Keep this at "info" so failures can be debugged from captured logs.
		"log": map[string]any{"loglevel": "info"},
		"dns": map[string]any{
			"servers":         []any{"fakedns"},
			"disableFallback": true,
		},
		"fakeDns": map[string]any{
			"ipPool":   "198.18.0.0/15",
			"poolSize": 65535,
		},
		"inbounds":  clientInbounds,
		"outbounds": clientOutbounds,
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules":          clientRules,
		},
	}

	serverCfgPath := filepath.Join(tmpDir, "server.json")
	clientCfgPath := filepath.Join(tmpDir, "client.json")
	writeJSONFile(t, serverCfgPath, serverCfg)
	writeJSONFile(t, clientCfgPath, clientCfg)

	// Start acore server/client.
	serverCmd, serverOut := startAcoreWithJSON(t, serverCfgPath)
	defer stopProcess(serverCmd)
	for _, c := range cases {
		if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", c.serverInboundPort), 10*time.Second); err != nil {
			t.Fatalf("server inbound not ready (tag=%s port=%d): %v\n%s", c.serverInboundTag, c.serverInboundPort, err, serverOut.String())
		}
	}

	clientCmd, clientOut := startAcoreWithJSON(t, clientCfgPath)
	defer stopProcess(clientCmd)
	// Wait for all TCP inbounds we will dial directly (and the shared SOCKS inbound).
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", socksMetaPort), 10*time.Second); err != nil {
		t.Fatalf("client socks inbound not ready (port=%d): %v\n%s", socksMetaPort, err, clientOut.String())
	}
	for _, c := range cases {
		if c.inject != "direct-tcp" {
			continue
		}
		if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", c.clientInboundPort), 10*time.Second); err != nil {
			t.Fatalf("client inbound not ready (tag=%s port=%d): %v\n%s", c.clientInboundTag, c.clientInboundPort, err, clientOut.String())
		}
	}

	// Seed FakeDNS mapping via dns outbound.
	seedDomain := "seed-fakedns.local"
	seedID := uint16(0xCAFE)
	seedQuery := buildDNSQueryA(t, seedDomain, seedID)
	var (
		fakeIP  net.IP
		lastErr error
	)
	for attempt := 0; attempt < 10 && (fakeIP == nil || fakeIP.To4() == nil); attempt++ {
		conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dnsSeedPort})
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(seedQuery); err != nil {
				lastErr = err
				return
			}
			buf := make([]byte, 1500)
			n, err := conn.Read(buf)
			if err != nil {
				lastErr = err
				return
			}
			fakeIP = parseDNSAnswerA(t, buf[:n], seedID, seedDomain)
			lastErr = nil
		}()
		if fakeIP != nil && fakeIP.To4() != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if fakeIP == nil || fakeIP.To4() == nil {
		t.Fatalf("failed to seed fakedns mapping (dnsSeedPort=%d): %v\n%s", dnsSeedPort, lastErr, clientOut.String())
	}

	// Execute all cases.
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("client log:\n%s", clientOut.String())
					t.Logf("server log:\n%s", serverOut.String())
				}
			})

			select {
			case <-ctx.Done():
				t.Fatalf("test timeout: %v\nclient:\n%s\nserver:\n%s", ctx.Err(), clientOut.String(), serverOut.String())
			default:
			}

			switch c.inject {
			case "direct-tcp":
				dialAndExchangeTCP(t, c.clientInboundPort, c.localPort, c.payload, c.key)
			case "direct-udp":
				dialAndExchangeUDP(t, c.clientInboundPort, c.localPort, c.payload, c.key)
			case "socks-tcp":
				dest := strings.ReplaceAll(c.socksDest, "{FAKEIP}", fakeIP.String())
				if strings.Contains(dest, "{FAKEIP}") {
					t.Fatalf("fake ip placeholder not substituted: %q", dest)
				}
				dialAndExchangeSocksTCP(t, c.socksAddr, dest, c.payload, c.key)
			default:
				t.Fatalf("unknown inject kind: %q", c.inject)
			}
		})
	}
}
