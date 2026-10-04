package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	dispatcherapp "github.com/ImAubrey/acore/app/dispatcher"
	routerapp "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/platform"
	tlsproto "github.com/ImAubrey/acore/common/protocol/tls"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	core "github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/policy"
	"github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

type flowCaptureHandler struct {
	tag     string
	started chan struct{}
	release chan struct{}
	once    sync.Once

	mu        sync.Mutex
	gotJA4    string
	gotJA4Tag string
}

const testAcoreKey core.AcoreKey = 1

func (h *flowCaptureHandler) Tag() string                          { return h.tag }
func (h *flowCaptureHandler) Start() error                         { return nil }
func (h *flowCaptureHandler) Close() error                         { return nil }
func (h *flowCaptureHandler) SenderSettings() *serial.TypedMessage { return nil }
func (h *flowCaptureHandler) ProxySettings() *serial.TypedMessage  { return nil }

func (h *flowCaptureHandler) Dispatch(ctx context.Context, _ *transport.Link) {
	if content := session.ContentFromContext(ctx); content != nil {
		h.mu.Lock()
		h.gotJA4 = content.Attribute("ja4")
		h.gotJA4Tag = content.Attribute("ja4_tag")
		h.mu.Unlock()
	}
	h.once.Do(func() { close(h.started) })
	<-h.release
}

type flowOutboundManager struct {
	handler outbound.Handler
}

func (m *flowOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (m *flowOutboundManager) Start() error      { return nil }
func (m *flowOutboundManager) Close() error      { return nil }
func (m *flowOutboundManager) GetHandler(tag string) outbound.Handler {
	if m.handler != nil && m.handler.Tag() == tag {
		return m.handler
	}
	return nil
}
func (m *flowOutboundManager) GetDefaultHandler() outbound.Handler                { return m.handler }
func (m *flowOutboundManager) AddHandler(context.Context, outbound.Handler) error { return nil }
func (m *flowOutboundManager) RemoveHandler(context.Context, string) error        { return nil }
func (m *flowOutboundManager) ListHandlers(context.Context) []outbound.Handler    { return nil }

type flowNoopWriter struct{}

func (flowNoopWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func buildTLSClientHelloForMetricsJA4Test() []byte {
	handshake := []byte{
		0x01, 0x00, 0x00, 0x2b, // Handshake: ClientHello, length=43
		0x03, 0x03, // legacy_version
	}
	handshake = append(handshake, make([]byte, 32)...) // random
	handshake = append(handshake,
		0x00,       // session_id_len
		0x00, 0x02, // cipher_suites_len
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01,       // compression_methods_len
		0x00,       // compression_method: null
		0x00, 0x00, // extensions_len
	)
	record := []byte{
		0x16, 0x03, 0x01, 0x00, byte(len(handshake)),
	}
	return append(record, handshake...)
}

func TestConnectionsHandlerReportsJA4FromSniffedFlow(t *testing.T) {
	packet := buildTLSClientHelloForMetricsJA4Test()
	sniffResult, err := tlsproto.SniffTLSWithJA4(packet, true)
	if err != nil {
		t.Fatalf("SniffTLSWithJA4 failed: %v", err)
	}
	fingerprint := sniffResult.JA4()
	if fingerprint == "" {
		t.Fatal("expected non-empty JA4 fingerprint from test packet")
	}

	dbPath := filepath.Join(t.TempDir(), "ja4_curated.db")
	dbRaw := []byte(fingerprint + ",source:ja4db\n")
	compiled, err := ja4db.Compile(dbRaw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(dbPath, compiled, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}

	r := &routerapp.Router{}
	cfg := &routerapp.Config{
		Rule: []*routerapp.RoutingRule{
			{
				TargetTag: &routerapp.RoutingRule_Tag{Tag: "tls-out"},
				RuleTag:   "sniffer-socket",
				Attributes: map[string]string{
					"ja4": routerapp.EncodeJA4DBAttributeValue(dbPath, "source:ja4db"),
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init failed: %v", err)
	}

	ctMgr := conntrack.NewManager()
	handler := &flowCaptureHandler{
		tag:     "tls-out",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}

	d := &dispatcherapp.DefaultDispatcher{}
	if err := d.Init(&dispatcherapp.Config{}, &flowOutboundManager{handler: handler}, r, firewall.DefaultManager{}, policy.DefaultManager{}, stats.NoopManager{}, nil, ctMgr); err != nil {
		t.Fatalf("dispatcher init failed: %v", err)
	}

	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.10"), 12345),
		Local:  net.TCPDestination(net.ParseAddress("0.0.0.0"), 7894),
		Tag:    "l_lan",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled: false,
		},
	})
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatalf("build test core instance: %v", err)
	}
	ctx = context.WithValue(ctx, testAcoreKey, v)

	reader, writer := pipe.New()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(packet)}); err != nil {
		t.Fatalf("write test packet failed: %v", err)
	}

	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- d.DispatchLink(ctx, ob.Target, &transport.Link{
			Reader: reader,
			Writer: flowNoopWriter{},
		})
	}()

	select {
	case <-handler.started:
	case err := <-dispatchDone:
		t.Fatalf("dispatch finished unexpectedly before metrics check: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting handler dispatch")
	}

	setConntrackManager(ctMgr)
	defer setConntrackManager(nil)

	snapshot := buildGroupedSnapshot()
	if len(snapshot.Connections) == 0 || len(snapshot.Connections[0].Details) == 0 {
		t.Fatalf("expected active connection snapshot, got %#v", snapshot)
	}
	meta := snapshot.Connections[0].Details[0].Metadata
	if meta.JA4 == "" {
		t.Fatalf("expected metrics metadata JA4, got %+v", meta)
	}
	if meta.JA4Tag != "source:ja4db" {
		t.Fatalf("expected metrics metadata JA4Tag=source:ja4db, got %q", meta.JA4Tag)
	}

	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal snapshot map: %v", err)
	}

	connections, ok := payload["connections"].([]interface{})
	if !ok || len(connections) == 0 {
		t.Fatalf("expected connections in JSON payload, got %#v", payload["connections"])
	}

	handler.mu.Lock()
	gotJA4 := handler.gotJA4
	gotJA4Tag := handler.gotJA4Tag
	handler.mu.Unlock()
	if gotJA4 == "" {
		t.Fatal("expected JA4 attribute in routed handler context")
	}
	if gotJA4Tag != "source:ja4db" {
		t.Fatalf("expected JA4 tag attribute in routed handler context, got %q", gotJA4Tag)
	}

	close(handler.release)
	if err := waitDispatch(dispatchDone, 2*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionsHandlerAutoLabelsJA4WithTriggerOnlyRule(t *testing.T) {
	packet := buildTLSClientHelloForMetricsJA4Test()
	sniffResult, err := tlsproto.SniffTLSWithJA4(packet, true)
	if err != nil {
		t.Fatalf("SniffTLSWithJA4 failed: %v", err)
	}
	fingerprint := sniffResult.JA4()
	if fingerprint == "" {
		t.Fatal("expected non-empty JA4 fingerprint from test packet")
	}

	assetDir := t.TempDir()
	t.Setenv(platform.AssetLocation, assetDir)
	compiled, err := ja4db.Compile([]byte(fingerprint + ",source:ja4db\n"))
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), compiled, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}

	r := &routerapp.Router{}
	cfg := &routerapp.Config{
		Rule: []*routerapp.RoutingRule{
			{
				RuleTag: "sniffer-socket",
				Protocol: []string{
					"tls",
					"rdp",
					"ssh",
					"ech",
					"mtproto",
					"wireguard",
					"zerotier",
				},
				Attributes: map[string]string{
					"ja4": "",
				},
			},
		},
	}
	if err := r.Init(context.Background(), cfg, nil, nil, nil); err != nil {
		t.Fatalf("router init failed: %v", err)
	}

	ctMgr := conntrack.NewManager()
	handler := &flowCaptureHandler{
		tag:     "default-out",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}

	d := &dispatcherapp.DefaultDispatcher{}
	if err := d.Init(&dispatcherapp.Config{}, &flowOutboundManager{handler: handler}, r, firewall.DefaultManager{}, policy.DefaultManager{}, stats.NoopManager{}, nil, ctMgr); err != nil {
		t.Fatalf("dispatcher init failed: %v", err)
	}

	ob := &session.Outbound{
		Target: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("203.0.113.10"), 12345),
		Local:  net.TCPDestination(net.ParseAddress("0.0.0.0"), 7894),
		Tag:    "l_lan",
	})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled: false,
		},
	})
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatalf("build test core instance: %v", err)
	}
	ctx = context.WithValue(ctx, testAcoreKey, v)

	reader, writer := pipe.New()
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(packet)}); err != nil {
		t.Fatalf("write test packet failed: %v", err)
	}

	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- d.DispatchLink(ctx, ob.Target, &transport.Link{
			Reader: reader,
			Writer: flowNoopWriter{},
		})
	}()

	select {
	case <-handler.started:
	case err := <-dispatchDone:
		t.Fatalf("dispatch finished unexpectedly before metrics check: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting handler dispatch")
	}

	setConntrackManager(ctMgr)
	defer setConntrackManager(nil)

	snapshot := buildGroupedSnapshot()
	if len(snapshot.Connections) == 0 || len(snapshot.Connections[0].Details) == 0 {
		t.Fatalf("expected active connection snapshot, got %#v", snapshot)
	}
	meta := snapshot.Connections[0].Details[0].Metadata
	if meta.JA4 == "" {
		t.Fatalf("expected metrics metadata JA4, got %+v", meta)
	}
	if meta.JA4Tag != "source:ja4db" {
		t.Fatalf("expected auto JA4Tag=source:ja4db, got %q", meta.JA4Tag)
	}

	handler.mu.Lock()
	gotJA4 := handler.gotJA4
	gotJA4Tag := handler.gotJA4Tag
	handler.mu.Unlock()
	if gotJA4 == "" {
		t.Fatal("expected JA4 attribute in routed handler context")
	}
	if gotJA4Tag != "source:ja4db" {
		t.Fatalf("expected JA4 tag attribute in routed handler context, got %q", gotJA4Tag)
	}

	close(handler.release)
	if err := waitDispatch(dispatchDone, 2*time.Second); err != nil {
		t.Fatal(err)
	}
}

func waitDispatch(dispatchDone <-chan error, timeout time.Duration) error {
	select {
	case err := <-dispatchDone:
		return err
	case <-time.After(timeout):
		return context.DeadlineExceeded
	}
}
