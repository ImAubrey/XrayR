package mydispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/transport"

	"github.com/ImAubrey/acore-backend/common/rule"
)

type staticMultiBufferReader struct {
	payload []byte
	read    bool
}

func (r *staticMultiBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.read {
		return nil, nil
	}
	r.read = true
	buffer := buf.New()
	if _, err := buffer.Write(r.payload); err != nil {
		buffer.Release()
		return nil, err
	}
	return buf.MultiBuffer{buffer}, nil
}

func TestCachedReaderWrapsNonPipeReader(t *testing.T) {
	reader := &staticMultiBufferReader{
		payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}
	cReader := &cachedReader{reader: toTimeoutReader(reader)}
	payload := buf.New()
	defer payload.Release()

	if err := cReader.Cache(payload, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	if payload.IsEmpty() {
		t.Fatal("expected cached payload from non-pipe reader")
	}
}

func TestCachedReaderExposesCachedDataForSplice(t *testing.T) {
	type spliceCachedReader interface {
		ReadCachedMultiBuffer() (buf.MultiBuffer, bool)
		UnderlyingReader() buf.TimeoutReader
	}

	reader := &staticMultiBufferReader{
		payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}
	underlying := toTimeoutReader(reader)
	cached := &cachedReader{reader: underlying}
	var cReader spliceCachedReader = cached
	payload := buf.New()
	defer payload.Release()

	if err := cached.Cache(payload, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	mb, ok := cReader.ReadCachedMultiBuffer()
	if !ok || mb.IsEmpty() {
		t.Fatal("expected cached payload to be exposed")
	}
	buf.ReleaseMulti(mb)
	if cReader.UnderlyingReader() != underlying {
		t.Fatal("unexpected underlying reader")
	}
}

type blockingOutboundHandler struct {
	entered chan struct{}
	release chan struct{}
}

func (h *blockingOutboundHandler) Start() error { return nil }

func (h *blockingOutboundHandler) Close() error { return nil }

func (h *blockingOutboundHandler) Tag() string { return "out" }

func (h *blockingOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }

func (h *blockingOutboundHandler) ProxySettings() *serial.TypedMessage { return nil }

func (h *blockingOutboundHandler) Dispatch(context.Context, *transport.Link) {
	close(h.entered)
	<-h.release
}

type testOutboundManager struct {
	handler outbound.Handler
}

func (m *testOutboundManager) Type() interface{} { return outbound.ManagerType() }

func (m *testOutboundManager) Start() error { return nil }

func (m *testOutboundManager) Close() error { return nil }

func (m *testOutboundManager) GetHandler(string) outbound.Handler { return nil }

func (m *testOutboundManager) GetDefaultHandler() outbound.Handler { return m.handler }

func (m *testOutboundManager) AddHandler(context.Context, outbound.Handler) error { return nil }

func (m *testOutboundManager) RemoveHandler(context.Context, string) error { return nil }

func (m *testOutboundManager) ListHandlers(context.Context) []outbound.Handler {
	return []outbound.Handler{m.handler}
}

func TestDispatchLinkWaitsForOutboundDispatch(t *testing.T) {
	handler := &blockingOutboundHandler{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	dispatcher := &DefaultDispatcher{
		ohm:         &testOutboundManager{handler: handler},
		RuleManager: rule.New(),
	}
	done := make(chan error, 1)

	go func() {
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{})
		done <- dispatcher.DispatchLink(
			ctx,
			net.TCPDestination(net.DomainAddress("example.com"), 443),
			&transport.Link{},
		)
	}()

	select {
	case <-handler.entered:
	case <-time.After(time.Second):
		t.Fatal("outbound handler was not dispatched")
	}

	select {
	case err := <-done:
		t.Fatalf("DispatchLink returned before outbound completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(handler.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DispatchLink returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DispatchLink did not return after outbound completed")
	}
}
