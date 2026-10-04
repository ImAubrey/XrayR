package outbound

import (
	"context"
	"reflect"
	"testing"

	"github.com/ImAubrey/acore/app/proxyman"
	"github.com/ImAubrey/acore/common/serial"
	feature_outbound "github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/transport"
)

type testHandler struct {
	tag string
}

func (h *testHandler) Start() error { return nil }

func (h *testHandler) Close() error { return nil }

func (h *testHandler) Tag() string { return h.tag }

func (*testHandler) Dispatch(context.Context, *transport.Link) {}

func (*testHandler) SenderSettings() *serial.TypedMessage { return nil }

func (*testHandler) ProxySettings() *serial.TypedMessage { return nil }

func TestManagerListHandlersPreservesAddOrder(t *testing.T) {
	m, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	add := func(tag string) {
		if err := m.AddHandler(context.Background(), &testHandler{tag: tag}); err != nil {
			t.Fatalf("AddHandler(%q) error = %v", tag, err)
		}
	}

	// Keep one untagged handler to verify list layout remains:
	// [untagged..., tagged in config order...].
	add("")
	add("node-c")
	add("node-a")
	add("node-b")

	list := m.ListHandlers(context.Background())
	got := make([]string, 0, len(list))
	for _, h := range list {
		if h == nil {
			got = append(got, "<nil>")
			continue
		}
		got = append(got, h.Tag())
	}

	want := []string{"", "node-c", "node-a", "node-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListHandlers() order mismatch, got=%v want=%v", got, want)
	}

	if err := m.RemoveHandler(context.Background(), "node-a"); err != nil {
		t.Fatalf("RemoveHandler() error = %v", err)
	}
	list = m.ListHandlers(context.Background())
	got = got[:0]
	for _, h := range list {
		got = append(got, h.Tag())
	}
	want = []string{"", "node-c", "node-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListHandlers() order after remove mismatch, got=%v want=%v", got, want)
	}
}

var _ feature_outbound.Handler = (*testHandler)(nil)
