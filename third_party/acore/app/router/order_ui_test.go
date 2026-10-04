package router_test

import (
	"context"
	"reflect"
	"testing"

	. "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/serial"
	feature_outbound "github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/testing/mocks"
	"github.com/ImAubrey/acore/transport"
	"github.com/golang/mock/gomock"
)

type orderedOutboundHandler struct {
	tag string
}

func (h *orderedOutboundHandler) Start() error { return nil }

func (h *orderedOutboundHandler) Close() error { return nil }

func (h *orderedOutboundHandler) Tag() string { return h.tag }

func (*orderedOutboundHandler) Dispatch(context.Context, *transport.Link) {}

func (*orderedOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }

func (*orderedOutboundHandler) ProxySettings() *serial.TypedMessage { return nil }

func TestListBalancerTagsPreservesConfigOrder(t *testing.T) {
	config := &Config{
		BalancingRule: []*BalancingRule{
			{Tag: "group-z", OutboundSelector: []string{"node-"}},
			{Tag: "group-a", OutboundSelector: []string{"node-"}},
			{Tag: "group-m", OutboundSelector: []string{"node-"}},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return(nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	got := r.ListBalancerTags()
	want := []string{"group-z", "group-a", "group-m"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListBalancerTags() order mismatch, got=%v want=%v", got, want)
	}
}

func TestPrincipleTargetUsesOutboundConfigOrder(t *testing.T) {
	config := &Config{
		BalancingRule: []*BalancingRule{
			{
				Tag:              "balance",
				Strategy:         "roundrobin",
				OutboundSelector: []string{"node-"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockOhm.EXPECT().ListHandlers(gomock.Any()).Return([]feature_outbound.Handler{
		&orderedOutboundHandler{tag: "node-c"},
		&orderedOutboundHandler{tag: "node-a"},
		&orderedOutboundHandler{tag: "node-b"},
	}).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	got, err := r.GetPrincipleTarget("balance")
	common.Must(err)
	want := []string{"node-c", "node-a", "node-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetPrincipleTarget() order mismatch, got=%v want=%v", got, want)
	}
}
