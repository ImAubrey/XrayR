package router_test

import (
	"context"
	"testing"

	. "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/testing/mocks"
	"github.com/golang/mock/gomock"
)

func TestShouldSniffProtocolDOT(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Protocol: []string{"dot"},
			},
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

	if !r.ShouldSniffProtocol("dot") {
		t.Fatal("expected dot sniffing to be enabled by routing rule")
	}
}
