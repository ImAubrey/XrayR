package net_test

import (
	"testing"

	. "github.com/ImAubrey/acore/common/net"
)

func TestPortRangeContains(t *testing.T) {
	portRange := &PortRange{
		From: 53,
		To:   53,
	}

	if !portRange.Contains(Port(53)) {
		t.Error("expected port range containing 53, but actually not")
	}
}

func TestPortRange_FromToPort_OutOfRangeClampedToZero(t *testing.T) {
	portRange := &PortRange{
		From: 70000,
		To:   70001,
	}

	if got := portRange.FromPort(); got != 0 {
		t.Fatalf("expected FromPort to be 0 for out-of-range input, got %d", got)
	}
	if got := portRange.ToPort(); got != 0 {
		t.Fatalf("expected ToPort to be 0 for out-of-range input, got %d", got)
	}
}

func TestPortListFromProto_OutOfRangeDoesNotWrap(t *testing.T) {
	list := &PortList{
		Range: []*PortRange{
			{From: 53, To: 53},
			{From: 70000, To: 70001},
		},
	}

	got := PortListFromProto(list)
	if len(got) != 2 {
		t.Fatalf("unexpected range count: %d", len(got))
	}
	if got[0].From != 53 || got[0].To != 53 {
		t.Fatalf("unexpected first range: %+v", got[0])
	}
	if got[1].From != 0 || got[1].To != 0 {
		t.Fatalf("expected out-of-range values to be clamped to 0, got %+v", got[1])
	}
}
