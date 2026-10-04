package dispatcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/core"
)

type branchTestSniffResult struct {
	protocol string
}

func (r branchTestSniffResult) Protocol() string { return r.protocol }
func (branchTestSniffResult) Domain() string     { return "" }

func TestSnifferFiltersByNetworkBranch(t *testing.T) {
	tcpCalls := 0
	udpCalls := 0

	s := &Sniffer{
		sniffer: []protocolSnifferWithMetadata{
			udpSniffer(func(context.Context, []byte) (SniffResult, error) {
				udpCalls++
				return nil, common.ErrNoClue
			}),
			tcpSniffer(func(context.Context, []byte) (SniffResult, error) {
				tcpCalls++
				return nil, common.ErrNoClue
			}),
		},
	}

	_, err := s.Sniff(context.Background(), []byte("GET / HTTP/1.1\r\n\r\n"), net.Network_TCP)
	if !errors.Is(err, common.ErrNoClue) {
		t.Fatalf("expected common.ErrNoClue, got %v", err)
	}
	if tcpCalls != 1 {
		t.Fatalf("expected tcp sniffer called once, got %d", tcpCalls)
	}
	if udpCalls != 0 {
		t.Fatalf("expected udp sniffer not called, got %d", udpCalls)
	}
	if len(s.sniffer) != 1 || s.sniffer[0].network != net.Network_TCP {
		t.Fatalf("expected only tcp branch to remain, got %#v", s.sniffer)
	}
}

func TestSnifferSkipsTLSOnlySniffersForNonTLSPayload(t *testing.T) {
	tlsCalls := 0
	otherCalls := 0

	s := &Sniffer{
		sniffer: []protocolSnifferWithMetadata{
			tcpTLSSniffer(func(context.Context, []byte) (SniffResult, error) {
				tlsCalls++
				return nil, common.ErrNoClue
			}),
			tcpSniffer(func(context.Context, []byte) (SniffResult, error) {
				otherCalls++
				return nil, common.ErrNoClue
			}),
		},
	}

	_, err := s.Sniff(context.Background(), []byte("GET / HTTP/1.1\r\n\r\n"), net.Network_TCP)
	if !errors.Is(err, common.ErrNoClue) {
		t.Fatalf("expected common.ErrNoClue, got %v", err)
	}
	if tlsCalls != 0 {
		t.Fatalf("expected tls-only sniffer to be skipped, got %d calls", tlsCalls)
	}
	if otherCalls != 1 {
		t.Fatalf("expected non-tls sniffer called once, got %d", otherCalls)
	}
	if len(s.sniffer) != 1 || s.sniffer[0].tlsOnly {
		t.Fatalf("expected only non-tls sniffer to remain, got %#v", s.sniffer)
	}
}

func TestSnifferRunsTLSOnlySniffersForTLSPayload(t *testing.T) {
	tlsCalls := 0

	s := &Sniffer{
		sniffer: []protocolSnifferWithMetadata{
			tcpTLSSniffer(func(context.Context, []byte) (SniffResult, error) {
				tlsCalls++
				return branchTestSniffResult{protocol: "tls-test"}, nil
			}),
			tcpSniffer(func(context.Context, []byte) (SniffResult, error) {
				return nil, common.ErrNoClue
			}),
		},
	}

	result, err := s.Sniff(context.Background(), []byte{0x16, 0x03, 0x01, 0x00, 0x00}, net.Network_TCP)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "tls-test" {
		t.Fatalf("expected tls-test result, got %#v", result)
	}
	if tlsCalls != 1 {
		t.Fatalf("expected tls-only sniffer called once, got %d", tlsCalls)
	}
}

func TestSnifferReturnsFastestPositiveMatch(t *testing.T) {
	s := &Sniffer{
		sniffer: []protocolSnifferWithMetadata{
			tcpSniffer(func(context.Context, []byte) (SniffResult, error) {
				time.Sleep(50 * time.Millisecond)
				return branchTestSniffResult{protocol: "slow-positive"}, nil
			}),
			tcpSniffer(func(context.Context, []byte) (SniffResult, error) {
				return branchTestSniffResult{protocol: "fast-positive"}, nil
			}),
		},
	}

	result, err := s.Sniff(context.Background(), []byte("payload"), net.Network_TCP)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil || result.Protocol() != "fast-positive" {
		t.Fatalf("expected fastest positive result, got %#v", result)
	}
}

func TestSnifferZeroTierRespectsContextFlag(t *testing.T) {
	packet := makeZeroTierHelloPacket()
	baseCtx := context.WithValue(context.Background(), core.AcoreKey(1), &core.Instance{})

	disabled := NewSniffer(baseCtx)
	result, err := disabled.Sniff(baseCtx, packet, net.Network_UDP)
	if result != nil && result.Protocol() == "zerotier" {
		t.Fatalf("unexpected zerotier match without enable flag, err=%v", err)
	}

	enabledCtx := context.WithValue(baseCtx, zeroTierSniffingEnabledKey{}, true)
	enabled := NewSniffer(enabledCtx)
	result, err = enabled.Sniff(enabledCtx, packet, net.Network_UDP)
	if err != nil {
		t.Fatalf("expected zerotier match with enable flag, got err=%v", err)
	}
	if result == nil || result.Protocol() != "zerotier" {
		t.Fatalf("expected zerotier result with enable flag, got %#v", result)
	}
}
