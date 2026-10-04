package outbound_test

import (
	"context"
	"fmt"
	gonet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ImAubrey/acore/app/policy"
	"github.com/ImAubrey/acore/app/proxyman"
	. "github.com/ImAubrey/acore/app/proxyman/outbound"
	"github.com/ImAubrey/acore/app/stats"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	core "github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/proxy/freedom"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/stat"
	_ "github.com/ImAubrey/acore/transport/internet/tcp"
)

func TestInterfaces(t *testing.T) {
	_ = (outbound.Handler)(new(Handler))
	_ = (outbound.Manager)(new(Manager))
}

const acoreKey core.AcoreKey = 1

func TestOutboundWithoutStatCounter(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						InboundUplink: true,
					},
				},
			}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature((outbound.Manager)(new(Manager)))
	ctx := context.WithValue(context.Background(), acoreKey, v)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	h, _ := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:           "tag",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
	})
	conn, _ := h.(*Handler).Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146))
	_, ok := conn.(*stat.CounterConnection)
	if ok {
		t.Errorf("Expected conn to not be CounterConnection")
	}
}

func TestOutboundWithStatCounter(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						OutboundUplink:   true,
						OutboundDownlink: true,
					},
				},
			}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature((outbound.Manager)(new(Manager)))
	ctx := context.WithValue(context.Background(), acoreKey, v)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	h, _ := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:           "tag",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
	})
	conn, _ := h.(*Handler).Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146))
	_, ok := conn.(*stat.CounterConnection)
	if !ok {
		t.Errorf("Expected conn to be CounterConnection")
	}
}

func TestDialSetsOutboundConnWhenConcurrentPath(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature((outbound.Manager)(new(Manager)))
	baseCtx := context.WithValue(context.Background(), acoreKey, v)

	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		accepted <- struct{}{}
	}()

	h, err := NewHandler(baseCtx, &core.OutboundHandlerConfig{
		Tag:            "tag",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}), // default tcpConcurrent=true
		ProxySettings:  serial.ToTypedMessage(&freedom.Config{}),
	})
	if err != nil {
		t.Fatalf("failed to build handler: %v", err)
	}

	target := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*gonet.TCPAddr).Port))
	ob := &session.Outbound{Target: target}
	ctx, cancel := context.WithTimeout(session.ContextWithOutbounds(baseCtx, []*session.Outbound{ob}), 3*time.Second)
	defer cancel()

	conn, err := h.(*Handler).Dial(ctx, target)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if ob.Conn == nil {
		t.Fatal("expected outbound session connection to be set")
	}

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("expected backend listener accept")
	}
}

func TestTagsCache(t *testing.T) {

	test_duration := 10 * time.Second
	threads_num := 50
	delay := 10 * time.Millisecond
	tags_prefix := "node"

	tags := sync.Map{}
	counter := atomic.Uint64{}

	ohm, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Error("failed to create outbound handler manager")
	}
	config := &core.Config{
		App: []*serial.TypedMessage{},
	}
	v, _ := core.New(config)
	v.AddFeature(ohm)
	ctx := context.WithValue(context.Background(), acoreKey, v)

	var stopAddRemove atomic.Bool
	wg_add_rm := sync.WaitGroup{}
	addHandlers := func() {
		defer wg_add_rm.Done()
		for !stopAddRemove.Load() {
			time.Sleep(delay)
			idx := counter.Add(1)
			tag := fmt.Sprintf("%s%d", tags_prefix, idx)
			cfg := &core.OutboundHandlerConfig{
				Tag:           tag,
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			}
			if h, err := NewHandler(ctx, cfg); err == nil {
				if err := ohm.AddHandler(ctx, h); err == nil {
					// t.Log("add handler:", tag)
					tags.Store(tag, nil)
				} else {
					t.Error("failed to add handler:", tag)
				}
			} else {
				t.Error("failed to create handler:", tag)
			}
		}
	}

	rmHandlers := func() {
		defer wg_add_rm.Done()
		for !stopAddRemove.Load() {
			time.Sleep(delay)
			tags.Range(func(key interface{}, value interface{}) bool {
				if _, ok := tags.LoadAndDelete(key); ok {
					// t.Log("remove handler:", key)
					ohm.RemoveHandler(ctx, key.(string))
					return false
				}
				return true
			})
		}
	}

	selectors := []string{tags_prefix}
	wg_get := sync.WaitGroup{}
	var stopGet atomic.Bool
	getTags := func() {
		defer wg_get.Done()
		for !stopGet.Load() {
			time.Sleep(delay)
			_ = ohm.Select(selectors)
			// t.Logf("get tags: %v", tag)
		}
	}

	for i := 0; i < threads_num; i++ {
		wg_add_rm.Add(2)
		go rmHandlers()
		go addHandlers()
		wg_get.Add(1)
		go getTags()
	}

	time.Sleep(test_duration)
	stopAddRemove.Store(true)
	wg_add_rm.Wait()
	stopGet.Store(true)
	wg_get.Wait()
}

func TestSetOutboundGatewaySrcipWithFallbackStrategy(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature((outbound.Manager)(new(Manager)))
	ctx := context.WithValue(context.Background(), acoreKey, v)

	sender := &proxyman.SenderConfig{
		Via: &net.IPOrDomain{
			Address: &net.IPOrDomain_Domain{Domain: "srcip"},
		},
		TargetStrategy: internet.DomainStrategy_USE_IP64,
	}

	h, err := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:            "srcip",
		SenderSettings: serial.ToTypedMessage(sender),
		ProxySettings:  serial.ToTypedMessage(&freedom.Config{}),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	ob := &session.Outbound{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})

	srcIP := net.ParseAddress("240d:1b:da:35ff::42")
	inbound := &session.Inbound{
		Source: net.TCPDestination(srcIP, 12345),
	}
	ctx = session.ContextWithInbound(ctx, inbound)

	h.(*Handler).SetOutboundGateway(ctx, ob)

	if ob.Gateway == nil {
		t.Fatal("gateway not set for srcip")
	}
	if !ob.Gateway.Family().IsIPv6() {
		t.Fatalf("gateway family mismatch: %v", ob.Gateway)
	}
	if ip := ob.Gateway.IP(); ip == nil || !ip.Equal(srcIP.IP()) {
		t.Fatalf("gateway IP mismatch: got %v want %v", ob.Gateway, srcIP)
	}
}

func TestNewHandlerPrecompilesSendThrough(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature((outbound.Manager)(new(Manager)))
	ctx := context.WithValue(context.Background(), acoreKey, v)

	sender := &proxyman.SenderConfig{
		Via: &net.IPOrDomain{
			Address: &net.IPOrDomain_Ip{Ip: []byte{10, 0, 0, 1}},
		},
		ViaCidr: "24",
		Via6: &net.IPOrDomain{
			Address: &net.IPOrDomain_Ip{Ip: net.ParseAddress("2001:db8::1").IP()},
		},
		Via6Cidr: "64",
	}

	h, err := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:            "precompile",
		SenderSettings: serial.ToTypedMessage(sender),
		ProxySettings:  serial.ToTypedMessage(&freedom.Config{}),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	settings := h.(*Handler).FreedomDialerSettings()
	if settings == nil {
		t.Fatal("expected precompiled freedom settings")
	}
	if settings.ViaCompiled == nil {
		t.Fatal("expected ipv4 sendThrough plan")
	}
	if settings.Via6Compiled == nil {
		t.Fatal("expected ipv6 sendThrough plan")
	}

	ob := &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 443)}
	ip4 := internet.ParseRandomIPCompiled(context.Background(), settings.ViaCompiled, ob)
	if ip4 == nil {
		t.Fatal("expected ipv4 gateway from compiled plan")
	}
	v4 := ip4.IP().To4()
	if v4 == nil || v4[0] != 10 || v4[1] != 0 || v4[2] != 0 {
		t.Fatalf("ipv4 gateway out of subnet: %v", ip4)
	}

	ip6 := internet.ParseRandomIPCompiled(context.Background(), settings.Via6Compiled, ob)
	if ip6 == nil {
		t.Fatal("expected ipv6 gateway from compiled plan")
	}
	v6 := ip6.IP().To16()
	if v6 == nil || v6.To4() != nil {
		t.Fatalf("expected ipv6 gateway, got %v", ip6)
	}
	if v6[0] != 0x20 || v6[1] != 0x01 || v6[2] != 0x0d || v6[3] != 0xb8 {
		t.Fatalf("ipv6 gateway out of subnet: %v", ip6)
	}
}
