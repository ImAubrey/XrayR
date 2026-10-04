package firewall

import (
	"context"
	"time"

	"github.com/ImAubrey/acore/features"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/routing"
)

// Action is the result of firewall evaluation for a connection.
type Action uint8

const (
	ActionAllow Action = iota
	ActionBlock
)

// Decision describes the terminal firewall outcome for a connection.
type Decision struct {
	Action            Action
	RuleTag           string
	CounterMode       conntrack.CounterMode
	CounterType       conntrack.CounterType
	SourceIP          string
	DestinationIP     string
	SourcePrefix      string
	DestinationPrefix string
	Count             uint32
	Max               uint32
	Window            time.Duration
}

// FlowObserver inspects the actual routed byte stream and may trigger firewall action later.
type FlowObserver interface {
	OnUpload([]byte)
	OnDownload([]byte)
	OnClose(error)
}

// FlowObserverCloner creates an independent observer for a single transport connection.
// A routed request may trigger multiple concurrent dial attempts; each attempt must keep
// its own detector state to avoid cross-connection contamination.
type FlowObserverCloner interface {
	CloneFlowObserver() FlowObserver
}

// Manager evaluates firewall rules against routing/session context.
type Manager interface {
	features.Feature
	Evaluate(ctx context.Context, routingCtx routing.Context) Decision
	ShouldSniffProtocol(protocol string) bool
	ShouldSniffProtocolForContext(protocol string, ctx routing.Context) bool
	NewFlowObserver(ctx context.Context, routingCtx routing.Context, onDecision func(Decision)) FlowObserver
}

// ManagerType returns the type marker for firewall manager.
func ManagerType() interface{} {
	return (*Manager)(nil)
}

// DefaultManager is a no-op firewall implementation.
type DefaultManager struct{}

// Type implements common.HasType.
func (DefaultManager) Type() interface{} {
	return ManagerType()
}

// Evaluate allows all connections.
func (DefaultManager) Evaluate(ctx context.Context, routingCtx routing.Context) Decision {
	_ = ctx
	_ = routingCtx
	return Decision{Action: ActionAllow}
}

// ShouldSniffProtocol reports no extra sniffing requirement.
func (DefaultManager) ShouldSniffProtocol(protocol string) bool {
	_ = protocol
	return false
}

// ShouldSniffProtocolForContext reports no extra sniffing requirement.
func (DefaultManager) ShouldSniffProtocolForContext(protocol string, ctx routing.Context) bool {
	_ = protocol
	_ = ctx
	return false
}

// NewFlowObserver reports no live stream inspection requirement.
func (DefaultManager) NewFlowObserver(ctx context.Context, routingCtx routing.Context, onDecision func(Decision)) FlowObserver {
	_ = ctx
	_ = routingCtx
	_ = onDecision
	return nil
}

type contextKey struct{}

// ContextWithFlowObserver stores a stream observer in context for transport dialers.
func ContextWithFlowObserver(ctx context.Context, observer FlowObserver) context.Context {
	if observer == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, observer)
}

// FlowObserverFromContext retrieves a stream observer from context.
func FlowObserverFromContext(ctx context.Context) FlowObserver {
	if ctx == nil {
		return nil
	}
	if observer, ok := ctx.Value(contextKey{}).(FlowObserver); ok {
		return observer
	}
	return nil
}

// Start implements common.Runnable.
func (DefaultManager) Start() error { return nil }

// Close implements common.Closable.
func (DefaultManager) Close() error { return nil }
