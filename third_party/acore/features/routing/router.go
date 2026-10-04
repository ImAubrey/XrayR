package routing

import (
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/features"
)

// Router is a feature to choose an outbound tag for the given request.
//
// acore:api:stable
type Router interface {
	features.Feature

	// PickRoute returns a route decision based on the given routing context.
	PickRoute(ctx Context) (Route, error)
	AddRule(config *serial.TypedMessage, shouldAppend bool) error
	RemoveRule(tag string) error
}

// Route is the routing result of Router feature.
//
// acore:api:stable
type Route interface {
	// A Route is also a routing context.
	Context

	// GetOutboundGroupTags returns the detoured outbound group tags in sequence before a final outbound is chosen.
	GetOutboundGroupTags() []string

	// GetOutboundTag returns the tag of the outbound the connection was dispatched to.
	GetOutboundTag() string

	// GetRuleTag returns the matching rule tag for debugging if exists
	GetRuleTag() string
}

// RouterType return the type of Router interface. Can be used to implement common.HasType.
//
// acore:api:stable
func RouterType() interface{} {
	return (*Router)(nil)
}

// DefaultRouter is an implementation of Router, which always returns ErrNoClue for routing decisions.
type DefaultRouter struct{}

// Type implements common.HasType.
func (DefaultRouter) Type() interface{} {
	return RouterType()
}

// PickRoute implements Router.
func (DefaultRouter) PickRoute(ctx Context) (Route, error) {
	return nil, common.ErrNoClue
}

// AddRule implements Router.
func (DefaultRouter) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	return common.ErrNoClue
}

// RemoveRule implements Router.
func (DefaultRouter) RemoveRule(tag string) error {
	return common.ErrNoClue
}

// Start implements common.Runnable.
func (DefaultRouter) Start() error {
	return nil
}

// Close implements common.Closable.
func (DefaultRouter) Close() error {
	return nil
}
