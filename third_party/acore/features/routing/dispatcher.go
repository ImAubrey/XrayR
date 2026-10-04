package routing

import (
	"context"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/features"
	"github.com/ImAubrey/acore/transport"
)

// Dispatcher is a feature that dispatches inbound requests to outbound handlers based on rules.
// Dispatcher is required to be registered in a Acore instance to make Acore function properly.
//
// acore:api:stable
type Dispatcher interface {
	features.Feature

	// Dispatch returns a Ray for transporting data for the given request.
	Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error)
	DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error
}

// DispatcherType returns the type of Dispatcher interface. Can be used to implement common.HasType.
//
// acore:api:stable
func DispatcherType() interface{} {
	return (*Dispatcher)(nil)
}

// Just for type assertion
type WrapLinkDispatcher interface {
	Dispatcher
	WrapLink(ctx context.Context, link *transport.Link) *transport.Link
}
