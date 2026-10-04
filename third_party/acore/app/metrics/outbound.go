package metrics

import "github.com/ImAubrey/acore/app/internal/relayoutbound"

// OutboundListener is a net.Listener for listening metrics HTTP connections.
type OutboundListener = relayoutbound.Listener

// Outbound is an outbound.Handler that handles metrics HTTP connections.
type Outbound = relayoutbound.Handler

func newOutboundListener(bufferSize int) *OutboundListener {
	return relayoutbound.NewListener(bufferSize)
}

func newOutbound(tag string, listener *OutboundListener) *Outbound {
	return relayoutbound.NewHandler(tag, listener)
}
