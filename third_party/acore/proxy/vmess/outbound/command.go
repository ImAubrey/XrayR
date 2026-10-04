package outbound

import (
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
)

// As a stub command consumer.
func (h *Handler) handleCommand(dest net.Destination, cmd protocol.ResponseCommand) {
	switch cmd.(type) {
	default:
	}
}
