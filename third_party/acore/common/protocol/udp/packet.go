package udp

import (
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/net"
)

// Packet is a UDP packet together with its source and destination address.
type Packet struct {
	Payload *buf.Buffer
	Source  net.Destination
	Target  net.Destination
}
